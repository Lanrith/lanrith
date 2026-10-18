"""Check mandatory defaults independently of an owner's ordinary access list."""

import copy
from pathlib import Path
import unittest

from lanrith import config
from lanrith.release import ReleaseError


ROOT = Path(__file__).resolve().parents[1]


class FirewallDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.value = config.load(ROOT/'examples/segmented.yaml')

    def firewall(self):
        return config.render(self.value)['etc/nftables.conf']

    def test_input_forward_and_output_all_default_to_deny(self):
        text = self.firewall()
        for chain in ('input', 'forward', 'output'):
            self.assertIn(f'chain {chain} {{ type filter hook {chain} priority filter; policy drop;', text)

    def test_wan_cannot_spoof_declared_connected_or_routed_networks(self):
        self.value['networks']['home']['routed_prefixes'] = ['10.30.0.0/16', 'fd42:3000::/48']
        text = self.firewall()
        for prefix in ('192.168.10.0/24', '172.20.20.0/24', '10.30.0.0/16', 'fd42:3000::/48'):
            lines = [line for line in text.splitlines() if 'iifname "wan"' in line and 'saddr' in line and 'drop' in line]
            self.assertTrue(any(prefix in line for line in lines), prefix)
        # Private/CGNAT uplinks are valid; do not blacklist all private space.
        self.assertNotIn('iifname "wan" ip saddr { 10.0.0.0/8', text)

    def test_invalid_guard_precedes_wildcard_policy_and_return_permit(self):
        self.value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any'}]}
        text = self.firewall()
        forward = text[text.index('chain forward'):text.index('chain output')]
        self.assertLess(forward.index('ct state invalid,untracked drop'), forward.index('ct state { new, established, related } accept'))

    def test_disabled_forwarding_blocks_both_directions_before_policy_and_nat(self):
        self.value['networks']['guest']['forwarding'] = False
        self.value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any'}]}
        text = self.firewall()
        forward = text[text.index('chain forward'):text.index('chain output')]
        for direction in ('iifname', 'oifname'):
            self.assertLess(forward.index(direction+' "lan.20" drop'), forward.index('ct state { new, established, related } accept'))
        self.assertNotIn('ip saddr 172.20.20.0/24 oifname "wan" masquerade', text)

    def test_dhcp_and_router_advertisements_follow_the_selected_uplink_mode(self):
        self.value['uplink'] = {'interface': 'wan', 'ipv4': 'disabled', 'ipv6': 'disabled'}
        text = self.firewall()
        self.assertNotIn('iifname "wan" udp sport 67 udp dport 68 accept', text)
        self.assertNotIn('oifname "wan" udp sport 68 udp dport 67 accept', text)
        self.assertNotIn('iifname "wan" ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert', text)
        self.value['uplink'] = {'interface': 'wan'}
        text = self.firewall()
        self.assertIn('iifname "wan" udp sport 67 udp dport 68 accept', text)
        self.assertIn('iifname "wan" ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert icmpv6 code 0 accept', text)

    def test_dhcp_bootstrap_is_local_and_zero_sources_cannot_be_forwarded(self):
        text = self.firewall()
        self.assertIn('ip saddr 0.0.0.0 ip daddr { 255.255.255.255, 192.168.10.1 } udp sport 68 udp dport 67 accept', text)
        self.assertNotIn('ip saddr 0.0.0.0 udp sport 68 udp dport 67 accept', text)
        forward = text[text.index('chain forward'):text.index('chain output')]
        self.assertIn('ip saddr { 0.0.0.0/8,', forward)

    def test_ipv6_control_is_scoped_to_declared_interfaces_and_valid_link_hops(self):
        text = self.firewall()
        self.assertIn('iifname { "lan.10", "lan.20", "wan" } ip6 hoplimit 255 icmpv6 type', text)
        self.assertIn('icmpv6 code 0 accept', text)
        self.assertIn('ip6 daddr ff02::1:ff00:0/104', text)
        self.assertIn('ip6 saddr { ::/128, ::1/128, fe80::/10 } drop', text)

    def test_management_and_services_are_generated_with_exact_address_scopes(self):
        text = self.firewall()
        self.assertIn('iifname "lan.10" ip saddr { 192.168.10.0/24 } ip daddr { 192.168.10.1 } tcp dport 22 accept', text)
        self.assertNotIn('ip daddr { 172.20.20.1 } tcp dport 22 accept', text)
        self.value['networks']['guest']['dns'] = False
        text = self.firewall()
        self.assertNotIn('ip daddr { 172.20.20.1 } udp dport 53 accept', text)

    def test_service_egress_is_selected_and_account_scoped(self):
        text = self.firewall()
        self.assertIn('meta skuid "unbound" udp dport 53 accept', text)
        self.assertNotIn('meta skuid "_chrony" udp dport 123 accept', text)
        self.assertNotIn('tcp dport 443 accept', text)
        self.value['services']['ntp'] = {'enabled': True}
        self.assertIn('meta skuid "_chrony" udp dport 123 accept', self.firewall())

    def test_overlapping_or_unbounded_routed_prefixes_are_rejected(self):
        for prefixes in (['0.0.0.0/0'], ['172.20.20.0/24'], ['10.30.0.0/16', '10.30.1.0/24'],
                         ['fe80::/64'], ['bad'], ['10.30.0.0/16']*33):
            value = copy.deepcopy(self.value)
            value['networks']['home']['routed_prefixes'] = prefixes
            with self.subTest(prefixes=prefixes), self.assertRaises(ReleaseError):
                config.normalize(value)


if __name__ == '__main__':
    unittest.main()
