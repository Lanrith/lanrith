"""Check mandatory defaults independently of an owner's ordinary access list."""

import copy
import json
import ipaddress
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from lanrith import config, firewall, firewall_activation, service_plane
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
        self.assertLess(forward.index('ct state invalid,untracked drop'), forward.index('goto tp_access'))

    def test_unconfigured_interfaces_cannot_inherit_wildcard_owner_permission(self):
        self.value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any',
                                        'authorization': 'owner'}]}
        text = self.firewall()
        self.assertIn('iifname != { "wan", "lan.10", "lan.20", "lr-services" } drop', text)
        self.assertLess(text.index('iifname !='), text.index('chain forward'))

    def test_disabled_forwarding_blocks_both_directions_before_policy_and_nat(self):
        self.value['networks']['guest']['forwarding'] = False
        self.value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any'}]}
        text = self.firewall()
        forward = text[text.index('chain forward'):text.index('chain output')]
        for direction in ('iifname', 'oifname'):
            self.assertLess(forward.index(direction+' "lan.20" drop'), forward.index('goto tp_access'))
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
        self.assertIn('iifname { "lan.10", "lan.20", "wan", "lr-services" } ip6 hoplimit 255 icmpv6 type', text)
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
        self.value['services']['ntp'] = {'enabled': True, 'upstreams': ['192.0.2.123']}
        files = config.render(self.value)
        text = files['etc/lanrith/services.nft']
        self.assertIn('meta skuid "unbound" ip saddr', text)
        self.assertIn('meta skuid "_chrony" ip saddr', text)
        self.assertNotIn('tcp dport 443 accept', text)
        self.assertNotIn('meta skuid "unbound"', files['etc/nftables.conf'])
        self.value['services']['ntp'] = {'enabled': False}
        self.assertNotIn('meta skuid "_chrony"', config.render(self.value)['etc/lanrith/services.nft'])

    def test_public_resolver_and_both_filters_agree_on_wan_destinations(self):
        for upstreams, disabled_v4 in (([], False), (['2001:db8::53', '2001:db8::54'], False),
                                        (['192.0.2.53', '2001:db8::53'], False),
                                        (['192.0.2.53', '2001:db8::53'], True)):
            with self.subTest(upstreams=upstreams, disabled_v4=disabled_v4):
                self.value['uplink']['ipv4'] = 'disabled' if disabled_v4 else 'dhcp'
                self.value['services']['dns']['upstreams'] = upstreams
                rendered = config.render(self.value)
                dns = rendered['etc/unbound/unbound.conf.d/lanrith.conf']
                self.assertEqual([line.split()[-1] for line in dns.splitlines() if 'forward-addr:' in line], upstreams)
                host = [line for line in rendered['etc/nftables.conf'].splitlines()
                        if 'iifname "lr-services" oifname "wan"' in line and 'dport 53' in line]
                namespace = [line for line in rendered['etc/lanrith/services.nft'].splitlines()
                             if line.startswith('meta skuid "unbound"') and 'dport 53' in line]
                model = [path for path in service_plane.egress(config.normalize(self.value)) if path['kind'] == 'dns']
                for family, spelling in ((4, 'ip'), (6, 'ip6')):
                    expected = {address for address in upstreams if (':' in address) == (family == 6)}
                    active = (bool(expected) or not upstreams) and (family == 6 or not disabled_v4)
                    entries = [path for path in model if (':' in path['address']) == (family == 6)]
                    targets = {target for entry in entries for target in entry['destinations']}
                    self.assertEqual(targets, ({str(ipaddress.ip_network(addr)) for addr in expected} or
                                     {'::/0' if family == 6 else '0.0.0.0/0'}) if active else set())
                    for protocol in ('tcp', 'udp'):
                        for rules in (host, namespace):
                            selected = [line for line in rules if spelling+' saddr' in line
                                        and protocol+' dport 53 accept' in line]
                            self.assertEqual(bool(selected), active)
                            destinations = set()
                            for line in selected:
                                if ' daddr ' in line:
                                    scope = line.split(' daddr ', 1)[1].split(protocol+' dport')[0]
                                    destinations.update(scope.strip('{} ').split(', '))
                                else:
                                    self.assertFalse(expected)
                            self.assertEqual(destinations, expected if active else set())

    def test_dns_over_tls_scopes_both_wan_filters_to_exact_tcp_endpoints(self):
        value = config.normalize(self.value)
        peer = '2001:db8:1::53'
        value['services']['dns']['tls_forwarding'] = {
            'trust': 'system', 'upstreams': [{'address': peer, 'authentication_name': 'dns.example.test'}]}
        plane = service_plane.topology(value)
        host = [line.strip() for line in firewall.core_forward(value, plane)
                if 'iifname "lr-services" oifname "wan"' in line and 'dport 123' not in line]
        namespace = [line for line in service_plane.namespace_firewall(value, plane).splitlines()
                     if line.startswith('meta skuid "unbound"') and ' dport ' in line]
        self.assertEqual(host, [f'iifname "lr-services" oifname "wan" ip6 saddr {{ {plane["endpoints"]["dns"][1]} }} '
                                f'ip6 daddr {peer} tcp dport 853 accept'])
        self.assertEqual(namespace, [f'meta skuid "unbound" ip6 saddr {{ {plane["endpoints"]["dns"][1]} }} '
                                     f'ip6 daddr {{ {peer} }} tcp dport 853 accept'])
        self.assertEqual([p['kind'] for p in service_plane.egress(value) if p['kind'].startswith('dns')], ['dns_tls'])

    def test_recovery_floor_allows_only_explicitly_administered_management(self):
        self.value['hardware']['interfaces']['rescue'] = {'name': 'rescue0', 'match': {'mac': '02:00:00:00:01:03'}}
        self.value['networks']['rescue'] = {'interface': 'rescue', 'role': 'management', 'addresses': ['192.0.2.1/28']}
        def policies():
            files = config.render(self.value)
            return files, files[firewall_activation.FLOOR.lstrip('/')]
        files, floor = policies()
        self.assertEqual(floor.count('policy drop;'), 3)
        self.assertNotIn('tcp ', floor)
        self.value['administration']['networks'].append('rescue')
        self.value['administration']['ssh_port'] = 2222
        self.value['networks']['rescue']['additional_subnets'] = ['192.0.2.64/28']
        files, floor = policies()
        self.assertIn('iifname "rescue0" ip saddr 192.0.2.0/28 ip daddr 192.0.2.1 tcp dport 2222', floor)
        self.assertIn('ct direction reply ct state established accept', floor)
        self.assertNotIn('lan.10', floor)
        self.assertNotIn('192.0.2.64/28', floor)
        self.assertNotIn('flush ruleset', floor)
        for unit in ('ssh.service.d/10-lanrith-firewall.conf', 'systemd-networkd.service.d/60-lanrith-firewall-floor.conf'):
            prerequisite = files['etc/systemd/system/'+unit]
            self.assertIn('Requires=lanrith-firewall-floor.service', prerequisite)
            self.assertIn('After=lanrith-firewall-floor.service', prerequisite)
        start = files['etc/systemd/system/nftables.service.d/60-lanrith-activation.conf']
        self.assertIn('ExecReload=\nExecStop=\nExecStopPost=/usr/sbin/nft -f '+firewall_activation.FLOOR, start)
        self.assertIn('RuntimeDirectoryPreserve=yes', start)
        self.assertNotIn('ip_forward', files[firewall_activation.HARDENING.lstrip('/')])
        simple = config.render(config.load(ROOT/'examples/simple.yaml'))
        self.assertEqual(simple[firewall_activation.FORWARDING.lstrip('/')],
                         'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=0\n')

    def test_activation_finishes_behind_floor_and_restart_retains_kernel_objects(self):
        nft = firewall_activation.NFT
        hooks = [{'chain': {'family': 'inet', 'table': 'lanrith', 'type': 'filter', 'hook': hook,
                            'name': hook, 'policy': 'drop'}} for hook in ('input', 'forward', 'output')]
        table = {'table': {'family': 'inet', 'name': 'lanrith'}}
        with tempfile.TemporaryDirectory() as root, mock.patch.object(subprocess, 'run') as run:
            stamp = Path(root)/'installed'
            run.side_effect = subprocess.CalledProcessError(1, 'nft')
            with self.assertRaises(subprocess.CalledProcessError):
                firewall_activation.activate(stamp)
            self.assertFalse(stamp.exists())
            run.reset_mock(side_effect=True)
            run.return_value.stdout = json.dumps({'nftables': [table, *hooks[:2]]}).encode()
            with self.assertRaises(RuntimeError):
                firewall_activation.activate(stamp)
            self.assertFalse(stamp.exists())
            self.assertEqual(run.call_count, 2)
            run.reset_mock()
            run.return_value.stdout = json.dumps({'nftables': [table, *hooks]}).encode()
            firewall_activation.activate(stamp)
            self.assertTrue(stamp.exists())
            self.assertEqual(run.call_args_list[0].kwargs['input'].decode().splitlines(), [
                'include "/etc/nftables.conf"', f'include "{firewall_activation.FLOOR}"'])
            actions = [call.args[0] for call in run.call_args_list]
            self.assertEqual(actions[1:], [[nft, '-j', '-t', 'list', 'table', 'inet', 'lanrith'],
                ['/usr/lib/systemd/systemd-sysctl', '--strict', firewall_activation.FORWARDING, firewall_activation.HARDENING],
                [nft, 'delete', 'table', 'inet', 'lanrith_recovery']])
            run.reset_mock()
            firewall_activation.activate(stamp)
            self.assertEqual([call.args[0] for call in run.call_args_list], actions[1:])

    def test_selected_masquerading_includes_routed_sources_without_granting_access(self):
        self.value['networks']['home']['routed_prefixes'] = ['10.30.0.0/16']
        self.value['access'] = {'rules': []}
        text = self.firewall()
        self.assertIn('ip saddr 10.30.0.0/16 oifname "wan" masquerade', text)
        forward = text[text.index('chain forward'):text.index('chain output')]
        self.assertFalse(any('iifname "lan.10" oifname "wan"' in rule and not rule.endswith(' drop')
                             for rule in forward.splitlines()))
        self.value['networks']['home']['forwarding'] = False
        self.assertNotIn('ip saddr 10.30.0.0/16 oifname "wan" masquerade', self.firewall())

    def test_overlapping_or_unbounded_routed_prefixes_are_rejected(self):
        for prefixes in (['0.0.0.0/0'], ['172.20.20.0/24'], ['10.30.0.0/16', '10.30.1.0/24'],
                         ['fe80::/64'], ['bad'], ['10.30.0.0/16']*33):
            value = copy.deepcopy(self.value)
            value['networks']['home']['routed_prefixes'] = prefixes
            with self.subTest(prefixes=prefixes), self.assertRaises(ReleaseError):
                config.normalize(value)


if __name__ == '__main__':
    unittest.main()
