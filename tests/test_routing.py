"""Routing supplies reachability while data-plane access remains explicit."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from lanrith import config, routing, routing_runtime
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
    value['groups'] = {'work': ['fd42:1234:5678:400::/56'],
                       'vpn': ['fd42:9876:5432::/48']}
    value['access'] = {'default': 'deny', 'rules': []}
    value['routing'] = {'static_routes': [
        {'to': 'fd42:1234:5678:500::/64', 'network': 'home', 'on_link': True}],
        'bgp': {'enabled': True, 'asn': 64520, 'network': 'home', 'peer_groups': {
            'nodes': {'remote_asn': 64521, 'import': [
                {'group': 'work', 'prefix_length': 64, 'purpose': 'network'}],
                'maximum_prefixes': 17, 'peers': {'node-a': 'fd42:1234:5678:10::20'}},
            'vpn': {'remote_asn': 64522, 'network': 'home', 'import': [
                {'group': 'vpn', 'exact': True, 'purpose': 'network'}],
                'credential': 'vpn_bgp', 'hold_seconds': 9,
                'maximum_prefixes': 1, 'services': ['dns'],
                'dynamic': {'enabled': True, 'range': 'fd42:1234:5678:10::e100/120',
                            'maximum_peers': 8}}}}}
    return value


class RoutingTests(unittest.TestCase):
    def test_bounded_imports_no_exports_and_explicit_control_plane(self):
        value = config.normalize(declaration())
        files = config.render(value)
        text = files['etc/frr/frr.conf']
        self.assertIn('fd42:1234:5678:400::/56 ge 64 le 64', text)
        self.assertIn('permit fd42:9876:5432::/48\n', text)
        self.assertIn('neighbor LR1 timers 3 9', text)
        self.assertIn('neighbor LR0 maximum-prefix 17', text)
        self.assertIn('route-map LR0-OUT deny 10', text)
        self.assertNotIn('redistribute', text)
        self.assertNotIn('default-originate', text)
        self.assertIn('bgp listen limit 8', text)
        self.assertIn('Destination=fd42:1234:5678:500::/64\nScope=link', files[
            'etc/systemd/network/40-home.network'])
        firewall = files['etc/nftables.conf']
        self.assertIn('ip6 saddr { fd42:1234:5678:10::e100/120 } '
                      'ip6 daddr { fd42:1234:5678:10::1 } tcp dport 179 accept', firewall)
        self.assertIn('meta skuid "frr" oifname "lan"', firewall)
        forward = firewall.split(' chain forward {')[1].split(' chain output {')[0]
        self.assertNotIn('dport 179', forward)
        self.assertNotIn('ip6 daddr { fd42:1234:5678:400::/56 }', forward)
        # VPN service permission is DNS only, not general router admission.
        self.assertIn('ip6 saddr { fd42:9876:5432::/48 } ip6 daddr '
                      '{ fd42:1234:5678:fe02::10 } tcp dport 53 accept', forward)
        self.assertNotIn('ip6 saddr { fd42:9876:5432::/48 } ip6 daddr '
                         '{ fd42:1234:5678:fe02::40 }', forward)
        self.assertIn('access-control: fd42:9876:5432::/48 allow',
                      files['etc/unbound/unbound.conf.d/lanrith.conf'])
        self.assertNotIn('allow fd42:9876:5432::/48', files['etc/chrony/chrony.conf'])
        self.assertEqual(value, config.normalize(value))

    def test_disabled_bgp_removes_peer_services_credentials_and_prefixes(self):
        value = declaration()
        value['routing']['bgp']['enabled'] = False
        files = config.render(value)
        self.assertFalse(any('frr' in name or 'routing.json' in name for name in files))
        self.assertNotIn('fd42:9876:5432::/48', files['etc/nftables.conf'])
        self.assertNotIn('fd42:9876:5432::/48', files['etc/unbound/unbound.conf.d/lanrith.conf'])
        self.assertIn('[Route]', files['etc/systemd/network/40-home.network'])

    def test_additional_attachments_keep_their_own_gateway_without_ra(self):
        value = declaration()
        value['networks']['home']['additional_subnets'] = ['fd42:1234:5678:500::60/124',
                                                          'fd42:1234:5678:500::80/124']
        files = config.render(value)
        text = files['etc/systemd/network/40-home.network']
        self.assertIn('Address=fd42:1234:5678:500::61/124', text)
        self.assertIn('Address=fd42:1234:5678:500::81/124', text)
        self.assertNotIn('Prefix=fd42:1234:5678:500::', text)

    def test_router_identifier_is_stable_without_ipv4(self):
        value = declaration()
        del value['networks']['home']['ipv4'], value['networks']['home']['dhcp4']
        files = config.render(value)
        self.assertRegex(files['etc/frr/frr.conf'], r'bgp router-id 10\.\d+\.\d+\.\d+')

    def test_static_route_does_not_admit_new_source_identities(self):
        value = declaration()
        value['routing']['bgp']['enabled'] = False
        files = config.render(value)
        self.assertIn('Destination=fd42:1234:5678:500::/64', files['etc/systemd/network/40-home.network'])
        self.assertNotIn('fd42:1234:5678:500::/64', files['etc/nftables.conf'])

    def test_reject_routes_into_other_attachments_and_control_addresses(self):
        for prefix in ('fd42:1234:5678:fe02::/64', 'fd42:1234:5678:10::/64', '192.168.10.1/32'):
            value = declaration()
            value['routing']['static_routes'][0]['to'] = prefix
            with self.subTest(prefix=prefix), self.assertRaises(ReleaseError):
                config.normalize(value)
        value = declaration()
        value['networks']['guest'] = {'interface': 'lan', 'vlan': 30, 'ipv4': '192.168.30.0/24'}
        value['routing']['static_routes'][0]['to'] = '192.168.30.0/24'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_static_routes_cannot_claim_the_provider_service_subnet(self):
        value = declaration()
        value['uplink']['ipv6'] = {'address': '2001:db8:20::2/48', 'gateway': '2001:db8:20::1',
                                  'downstream_prefix': '2001:db8:20::/48', 'delivery': 'on_link'}
        value['routing']['static_routes'][0]['to'] = '2001:db8:20:fe02::/64'
        with self.assertRaisesRegex(ReleaseError, 'managed service'):
            config.normalize(value)

    def test_dynamic_limits_cannot_be_silently_merged(self):
        value = declaration()
        groups = value['routing']['bgp']['peer_groups']
        groups['extra'] = copy.deepcopy(groups['vpn'])
        groups['extra']['dynamic']['range'] = 'fd42:1234:5678:10::e200/120'
        with self.assertRaisesRegex(ReleaseError, 'One bounded'):
            config.normalize(value)

    def test_unsafe_dsr_remains_gated(self):
        value = declaration()
        value['routing']['asymmetric_replies'] = [{
            'mode': 'tcp_dsr', 'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::/64'},
            'to': {'network': 'home', 'group': 'work'}}]
        with self.assertRaisesRegex(ReleaseError, 'asymmetric repl'):
            config.render(value)

    def test_credentials_are_references_not_build_inputs(self):
        value = config.normalize(declaration())
        files = config.render(value)
        manifest = json.loads(files['usr/share/lanrith/routing.json'])
        self.assertEqual(manifest['credentials'], {'@LANRITH_BGP_1@': 'vpn_bgp'})
        self.assertIn('LoadCredential=vpn_bgp:/var/lib/lanrith/credentials/vpn_bgp',
                      files['usr/lib/systemd/system/lanrith-routing-credentials.service'])
        self.assertIn('BindReadOnlyPaths=/run/lanrith-routing/frr.conf:/etc/frr/frr.conf',
                      files['etc/systemd/system/frr.service.d/60-lanrith-routing.conf'])

    @unittest.skipUnless(os.geteuid() == 0, 'systemd credentials require root ownership')
    def test_credential_materialization_is_atomic_and_rejects_injection(self):
        manifest = json.loads(config.render(declaration())['usr/share/lanrith/routing.json'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root/'vpn_bgp', root/'frr.conf'
            source.write_text('synthetic-test-password\n')
            source.chmod(0o600)
            routing_runtime.materialize(manifest, root, target)
            original = target.read_bytes()
            self.assertIn(b'neighbor LR1 password synthetic-test-password\n', original)
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            for bad in ('bad\nrouter bgp 1', 'bad password', 'bad;password', '@unresolved@', 'x'*81):
                source.write_text(bad)
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    routing_runtime.materialize(manifest, root, target)
                self.assertEqual(target.read_bytes(), original)
            source.write_text('safe')
            source.chmod(0o644)
            with self.assertRaises(ValueError):
                routing_runtime.materialize(manifest, root, target)
            source.unlink()
            source.symlink_to(target)
            with self.assertRaises(OSError):
                routing_runtime.materialize(manifest, root, target)
            self.assertEqual(target.read_bytes(), original)
