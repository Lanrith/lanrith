"""The alias and IPv6 destination share ordered policy, never an implicit permit."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import build, config, firewall, nat46, translation_runtime
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['hardware']['interfaces']['servers'] = {'match': {'mac': '02:00:00:00:03:01'}}
    value['networks']['servers'] = {'interface': 'servers',
                                  'ipv6': {'subnet_id': 32, 'gua': False, 'ra': False}}
    value['translation'] = {'nat46': {'enabled': True, 'mappings': {
        'service'+str(i): {'ipv4': '10.255.200.'+str(i+2), 'ipv6': 'fd42:1234:5678:20::'+str(i+10)}
        for i in range(6)}}}
    value['access'] = {'default': 'deny', 'rules': [
        {'action': 'deny', 'from': {'network': 'home', 'addresses': '192.168.10.90'},
         'to': 'servers'},
        {'action': 'allow', 'from': 'home', 'to': {'translation': 'nat46'},
         'protocol': ['tcp', 'udp', 'icmp'], 'authorization': 'owner'}]}
    return value


class Nat46Tests(unittest.TestCase):
    def test_translated_destination_keeps_address_with_its_attachment(self):
        value = config.normalize(declaration())
        entry = next(iter(nat46.component(value)['mappings'].values()))
        for selected, expected in (
                ({'interface': 'nat46', 'addresses': entry['ipv4']}, True),
                ({'network': 'servers', 'addresses': entry['ipv6']}, True),
                ({'interface': 'nat46', 'addresses': entry['ipv6']}, False),
                ({'network': 'servers', 'addresses': entry['ipv4']}, False)):
            with self.subTest(selected=selected):
                rule = {'action': 'allow', 'from': 'home', 'to': selected}
                self.assertEqual(nat46.destinations(value, rule, entry), expected)


    def test_mapped_destination_deny_precedes_alias_permission(self):
        value = config.normalize(declaration())
        entry = next(iter(nat46.component(value)['mappings'].values()))
        rules = nat46.original_rules(value, entry)
        self.assertIn('192.168.10.90/32', rules[0])
        self.assertIn('oifname "nat46"', rules[0])
        self.assertTrue(rules[0].endswith('drop'))
        self.assertEqual(len(rules), 4)
        text = firewall.render(value)
        self.assertLess(text.index('jump nat46_output'), text.index('chain output'))
        self.assertLess(text.index('iifname "lr-services" drop'), text.index('jump nat46_output'))
        self.assertIn('@nh,160,32 . tcp sport . tcp dport @n46_0_tcp_forward', text)
        self.assertIn('@nh,128,32 . udp dport . udp sport @n46_5_udp_reply', text)
        self.assertIn('iifname != "nat46" ip6 saddr fd42:1234:5678:fd46::/96 drop', text)
        self.assertIn('ct state related ct direction reply ct original ip6 daddr', text)
        self.assertIn('timeout 2s; size 1024', text)

    def test_static_translation_does_not_take_custody_of_legacy_state(self):
        files = config.render(declaration())
        self.assertNotIn('data-dir', files['etc/tayga-nat46.conf'])
        self.assertNotIn('usr/lib/tmpfiles.d/80-lanrith-nat46.conf', files)
        self.assertNotIn('ReadWritePaths=', files['usr/lib/systemd/system/lanrith-nat46.service'])

    def test_partial_owner_permissions_keep_source_ports_and_destination(self):
        raw = declaration()
        raw['access']['rules'] = [
            {'action': 'allow', 'from': {'network': 'home', 'addresses': '192.168.10.2', 'mac': '02:00:00:00:01:02'},
             'to': {'network': 'servers', 'addresses': 'fd42:1234:5678:20::10'}, 'protocol': 'tcp',
             'ports': [443], 'authorization': 'owner'}]
        value = config.normalize(raw)
        entries = list(nat46.component(value)['mappings'].values())
        result = nat46.original_rules(value, entries[0])
        self.assertEqual(len(result), 1)
        for scope in ('192.168.10.2/32', 'iifname "lan"', 'ether saddr 02:00:00:00:01:02', 'tcp dport { 443 }'):
            self.assertIn(scope, result[0])
        self.assertEqual(nat46.original_rules(value, entries[1]), [])
        raw['access']['rules'][0]['to']['network'] = 'home'
        with self.assertRaises(ReleaseError):
            config.normalize(raw)

    def test_directory_requirement_is_terminal_and_remains_gated(self):
        raw = declaration()
        raw['access']['rules'].insert(0, {'action': 'allow', 'from': 'home',
                                         'to': 'servers', 'authorization': 'directory'})
        value = config.normalize(declaration())
        value['access']['rules'] = raw['access']['rules']
        rules = nat46.original_rules(value, next(iter(nat46.component(value)['mappings'].values())))
        self.assertTrue(rules[0].endswith('jump directory_grants'))
        with self.assertRaisesRegex(ReleaseError, 'Directory-authorized rules require'):
            config.render(value)
        # A directory rule cannot be enabled accidentally by leaving identity off.
        raw['translation'] = {}
        raw['access']['rules'] = [raw['access']['rules'][0]]
        with self.assertRaisesRegex(ReleaseError, 'Directory-authorized rules require'):
            config.render(raw)

    def test_disabled_component_leaves_no_routes_units_sets_or_interfaces(self):
        raw = declaration()
        raw['translation']['nat46']['enabled'] = False
        raw['access']['rules'] = []
        value = config.normalize(raw)
        self.assertEqual(nat46.render(value), {})
        self.assertNotIn('nat46', firewall.render(value))

    def test_foreign_interface_is_not_adopted_or_removed(self):
        manifest = {'config_sha256': '0'*64}
        for link in ({'ifname': 'nat46', 'linkinfo': {'info_kind': 'dummy'}},
                     {'ifname': 'nat46', 'ifalias': 'lanrith-nat46:'+'0'*64,
                      'linkinfo': {'info_kind': 'tun', 'info_data': {'type': 'tun', 'user': 10}}}):
            with patch.object(translation_runtime, 'run', return_value=[link]):
                with self.assertRaises(ReleaseError):
                    translation_runtime.existing(manifest, 20)

    def test_render_is_independent_of_nat64_and_preserves_all_maps(self):
        raw = declaration()
        value = config.normalize(raw)
        files = nat46.render(value)
        rendered = config.render(value)
        for name, content in files.items():
            self.assertEqual(rendered[name], content)
        self.assertEqual(files['etc/tayga-nat46.conf'].count('\nmap '), 6)
        self.assertNotIn('dynamic-pool', files['etc/tayga-nat46.conf'])
        self.assertIn('User=lanrith-nat46', files['usr/lib/systemd/system/lanrith-nat46.service'])
        self.assertIn('CapabilityBoundingSet=\n', files['usr/lib/systemd/system/lanrith-nat46.service'])
        self.assertIn('MemoryMax=128M\nMemorySwapMax=0\nTasksMax=16\nLimitNOFILE=256\n',
                      files['usr/lib/systemd/system/lanrith-nat46.service'])
        changed = copy.deepcopy(raw)
        changed['translation']['nat64'] = {'enabled': True}
        self.assertEqual(files, nat46.render(config.normalize(changed)))

    def test_translator_cannot_adopt_a_physical_name_or_mapped_ipv4_target(self):
        for change in ('interface', 'target'):
            with self.subTest(change=change):
                value = declaration()
                if change == 'interface':
                    value['hardware']['interfaces']['lan']['name'] = 'nat46'
                else:
                    value['translation']['nat46']['mappings']['service0']['ipv6'] = '::ffff:192.168.10.2'
                with self.assertRaises(ReleaseError):
                    config.normalize(value)

    def test_mismatched_configuration_fails_before_touching_network_state(self):
        manifest = json.loads(nat46.render(config.normalize(declaration()))['usr/share/lanrith/nat46.json'])
        with patch.object(translation_runtime, 'read', return_value=b'changed map'), \
                patch.object(translation_runtime, 'run') as command:
            with self.assertRaises(ReleaseError):
                translation_runtime.configure(manifest, 'start')
            command.assert_not_called()

    def test_failed_setup_removes_only_the_interface_it_created(self):
        manifest = json.loads(nat46.render(config.normalize(declaration()))['usr/share/lanrith/nat46.json'])
        for present in (False, True):
            calls = []
            def command(*arguments, **unused):
                calls.append(arguments)
                if 'address' in arguments:
                    raise OSError('Synthetic interrupted setup')
                return []
            with self.subTest(present=present), patch.object(translation_runtime, 'validate'), \
                    patch.object(translation_runtime, 'existing', return_value=present), \
                    patch.object(translation_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=61000)), \
                    patch.object(translation_runtime, 'run', side_effect=command):
                with self.assertRaises(OSError):
                    translation_runtime.configure(manifest, 'start')
            deleted = ('ip', 'link', 'delete', 'dev', 'nat46') in calls
            self.assertEqual(deleted, not present)

    def test_rule_names_are_not_part_of_enforcement(self):
        raw = declaration()
        before = firewall.render(config.normalize(raw))
        for index, rule in enumerate(raw['access']['rules']):
            rule['name'] = 'Descriptive name '+str(index)
        self.assertEqual(before, firewall.render(config.normalize(raw)))

    def test_assembly_activates_translator_and_requires_its_health(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-assembly-input')
            build.assembly(declaration(), base, root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            service = 'lanrith-nat46.service'
            self.assertEqual((overlay/'etc/systemd/system'/service).readlink(),
                             Path('/usr/lib/systemd/system')/service)
            self.assertIn(service, (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/translation_runtime.py').is_file())
            self.assertEqual(json.loads((overlay/'usr/share/lanrith/nat46.json').read_text())['component'], 'nat46')
            self.assertFalse((overlay/'etc/tayga.conf').exists())


if __name__ == '__main__':
    unittest.main()
