"""Exercise independent topologies, privacy boundaries and configuration failures."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from lanrith import config
from lanrith.release import ReleaseError


ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.example = config.load(ROOT / 'examples/minimal.yaml')

    def test_independent_topologies_have_explicit_management_and_no_cross_network_default(self):
        for example in ('minimal.yaml', 'segmented.yaml'):
            value = config.load(ROOT / 'examples' / example)
            files = config.render(value)
            firewall = files['etc/nftables.conf']
            self.assertIn('policy drop;', firewall)
            self.assertIn('chain source_guard', firewall)
            self.assertIn('iifname', firewall)
            self.assertNotIn('usr/share/lanrith/resolved.json', files)
            self.assertEqual(json.loads(files['usr/share/lanrith/health.json'])['schema'], 1)
            for network in value['networks'].values():
                self.assertIn(network['name'], firewall)
            if example == 'segmented.yaml':
                self.assertNotIn('oifname "lan.20" accept', firewall)
                self.assertIn('iifname "lan.10" ip saddr { 192.168.10.0/24 } ip daddr { 192.168.10.1 } tcp dport 22 accept', firewall)
                self.assertNotIn('ip daddr { 172.20.20.1 } tcp dport 22 accept', firewall)

    def test_explicit_connection_is_generated_without_widening_other_ports(self):
        value = config.load(ROOT / 'examples/segmented.yaml')
        value['access']['rules'] += [{'action': 'allow', 'from': 'home', 'to': 'guest', 'protocol': 'tcp', 'ports': [443]}]
        firewall = config.render(value)['etc/nftables.conf']
        self.assertIn('iifname "lan.10" oifname "lan.20" meta l4proto tcp tcp dport { 443 }', firewall)
        self.assertNotIn('tcp dport { 80', firewall)

    def test_duplicate_yaml_unknown_fields_and_recursive_yaml_are_rejected(self):
        for data in ('schema: 1\nschema: 1\n', 'schema: &recursive [*recursive]\n'):
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'input.yaml'
                path.write_text(data)
                with self.assertRaises(ReleaseError):
                    config.load(path)
        value = copy.deepcopy(self.example)
        value['administration']['password'] = 'never-log-this'
        with self.assertRaises(ReleaseError) as caught:
            config.normalize(value)
        self.assertNotIn('never-log-this', str(caught.exception))

    def test_invalid_allocations_hardware_and_features_are_rejected(self):
        mutations = (
            lambda value: value['hardware'].update(architecture='arm64'),
            lambda value: value['hardware']['interfaces']['lan']['match'].update(mac='bad\nselector'),
            lambda value: value['networks']['home'].update(interface='wan'),
            lambda value: value['networks']['home']['dhcp4'].update(pool=['192.168.10.1', '192.168.10.200']),
            lambda value: value['services'].update(vpp={'enabled': True}),
            lambda value: value['services'].update(policy={'enabled': True, 'configuration': 'missing'}),
            lambda value: value['administration'].update(networks=[]),
            lambda value: value['networks'].update(other=copy.deepcopy(value['networks']['home'])),
            lambda value: value['hardware'].update(boot={'secure_boot': 'false'}),
            lambda value: value['hardware'].update(watchdog={'mode': 'arbitrary'}),
            lambda value: value['hardware'].update(watchdog={'device': '/dev/watchdog0\nOtherSetting=yes'}),
            lambda value: value['hardware'].update(watchdog={'device': '/dev/disk/by-id/target'}),
            lambda value: value['hardware'].update(watchdog={'timeout_seconds': True}),
            lambda value: value['hardware'].update(watchdog={'timeout_seconds': 0}),
        )
        for mutate in mutations:
            value = copy.deepcopy(self.example)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises((ReleaseError, ValueError)):
                config.normalize(value)

    def test_output_is_exclusive_and_sudo_policy_is_protected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'rendered'
            digest = config.write(self.example, output)
            self.assertEqual(len(digest), 64)
            self.assertEqual((output / 'etc/sudoers.d/60-lanrith').stat().st_mode & 0o777, 0o440)
            self.assertIn('PermitRootLogin no', (output/'etc/ssh/sshd_config.d/00-lanrith.conf').read_text())
            with self.assertRaises(ReleaseError):
                config.write(self.example, output)

    def test_root_access_is_a_build_time_mode_with_a_rootless_variant(self):
        self.assertEqual(self.example['administration']['root_access'], 'enabled')
        enabled = config.render(self.example)
        self.assertIn('etc/sudoers.d/60-lanrith', enabled)
        self.assertIn('etc/security/authorized_keys', enabled)
        self.assertNotIn('AllowAgentForwarding no', enabled['etc/ssh/sshd_config.d/00-lanrith.conf'])

        value = copy.deepcopy(self.example)
        value['administration']['root_access'] = 'disabled'
        disabled = config.render(value)
        self.assertNotEqual(enabled['usr/share/lanrith/configuration.sha256'],
                            disabled['usr/share/lanrith/configuration.sha256'])
        self.assertNotIn('etc/sudoers.d/60-lanrith', disabled)
        self.assertNotIn('etc/security/authorized_keys', disabled)
        self.assertIn('PermitRootLogin no', disabled['etc/ssh/sshd_config.d/00-lanrith.conf'])
        self.assertIn('AllowAgentForwarding no', disabled['etc/ssh/sshd_config.d/00-lanrith.conf'])
        ssh = disabled['etc/systemd/system/ssh.service.d/60-lanrith-rootless.conf']
        self.assertIn('NoNewPrivileges=yes', ssh)
        self.assertIn('ProtectSystem=strict', ssh)
        self.assertIn('ReadWritePaths=/var/tmp/lanrith-update', ssh)
        self.assertNotIn('etc/systemd/system/ssh.service.d/60-lanrith-rootless.conf',
                         enabled)
        manifest = json.loads(disabled['usr/share/lanrith/administration.json'])
        self.assertEqual(manifest['root_access'], 'disabled')
        self.assertFalse(any(path.endswith(('.yaml', '.yml')) for path in disabled))

    def test_rootless_mode_rejects_serial_recovery_and_unknown_values(self):
        for root_access in (False, 'sometimes'):
            value = copy.deepcopy(self.example)
            value['administration']['root_access'] = root_access
            with self.subTest(root_access=root_access), self.assertRaises(ReleaseError):
                config.normalize(value)
        value = copy.deepcopy(self.example)
        value['administration']['root_access'] = 'disabled'
        value['administration']['serial'] = {'enabled': True}
        with self.assertRaisesRegex(ReleaseError, 'Serial recovery requires root access'):
            config.normalize(value)


if __name__ == '__main__':
    unittest.main()
