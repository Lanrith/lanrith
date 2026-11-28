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

    def test_sudo_services_use_profile_methods_and_retain_login_shell_session(self):
        for serial in (False, True):
            self.example['administration']['serial'] = {'enabled': serial}
            files = config.render(self.example)
            stack = files['etc/pam.d/lanrith-sudo-auth']
            self.assertIn('pam_rssh.so auth_key_file=/etc/security/authorized_keys', stack)
            self.assertEqual('verify-serial-passphrase' in stack, serial)
            self.assertIn('pam_deny.so', stack)
            for name, session in (('sudo', 'common-session-noninteractive'), ('sudo-i', 'common-session')):
                lines = files['etc/pam.d/'+name].splitlines()
                self.assertIn('@include lanrith-sudo-auth', lines)
                self.assertIn('@include common-account', lines)
                self.assertIn('@include '+session, lines)
                self.assertEqual('session required pam_limits.so' in lines, name == 'sudo-i')
        self.example['administration'].update(root_access='disabled', serial={'enabled': False})
        files = config.render(self.example)
        for name in ('sudo', 'sudo-i', 'lanrith-sudo-auth'):
            self.assertNotIn('etc/pam.d/'+name, files)

    def test_serial_cooldown_requires_enabled_serial_and_bounded_integers(self):
        for enabled, attempts, seconds in ((False, 2, 30), (True, 1, 30), (True, 11, 30),
                                           (True, True, 30), (True, 2, 0), (True, 2, 301), (True, 2, True)):
            with self.subTest(enabled=enabled, attempts=attempts, seconds=seconds):
                self.example['administration']['serial'] = {
                    'enabled': enabled, 'cooldown': {'attempts': attempts, 'seconds': seconds}}
                with self.assertRaisesRegex(ReleaseError, 'cooldown'):
                    config.normalize(self.example)

    def test_networkd_preserves_routes_owned_by_other_router_components(self):
        files = config.render(self.example)
        ownership = files['etc/systemd/networkd.conf.d/60-lanrith-route-owners.conf']
        self.assertIn('ManageForeignRoutes=no\n', ownership)
        self.assertIn('ManageForeignNextHops=no\n', ownership)

    def test_independent_topologies_have_explicit_management_and_no_cross_network_default(self):
        for example in ('minimal.yaml', 'segmented.yaml'):
            value = config.load(ROOT / 'examples' / example)
            files = config.render(value)
            firewall = files['etc/nftables.conf']
            self.assertIn('policy drop;', firewall)
            self.assertIn('chain source_guard', firewall)
            self.assertIn('iifname', firewall)
            self.assertNotIn('usr/share/lanrith/resolved.json', files)
            self.assertEqual(json.loads(files['usr/share/lanrith/health.json'])['schema'], 2)
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
        self.assertIn('"lan.10" . 0.0.0.0/0', firewall)
        self.assertIn('"lan.20" . 0.0.0.0/0', firewall)
        self.assertIn('meta l4proto tcp tcp dport { 443 } goto tp_inherit', firewall)
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
        self.assertEqual([line for line in ssh.splitlines() if line.startswith('BindPaths=')],
                         ['BindPaths=/var/tmp/lanrith-update'])
        self.assertEqual([line for line in ssh.splitlines() if line.startswith('SystemCallFilter=')], [
            'SystemCallFilter=~@cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap',
            'SystemCallFilter=chroot'])
        self.assertNotIn('etc/systemd/system/ssh.service.d/60-lanrith-rootless.conf',
                         enabled)
        manifest = json.loads(disabled['usr/share/lanrith/administration.json'])
        self.assertEqual(manifest['root_access'], 'disabled')
        self.assertEqual(manifest['host_key_rotation'], 'retain')
        self.assertFalse(any(path.endswith(('.yaml', '.yml')) for path in disabled))

    def test_ssh_listener_contract_uses_only_selected_gateways_and_port(self):
        config_value = config.load(ROOT/'examples/segmented.yaml')
        config_value['administration']['ssh_port'] = 2202
        files = config.render(config_value)
        contract = json.loads(files['usr/share/lanrith/ssh-listeners.json'])
        self.assertEqual(contract, {'interfaces': {'lan.10': ['192.168.10.1', 'fd42:1000:1000:10::1']}, 'port': 2202})
        listeners = [line.split()[1] for line in files['etc/ssh/sshd_config.d/00-lanrith.conf'].splitlines()
                     if line.startswith('ListenAddress ')]
        self.assertEqual(listeners, contract['interfaces']['lan.10'])
        self.assertIn('Port 2202\n', files['etc/ssh/sshd_config.d/00-lanrith.conf'])

    def test_ssh_limits_and_channel_choices_reject_ambiguous_or_unusable_values(self):
        for field, entry in (('ssh_forwarding', {'unknown': False}), ('ssh_forwarding', {'x11': 'false'}),
                             ('ssh_limits', {'max_auth_tries': True}), ('ssh_limits', {'max_auth_tries': 0}),
                             ('ssh_limits', {'client_alive_count_max': -1}),
                             ('ssh_limits', {'client_alive_interval_seconds': 2147483648}),
                             ('ssh_limits', {'login_grace_seconds': '30s'})):
            with self.subTest(field=field, entry=entry), self.assertRaises(ReleaseError):
                value = copy.deepcopy(self.example)
                value['administration'][field] = entry
                config.normalize(value)
        self.example['administration']['ssh_limits'] = {'login_grace_seconds': 0, 'client_alive_count_max': 0,
                                                        'client_alive_interval_seconds': 0}
        self.example['administration']['ssh_forwarding'] = {'tcp': False, 'agent': False}
        snippet = config.render(self.example)['etc/ssh/sshd_config.d/00-lanrith.conf']
        for line in ('AllowAgentForwarding no', 'AllowTcpForwarding no', 'LoginGraceTime 0', 'ClientAliveCountMax 0', 'ClientAliveInterval 0'):
            self.assertIn(line, snippet.splitlines())
        self.assertNotIn('AllowStreamLocalForwarding', snippet)
        self.assertNotIn('X11Forwarding', snippet)
        self.example['administration'].update(root_access='disabled', ssh_forwarding={'agent': True})
        with self.assertRaisesRegex(ReleaseError, 'Rootless SSH'):
            config.normalize(self.example)

    def test_host_key_recovery_rotation_is_a_build_time_generation(self):
        value = copy.deepcopy(self.example)
        value['administration']['host_key_rotation'] = '0123456789abcdef0123456789abcdef'
        files = config.render(value)
        manifest = json.loads(files['usr/share/lanrith/administration.json'])
        self.assertEqual(manifest['host_key_rotation'], value['administration']['host_key_rotation'])
        self.assertNotIn('host_key_rotation', files['etc/ssh/sshd_config.d/00-lanrith.conf'])
        for invalid in ('rotate', '0'*31, 'G'*32, True):
            changed = copy.deepcopy(value)
            changed['administration']['host_key_rotation'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ReleaseError):
                config.normalize(changed)

    def test_ssh_host_key_pin_requires_a_canonical_fingerprint_and_selected_generation(self):
        pin = {'generation': '1'*32, 'fingerprint': 'SHA256:'+'A'*43}
        admin = self.example['administration']
        admin['host_key_pin'] = pin
        files = config.render(self.example)
        self.assertEqual(json.loads(files['usr/share/lanrith/administration.json'])['host_key_pin'], pin)
        for invalid in (None, {}, {**pin, 'generation': 'old'}, {**pin, 'fingerprint': 'from-disk'},
                        {**pin, 'fingerprint': 'SHA256:'+'B'*43}, {**pin, 'path': '/var/backup'}):
            admin['host_key_pin'] = invalid
            with self.assertRaises(ReleaseError):
                config.normalize(self.example)
        admin.update(host_key_pin=pin, host_key_rotation='2'*32)
        with self.assertRaisesRegex(ReleaseError, 'matching generation'):
            config.normalize(self.example)

    def test_rootless_mode_rejects_serial_recovery_and_unknown_values(self):
        for root_access in (False, 'sometimes'):
            value = copy.deepcopy(self.example)
            value['administration']['root_access'] = root_access
            with self.subTest(root_access=root_access), self.assertRaises(ReleaseError):
                config.normalize(value)
        value = copy.deepcopy(self.example)
        value['administration']['root_access'] = 'disabled'
        value['administration']['serial'] = {'enabled': True}
        with self.assertRaisesRegex(ReleaseError, 'Serial login requires root access'):
            config.normalize(value)


if __name__ == '__main__':
    unittest.main()
