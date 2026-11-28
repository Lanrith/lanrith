"""Chrony source selection, local service admission and interception contracts."""

import ast
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lanrith import build, config
from lanrith.release import ReleaseError
from test_intent import minimal
from test_policy_agent import declaration


class ChronyTests(unittest.TestCase):
    def test_unselected_service_is_absent_from_assembled_boot_and_dhcp(self):
        value = minimal()
        del value['services']['ntp']
        normalized = config.normalize(value)
        self.assertFalse(normalized['services']['ntp']['enabled'])
        files = config.render(normalized)
        self.assertNotIn('ntp', json.loads(files['usr/share/lanrith/service-plane.json'])['endpoints'])
        self.assertNotIn('chrony.service', json.loads(files['usr/share/lanrith/health.json'])['units'])
        self.assertNotIn('ntp-servers', files['etc/kea/kea-dhcp4.conf'])
        self.assertNotIn('etc/chrony/chrony.conf', files)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            base = work/'base.tar'
            base.write_bytes(b'synthetic')
            build.assembly(normalized, base, work/'image', version='0.1.0', sequence=2)
            overlay = work/'image/mkosi.extra'
            neutral_mask = overlay/'etc/systemd/system/chrony.service'
            neutral_mask.symlink_to('/dev/null')
            subprocess.run(['python3', work/'image/mkosi.postinst'], env={**os.environ, 'BUILDROOT': str(overlay)},
                           check=True)
            self.assertEqual(neutral_mask.readlink(), Path('/dev/null'))
            self.assertFalse(any(p.name == 'chrony.service' for p in overlay.glob('**/*.wants/*')))
        for settings in ({'enabled': True}, {'enabled': True, 'upstreams': []}):
            value['services']['ntp'] = settings
            with self.assertRaisesRegex(ReleaseError, 'explicit site upstreams'):
                config.normalize(value)
        del value['services']['ntp']
        value['networks']['home']['ntp'] = True
        with self.assertRaisesRegex(ReleaseError, 'LAN NTP access'):
            config.normalize(value)
        policy = declaration()
        del policy['services']['ntp']
        with self.assertRaisesRegex(ReleaseError, 'synchronized time'):
            config.normalize(policy)

    def test_source_targets_and_reply_limits(self):
        value = minimal()
        settings = value['services']['ntp']
        settings.update(upstreams=['legacy.example.test', {'type': 'server', 'address': '192.0.2.123'},
                                   {'type': 'pool', 'address': 'v6.example.test', 'family': 'ipv6', 'maxsources': 2}],
                        total_sources=7, require_numeric_source=True)
        def policy():
            return config.render(value)['etc/chrony/chrony.conf']
        self.assertIn('pool legacy.example.test iburst\nserver 192.0.2.123 iburst\n'
                      'pool v6.example.test iburst ipv6 maxsources 2\n', policy())
        self.assertNotIn('ratelimit', policy())
        for limits in ({}, {'interval': -19, 'leak': 4}, {'burst': 255, 'interval': 12}):
            settings['ratelimit'] = limits
            expected = 'ratelimit'+''.join(f' {k} {limits[k]}' for k in ('interval', 'burst', 'leak') if k in limits)
            self.assertIn(expected, policy().splitlines())
        for patch in ({'ratelimit': {'interval': -20}}, {'ratelimit': {'burst': 256}},
                      {'ratelimit': {'leak': 0}}, {'ratelimit': {'burst': True}}, {'total_sources': 6},
                      {'require_numeric_source': 1}, {'upstreams': ['v6.example.test'], 'total_sources': 4}):
            with self.subTest(patch=patch), self.assertRaises(ReleaseError):
                config.normalize({**value, 'services': {'ntp': {**settings, **patch}}})
        disabled = {**value, 'uplink': {**value['uplink'], 'ipv4': 'disabled'}}
        with self.assertRaisesRegex(ReleaseError, 'enabled uplink family'):
            config.normalize(disabled)
        for source in ({'type': 'server', 'address': 'ntp.test', 'maxsources': 1},
                       {'type': 'pool', 'address': 'ntp.test', 'maxsources': 17},
                       {'type': 'server', 'address': '192.0.2.1', 'family': 'ipv6'},
                       {'type': 'peer', 'address': 'ntp.test'}, {'type': 'server', 'address': '::'},
                       {'type': 'server', 'address': 'name.test\nport 0'}, '127.0.0.1'):
            value['services']['ntp'] = {'enabled': True, 'upstreams': [source]}
            with self.subTest(source=source), self.assertRaises(ReleaseError):
                policy()

    def test_final_image_rejects_a_binary_without_the_required_seccomp_feature(self):
        path = Path(__file__).resolve().parents[1]/'scripts/finalize-image.py'
        check = next(node for node in ast.parse(path.read_text()).body
                     if isinstance(node, ast.FunctionDef) and node.name == 'check_chrony')
        namespace = {'subprocess': subprocess}
        exec(compile(ast.Module(body=[check], type_ignores=[]), str(path), 'exec'), namespace)
        with mock.patch.object(subprocess, 'run') as run:
            run.return_value.stdout = 'chronyd (chrony) version 4.6.1 (+CMDMON -SCFILTER +IPV6)'
            with self.assertRaisesRegex(ValueError, 'syscall filter'):
                namespace['check_chrony']('/fixture')
            self.assertEqual(run.call_count, 1)
            run.return_value.stdout = 'chronyd (chrony) version 4.6.1 (+CMDMON +SCFILTER +IPV6)'
            namespace['check_chrony']('/fixture')
            self.assertEqual(run.call_args.args[0], ['chroot', '/fixture', '/usr/sbin/chronyd',
                                                     '-F', '1', '-p', '-f', '/etc/chrony/chrony.conf'])

    def test_redirect_only_selected_eligible_sources(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/segmented.yaml')
        value['services']['ntp'] = {'enabled': True, 'upstreams': ['192.0.2.123']}
        for network in value['networks'].values():
            network['ntp'] = True
        self.assertNotIn('time_redirect', config.render(value)['etc/nftables.conf'])
        value['networks']['home']['ntp_intercept'] = True
        files = config.render(value)
        rules = [r for r in files['etc/nftables.conf'].splitlines() if 'udp dport 123 dnat' in r]
        self.assertEqual(len(rules), 2)
        self.assertTrue(all('iifname "lan.10"' in r for r in rules))
        for scope in json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4']['subnet4']:
            self.assertIn('ntp-servers', [o['name'] for o in scope['option-data']])
        for key, setting in (('ntp', False), ('forwarding', False), ('ntp_intercept', 'yes')):
            original = value['networks']['home'].copy()
            value['networks']['home'][key] = setting
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                config.normalize(value)
            value['networks']['home'] = original
