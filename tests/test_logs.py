"""Log delivery uses compiled policy, an exact path, and runtime credentials."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build, config, credential_config, credential_image, logs_runtime, policy_agent
from lanrith.release import ReleaseError
from test_policy_agent import declaration as policy_declaration


def declaration():
    value = policy_declaration()
    value['networks']['home']['vlan'] = 1
    value['observability'] = {'logs': {
        'enabled': True,
        'endpoint': 'https://[fd42:1234:5678:10::31]/otlp',
        'tls_server_name': 'logs.example.test',
        'username': 'synthetic-router',
        'credential': 'log_ingest',
    }}
    return value


class LogsContractTests(unittest.TestCase):
    def test_render_is_exact_and_contains_no_secret_or_source_intent(self):
        value = config.normalize(declaration())
        files = config.render(value)
        policy = json.loads(files['usr/share/lanrith/logs.json'])
        self.assertEqual(policy, {
            'schema_version': 1,
            'endpoint': 'https://[fd42:1234:5678:10::31]/otlp',
            'target': 'fd42:1234:5678:10::31',
            'source': 'fd42:1234:5678:fe02::60',
            'tls_server_name': 'logs.example.test',
            'authentication': 'basic',
            'username': 'synthetic-router',
            'credential_name': 'log_ingest',
        })
        unit = files['etc/systemd/system/alloy.service.d/60-lanrith.conf']
        self.assertIn('LoadCredential=log_ingest:/var/lib/lanrith/credentials/log_ingest', unit)
        self.assertIn('NetworkNamespacePath=/run/netns/lanrith-services', unit)
        self.assertIn('ExecStartPre=+/usr/lib/lanrith/logs-runtime stage', unit)
        self.assertIn('ExecStart=\nExecStart=/usr/lib/lanrith/logs-runtime run\n', unit)
        self.assertIn('Type=notify\nNotifyAccess=main\n', unit)
        self.assertIn('WatchdogSec=30s\n', unit)
        self.assertIn('StateDirectory=lanrith/alloy\n', unit)
        self.assertIn('BindPaths=/var/lib/lanrith/alloy:/var/lib/lanrith-alloy\n', unit)
        self.assertIn('WorkingDirectory=/var/lib/lanrith-alloy\n', unit)
        heartbeat = files['usr/lib/systemd/system/lanrith-telemetry-heartbeat.service']
        timer = files['usr/lib/systemd/system/lanrith-telemetry-heartbeat.timer']
        self.assertIn('User=alloy\n', heartbeat)
        self.assertIn('NoNewPrivileges=yes\n', heartbeat)
        self.assertIn('ExecStart=/usr/bin/lanrith-runtime telemetry\n', heartbeat)
        self.assertIn('OnUnitActiveSec=60s\n', timer)
        self.assertIn('lanrith-telemetry-heartbeat.timer',
                      json.loads(files['usr/share/lanrith/health.json'])['units'])
        alloy = files['etc/alloy/config.alloy']
        self.assertIn('loki.process "router_redaction"', alloy)
        self.assertLess(alloy.index('loki.process "router_redaction"'), alloy.index('otelcol.storage.file "router"'))
        self.assertIn('queue_size        = 67108864', alloy)
        self.assertIn('min_version = "1.2"', alloy)
        self.assertIn('regex         = "alloy\\\\.service"\n    action        = "drop"', alloy)
        self.assertNotIn('password = "', alloy)
        self.assertFalse(any(path.endswith(('.yaml', '.yml')) for path in files))

        model = policy_agent.baseline(value)['network_model']
        path = next(item for item in model['core_egress'] if item['kind'] == 'logs')
        self.assertEqual(path, {
            'kind': 'logs', 'interface': 'lr-services',
            'address': 'fd42:1234:5678:fe02::60',
            'destinations': ['fd42:1234:5678:10::31/128'],
            'masquerade': False, 'destination_interface': 'lan.1',
        })
        self.assertIn('tcp dport 443 accept', files['etc/lanrith/services.nft'])
        self.assertIn('meta skuid "alloy" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport 12345 accept',
                      files['etc/lanrith/services.nft'])
        self.assertIn('oifname "lan.1"', files['etc/nftables.conf'])
        plane = json.loads(files['usr/share/lanrith/service-plane.json'])
        self.assertIn({'to': 'fd42:1234:5678:10::31/128', 'via': 'fd42:1234:5678:fe02::1',
                       'source': 'fd42:1234:5678:fe02::60'}, plane['dependency_routes'])

    def test_runtime_manifest_is_strict(self):
        files = config.render(config.normalize(declaration()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'logs.json'
            path.write_text(files['usr/share/lanrith/logs.json'])
            path.chmod(0o600)
            self.assertEqual(logs_runtime.load(path, owner=os.getuid())['credential_name'], 'log_ingest')
            document = json.loads(path.read_text())
            for changed in ({**document, 'authentication': 'none'},
                            {key: item for key, item in document.items() if key != 'credential_name'}):
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    logs_runtime.load(path, owner=os.getuid())
            document['configuration'] = 'owner.yaml'
            path.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                logs_runtime.load(path, owner=os.getuid())

    def test_disabled_and_unsafe_destinations_leave_no_listener_or_path(self):
        value = declaration()
        value['observability']['logs']['enabled'] = False
        files = config.render(config.normalize(value))
        self.assertNotIn('usr/share/lanrith/logs.json', files)
        self.assertNotIn('etc/alloy/config.alloy', files)
        self.assertNotIn('usr/lib/systemd/system/lanrith-telemetry-heartbeat.timer', files)
        self.assertNotIn('12345', files['etc/lanrith/services.nft'])
        for endpoint in ('https://logs.example.test/otlp',
                         'https://[fd42:1234:5678:99::31]/otlp',
                         'https://[fd42:1234:5678:10::31]:8443/otlp'):
            value = declaration()
            value['observability']['logs']['endpoint'] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(ReleaseError):
                config.render(config.normalize(value))

    def test_enabled_logging_without_client_authentication_needs_no_secret(self):
        from test_intent import minimal
        for explicit in (False, True):
            value = minimal()
            value['observability'] = {'logs': {
                'enabled': True, 'endpoint': 'https://192.168.10.31/otlp',
                'tls_server_name': 'logs.example.test'}}
            if explicit:
                value['observability']['logs']['authentication'] = 'none'
            with self.subTest(explicit=explicit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base = root/'base.tar'; base.write_bytes(b'synthetic')
                with patch.object(credential_image, 'private_read') as read:
                    build.assembly(value, base, root/'image', version='0.1.0', sequence=1)
                    read.assert_not_called()
                tree = root/'image/mkosi.extra'
                policy = logs_runtime.load(tree/'usr/share/lanrith/logs.json', owner=os.getuid())
                self.assertEqual(policy['authentication'], 'none')
                self.assertNotIn('credential_name', policy)
                self.assertNotIn('username', policy)
                alloy = (tree/'etc/alloy/config.alloy').read_text()
                self.assertNotIn('otelcol.auth.basic', alloy)
                self.assertNotIn('local.file', alloy)
                self.assertIn('endpoint = "https://192.168.10.31/otlp"', alloy)
                self.assertIn('min_version = "1.2"', alloy)
                unit = (tree/'etc/systemd/system/alloy.service.d/60-lanrith.conf').read_text()
                self.assertNotIn('LoadCredential=', unit)
                self.assertFalse((tree/'usr/lib/systemd/system/lanrith-credential-ready.service').exists())
                self.assertIn('alloy.service', json.loads((tree/'usr/share/lanrith/health.json').read_bytes())['units'])

    def test_partial_or_conflicting_authentication_never_falls_back_to_none(self):
        for authentication, omitted in (('basic', ('username',)), ('basic', ('credential',)),
                                         ('basic', ('username', 'credential')), ('none', ()),
                                         ('unknown', ())):
            value = declaration()
            settings = value['observability']['logs']
            settings['authentication'] = authentication
            for field in omitted:
                settings.pop(field)
            with self.subTest(authentication=authentication, omitted=omitted), self.assertRaises(ValueError):
                config.normalize(value)
        for omitted in ('username', 'credential'):
            value = declaration()
            value['observability']['logs'].pop(omitted)
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                config.normalize(value)


if __name__ == '__main__':
    unittest.main()
