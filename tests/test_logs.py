"""Log delivery uses compiled policy, an exact path, and runtime credentials."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from lanrith import config, logs_runtime, policy_agent
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
            'username': 'synthetic-router',
            'credential_name': 'log_ingest',
        })
        unit = files['etc/systemd/system/alloy.service.d/60-lanrith.conf']
        self.assertIn('LoadCredential=log_ingest:/var/lib/lanrith/credentials/log_ingest', unit)
        self.assertIn('NetworkNamespacePath=/run/netns/lanrith-services', unit)
        self.assertIn('ExecStartPre=+/usr/lib/lanrith/logs-runtime stage', unit)
        alloy = files['etc/alloy/config.alloy']
        self.assertIn('loki.process "router_redaction"', alloy)
        self.assertLess(alloy.index('loki.process "router_redaction"'), alloy.index('otelcol.storage.file "router"'))
        self.assertIn('queue_size        = 67108864', alloy)
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
        for endpoint in ('https://logs.example.test/otlp',
                         'https://[fd42:1234:5678:99::31]/otlp',
                         'https://[fd42:1234:5678:10::31]:8443/otlp'):
            value = declaration()
            value['observability']['logs']['endpoint'] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(ReleaseError):
                config.render(config.normalize(value))


if __name__ == '__main__':
    unittest.main()
