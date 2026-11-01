"""Admitted default-deny metadata has no new forwarding or reader authority."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from lanrith import build, config, dns_observations, extension_network, extension_observations, extensions, firewall
from lanrith import firewall_metadata as wire, firewall_observations as generation, firewall_observations_runtime as runtime
from lanrith.release import ReleaseError
from test_extension_network import IDENTITIES, listener, manifest, settings
from test_firewall_metadata import frame


OBSERVER = {'user': 'example-agent', 'uid': 1801, 'gid': 1801}
SELECTED = [{'service': 'firewall', 'user': 'example-agent'}]


class FirewallObservationAdmissionTests(unittest.TestCase):
    def test_final_network_rules_and_core_health_are_preserved_with_bound_sampled_drops(self):
        value = settings()
        original = config.render(value)
        network = {'listeners': [listener()]}
        plan = extension_network.resolve(value, [extension_network.declarations(network, IDENTITIES)])
        before = firewall.render(value, extension_rules=plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension, output = root/'extension', root/'output'
            extension.mkdir()
            pin = manifest(extension, network=network, observations=SELECTED)
            config.write(value, output)
            result = extensions.overlay(value, {'example-observer': (extension, pin)}, output)
            expected = generation.render(OBSERVER, before)
            self.assertEqual((output/generation.RULESET).read_text(), expected[generation.RULESET])
            self.assertIn('tcp dport 8443 ct state new accept', (output/generation.RULESET).read_text())
            self.assertEqual(result['health_units'], [])
            self.assertEqual((output/'usr/share/lanrith/health.json').read_text(), original['usr/share/lanrith/health.json'])
            self.assertEqual((output/'etc/lanrith/services.nft').read_text(), original['etc/lanrith/services.nft'])
            self.assertEqual((output/dns_observations.RESOLVER).read_text(), original[dns_observations.RESOLVER])
            contract = json.loads((output/generation.CONFIG).read_bytes())
            self.assertEqual(contract['observer'], OBSERVER)
            self.assertEqual(contract['firewall_sha256'], hashlib.sha256(expected[generation.RULESET].encode()).hexdigest())
            unit = expected['etc/systemd/system/'+generation.SERVICE]
            self.assertIn('User=lanrith-firewall-observer\nGroup=1801\n', unit)
            self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_ADMIN\n', unit)
            self.assertIn('RestrictAddressFamilies=AF_NETLINK AF_UNIX\n', unit)
            self.assertNotIn('PrivateNetwork=yes', unit)
            self.assertIn('MemoryMax=64M\nMemorySwapMax=0\nCPUQuota=5%\n', unit)
            self.assertIn('Restart=always\nRestartSec=5s\nSuccessExitStatus=1\n', unit)
            self.assertNotIn('Requires=', unit)
            self.assertNotIn('BindsTo=', unit)
            self.assertFalse(any('sysusers' in name for name in expected))

    def test_default_selection_has_no_collector_account_rules_or_dependency(self):
        value = settings()
        original = config.render(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension, output = root/'extension', root/'output'
            extension.mkdir()
            pin = manifest(extension)
            config.write(value, output)
            extensions.overlay(value, {'example-observer': (extension, pin)}, output)
            self.assertFalse((output/generation.CONFIG).exists())
            self.assertFalse((output/'etc/systemd/system'/generation.SERVICE).exists())
            self.assertEqual((output/generation.RULESET).read_text(), original[generation.RULESET])
            self.assertEqual(generation.account_declarations({}, [], output), [])

    def test_all_four_endpoints_have_one_owned_reader_and_no_arbitrary_fields(self):
        choices = [{'service': name, 'user': 'example-agent'} for name in ('policy', 'logs', 'dns', 'firewall')]
        self.assertEqual(len(extension_observations.declarations(choices, IDENTITIES)), 4)
        for values in (choices+SELECTED, [{'service': 'firewall', 'user': 'root'}],
                       [{'service': 'firewall', 'user': 'example-agent', 'group': wire.GROUP}]):
            with self.subTest(values=values), self.assertRaises(ReleaseError):
                extension_observations.declarations(values, IDENTITIES)
        declaration = extension_observations.declarations(SELECTED, IDENTITIES)
        with self.assertRaises(ReleaseError):extension_observations.resolve(settings(), [declaration, declaration], service='firewall')

    def test_account_allocation_is_build_time_distinct_from_dns_and_locked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension = root/'extension'
            extension.mkdir()
            pin = manifest(extension, observations=[*SELECTED, {'service': 'dns', 'user': 'example-agent'}])
            base = root/'base.tar'
            with tarfile.open(base, 'w') as archive:
                for name, data in {'etc/passwd': b'root:*:0:0:root:/root:/bin/sh\n', 'etc/group': b'root:x:0:\n'}.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
            build.assembly(settings(), base, root/'assembly', version='0.1.0', sequence=9,
                           integrations={'example-observer': (extension, pin)})
            tree = root/'assembly/mkosi.extra'
            accounts = {row[0]: row for line in (tree/'etc/passwd').read_text().splitlines() if (row := line.split(':'))}
            for name in (generation.ACCOUNT, dns_observations.ACCOUNT):
                self.assertEqual(accounts[name][1], '*')
                self.assertEqual(accounts[name][-1], '/usr/sbin/nologin')
                self.assertTrue(100 <= int(accounts[name][2]) < 1000)
            self.assertNotEqual(accounts[generation.ACCOUNT][2], accounts[dns_observations.ACCOUNT][2])
            for name in ('observation_spool.py', 'firewall_metadata.py', 'firewall_observations_runtime.py'):
                self.assertTrue((tree/'usr/lib/lanrith/lanrith'/name).is_file())
            self.assertFalse((tree/'usr/lib/lanrith/lanrith/observation_accounts.py').exists())
            self.assertFalse((tree/'usr/lib/lanrith/lanrith/config.py').exists())
            self.assertFalse(list(tree.rglob('config.yaml')))


class FirewallObservationRuntimeTests(unittest.TestCase):
    def test_native_manifest_rejects_identity_ruleset_version_or_prefix_drift(self):
        generated = generation.render(OBSERVER, config.render(settings())[generation.RULESET])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, nft = root/'contract', root/'ruleset'
            nft.write_text(generated[generation.RULESET])
            value = json.loads(generated[generation.CONFIG])
            with patch.object(runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1801, pw_gid=1801)):
                path.write_text(json.dumps(value))
                self.assertEqual(runtime.load(path, ruleset=nft, owner=os.getuid()), value)
                for change in ({'schema': True}, {'record_schema': 2}, {'group': True}, {'prefixes': {}},
                               {'firewall_sha256': 'f'*64}, {'path': '/arbitrary'}):
                    path.write_text(json.dumps({**value, **change}))
                    with self.subTest(change=change), self.assertRaises(ValueError):runtime.load(path, ruleset=nft, owner=os.getuid())
                path.write_text(json.dumps(value))
                nft.write_text(nft.read_text()+'\n# unexpected replacement\n')
                with self.assertRaises(ValueError):runtime.load(path, ruleset=nft, owner=os.getuid())

    def test_stream_keeps_original_time_counts_loss_and_ignores_untrusted_or_duplicate_messages(self):
        source = Mock()
        counts, rows, health = dict.fromkeys(runtime.COUNTERS, 0), [], []
        def bump(name, count=1):counts[name] += count
        spool = SimpleNamespace(bump=bump, append=rows.append, health=lambda: health.append(True))
        def payload(sequence):
            data = bytearray(frame())
            # Last attribute is NFULA_SEQ, encoded as a network-order uint32.
            data[-4:] = struct.pack('!I', sequence)
            return bytes(data)
        messages = [(payload(0), [], socket.MSG_TRUNC, (0, 0)), (payload(1), [], 0, (0, 0)),
                    (payload(3), [], 0, (0, 0)), (payload(3), [], 0, (0, 0)), (payload(4), [], 0, (2002, 0))]
        consumed = 0
        def receive(maximum):
            nonlocal consumed
            value = messages[consumed]
            consumed += 1
            return value
        source.recvmsg.side_effect = receive
        from test_firewall_metadata import PREFIXES
        with patch.object(runtime.select, 'select', return_value=([source], [], [])), \
                patch.object(runtime.time, 'time_ns', return_value=1793500000123456000), \
                patch.object(runtime, 'interface', return_value='synthetic0'):
            runtime.serve(source, spool, {'prefixes': PREFIXES, 'firewall_sha256': 'a'*64}, stopped=lambda: consumed == len(messages))
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['observed_ns'] for row in rows}, {1793500000123456000})
        self.assertEqual(counts['kernel_sequence_gaps'], 2)
        self.assertEqual(counts['startup_gaps'], 1)
        self.assertEqual(counts['rejected'], 3)
        self.assertTrue(health)
        self.assertNotIn('PRIVATE', json.dumps(rows))


if __name__ == '__main__':
    unittest.main()
