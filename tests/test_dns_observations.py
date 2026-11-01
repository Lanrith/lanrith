"""DNS observations do not add listeners, permission, dependencies or wire data."""

import copy
import io
import json
import os
from pathlib import Path
import socket
import struct
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lanrith import build, config, dns_metadata as wire, dns_observations as generation
from lanrith import dns_observations_runtime as runtime, extension_observations, extensions
from lanrith.release import ReleaseError
from test_extension_network import IDENTITIES, manifest, settings


OBSERVER = {'user': 'example-agent', 'uid': 1801, 'gid': 1801}
SELECTED = [{'service': 'dns', 'user': 'example-agent'}]
NOW = 1793500000*10**9


def integer(value):
    result = b''
    while value > 127:
        result += bytes([(value & 127) | 128])
        value >>= 7
    return result+bytes([value])


def proto(fields):
    result = b''
    for number, kind, value in fields:
        result += integer(number*8+kind)
        result += integer(value) if kind == 0 else (struct.pack('<I', value) if kind == 5 else integer(len(value))+value)
    return result


def dns(*, response=True, txt=False, ipv6=False):
    question = b'\x06answer\x07example\0'+struct.pack('!HH', 16 if txt else 28 if ipv6 else 1, 1)
    header = struct.pack('!6H', 1234, 0x8180 if response else 0x0100, 1, int(response), 0, 0)
    data = b'PRIVATE-TXT-PAYLOAD' if txt else socket.inet_pton(socket.AF_INET6, '2001:db8::7') if ipv6 else b'\xcb\x00\x71\x07'
    return header+question+(b'\xc0\x0c'+struct.pack('!HHIH', 16 if txt else 28 if ipv6 else 1, 1, 120, len(data))+data if response else b'')


def frame(*, response=True, txt=False, ipv6=False, fields=None):
    value = fields if fields is not None else [(1, 0, 6 if response else 5), (2, 0, 2 if ipv6 else 1),
        (3, 0, 1), (4, 2, socket.inet_pton(socket.AF_INET6, '2001:db8::2') if ipv6 else b'\xc0\x00\x02\x02'),
        (6, 0, 20000), (8, 0, NOW//10**9), (9, 5, 1000000),
        *([(12, 0, NOW//10**9), (13, 5, 2000000)] if response else []),
        (14 if response else 10, 2, dns(response=response, txt=txt, ipv6=ipv6))]
    return proto([(15, 0, 1), (14, 2, proto(value))])


class DnsObservationAdmissionTests(unittest.TestCase):
    def test_admitted_reader_keeps_core_firewall_health_and_resolver_bytes(self):
        value = settings()
        original = config.render(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension, output = root/'extension', root/'output'
            extension.mkdir()
            pin = manifest(extension, observations=SELECTED)
            config.write(value, output)
            installed = extensions.overlay(value, {'example-observer': (extension, pin)}, output)
            self.assertEqual(installed['health_units'], [])
            for name in ('etc/nftables.conf', 'etc/lanrith/services.nft', 'usr/share/lanrith/health.json', generation.RESOLVER):
                self.assertEqual((output/name).read_text(), original[name])
            self.assertEqual(json.loads((output/generation.CONFIG).read_bytes()), {'schema': 1, 'observer': OBSERVER})
            files = generation.render(OBSERVER)
            service = files['etc/systemd/system/'+generation.SERVICE]
            self.assertIn('User=lanrith-dns-observer\n', service)
            self.assertFalse(any('sysusers' in name for name in files))
            self.assertIn('Group=1801\n', service)
            self.assertIn('CapabilityBoundingSet=\nAmbientCapabilities=\n', service)
            self.assertIn('PrivateNetwork=yes\n', service)
            self.assertIn('RestrictAddressFamilies=AF_UNIX\n', service)
            self.assertIn('MemoryMax=64M\nMemorySwapMax=0\n', service)
            self.assertIn('Restart=always\nRestartSec=5s\nSuccessExitStatus=1\n', service)
            self.assertIn('StartLimitIntervalSec=0\n', service)
            self.assertNotIn('example-agent', service)
            socket_unit = files['etc/systemd/system/'+generation.SOCKET]
            self.assertIn('SocketUser=unbound\nSocketGroup=unbound\nSocketMode=0600\n', socket_unit)
            resolver_unit = files['etc/systemd/system/unbound.service.d/62-lanrith-observations.conf']
            self.assertNotIn('Requires=', resolver_unit)
            self.assertNotIn('BindsTo=', resolver_unit)
            self.assertEqual((output/'usr/lib/lanrith/dns-observations-runtime').stat().st_mode & 0o777, 0o755)

    def test_default_disabled_duplicate_and_identity_drift(self):
        value = settings()
        self.assertFalse(any('dnstap' in text for text in config.render(value).values()))
        declarations = extension_observations.declarations(SELECTED, IDENTITIES)
        self.assertEqual(extension_observations.resolve(value, [declarations], service='dns'), OBSERVER)
        with self.assertRaises(ReleaseError):
            extension_observations.resolve(value, [declarations, declarations], service='dns')
        value['services']['dns']['enabled'] = False
        with self.assertRaises(ReleaseError):
            extension_observations.resolve(value, [declarations], service='dns')
        for kind in ('users', 'groups'):
            identities = copy.deepcopy(IDENTITIES)
            identities[kind][0]['name'] = 'lanrith-dns-observer'
            with self.assertRaises(ReleaseError):
                extensions.identity_declarations(identities)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'runtime.json'
            path.write_text(json.dumps({'schema': 1, 'observer': OBSERVER}))
            with patch.object(runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1801, pw_gid=1801)):
                self.assertEqual(runtime.load(path, owner=os.getuid()), OBSERVER)
            with patch.object(runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1802, pw_gid=1801)):
                with self.assertRaises(ValueError):
                    runtime.load(path, owner=os.getuid())

    def test_all_three_observation_components_are_independent(self):
        choices = [{'service': name, 'user': 'example-agent'} for name in ('policy', 'logs', 'dns')]
        self.assertEqual(len(extension_observations.declarations(choices, IDENTITIES)), 3)
        with self.assertRaises(ReleaseError):
            extension_observations.declarations(choices+SELECTED, IDENTITIES)

    def test_owner_assembly_contains_locked_account_and_native_runtime_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension = root/'extension'
            extension.mkdir()
            pin = manifest(extension, observations=SELECTED)
            base = root/'base.tar'
            with tarfile.open(base, 'w') as archive:
                for name, data in {'etc/passwd': b'root:*:0:0:root:/root:/bin/sh\n',
                                   'etc/group': b'root:x:0:\n'}.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            build.assembly(settings(), base, root/'assembly', version='0.1.0', sequence=9,
                           integrations={'example-observer': (extension, pin)})
            overlay = root/'assembly/mkosi.extra'
            self.assertIn('lanrith-dns-observer:*:100:100:', (overlay/'etc/passwd').read_text())
            self.assertTrue((overlay/'usr/lib/lanrith/dns-observations-runtime').is_file())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/dns_observations_runtime.py').is_file())
            self.assertNotIn('dns-observations', (overlay/'usr/share/lanrith/health.json').read_text())
            self.assertFalse(any(path.name in ('minimal.yaml', 'configuration.yaml') for path in overlay.rglob('*')))

    def test_collector_account_is_built_locked_without_boot_time_account_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root/generation.CONFIG
            path.parent.mkdir(parents=True)
            path.write_text('{}')
            accounts = {'passwd': b'root:*:0:0:root:/root:/bin/sh\nbase:*:100:101::/nonexistent:/usr/sbin/nologin\n',
                        'group': b'root:x:0:\nbase:x:101:\n'}
            identities = [{'users': [{'name': 'example-agent', 'uid': 102, 'gid': 103}],
                           'groups': [{'name': 'example-agent', 'gid': 103}]}]
            extensions.account_overlay(accounts, identities, root)
            self.assertIn('lanrith-dns-observer:*:104:104:Lanrith integration service:/nonexistent:/usr/sbin/nologin\n',
                          (root/'etc/passwd').read_text())
            self.assertIn('lanrith-dns-observer:x:104:\n', (root/'etc/group').read_text())
            self.assertFalse(any('sysusers' in str(item) for item in root.rglob('*')))
            accounts['group'] += b'lanrith-dns-observer:x:105:\n'
            with self.assertRaises(ReleaseError):
                generation.account_declarations(accounts, identities, root)


class DnsMetadataTests(unittest.TestCase):
    def test_query_response_ipv4_ipv6_identity_and_time(self):
        for ipv6 in (False, True):
            query = wire.normalize(frame(response=False, ipv6=ipv6), now_ns=NOW)
            response = wire.normalize(frame(ipv6=ipv6), now_ns=NOW)
            self.assertEqual(query['transaction'], response['transaction'])
            self.assertEqual(response['query'], 'answer.example')
            self.assertEqual(response['latency_ms'], 1.)
            self.assertEqual(response['observed_ns'], NOW+2000000)
            self.assertEqual(query['result'], 'UNOBSERVED_RESPONSE')
            self.assertEqual(response['result'], 'NOERROR')
            self.assertEqual(response['answer_records'][0]['value'], '2001:db8::7' if ipv6 else '203.0.113.7')

    def test_wire_txt_and_identity_are_not_exported(self):
        result = wire.normalize(frame(txt=True), now_ns=NOW)
        self.assertEqual(result['answer_records'], [])
        self.assertTrue(result['answers_omitted'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('wire', result)
        for kind in (1, 2, 3, 4, 7, 8, 9, 10):
            self.assertIsNone(wire.normalize(frame(fields=[(1, 0, kind)]), now_ns=NOW))

    def test_malformed_protobuf_wire_dns_and_stale_times(self):
        invalid = [b'\x80', b'\x80'*10+b'\0', b'\0', b'\x0b', b'\x0a\x08x',
                   proto([(15, 0, 1), (15, 0, 1)]), proto([(15, 2, b'1')]),
                   proto([(15, 0, 1), (14, 2, proto([(1, 2, b'6')]))]), b'x'*(wire.FRAME_LIMIT+1)]
        for value in invalid:
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                wire.normalize(value, now_ns=NOW)
        for now in (NOW-6*10**9, NOW+7000*10**9):
            with self.assertRaises(ValueError):
                wire.normalize(frame(), now_ns=now)
        for value in (dns()[:11], dns()+b'x', dns()[:12]+b'\xc0\x0c'+dns()[14:],
                      dns()[:12]+b'\xc0\xff'+dns()[14:]):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                wire.message(value, True)
        with self.assertRaises(ValueError):
            wire.message(dns(response=False), True)

    def test_dnstap_family_transport_port_and_nanosecond_bounds(self):
        original = wire.protobuf(wire.field(wire.protobuf(frame()), 14, 2))
        for number, kind, value in ((2, 0, 2), (3, 0, 3), (6, 0, 0), (6, 0, 65536),
                                    (4, 2, b'bad'), (9, 5, 10**9), (13, 5, 10**9),
                                    (12, 2, b'wrong-wire')):
            changed = {**original, number: (kind, value)}
            payload = frame(fields=[(key, wire_type, item) for key, (wire_type, item) in changed.items()])
            with self.subTest(number=number, value=value), self.assertRaises(ValueError):
                wire.normalize(payload, now_ns=NOW)

    def test_ready_start_fragmentation_stop_and_invalid_order(self):
        payload = frame()
        raw = wire.control(4)+wire.control(2)+struct.pack('!I', len(payload))+payload+wire.control(3, False)
        stream, frames, replies = wire.FrameStream(), [], []
        for byte in raw:
            found, reply = stream.feed(bytes([byte]))
            frames += found
            replies += reply
        self.assertEqual(frames, [payload])
        self.assertEqual(replies, [wire.control(1), wire.control(5, False)])
        self.assertEqual(stream.state, 'finished')
        for raw in (wire.control(2), wire.control(3, False), struct.pack('!I', 1)+b'x',
                    wire.control(4)+wire.control(4), struct.pack('!I', wire.FRAME_LIMIT+1),
                    struct.pack('!II', 0, 513), b'x'*(2*wire.FRAME_LIMIT+1)):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                wire.FrameStream().feed(raw)


@unittest.skipUnless(os.geteuid() == 0, 'Spool custody needs isolated root.')
class DnsSpoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dns-spool-test.', dir='/run')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.path.chmod(0o750)

    def spool(self):
        return runtime.Spool(self.path, boot=Path('/proc/sys/kernel/random/boot_id'))

    def test_rotation_bounds_restarts_and_exact_overwrites(self):
        with patch.object(runtime, 'LIMIT', 1024), patch.object(runtime, 'LINE', 1024):
            spool = self.spool()
            for count in range(30):
                spool.append({'sequence': count, 'padding': 'x'*250})
            spool.health()
            self.assertEqual(spool.counters['emitted'], 30)
            remaining = sum(len((self.path/name).read_bytes().splitlines()) for name in spool.counts)
            self.assertEqual(spool.counters['overwritten'], 30-remaining)
            self.assertLessEqual(sum(path.stat().st_size for path in self.path.glob('events*')), 3*1024)
            previous = spool.epoch
            restarted = self.spool()
            self.assertNotEqual(previous, restarted.epoch)
            self.assertEqual(restarted.counters['emitted'], 0)
            self.assertEqual(restarted.counts, spool.counts)

    def test_custody_rejects_links_extra_files_and_wrong_modes(self):
        file = self.path/'events.jsonl'
        file.symlink_to('/etc/passwd')
        with self.assertRaises((ValueError, OSError)):
            self.spool()
        file.unlink()
        file.write_text('{}\n')
        file.chmod(0o644)
        with self.assertRaises(ValueError):
            self.spool()
        file.chmod(0o640)
        alias = self.path/'events.jsonl.1'
        os.link(file, alias)
        with self.assertRaises(ValueError):
            self.spool()
        alias.unlink()
        (self.path/'unexpected').write_text('no adoption')
        with self.assertRaises(ValueError):
            self.spool()

    def test_partial_write_repair_and_record_bound(self):
        file = self.path/'events.jsonl'
        file.write_bytes(b'{}\npartial')
        file.chmod(0o640)
        spool = self.spool()
        self.assertEqual(file.read_bytes(), b'{}\n')
        with patch.object(runtime.os, 'write', return_value=2), self.assertRaises(OSError):
            spool.append({'sequence': 1})
        self.assertEqual(file.read_bytes(), b'{}\n')
        spool.append({'sequence': 2})
        self.assertEqual(json.loads(file.read_bytes().splitlines()[-1]), {'sequence': 2})
        spool.append({'too_big': 'x'*runtime.LINE})
        self.assertEqual(spool.counters['rejected'], 1)
        self.assertEqual(file.read_bytes(), b'{}\n{"sequence":2}\n')


if __name__ == '__main__':
    unittest.main()
