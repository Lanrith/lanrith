"""Admitted extension access stays narrow and separate from core boot health."""

import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from lanrith import build, config, extension_network, extensions, firewall, service_plane
from lanrith.release import canonical, file_record, ReleaseError


ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = {'users': [{'name': 'example-agent', 'uid': 1801, 'gid': 1801}],
              'groups': [{'name': 'example-agent', 'gid': 1801}]}


def settings():
    value = config.load(ROOT/'examples/minimal.yaml')
    value['extensions'] = ['example-observer']
    return value


def listener():
    return {'user': 'example-agent', 'network': 'home', 'address': '192.168.10.1',
            'sources': ['192.168.10.0/24'], 'protocol': 'tcp', 'port': 8443}


def manifest(root, *, network=None, **extra):
    name = 'usr/lib/systemd/system/example-agent.service'
    path = root/'root'/name
    path.parent.mkdir(parents=True)
    path.write_text('[Unit]\nAfter=network.target nftables.service\n'
                    '[Service]\nUser=example-agent\nExecStart=/usr/bin/false\n')
    path.chmod(0o644)
    record = file_record(path)
    record.pop('name')
    value = {'schema': 1, 'id': 'example-observer', 'features': [], 'health_units': [],
             'start_units': ['example-agent.service'], 'identities': IDENTITIES,
             'files': {name: {**record, 'mode': 0o644}}, 'network': network or {}, **extra}
    encoded = canonical(value)
    (root/'extension.json').write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


class ExtensionNetworkTests(unittest.TestCase):
    def resolve(self, network, value=None, identities=None):
        return extension_network.resolve(value or settings(), [extension_network.declarations(
            network, identities or IDENTITIES)])

    def test_listener_and_service_rules_use_exact_interface_address_port_and_uid(self):
        value = settings()
        value['observability'] = {'metrics': {'enabled': True, 'clients': ['home']}}
        plan = self.resolve({'listeners': [listener()],
                             'services': [{'user': 'example-agent', 'service': 'metrics', 'family': 4}]}, value)
        text = firewall.render(value, extension_rules=plan)
        self.assertIn('iifname "lan" ip saddr { 192.168.10.0/24 } ip daddr 192.168.10.1 '
                      'tcp dport 8443 ct state new accept', text)
        self.assertIn('meta skuid 1801 oifname "lr-services" ip saddr 10.255.254.1 '
                      'ip daddr { 10.255.254.50 } tcp dport 9100 ct direction original '
                      'ct state new,established,related accept', text)
        output = text.split(' chain output {', 1)[1]
        self.assertLess(output.index('jump extension_output'), output.index('ct state established,related accept'))
        self.assertIn('meta skuid != 0 oifname "lr-services" ip daddr { 10.255.254.50 } tcp dport 9100 drop', text)
        self.assertIn('meta skuid { 1801 } drop', text)
        self.assertEqual(text.split(' chain forward {')[1].split(' chain output {')[0],
                         firewall.render(value).split(' chain forward {')[1].split(' chain output {')[0])
        native = service_plane.namespace_firewall(value, service_plane.topology(value), extension_rules=plan)
        self.assertIn('iifname "lr-host" ip saddr 10.255.254.1 ip daddr { 10.255.254.50 } tcp dport 9100 accept', native)

    def test_empty_contract_keeps_existing_rules_byte_identical(self):
        value = settings()
        plan = self.resolve({})
        self.assertEqual(firewall.render(value), firewall.render(value, extension_rules=plan))
        self.assertEqual(service_plane.namespace_firewall(value, service_plane.topology(value)),
                         service_plane.namespace_firewall(value, service_plane.topology(value), extension_rules=plan))

    def test_management_attachment_and_ipv6_are_independent(self):
        value = settings()
        value['networks']['rescue'] = {'name': 'rescue0', 'addresses': ['198.51.100.11/24'],
                                       'forwarding': False, 'ra': False}
        entry = {**listener(), 'network': 'rescue', 'address': '198.51.100.11',
                 'sources': ['198.51.100.0/24']}
        self.assertEqual(self.resolve({'listeners': [entry]}, value)['listeners'][0]['interface'], 'rescue0')
        entry = {**listener(), 'address': 'fd42:1000:1000:10::1', 'sources': ['fd42:1000:1000:10::/64']}
        self.assertIn('ip6 saddr', extension_network.input_rules(self.resolve({'listeners': [entry]}))[0])

    def test_malformed_or_undeclared_scopes_fail_closed(self):
        changes = [{'user': 'root'}, {'user': []}, {'network': 'uplink'}, {'network': 'missing'},
                   {'address': '0.0.0.0'}, {'address': '192.168.10.99'}, {'address': '127.0.0.1'},
                   {'address': 'fd42:1000:1000:10:0:0:0:1'}, {'port': True}, {'port': 22},
                   {'port': 65536}, {'port': 2222, 'unexpected': 'raw'}, {'protocol': 'tcp; accept'},
                   {'sources': []}, {'sources': ['192.168.10.1/24']}, {'sources': ['0.0.0.0/0']},
                   {'sources': ['192.168.20.0/24']}, {'sources': ['fd42:1000:1000:10::/64']},
                   {'sources': ['192.168.10.0/24']*2}, {'sources': [{}]}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                self.resolve({'listeners': [{**listener(), **change}]})
        value = settings()
        value['administration']['ssh_port'] = 8443
        with self.assertRaises(ReleaseError):
            self.resolve({'listeners': [listener()]}, value)
        for selected in ({'egress': []}, {'listeners': {}}, {'listeners': [listener()]*65}):
            with self.subTest(selected=str(selected)[:80]), self.assertRaises(ReleaseError):
                self.resolve(selected)

    def test_service_dependencies_require_enabled_component_owned_uid_and_supported_family(self):
        selected = {'user': 'example-agent', 'service': 'metrics', 'family': 4}
        with self.assertRaises(ReleaseError):
            self.resolve({'services': [selected]})
        for change in ({'user': 'prometheus'}, {'service': 'dns'}, {'family': True}, {'family': 5},
                       {'port': 22}, {'service': []}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                self.resolve({'services': [{**selected, **change}]})

    def test_different_extension_uids_cannot_claim_the_same_socket(self):
        first = extension_network.declarations({'listeners': [listener()]}, IDENTITIES)
        other = copy.deepcopy(IDENTITIES)
        other['users'][0]['uid'] = 1802
        second = extension_network.declarations({'listeners': [listener()]}, other)
        with self.assertRaises(ReleaseError):
            extension_network.resolve(settings(), [first, second])

    def test_optional_start_requires_inventoried_units_and_does_not_add_boot_health(self):
        for start in (['ssh.service'], ['example-agent.service']*2, ['var.mount'], [None],
                      ['example@.service'], ['-example.service'], ['example\\x20ssh.service']):
            with self.subTest(start=start), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pin = manifest(root, start_units=start)
                with self.assertRaises(ReleaseError):
                    extensions.admit(root, pin)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension = root/'extension'
            extension.mkdir()
            pin = manifest(extension, network={'listeners': [listener()]})
            base = root/'base.tar'
            with tarfile.open(base, 'w') as archive:
                for name, data in {'etc/passwd': b'root:*:0:0:root:/root:/bin/bash\n',
                                   'etc/group': b'root:x:0:\n'}.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            build.assembly(settings(), base, root/'work', version='0.1.0', sequence=9,
                           integrations={'example-observer': (extension, pin)})
            overlay = root/'work/mkosi.extra'
            self.assertFalse((overlay/'usr/lib/systemd/system/multi-user.target.wants/example-agent.service').exists())
            self.assertTrue((overlay/'usr/lib/systemd/system/multi-user.target.wants/lanrith-extension-start.service').is_symlink())
            starter = (overlay/'usr/lib/systemd/system/lanrith-extension-start.service').read_text()
            self.assertIn('After=boot-complete.target lanrith-observation.service', starter)
            self.assertIn('ExecStart=/usr/bin/systemctl --no-block start -- example-agent.service', starter)
            installed = json.loads((overlay/'usr/share/lanrith/installed.json').read_bytes())
            self.assertEqual(installed['integration_health_units'], [])
            self.assertNotIn('example-agent.service', (overlay/'usr/share/lanrith/health.json').read_text())
            self.assertIn('tcp dport 8443', (overlay/'etc/nftables.conf').read_text())
            self.assertNotIn('example-agent', (overlay/'usr/share/lanrith/health.json').read_text())

    def test_typed_access_cannot_silently_override_an_admitted_whole_firewall(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = manifest(root, network={'listeners': [listener()]})
            value = json.loads((root/'extension.json').read_bytes())
            path = root/'root/etc/nftables.conf'
            path.parent.mkdir(parents=True)
            path.write_text('# explicit owner replacement\n')
            path.chmod(0o644)
            record = file_record(path)
            record.pop('name')
            value['files']['etc/nftables.conf'] = {**record, 'mode': 0o644}
            value['replaces'] = ['etc/nftables.conf']
            encoded = canonical(value)
            (root/'extension.json').write_bytes(encoded)
            pin = hashlib.sha256(encoded).hexdigest()
            output = root/'output'
            config.write(settings(), output)
            with self.assertRaises(ReleaseError):
                extensions.overlay(settings(), {'example-observer': (root, pin)}, output)


if __name__ == '__main__':
    unittest.main()
