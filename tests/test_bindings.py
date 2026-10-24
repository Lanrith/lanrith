"""Migration bindings preserve identities and never install secret contents."""

import copy
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from lanrith import bindings, build, config, extensions
from lanrith.release import ReleaseError
from test_authoritative import declaration as dns_declaration
from test_intent import minimal
from test_routing import declaration as routing_declaration


ACCOUNTS = {'passwd': b'root:*:0:0:root:/root:/bin/bash\nbind:*:109:113:DNS:/var/cache/bind:/usr/sbin/nologin\n',
            'group': b'root:x:0:\nbind:x:113:\n'}
ASSERTION = {'bind': {'uid': 109, 'gid': 113, 'home': '/var/cache/bind', 'shell': '/usr/sbin/nologin'}}


class RuntimeBindingTests(unittest.TestCase):
    def test_optional_absence_keeps_existing_configuration_and_digest(self):
        value = config.normalize(minimal())
        self.assertNotIn('runtime', value)
        self.assertEqual(config.normalize(value), value)
        changed = copy.deepcopy(value)
        changed['runtime'] = {'service_identities': copy.deepcopy(ASSERTION)}
        self.assertNotEqual(config.rendered_digest(changed), config.rendered_digest(value))

    def test_dns_and_bgp_credentials_use_explicit_paths_without_reading_them(self):
        for value, reference, unit in (
                (dns_declaration(), 'first_tsig', 'lanrith-dns-state'),
                (routing_declaration(), 'vpn_bgp', 'lanrith-routing-credentials')):
            selected = '/var/lib/owner-credentials/'+reference
            value['runtime'] = {'credentials': {reference: selected}}
            files = config.render(value)
            self.assertIn(f'LoadCredential={reference}:{selected}\n',
                          files['usr/lib/systemd/system/'+unit+'.service'])
            self.assertNotIn('var/lib/owner-credentials/'+reference, files)
            self.assertEqual(config.normalize(config.normalize(value)), config.normalize(value))

    def test_credentials_reject_dangling_refs_substitutions_and_shared_files(self):
        for reference, selected in (
                ('undeclared', '/var/lib/secrets/key'), ('first_tsig', '/etc/shadow'),
                ('first_tsig', '/var/lib/x/../secret'), ('first_tsig', '/var/lib//secret'),
                ('first_tsig', '/var/lib/%H'), ('first_tsig', '/var/lib/$NAME'),
                ('first_tsig', '/var/lib/key\nExecStart=/bin/sh'),
                ('first_tsig', '/var/lib/key:other'), ('first_tsig', '/var/lib/key ')):
            value = dns_declaration()
            value['runtime'] = {'credentials': {reference: selected}}
            with self.subTest(reference=reference, selected=selected), self.assertRaises(ReleaseError):
                config.normalize(value)
        value = dns_declaration()
        value['runtime'] = {'credentials': {'first_tsig': '/var/lib/lanrith/credentials/second_tsig'}}
        with self.assertRaisesRegex(ReleaseError, 'share'):
            config.normalize(value)

    def test_account_assertions_do_not_rewrite_accounts_or_chown_state(self):
        value = config.normalize(minimal())
        value['runtime'] = {'service_identities': copy.deepcopy(ASSERTION)}
        with tempfile.TemporaryDirectory() as temporary:
            overlay = Path(temporary)
            bindings.verify_accounts(value, ACCOUNTS, overlay)
            self.assertEqual(list(overlay.iterdir()), [])
            for mutation in ({'uid': 110}, {'gid': 114}, {'home': '/var/lib/bind'}, {'shell': '/bin/sh'}):
                changed = copy.deepcopy(value)
                changed['runtime']['service_identities']['bind'].update(mutation)
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ReleaseError, 'explicit migration'):
                    bindings.verify_accounts(changed, ACCOUNTS, overlay)
            missing = copy.deepcopy(value)
            missing['runtime']['service_identities'] = {'missing': {'uid': 109, 'gid': 113}}
            with self.assertRaisesRegex(ReleaseError, 'missing'):
                bindings.verify_accounts(missing, ACCOUNTS, overlay)

    def test_effective_admitted_extension_accounts_are_verified(self):
        value = config.normalize(minimal())
        value['runtime'] = {'service_identities': {'owner-worker': {'uid': 2000, 'gid': 2000}}}
        declarations = extensions.identity_declarations({'users': [
            {'name': 'owner-worker', 'uid': 2000, 'gid': 2000}],
            'groups': [{'name': 'owner-worker', 'gid': 2000}]})
        with tempfile.TemporaryDirectory() as temporary:
            overlay = Path(temporary)
            extensions.account_overlay(ACCOUNTS, [declarations], overlay)
            before = (overlay/'etc/passwd').read_bytes()
            bindings.verify_accounts(value, ACCOUNTS, overlay)
            self.assertEqual((overlay/'etc/passwd').read_bytes(), before)

    def test_ambiguous_and_malformed_registries_cannot_satisfy_an_assertion(self):
        value = config.normalize(minimal())
        value['runtime'] = {'service_identities': copy.deepcopy(ASSERTION)}
        for registry in (
                {**ACCOUNTS, 'passwd': ACCOUNTS['passwd']+b'bind:*:109:113:DNS:/var/cache/bind:/usr/sbin/nologin\n'},
                {**ACCOUNTS, 'passwd': ACCOUNTS['passwd']+b'alias:*:109:113:DNS:/var/cache/bind:/usr/sbin/nologin\n'},
                {**ACCOUNTS, 'group': ACCOUNTS['group']+b'alias:x:113:\n'},
                {**ACCOUNTS, 'passwd': b'bind:*:109\n'},
                {**ACCOUNTS, 'passwd': b'bind:*:nan:113:DNS:/var/cache/bind:/usr/sbin/nologin\n'},
                {**ACCOUNTS, 'group': b'bind:x:113:\x00\n'}):
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ReleaseError):
                bindings.verify_accounts(value, registry, Path(temporary))

    def test_assembly_checks_the_base_registry_and_does_not_add_an_account_overlay(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        value['runtime'] = {'service_identities': copy.deepcopy(ASSERTION)}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            with tarfile.open(base, 'w') as archive:
                for name, data in ACCOUNTS.items():
                    entry = tarfile.TarInfo('etc/'+name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            build.assembly(value, base, root/'valid', version='0.1.0', sequence=9)
            self.assertFalse((root/'valid/mkosi.extra/etc/passwd').exists())
            value['runtime']['service_identities']['bind']['uid'] = 110
            with self.assertRaisesRegex(ReleaseError, 'explicit migration'):
                build.assembly(value, base, root/'invalid', version='0.1.0', sequence=10)
            self.assertFalse((root/'invalid/mkosi.conf').exists())

    def test_trust_accepts_only_declared_public_certificates(self):
        value = minimal()
        value['identity'] = {'directories': {'inventory': {'enabled': False,
            'url': 'ldaps://[fd42:1234:5678:10::20]', 'base_dn': 'dc=example', 'bind_dn': 'cn=reader,dc=example',
            'credential': 'directory_bind', 'ca_file': 'trust/inventory.pem'}}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Synthetic migration CA', '-keyout', str(root/'key'), '-out', str(root/'cert')],
                check=True, capture_output=True)
            certificate = (root/'cert').read_text()
            value['runtime'] = {'trust': {'trust/inventory.pem': certificate}}
            files = config.render(value)
            self.assertEqual(files['usr/share/lanrith/trust/inventory.pem'], certificate)
            for name, content in (('trust/unknown.pem', certificate),
                    ('trust/inventory.pem', (root/'key').read_text()),
                    ('trust/inventory.pem', certificate+'# arbitrary payload\n'),
                    ('trust/inventory.pem', '-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n')):
                changed = copy.deepcopy(value)
                changed['runtime'] = {'trust': {name: content}}
                with self.subTest(name=name), self.assertRaises(ReleaseError):
                    config.normalize(changed)

    def test_runtime_cannot_become_a_filesystem_overlay_or_account_remapper(self):
        for selected in ({'overlay': '/tmp/tree'}, {'state_paths': {'nat64': '/tmp/state'}},
                {'service_identities': {'root-alias': {'uid': 0, 'gid': 0}}},
                {'service_identities': {'bind': {'uid': True, 'gid': 113}}},
                {'service_identities': {'bind': {'uid': 109, 'gid': 113, 'shell': '/bin/sh\nroot'}}}):
            value = minimal()
            value['runtime'] = selected
            with self.subTest(selected=selected), self.assertRaises(ReleaseError):
                config.normalize(value)


if __name__ == '__main__':
    unittest.main()
