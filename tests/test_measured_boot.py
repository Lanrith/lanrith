"""A signed PCR policy is not proof that a UKI has matching measurements."""

from pathlib import Path
from contextlib import ExitStack, nullcontext
import shutil
import sys
import base64
import hashlib
import struct
import tempfile
import os
import subprocess
import unittest
from unittest.mock import patch
import json

from lanrith import measured_boot, release, update


class MeasuredContentTests(unittest.TestCase):
    def test_signature_alone_cannot_authorize_mismatched_contents(self):
        policy = {'public_key_sha256': 'a'*64, 'signed_pcrs': [11]}
        observation = {'authorized_to_unlock': False, 'content_matches': False}
        signed = {b'.pcrsig': json.dumps({'sha256': [{'pol': 'b'*64}]}).encode()}
        with patch.object(measured_boot, 'inspect_signature', return_value=observation) as inspect, \
                patch.object(measured_boot, 'file_record', return_value={'sha256': 'a'*64}), \
                patch.object(measured_boot, 'initrd_policy_digest', return_value='c'*64), \
                patch.object(measured_boot, 'sections', return_value=signed):
            with self.assertRaisesRegex(release.ReleaseError, 'not covered'):
                measured_boot.verify(Path('/test/fixture.efi'), policy)
            inspect.assert_called_once_with(Path('/test/fixture.efi'), policy)

    def fixture(self, root, names, *, large=0, overrides=None):
        # Distinct nonzero file padding catches hashing raw instead of virtual bytes.
        contents = {name: name + b'\0payload' for name in names}
        contents.update(overrides or {})
        if large:
            contents[b'.initrd'] = None
        table_order = list(reversed(names))
        header = bytearray(4096)
        header[:2] = b'MZ'
        struct.pack_into('<I', header, 60, 128)
        header[128:132] = b'PE\0\0'
        struct.pack_into('<HH', header, 132, 0x8664, len(names))
        struct.pack_into('<H', header, 148, 240)
        struct.pack_into('<H', header, 152, 0x20b)
        struct.pack_into('<I', header, 152+32, 4096)
        table = 128+24+240
        address = 4096
        image = root/'fixture.efi'
        with image.open('wb') as stream:
            stream.write(header)
            for index, name in enumerate(table_order):
                data = contents[name]
                size = len(data) if data is not None else large
                start = stream.tell()
                if data is None:
                    stream.seek(size, 1)
                else:
                    stream.write(data)
                stream.write(b'padding')
                entry = table + index*40
                header[entry:entry+8] = name.ljust(8, b'\0')
                struct.pack_into('<IIII', header, entry+8, size, address, size+7, start)
                address += (size+7+4095)//4096*4096
            struct.pack_into('<I', header, 152+56, address)
            stream.seek(0)
            stream.write(header)
        return image, contents

    def test_initrd_policy_matches_packaged_systemd_measure(self):
        measure = os.environ.get('LANRITH_TEST_SYSTEMD_MEASURE', '/usr/lib/systemd/systemd-measure')
        if not Path(measure).is_file():
            self.skipTest('systemd-measure oracle is unavailable.')
        required = (b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig')
        optional = (b'.osrel', b'.cmdline', b'.ucode', b'.splash', b'.dtb', b'.uname', b'.sbat')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for extra in ((), *((x,) for x in optional), optional):
                with self.subTest(extra=extra):
                    image, contents = self.fixture(root, required + extra)
                    args = [measure, 'calculate', '--bank=sha256', '--phase=enter-initrd', '--json=short']
                    for name, data in contents.items():
                        if name != b'.pcrsig':
                            section = root/name[1:].decode()
                            section.write_bytes(data)
                            args.append('--'+section.name+'='+str(section))
                    output = json.loads(subprocess.check_output(args))
                    pcr = bytes.fromhex(output['sha256'][0]['hash'])
                    expected = hashlib.sha256(bytes(32)+bytes.fromhex('0000017f00000001000b03000800')+
                                              hashlib.sha256(pcr).digest()).hexdigest()
                    self.assertEqual(measured_boot.initrd_policy_digest(image), expected)

    def test_measured_content_uses_no_scratch_for_owner_sized_initrd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, _ = self.fixture(root, (b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig'), large=144985564)
            with patch.object(measured_boot.tempfile, 'TemporaryDirectory', side_effect=AssertionError('scratch')):
                self.assertRegex(measured_boot.initrd_policy_digest(image), '^[0-9a-f]{64}$')
            self.assertEqual(list(root.iterdir()), [image])

    def test_largest_supported_signed_measurement_fits_updater_memory(self):
        measure = os.environ.get('LANRITH_TEST_SYSTEMD_MEASURE', '/usr/lib/systemd/systemd-measure')
        if not Path(measure).is_file():
            self.skipTest('systemd-measure oracle is unavailable.')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root/'ephemeral-key.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                            '-out', str(private)], check=True, capture_output=True)
            public = subprocess.check_output(['openssl', 'pkey', '-in', str(private), '-pubout'])
            der = subprocess.check_output(['openssl', 'rsa', '-pubin', '-RSAPublicKey_out', '-outform', 'DER'],
                                          input=public)
            names = (b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig')
            size = 512*1024**2 - len(public) - len(b'kernel')
            with (root/'initrd').open('wb') as stream:
                stream.truncate(size)
            (root/'linux').write_bytes(b'kernel')
            (root/'pcrpkey').write_bytes(public)
            oracle = subprocess.check_output([measure, 'calculate', '--bank=sha256', '--phase=enter-initrd',
                '--json=short', '--linux='+str(root/'linux'), '--initrd='+str(root/'initrd'),
                '--pcrpkey='+str(root/'pcrpkey')])
            pcr = bytes.fromhex(json.loads(oracle)['sha256'][0]['hash'])
            digest = hashlib.sha256(bytes(32) + bytes.fromhex('0000017f00000001000b03000800') +
                                    hashlib.sha256(pcr).digest()).digest()
            signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(private)], input=digest)
            entry = {'pkfp': hashlib.sha256(der).hexdigest(), 'pcrs': [11], 'pol': digest.hex(),
                     'sig': base64.b64encode(signature).decode()}
            image, _ = self.fixture(root, names, large=size, overrides={b'.linux': b'kernel', b'.pcrpkey': public,
                                    b'.pcrsig': json.dumps({'sha256': [entry]}).encode()})
            policy = {'public_key_sha256': hashlib.sha256(public).hexdigest(), 'signed_pcrs': [11]}
            with image.open('r+b') as stream:
                stream.truncate(1024**3)  # Maximum accepted PE size, including unmeasured padding.
            # The oracle may map its own input. Limit only the appliance verifier.
            program = ('import json,resource,sys; from pathlib import Path; from lanrith import measured_boot; '
                       'resource.setrlimit(resource.RLIMIT_AS, (128*1024**2, 128*1024**2)); '
                       'assert measured_boot.verify(Path(sys.argv[1]), json.loads(sys.argv[2]))["content_matches"]')
            subprocess.run([sys.executable, '-c', program, str(image), json.dumps(policy)], check=True, timeout=120)

    @unittest.skipUnless(os.geteuid() == 0, 'Staging requires a protected root-owned inbox.')
    def test_authenticated_candidate_measurement_precedes_staging_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root/'cert', root/'key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=Staging fixture', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            public = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout'])
            der = subprocess.check_output(['openssl', 'rsa', '-pubin', '-RSAPublicKey_out', '-outform', 'DER'],
                                          input=public, stderr=subprocess.DEVNULL)
            source = root/'update-inbox/17'
            source.mkdir(parents=True, mode=0o700)
            accepted = root/'EFI/Linux/lanrith_10.efi'
            accepted.parent.mkdir(parents=True)
            accepted.write_bytes(b'accepted')
            pending = accepted.with_name('lanrith_17+3.efi')
            policy = {'signed_pcrs': [11], 'public_key_sha256': hashlib.sha256(public).hexdigest()}
            installed = root/'installed.json'
            installed.write_text(json.dumps({'state_directory': str(root), 'uki_name': accepted.name,
                'certificate': str(cert), 'update_image_id': 'lanrith', 'deployment_sequence': 10, 'tpm_policy': policy}))
            names = (b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig')
            image, _ = self.fixture(source, names, overrides={b'.pcrpkey': public})
            digest = bytes.fromhex(measured_boot.initrd_policy_digest(image))
            signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=digest)
            entry = {'pcrs': [11], 'pkfp': hashlib.sha256(der).hexdigest(), 'pol': digest.hex(),
                     'sig': base64.b64encode(signature).decode()}
            pieces = {b'.pcrpkey': public, b'.pcrsig': json.dumps({'sha256': [entry]}).encode()}
            roles = {role: role+'.raw' for role in ('root', 'verity', 'verity-sig')}
            for name in roles.values():
                (source/name).write_bytes(b'fixture partition')
            partition = {'number': 5, 'label': 'l_17_root', 'uuid': 'fixture'}
            planned = {'sequence': 17, 'image_id': 'lanrith', 'partitions': {'root': partition}}
            def command(args, **kwargs):
                if args[0] == 'systemctl':
                    return 'active'
                if args[0] == 'bootctl':
                    return str(accepted)
                if args[0] == 'sfdisk':
                    mutations.append('label')
                elif 'systemd-sysupdate' in args[0]:
                    mutations.append('transfer')
                    shutil.copyfile(image, pending)
                else:
                    self.fail('Unexpected fixture command '+args[0])
            for valid in (False, True):
                image, _ = self.fixture(source, names, overrides=pieces if valid else {**pieces, b'.initrd': b'newer initrd'})
                manifest = release.unsigned_manifest(source, purpose='update', version='0.1.0', sequence=17,
                    configuration_sha256='a'*64, files={**roles, 'uki': image.name})
                (source/'release.json').write_bytes(release.canonical(manifest))
                (source/'release.json.sig').unlink(missing_ok=True)
                release.sign(source, key)
                mutations = []
                with self.subTest(valid=valid), ExitStack() as stack:
                    for name, result in (('boot_esp', root), ('require_default', None), ('root_disk', ('/fixture', set())),
                                         ('geometry', [partition]), ('plan', planned), ('transfers', {})):
                        stack.enter_context(patch.object(update, name, return_value=result))
                    stack.enter_context(patch.object(update, 'command', side_effect=command))
                    stack.enter_context(patch.object(update, 'IMAGE_LOCK_DIR', root))
                    stack.enter_context(patch.object(Path, 'is_mount', return_value=True))
                    write = stack.enter_context(patch.object(update, 'writable_esp', return_value=nullcontext()))
                    select = stack.enter_context(patch.object(update, 'select_boot_once'))
                    if valid:
                        self.assertEqual(update.stage_locked(source, installed), planned)
                        self.assertEqual(mutations, ['label', 'transfer'])
                        select.assert_called_once_with(pending)
                    else:
                        with self.assertRaisesRegex(release.ReleaseError, 'not covered'):
                            update.stage_locked(source, installed)
                        self.assertFalse(mutations)
                        write.assert_not_called()
                        select.assert_not_called()
                        self.assertFalse(pending.exists())
                        self.assertEqual(accepted.read_bytes(), b'accepted')

    def test_invalid_layout_and_excessive_budget_are_rejected_at_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = (b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig')
            image, _ = self.fixture(root, names+(b'.profile',))
            with self.assertRaisesRegex(release.ReleaseError, 'Unsupported'):
                measured_boot.check_measurement_budget(image)
            image, _ = self.fixture(root, names, large=512*1024*1024)
            with self.assertRaisesRegex(release.ReleaseError, 'exceed'):
                measured_boot.check_measurement_budget(image)
            image, _ = self.fixture(root, names)
            with image.open('r+b') as stream:
                stream.seek(128+24+240+40+12)
                stream.write(struct.pack('<I', 4096))
            with self.assertRaisesRegex(release.ReleaseError, 'overlapping'):
                measured_boot.initrd_policy_digest(image)


if __name__ == '__main__':
    unittest.main()
