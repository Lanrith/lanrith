"""Inspect authenticated UKI PCR sections without executing or extracting code."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile

from .release import ReleaseError, file_record, require, unique

MEASURE = '/usr/lib/systemd/systemd-measure'
MEASURED_SECTIONS = {b'.linux', b'.osrel', b'.cmdline', b'.initrd', b'.ucode', b'.splash',
                     b'.dtb', b'.uname', b'.sbat', b'.pcrpkey'}
OTHER_SECTIONS = {b'.text', b'.rodata', b'.data', b'.reloc', b'.sdmagic', b'.pcrsig'}


def sections(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        dos = stream.read(64)
        require(len(dos) == 64 and dos[:2] == b'MZ', 'UKI lacks its PE header.')
        offset = struct.unpack_from('<I', dos, 60)[0]
        require(64 <= offset <= min(size-24, 1024*1024), 'UKI PE header offset is invalid.')
        stream.seek(offset)
        header = stream.read(24)
        require(len(header) == 24 and header[:4] == b'PE\0\0', 'UKI PE header is invalid.')
        machine, count = struct.unpack_from('<HH', header, 4)
        optional = struct.unpack_from('<H', header, 20)[0]
        require(machine == 0x8664 and 1 <= count <= 96 and 112 <= optional <= 4096 and
                offset+24+optional+count*40 <= size, 'Unsupported UKI PE layout.')
        stream.seek(offset+24+optional)
        table = stream.read(count*40)
        result = {}
        for index in range(count):
            entry = table[index*40:(index+1)*40]
            name = entry[:8].rstrip(b'\0')
            if name not in (b'.pcrsig', b'.pcrpkey'):
                continue
            require(name not in result, 'UKI contains duplicate measured-policy sections.')
            virtual_size, _, raw_size, raw_offset = struct.unpack_from('<IIII', entry, 8)
            require(0 < virtual_size <= raw_size <= 262144 and
                    raw_offset >= offset+24+optional+count*40 and raw_offset+raw_size <= size,
                    'UKI measured-policy section is out of bounds.')
            stream.seek(raw_offset)
            result[name] = stream.read(virtual_size).rstrip(b'\0')
        require(set(result) == {b'.pcrsig', b'.pcrpkey'}, 'UKI lacks its required measured-policy sections.')
        return result


def inspect_signature(path, policy):
    """Check the signature and authority only; this does not bind UKI contents."""
    value = sections(path)
    public = value[b'.pcrpkey']
    require(hashlib.sha256(public).hexdigest() == policy['public_key_sha256'],
            'UKI PCR policy authority differs from installed trust.')
    signatures = json.loads(value[b'.pcrsig'], object_pairs_hook=unique)
    require(isinstance(signatures, dict) and set(signatures) == {'sha256'} and
            isinstance(signatures['sha256'], list) and 1 <= len(signatures['sha256']) <= 16,
            'UKI PCR signature banks differ.')
    # systemd-measure fingerprints the DER PKCS#1 RSA key, rather than the
    # SubjectPublicKeyInfo envelope produced by `openssl pkey -outform DER`.
    result = subprocess.run(['openssl', 'rsa', '-pubin', '-RSAPublicKey_out', '-outform', 'DER'], input=public,
                            capture_output=True, timeout=15)
    require(result.returncode == 0 and result.stdout, 'UKI PCR policy public key is invalid.')
    fingerprint = hashlib.sha256(result.stdout).hexdigest()
    with tempfile.TemporaryDirectory(prefix='lanrith-pcr-verify.') as temporary:
        root = Path(temporary)
        (root/'public.pem').write_bytes(public)
        for entry in signatures['sha256']:
            require(isinstance(entry, dict) and set(entry) == {'pcrs', 'pkfp', 'pol', 'sig'} and
                    entry['pcrs'] == policy['signed_pcrs'] and entry['pkfp'] == fingerprint and
                    isinstance(entry['pol'], str) and re.fullmatch(r'[0-9a-f]{64}', entry['pol']) and
                    isinstance(entry['sig'], str) and len(entry['sig']) <= 4096,
                    'UKI PCR signature coverage or authority differs.')
            try:
                signature = base64.b64decode(entry['sig'], validate=True)
            except (ValueError, TypeError):
                raise ReleaseError('UKI PCR signature is malformed.') from None
            require(0 < len(signature) <= 2048, 'UKI PCR signature size differs.')
            (root/'signature').write_bytes(signature)
            (root/'policy').write_bytes(bytes.fromhex(entry['pol']))
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(root/'public.pem'),
                                     '-signature', str(root/'signature'), str(root/'policy')],
                                    capture_output=True, timeout=15)
            require(result.returncode == 0, 'UKI measured-policy signature is invalid.')
    return {'bank': 'sha256', 'signed_pcrs': policy['signed_pcrs'],
            'public_key_sha256': policy['public_key_sha256'], 'signatures': len(signatures['sha256']),
            'early_boot_only': False, 'content_matches': False, 'authorized_to_unlock': False}


def initrd_policy_digest(path):
    """Calculate the SHA-256 PolicyPCR digest for the UKI's initrd phase."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream, tempfile.TemporaryDirectory(prefix='lanrith-pcr-content.') as temporary:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 64 <= before.st_size <= 1024**3,
                'Unsafe measured UKI.')
        dos = stream.read(64)
        require(dos[:2] == b'MZ', 'UKI lacks its PE header.')
        offset = struct.unpack_from('<I', dos, 60)[0]
        require(64 <= offset <= min(before.st_size-24, 1024*1024), 'UKI PE header offset is invalid.')
        stream.seek(offset)
        header = stream.read(24)
        require(len(header) == 24 and header[:4] == b'PE\0\0', 'UKI PE header is invalid.')
        machine, count = struct.unpack_from('<HH', header, 4)
        optional = struct.unpack_from('<H', header, 20)[0]
        table_end = offset+24+optional+count*40
        require(machine == 0x8664 and 1 <= count <= 96 and 112 <= optional <= 4096 and table_end <= before.st_size,
                'Unsupported UKI PE layout.')
        stream.seek(offset+24)
        options = stream.read(optional)
        require(len(options) == optional and struct.unpack_from('<H', options, 0)[0] == 0x20b,
                'Unsupported UKI PE format.')
        alignment = struct.unpack_from('<I', options, 32)[0]
        image_size = struct.unpack_from('<I', options, 56)[0]
        require(alignment and not alignment & (alignment-1) and image_size > 0,
                'Invalid UKI virtual image geometry.')
        stream.seek(offset+24+optional)
        table = stream.read(count*40)
        found, extents, virtual_extents = {}, [], []
        for index in range(count):
            entry = table[index*40:(index+1)*40]
            name = entry[:8].rstrip(b'\0')
            size, address, raw_size, start = struct.unpack_from('<IIII', entry, 8)
            require(name in MEASURED_SECTIONS | OTHER_SECTIONS and name not in found,
                    'Unsupported or duplicate UKI section.')
            require(0 < size <= raw_size and start >= table_end and start+raw_size <= before.st_size and
                    address > 0 and address % alignment == 0 and address+max(size, raw_size) <= image_size,
                    'Invalid UKI section bounds.')
            found[name] = (start, size)
            extents.append((start, start+raw_size))
            virtual_extents.append((address, address+max(size, raw_size)))
        extents.sort()
        virtual_extents.sort()
        require(all(a[1] <= b[0] for a, b in zip(extents, extents[1:])) and
                all(a[1] <= b[0] for a, b in zip(virtual_extents, virtual_extents[1:])) and
                {b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig'} <= set(found),
                'UKI section layout is incomplete or overlapping.')
        args = [MEASURE, 'calculate', '--bank=sha256', '--phase=enter-initrd', '--json=short']
        total = 0
        for name in sorted(MEASURED_SECTIONS & found.keys()):
            start, size = found[name]
            total += size
            require(total <= 512*1024*1024, 'UKI measured sections exceed their bound.')
            target = Path(temporary)/name[1:].decode('ascii')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            stream.seek(start)
            with os.fdopen(fd, 'wb') as output:
                remaining = size
                while remaining:
                    block = stream.read(min(1024*1024, remaining))
                    require(block, 'UKI measured section is truncated.')
                    output.write(block)
                    remaining -= len(block)
            args.append('--'+name[1:].decode('ascii')+'='+str(target))
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'UKI changed during measured-content inspection.')
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
        require(result.returncode == 0 and 0 < len(result.stdout) <= 16384,
                'Cannot calculate UKI initrd measurement.')
        try:
            value = json.loads(result.stdout, object_pairs_hook=unique)
        except (UnicodeDecodeError, ValueError):
            raise ReleaseError('Invalid calculated UKI measurement.') from None
        require(isinstance(value, dict) and set(value) == {'sha256'} and isinstance(value['sha256'], list) and
                len(value['sha256']) == 1 and isinstance(value['sha256'][0], dict),
                'Unexpected calculated UKI measurement.')
        item = value['sha256'][0]
        require(set(item) == {'phase', 'pcr', 'hash'} and item['phase'] == 'enter-initrd' and item['pcr'] == 11 and
                isinstance(item['hash'], str) and re.fullmatch(r'[0-9a-f]{64}', item['hash']),
                'Unexpected calculated UKI initrd measurement.')
        # TPM2_PolicyPCR with SHA-256, PCR 11, three-byte PCR selection.
        selection = bytes.fromhex('00000001000b03000800')
        composite = hashlib.sha256(bytes.fromhex(item['hash'])).digest()
        return hashlib.sha256(bytes(32)+bytes.fromhex('0000017f')+selection+composite).hexdigest()


def verify(path, policy):
    """Check a signed policy against the UKI's calculated initrd measurement."""
    require(isinstance(policy, dict) and policy.get('signed_pcrs') == [11],
            'Only the PCR 11 initrd policy can be verified.')
    before = file_record(path)
    observation = inspect_signature(path, policy)
    expected = initrd_policy_digest(path)
    signatures = json.loads(sections(path)[b'.pcrsig'], object_pairs_hook=unique)['sha256']
    require(any(hmac.compare_digest(entry['pol'], expected) for entry in signatures),
            'UKI initrd measurement is not covered by its signed PCR policy.')
    require(file_record(path) == before, 'UKI changed during measured-policy verification.')
    return {**observation, 'content_matches': True}
