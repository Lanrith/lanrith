"""Bind bounded firewall observation evidence to exact base userspace bytes."""

import datetime
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile

from .release import ReleaseError, file_record, require


NFT = 'usr/sbin/nft'
HEX = re.compile(r'[a-f0-9]{64}\Z')
CHECKS = {
    'exact generated nft syntax and original rules preserved',
    'nonroot receiver discards all effective/permitted/inheritable/ambient capabilities',
    'receiver cannot write firewall or reconfigure the group',
    'group cannot be stolen; unrelated UID cannot bind',
    'real IPv4/IPv6 TCP/UDP/ICMP input and forward default-deny tuples',
    'stalled and absent receiver plus exhausted sampling never admits denied traffic or blocks allowed traffic',
    'actual build-allocated account, curated runtime and generated resource-bound systemd unit',
    'admitted reader can read but not write; unrelated capability-empty UID cannot read',
    'forced process loss changes producer epoch and resumes metadata',
    'invalid collector contract preserves firewall, allowed/denied packets and actual global boot check',
    'disabled endpoint removes metadata/activation and preserves default-deny and permitted forwarding'}
IMPLEMENTATION = {
    'lanrith/firewall_qualification.py', 'lanrith/firewall_observations.py', 'lanrith/firewall_observations_runtime.py',
    'lanrith/firewall_metadata.py', 'lanrith/observation_spool.py', 'lanrith/observation_accounts.py',
    'lanrith/extensions.py', 'lanrith/extension_observations.py', 'lanrith/extension_network.py',
    'lanrith/build.py', 'lanrith/config.py', 'lanrith/intent.py', 'lanrith/firewall.py', 'lanrith/access.py',
    'lanrith/service_plane.py', 'lanrith/nat46.py', 'lanrith/nat64.py', 'lanrith/translation.py',
    'lanrith/policy_runtime.py', 'lanrith/release.py', 'lanrith/admission.py',
    'scripts/qualify-firewall.py', 'scripts/qualify-base.py', 'scripts/build-base.py',
    'tests/firewall_metadata_native.py', 'tests/firewall_userspace.py', 'tests/firewall_service_native.py', 'tests/test_firewall_metadata.py',
    'tests/test_firewall_observations.py', 'tests/test_firewall_qualification.py', 'tests/firewall_fixture.py',
    'tests/test_extension_network.py', 'tests/test_intent.py', 'examples/minimal.yaml'}
ASSEMBLY = {'etc/nftables.conf', 'usr/share/lanrith/firewall-observations.json',
    'etc/modules-load.d/65-lanrith-firewall-observations.conf',
    'etc/systemd/system/nftables.service.d/62-lanrith-observations.conf',
    'etc/systemd/system/lanrith-firewall-observations.service', 'usr/lib/lanrith/firewall-observations-runtime',
    'etc/passwd', 'etc/group', 'usr/lib/lanrith/lanrith/firewall_observations_runtime.py',
    'usr/lib/lanrith/lanrith/firewall_metadata.py', 'usr/lib/lanrith/lanrith/observation_spool.py'}


def implementation(project):
    return {name: file_record(project/name)['sha256'] for name in sorted(IMPLEMENTATION)}


def library_path(name):
    if not isinstance(name, str) or len(name) > 256:
        return False
    path = PurePosixPath(name)
    return (str(path) == name and path.parts[:2] == ('usr', 'lib') and 3 <= len(path.parts) <= 6 and
            all(re.fullmatch(r'[A-Za-z0-9_+.-]{1,128}', part) and part not in ('.', '..') for part in path.parts) and
            re.fullmatch(r'[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*\.so(?:\.[A-Za-z0-9_.+-]+)?', path.name) is not None)


def library_inventory():
    """Inspect the staged executable using the immutable builder's loader tool.

    Never execute this on an unapproved host binary: native qualification calls
    it only inside its disposable, offline container after staging the subject.
    Resolve symlinks before comparing ordinary archive targets. All loaded
    libraries, including the interpreter and transitive dependencies, are bound.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith('LD_')}
    env.update(LC_ALL='C', LANG='C')
    result = subprocess.run(['/usr/bin/ldd', '/'+NFT], env=env, capture_output=True, timeout=5)
    require(result.returncode == 0 and len(result.stdout)+len(result.stderr) <= 65536,
            'Staged nft dependency inventory failed.')
    values = {}
    for line in result.stdout.decode('ascii').splitlines():
        stripped = line.strip()
        if re.fullmatch(r'linux-vdso\.so\.[0-9]+ \(0x[a-f0-9]+\)', stripped) or stripped == 'statically linked':
            continue
        match = re.fullmatch(r'(?:[A-Za-z0-9_.+-]+ => )?(/[^\s]+) \(0x[a-f0-9]+\)', stripped)
        require(match is not None, 'Staged nft has an unresolved or ambiguous dependency.')
        path = Path(match[1]).resolve(strict=True)
        name = str(path).removeprefix('/')
        info = path.stat()
        require(library_path(name) and stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not stat.S_IMODE(info.st_mode) & 0o7022 and 0 < info.st_size <= 64*1024*1024 and len(values) < 32,
                'Staged nft dependency custody differs.')
        values[name] = file_record(path)['sha256']
    require(values, 'Firewall gate requires an inventoried dynamic nft dependency closure.')
    return values


def subject(archive, libraries=(), *, destination=None, extract_libraries=False):
    """Hash fixed ordinary targets; optionally stage validated shared objects.

    No archive member supplies an extraction path. Library names are first
    restricted to canonical /usr/lib shared objects. Aliases, links, duplicates,
    sparse files, unsafe ownership/modes and allocation overflows are rejected.
    """
    require(isinstance(libraries, (dict, tuple, list, set)) and len(libraries) <= 32 and
            all(library_path(name) for name in libraries), 'Invalid nft dependency inventory.')
    require(type(extract_libraries) is bool and (not extract_libraries or destination is not None),
            'Library extraction requires an explicit private staging directory.')
    wanted, values, total = {NFT, *libraries}, {}, 0
    if destination is not None:
        require(destination.is_dir() and not destination.is_symlink() and not list(destination.iterdir()),
                'nft executable staging must be a new empty directory.')
    try:
        with tarfile.open(archive, mode='r|gz') as stream:
            for index, member in enumerate(stream):
                total += member.size
                require(index < 500000 and total <= 64*1024**3, 'Firewall base inventory exceeds its bound.')
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and '..' not in path.parts, 'Firewall base path is not relative.')
                name = str(path)
                if name in wanted:
                    require(name not in values and member.name in (name, './'+name) and member.isfile() and
                            not member.issparse() and member.uid == member.gid == 0 and
                            member.mode & 0o7777 in ((0o755,) if name == NFT else (0o444, 0o555, 0o644, 0o755)) and
                            0 < member.size <= 64*1024*1024, 'Firewall userspace target must be one canonical root-owned ordinary file.')
                    reader = stream.extractfile(member)
                    require(reader is not None, 'Firewall userspace target is unreadable.')
                    checksum, size = hashlib.sha256(), 0
                    output = (destination/('nft' if name == NFT else name)
                              if destination is not None and (name == NFT or extract_libraries) else None)
                    if output is not None:
                        output.parent.mkdir(parents=True, exist_ok=True)
                    target = output.open('xb') if output is not None else None
                    try:
                        with reader:
                            while block := reader.read(1024*1024):
                                checksum.update(block)
                                size += len(block)
                                if target is not None:
                                    target.write(block)
                        require(size == member.size, 'Firewall userspace target is truncated.')
                    finally:
                        if target is not None:
                            target.close()
                    if target is not None:
                        output.chmod(member.mode & 0o777)
                    values[name] = checksum.hexdigest()
                stream.members.clear()
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ReleaseError('Invalid base archive for firewall qualification.') from error
    require(set(values) == wanted, 'Base archive lacks required nft userspace targets.')
    return values


def validate(value, filesystem_sha256, *, project=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1 and
            value.get('test') == 'offline-firewall-observations' and value.get('result') == 'pass' and
            isinstance(value.get('checks'), list) and len(value['checks']) == len(CHECKS) and
            all(isinstance(item, str) for item in value['checks']) and set(value['checks']) == CHECKS and
            value.get('generated_service_tested') is True and value.get('external_network') is False and
            value.get('private_image_qualified') is False and value.get('image_boot_qualified') is False and
            value.get('container_cleanup') == 'removed' and value.get('container_runtime') in ('docker', 'podman') and
            isinstance(value.get('builder_image_sha256'), str) and HEX.fullmatch(value['builder_image_sha256']) and
            isinstance(filesystem_sha256, str) and HEX.fullmatch(filesystem_sha256) and value.get('filesystem_sha256') == filesystem_sha256,
            'Firewall qualification is incomplete or describes another base.')
    libraries = value.get('builder_libraries_sha256')
    require(isinstance(libraries, dict) and 1 <= len(libraries) <= 32 and all(library_path(name) and
            isinstance(digest, str) and HEX.fullmatch(digest) for name, digest in libraries.items()) and
            isinstance(value.get('nft_sha256'), str) and HEX.fullmatch(value['nft_sha256']) and
            value.get('base_userspace_sha256') == {NFT: value['nft_sha256'], **libraries},
            'Firewall qualification lacks matching executable and library bytes.')
    receiver = value.get('receiver', {})
    caps = receiver.get('capabilities', {}) if isinstance(receiver, dict) else {}
    require(isinstance(receiver, dict) and type(receiver.get('uid')) is int and 100 <= receiver['uid'] < 1000 and isinstance(caps, dict) and
            set(caps) == {'CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd', 'NoNewPrivs'} and
            all(caps[key] == '0000000000000000' for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')) and
            caps['CapBnd'] == '0000000000001000' and caps['NoNewPrivs'] == '1' and
            receiver.get('firewall_write_denied') is True and receiver.get('reconfiguration_denied') is True and
            type(value.get('unconditional_forward_drops')) is int and value['unconditional_forward_drops'] >= 1100 and
            type(value.get('allowed_echoes')) is int and value['allowed_echoes'] >= 4 and value.get('payload_exported') is False,
            'Firewall qualification does not establish its receiver and packet boundaries.')
    require(isinstance(value.get('kernel_release'), str) and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', value['kernel_release']) and
            isinstance(value.get('nft_version'), str) and value['nft_version'].startswith('nftables v') and len(value['nft_version']) <= 512,
            'Firewall qualification execution context is missing.')
    try:
        stamp = datetime.datetime.fromisoformat(value['assessed_at'])
    except (KeyError, TypeError, ValueError):
        require(False, 'Firewall qualification timestamp is invalid.')
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'Firewall qualification is stale or future-dated.')
    for field, expected in (('source_sha256', IMPLEMENTATION), ('assembly_sha256', ASSEMBLY)):
        bindings = value.get(field)
        require(isinstance(bindings, dict) and set(bindings) == expected and
                all(isinstance(item, str) and HEX.fullmatch(item) for item in bindings.values()),
                'Firewall qualification implementation/assembly bindings are incomplete.')
    if project is not None:
        require(value['source_sha256'] == implementation(project), 'Firewall implementation changed after qualification.')
    return value
