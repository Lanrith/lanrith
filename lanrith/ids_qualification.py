"""Build-time IDS evidence and exact base executable binding; no image boot claim."""

import datetime
import hashlib
from pathlib import PurePosixPath
import re
import tarfile

from .release import ReleaseError, file_record, require


CHECKS = {'generated-native-configuration', 'generated-command-root-working-directory',
          'dedicated-uid-net-raw', 'wan-only-no-firewall-mutation', 'forwarding-through-detector-outage'}
IMPLEMENTATION = {'lanrith/ids.py', 'lanrith/ids_qualification.py', 'lanrith/config.py',
    'lanrith/intent.py', 'lanrith/firewall.py', 'lanrith/runtime_plan.py',
    'tests/ids_native.py', 'tests/packets.py', 'tests/test_intent.py', 'tests/test_ids.py',
    'scripts/qualify-ids.py', 'scripts/build-base.py', 'scripts/qualify-base.py', 'lanrith/admission.py',
    'mkosi/base/mkosi.extra/usr/share/lanrith/suricata.rules'}
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def implementation(project):
    return {name: file_record(project/name)['sha256'] for name in sorted(IMPLEMENTATION)}


def base_binary(archive):
    """Hash the sole canonical root-owned executable without extracting the rootfs.

    The surrounding base admission validates the complete filesystem. This
    reader binds the component test to one actual ordinary file, not an archive
    filename, package version or caller-supplied digest of the executable.
    """
    digest = None
    try:
        with tarfile.open(archive, mode='r|gz') as stream:
            for index, member in enumerate(stream):
                require(index < 500000, 'Base archive has too many entries for IDS binding.')
                parts = PurePosixPath(member.name).parts
                require(not member.name.startswith('/') and '..' not in parts,
                        'Base archive has a nonrelative path.')
                if PurePosixPath(member.name) == PurePosixPath('usr/bin/suricata'):
                    require(digest is None and member.name in ('usr/bin/suricata', './usr/bin/suricata') and
                            member.isfile() and not member.issparse() and member.uid == member.gid == 0 and
                            member.mode & 0o7777 == 0o755 and 0 < member.size <= 64*1024*1024,
                            'Base detector must be one canonical root-owned executable.')
                    reader = stream.extractfile(member)
                    require(reader is not None, 'Base detector is unreadable.')
                    checksum, size = hashlib.sha256(), 0
                    with reader:
                        while block := reader.read(1024*1024):
                            checksum.update(block)
                            size += len(block)
                    require(size == member.size, 'Base detector is truncated.')
                    digest = checksum.hexdigest()
                # Stream mode does not need the member cache for this ordinary
                # file lookup; keep a large rootfs inventory out of memory.
                stream.members.clear()
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ReleaseError('Invalid base archive for IDS qualification.') from error
    require(digest is not None, 'Base archive has no detector executable.')
    return digest


def validate(value, filesystem_sha256, *, project=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1 and
            value.get('test') == 'offline-wan-ids' and value.get('result') == 'pass' and
            isinstance(value.get('checks'), list) and len(value['checks']) == len(CHECKS) and
            all(isinstance(item, str) for item in value['checks']) and set(value['checks']) == CHECKS and
            value.get('external_network') is False and value.get('image_boot_qualified') is False and
            value.get('container_cleanup') == 'removed' and value.get('container_runtime') in ('docker', 'podman') and
            isinstance(value.get('builder_image_sha256'), str) and SHA256.fullmatch(value['builder_image_sha256']) and
            isinstance(filesystem_sha256, str) and SHA256.fullmatch(filesystem_sha256) and
            value.get('filesystem_sha256') == filesystem_sha256 and value.get('base_binary_match') is True and
            isinstance(value.get('binary_sha256'), str) and SHA256.fullmatch(value['binary_sha256']) and
            value['binary_sha256'] == value.get('base_binary_sha256') and
            value.get('daemon_working_directory') == '/' and value.get('no_new_privileges') is True and
            type(value.get('detector_uid')) is int and 0 < value['detector_uid'] < 65535 and
            type(value.get('effective_capabilities')) is int and value['effective_capabilities'] == 1 << 13 and
            type(value.get('bounding_capabilities')) is int and value['bounding_capabilities'] == 1 << 13,
            'Native IDS evidence is incomplete or describes another base executable.')
    try:
        stamp = datetime.datetime.fromisoformat(value['assessed_at'])
    except (KeyError, TypeError, ValueError):
        require(False, 'Native IDS assessment timestamp is invalid.')
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'Native IDS qualification is stale or future-dated.')
    sources = value.get('implementation_sha256')
    require(isinstance(sources, dict) and set(sources) == IMPLEMENTATION and
            all(isinstance(item, str) and SHA256.fullmatch(item) for item in sources.values()),
            'Native IDS implementation bindings are incomplete.')
    require(value.get('source_sha256') == sources['tests/ids_native.py'], 'Native IDS test binding differs.')
    if project is not None:
        require(sources == implementation(project), 'IDS implementation changed after native qualification.')
    return value
