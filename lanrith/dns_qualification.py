"""Bind isolated DNS observation evidence to the exact base executables."""

import datetime
import hashlib
from pathlib import PurePosixPath
import re
import tarfile

from .release import ReleaseError, file_record, require
from . import dns_observations


BINARIES = {'usr/sbin/unbound', 'usr/sbin/unbound-checkconf'}
CHECKS = {'packaged-unbound-dnstap', 'generated-unit-verification',
    'ipv4-ipv6-udp-tcp-client-query-response', 'dedicated-nonroot-uid-no-capabilities-resource-bound',
    'reader-metadata-only-no-write-no-producer-socket', 'kernel-peer-uid-rejects-forged-producer',
    'dns-survives-stalled-reader-5000-queries', 'collector-failure-keeps-dns-and-global-boot-check-usable',
    'collector-restart-epoch-and-reconnect', 'dns-survives-absent-collector-and-socket',
    'disabled-selection-removes-endpoint-and-keeps-dns'}
IMPLEMENTATION = {'lanrith/dns_observations.py', 'lanrith/dns_observations_runtime.py', 'lanrith/dns_metadata.py',
    'lanrith/dns_qualification.py', 'lanrith/observation_accounts.py', 'lanrith/observation_spool.py', 'lanrith/extension_observations.py', 'lanrith/extensions.py',
    'tests/test_dns_observations.py', 'tests/dns_observations_native.py', 'lanrith/build.py', 'lanrith/config.py',
    'lanrith/intent.py', 'lanrith/service_plane.py', 'lanrith/policy_runtime.py', 'lanrith/release.py',
    'builders/unbound-source.lock', 'tests/test_extension_network.py', 'examples/minimal.yaml',
    'scripts/qualify-dns.py', 'scripts/build-base.py', 'scripts/qualify-base.py', 'lanrith/admission.py',
    'mkosi/base/mkosi.extra/etc/systemd/system/unbound.service.d/30-lanrith-hardening.conf',
    'mkosi/base/mkosi.extra/etc/unbound/unbound.conf.d/99-lanrith-runtime.conf'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
ASSEMBLY = set(dns_observations.render({'user': 'example-agent', 'uid': 1801, 'gid': 1801})) | {
    'etc/passwd', 'etc/group', 'usr/lib/lanrith/lanrith/dns_metadata.py',
    'usr/lib/lanrith/lanrith/dns_observations_runtime.py', 'usr/lib/lanrith/lanrith/observation_spool.py'}


def implementation(project):
    return {name: file_record(project/name)['sha256'] for name in sorted(IMPLEMENTATION)}


def binaries(archive, *, destination=None):
    """Hash/extract only two fixed ordinary files into a new private fixture.

    No archive path is used as an extraction target. Links, aliases, duplicate
    entries, wrong ownership/mode, sparse files and oversized subjects fail.
    """
    result, total = {}, 0
    if destination is not None:
        require(destination.is_dir() and not destination.is_symlink() and not list(destination.iterdir()),
                'DNS executable staging must be a new empty directory.')
    try:
        with tarfile.open(archive, mode='r|gz') as stream:
            for index, member in enumerate(stream):
                total += member.size
                require(index < 500000 and total <= 64*1024**3, 'DNS base inventory exceeds its bound.')
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and '..' not in path.parts, 'DNS base path is not relative.')
                if str(path) in BINARIES:
                    name = str(path)
                    require(name not in result and member.name in (name, './'+name) and member.isfile() and
                            not member.issparse() and member.uid == member.gid == 0 and
                            member.mode & 0o7777 == 0o755 and 0 < member.size <= 64*1024*1024,
                            'DNS executable must be one canonical root-owned ordinary file.')
                    reader = stream.extractfile(member)
                    require(reader is not None, 'DNS executable is unreadable.')
                    checksum, size = hashlib.sha256(), 0
                    target = (destination/path.name).open('xb') if destination is not None else None
                    try:
                        with reader:
                            while block := reader.read(1024*1024):
                                checksum.update(block)
                                size += len(block)
                                if target is not None:
                                    target.write(block)
                        require(size == member.size, 'DNS executable is truncated.')
                    finally:
                        if target is not None:
                            target.close()
                    if destination is not None:
                        (destination/path.name).chmod(0o755)
                    result[name] = checksum.hexdigest()
                stream.members.clear()
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ReleaseError('Invalid base archive for DNS qualification.') from error
    require(set(result) == BINARIES, 'Base archive lacks DNS executables.')
    return result


def validate(value, filesystem_sha256, *, project=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1 and
            value.get('test') == 'offline-dns-observations' and value.get('result') == 'pass' and
            isinstance(value.get('checks'), list) and len(value['checks']) == len(CHECKS) and
            all(isinstance(item, str) for item in value['checks']) and set(value['checks']) == CHECKS and
            value.get('external_network') is False and value.get('private_image_qualified') is False and
            value.get('image_boot_qualified') is False and value.get('container_cleanup') == 'removed' and
            value.get('container_runtime') in ('docker', 'podman') and
            isinstance(value.get('builder_image_sha256'), str) and HEX.fullmatch(value['builder_image_sha256']) and
            isinstance(filesystem_sha256, str) and HEX.fullmatch(filesystem_sha256) and
            value.get('filesystem_sha256') == filesystem_sha256 and
            value.get('base_binaries_sha256') == {'usr/sbin/unbound': value.get('unbound_sha256'),
                'usr/sbin/unbound-checkconf': value.get('unbound_checkconf_sha256')} and
            all(isinstance(value.get(key), str) and HEX.fullmatch(value[key]) for key in
                ('unbound_sha256', 'unbound_checkconf_sha256')) and
            type(value.get('collector_uid')) is int and 0 < value['collector_uid'] < 65535 and
            type(value.get('effective_capabilities')) is int and value['effective_capabilities'] == 0 and
            type(value.get('bounding_capabilities')) is int and value['bounding_capabilities'] == 0 and
            value.get('no_new_privileges') is True,
            'DNS qualification is incomplete or describes another base executable.')
    try:
        stamp = datetime.datetime.fromisoformat(value['assessed_at'])
    except (KeyError, TypeError, ValueError):
        require(False, 'DNS qualification timestamp is invalid.')
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'DNS qualification is stale or future-dated.')
    sources = value.get('source_sha256')
    require(isinstance(sources, dict) and set(sources) == IMPLEMENTATION and
            all(isinstance(item, str) and HEX.fullmatch(item) for item in sources.values()),
            'DNS qualification implementation bindings are incomplete.')
    assembly = value.get('assembly_sha256')
    require(isinstance(assembly, dict) and set(assembly) == ASSEMBLY and
            all(isinstance(item, str) and HEX.fullmatch(item) for item in assembly.values()),
            'DNS qualification lacks the assembled runtime/account bindings.')
    if project is not None:
        require(sources == implementation(project), 'DNS implementation changed after qualification.')
    return value
