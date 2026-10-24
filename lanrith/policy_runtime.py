"""Own the deployed policy helper from compiled JSON and immutable image pins.

The source YAML and its compiler are build inputs only.  This module accepts one
fixed, narrow runtime document and never searches for or reconstructs intent.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time


CONTRACT = Path('/etc/router-policy-agent/runtime/runtime.json')
NAT64_RUNTIME = Path('/etc/router-policy-agent/nat64-runtime')
ROOT = Path('/run/lanrith-policy')
CONFIG = ROOT/'config'
GENERATION = ROOT/'generation'
BINDINGS = ROOT/'bindings'
COLLECTOR = ROOT/'collector'
READER = Path('/run/router-policy-reader')
ENROLLMENT = Path('/var/lib/lanrith/policy-enrollment/enrolled')
HASH = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
IFNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z')


class PolicyRuntimeError(ValueError):
    """A fixed runtime prerequisite is absent or differs from the image policy."""


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise PolicyRuntimeError('Duplicate JSON field.')
        value[key] = item
    return value


def decode(data, maximum):
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        raise PolicyRuntimeError('Runtime document exceeds its boundary.')
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PolicyRuntimeError('Runtime document is invalid.') from error


def read(path, maximum, *, owner=0, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        allowed = (0o400, 0o600) if private else tuple(range(0o400, 0o645))
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or
                before.st_size <= 0 or before.st_size > maximum or
                (private and stat.S_IMODE(before.st_mode) not in allowed) or
                (not private and stat.S_IMODE(before.st_mode) & 0o022)):
            raise PolicyRuntimeError('Runtime input metadata differs.')
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(value) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise PolicyRuntimeError('Runtime input changed while being read.')
        return value


def exact(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise PolicyRuntimeError(label+' structure differs.')
    return value


def load_contract(path=CONTRACT, *, owner=0):
    value = exact(decode(read(path, 64*1024, owner=owner, private=True), 64*1024), {
        'schema_version', 'profile_directory', 'profile_metadata', 'generation_directory',
        'state_directory', 'binding_directory', 'nft_executable', 'helper_executable',
        'recover_executable', 'collector_executable', 'managed_interfaces', 'directory',
        'binding_collector', 'translation_manifests'}, 'Policy runtime')
    fixed = {
        'schema_version': 1,
        'profile_directory': '/etc/router-policy-agent/profile',
        'profile_metadata': '/usr/share/lanrith/policy-profile-metadata.json',
        'generation_directory': '/run/lanrith-policy/generation',
        'state_directory': '/var/lib/lanrith/policy-agent',
        'binding_directory': '/run/lanrith-policy/bindings',
        'nft_executable': '/usr/sbin/nft',
        'helper_executable': '/usr/bin/router-policy-helper',
        'recover_executable': '/usr/bin/router-policy-recover',
        'collector_executable': '/usr/bin/router-policy-collector',
    }
    if any(value[key] != expected for key, expected in fixed.items()):
        raise PolicyRuntimeError('Policy runtime fixed resources differ.')
    interfaces = value['managed_interfaces']
    if (not isinstance(interfaces, list) or not interfaces or interfaces != sorted(set(interfaces)) or
            len(interfaces) > 64 or any(not isinstance(name, str) or not IFNAME.fullmatch(name)
                                       for name in interfaces)):
        raise PolicyRuntimeError('Policy managed-interface inventory differs.')
    directory = exact(value['directory'], {'url', 'base_dn', 'bind_dn', 'credential_name', 'ca_file'},
                      'Directory runtime')
    if (not all(isinstance(directory[key], str) and 0 < len(directory[key]) <= 2048
                for key in directory) or not NAME.fullmatch(directory['credential_name']) or
            not directory['url'].startswith(('ldaps://', 'ldap+starttls://')) or
            not directory['ca_file'].startswith('/usr/share/lanrith/trust/') or
            not directory['ca_file'].endswith('.pem')):
        raise PolicyRuntimeError('Directory runtime value differs.')
    translations = value['translation_manifests']
    if not isinstance(translations, list) or len(translations) > 3:
        raise PolicyRuntimeError('Translation runtime inventory differs.')
    expected_paths = {'nat46': {'/usr/share/lanrith/nat46.json'},
                      'nat64': {'/usr/share/lanrith/nat64.json',
                                '/usr/share/lanrith/nat64-internal.json'}}
    seen = set()
    for entry in translations:
        exact(entry, {'kind', 'manifest'}, 'Translation runtime')
        pair = (entry['kind'], entry['manifest'])
        if entry['kind'] not in expected_paths or entry['manifest'] not in expected_paths[entry['kind']] or pair in seen:
            raise PolicyRuntimeError('Translation runtime reference differs.')
        seen.add(pair)
    if translations != sorted(translations, key=lambda item: (item['kind'], item['manifest'])):
        raise PolicyRuntimeError('Translation runtime inventory is not canonical.')
    collector = value['binding_collector']
    if collector is not None:
        exact(collector, {'radius_user', 'nas_prefixes', 'kea_user', 'kea_socket', 'subnet_id',
                          'ipv4_prefix', 'vlan', 'maximum_devices', 'interface', 'parent'},
              'Policy binding collector')
        import ipaddress
        try:
            prefix = ipaddress.ip_network(collector['ipv4_prefix'])
            nas = [ipaddress.ip_network(item) for item in collector['nas_prefixes']]
        except (TypeError, ValueError) as error:
            raise PolicyRuntimeError('Policy binding collector address differs.') from error
        if (collector['radius_user'] != 'freerad' or collector['kea_user'] != '_kea' or
                collector['kea_socket'] != '/run/kea/kea4-ctrl-socket' or prefix.version != 4 or
                str(prefix) != collector['ipv4_prefix'] or not isinstance(collector['nas_prefixes'], list) or
                not 1 <= len(nas) <= 64 or collector['nas_prefixes'] != sorted(set(map(str, nas))) or
                type(collector['subnet_id']) is not int or not 1 <= collector['subnet_id'] <= 2**32-1 or
                type(collector['vlan']) is not int or not 1 <= collector['vlan'] <= 4094 or
                type(collector['maximum_devices']) is not int or
                not 1 <= collector['maximum_devices'] <= 256 or
                any(not isinstance(collector[key], str) or not IFNAME.fullmatch(collector[key])
                    for key in ('interface', 'parent')) or collector['interface'] == collector['parent']):
            raise PolicyRuntimeError('Policy binding collector value differs.')
    return value


def private_directory(path, *, owner=0, group=0, parents=False):
    path.mkdir(mode=0o700, parents=parents, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_gid != group or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise PolicyRuntimeError('Policy runtime directory metadata differs.')


def atomic(path, value, *, owner=0, group=0, mode=0o600):
    data = value if isinstance(value, bytes) else json.dumps(
        value, sort_keys=True, separators=(',', ':')).encode()+b'\n'
    private_directory(path.parent, owner=path.parent.stat().st_uid,
                      group=path.parent.stat().st_gid)
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), owner, group)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def command(arguments, timeout=15):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode:
        raise PolicyRuntimeError('Policy runtime command failed: '+Path(arguments[0]).name+'.')


def metadata(contract):
    value = exact(decode(read(Path(contract['profile_metadata']), 4096), 4096),
                  {'schema_version', 'profile_sha256', 'floor_sha256', 'guards_sha256'},
                  'Policy profile metadata')
    if value['schema_version'] != 1 or any(not isinstance(value[key], str) or not HASH.fullmatch(value[key])
                                           for key in ('profile_sha256', 'floor_sha256', 'guards_sha256')):
        raise PolicyRuntimeError('Policy profile metadata value differs.')
    profile = read(Path(contract['profile_directory'])/'profile.json', 8*1024*1024, private=True)
    guards = read(Path(contract['profile_directory'])/'guards.nft', 8*1024*1024, private=True)
    if (hashlib.sha256(profile).hexdigest() != value['profile_sha256'] or
            hashlib.sha256(guards).hexdigest() != value['guards_sha256']):
        raise PolicyRuntimeError('Policy profile artifact differs from its image pin.')
    return value


def translation_hash(contract):
    evidence = []
    for entry in contract['translation_manifests']:
        path = Path(entry['manifest'])
        data = read(path, 1024*1024)
        manifest = decode(data, 1024*1024)
        if entry['kind'] == 'nat46':
            from .translation_runtime import status
        else:
            from .nat64_runtime import status
        status(manifest)
        evidence.append({'kind': entry['kind'], 'manifest': entry['manifest'],
                         'sha256': hashlib.sha256(data).hexdigest()})
    encoded = json.dumps({'schema_version': 1, 'translations': evidence},
                         sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def nat64_pin():
    path = NAT64_RUNTIME/'runtime.json'
    if not path.exists():
        return None
    data = read(path, 64*1024, private=True)
    value = exact(decode(data, 64*1024), {'schema_version', 'components'}, 'NAT64 runtime')
    if value['schema_version'] != 1 or not isinstance(value['components'], list) or not value['components']:
        raise PolicyRuntimeError('NAT64 runtime value differs.')
    return {'directory': str(NAT64_RUNTIME), 'sha256': hashlib.sha256(data).hexdigest()}


def wait_interfaces(contract):
    deadline = time.monotonic()+45
    while not all((Path('/sys/class/net')/name).exists() for name in contract['managed_interfaces']):
        if time.monotonic() >= deadline:
            raise PolicyRuntimeError('Policy guard interfaces are unavailable.')
        time.sleep(0.2)


def credential(contract):
    directory = os.environ.get('CREDENTIALS_DIRECTORY')
    if not directory:
        raise PolicyRuntimeError('Directory credential transport is unavailable.')
    root = Path(directory)
    value = read(root/contract['directory']['credential_name'], 4097, private=True)
    if value.endswith(b'\n'):
        value = value[:-1]
    if not value or len(value) > 4096 or b'\x00' in value:
        raise PolicyRuntimeError('Directory credential value differs.')
    try:
        return value.decode('utf-8')
    except UnicodeError as error:
        raise PolicyRuntimeError('Directory credential encoding differs.') from error


def prepare_reader(contract, password):
    account = pwd.getpwnam('router-policy-reader')
    if account.pw_uid == 0:
        raise PolicyRuntimeError('Directory reader identity is not isolated.')
    if not READER.exists():
        READER.mkdir(mode=0o700)
        os.chown(READER, account.pw_uid, account.pw_gid)
    private_directory(READER, owner=account.pw_uid, group=account.pw_gid)
    source = Path(contract['directory']['ca_file'])
    ca = read(source, 64*1024)
    reader = {'schema_version': 1, 'directory_url': contract['directory']['url'],
              'base_dn': contract['directory']['base_dn'],
              'helper_socket': '/run/router-policy-ipc/requests.sock', 'custom_ca': True}
    atomic(READER/'reader.json', reader, owner=account.pw_uid, group=account.pw_gid)
    atomic(READER/'credentials.json', {'bind_dn': contract['directory']['bind_dn'],
                                      'password': password}, owner=account.pw_uid, group=account.pw_gid)
    atomic(READER/'ca.pem', ca, owner=account.pw_uid, group=account.pw_gid)


def empty_bindings():
    now = datetime.now(timezone.utc)
    observed = now.isoformat(timespec='microseconds').replace('+00:00', 'Z')
    generation = 'compiled-empty-'+hashlib.sha256(observed.encode()).hexdigest()[:24]
    atomic(BINDINGS/'bindings.json', {'schema_version': 1, 'generation': generation,
                                     'observed_at': observed, 'complete': True, 'records': []})


def incomplete_bindings():
    now = datetime.now(timezone.utc)
    observed = now.isoformat(timespec='microseconds').replace('+00:00', 'Z')
    generation = 'collector-incomplete-'+hashlib.sha256(observed.encode()).hexdigest()[:24]
    atomic(BINDINGS/'bindings.json', {'schema_version': 1, 'generation': generation,
                                     'observed_at': observed, 'complete': False, 'records': []})


def cohort(contract):
    """Read only the helper-owned durable cohort; never infer membership."""
    state = exact(decode(read(Path(contract['state_directory'])/'state.json', 16*1024*1024,
                              private=True), 16*1024*1024),
                  {'schema_version', 'cohort_macs', 'classified_ipv4', 'classified_ipv6', 'ledger',
                   'last_directory_observed_at', 'directory_hash'}, 'Policy durable state')
    macs = state['cohort_macs']
    maximum = contract['binding_collector']['maximum_devices']
    if (state['schema_version'] != 2 or not isinstance(macs, list) or
            not all(isinstance(item, str) and MAC.fullmatch(item) for item in macs) or
            macs != sorted(set(macs)) or len(macs) > maximum):
        raise PolicyRuntimeError('Policy durable cohort differs.')
    return macs


def refresh_bindings(contract):
    collector = contract['binding_collector']
    if collector is None:
        empty_bindings()
        return
    # Close the feed before inspecting mutable runtime evidence. The native
    # collector replaces this only after all journal, DHCP and placement reads
    # agree, so every failure leaves directory grants unusable.
    incomplete_bindings()
    managed = cohort(contract)
    if not managed:
        empty_bindings()
        return
    configuration = {
        'schema_version': 1, 'mode': 'bindings', 'radius_user': collector['radius_user'],
        'nas_prefixes': collector['nas_prefixes'], 'kea_user': collector['kea_user'],
        'kea_socket': collector['kea_socket'], 'subnet_id': collector['subnet_id'],
        'ipv4_prefix': collector['ipv4_prefix'], 'vlan': collector['vlan'],
        'maximum_devices': collector['maximum_devices'], 'output_directory': str(BINDINGS),
        'host_placement': {'interface': collector['interface'], 'parent': collector['parent'],
                           'binding_mode': 'dhcp_packet_guarded'},
        'managed_macs': managed,
    }
    atomic(COLLECTOR/'collector.json', configuration)
    command([contract['collector_executable'], '-publish-bindings',
             '-config-directory', str(COLLECTOR)], timeout=35)


def publish_runtime(contract, profile, mapping):
    reader = pwd.getpwnam('router-policy-reader').pw_uid
    operator = pwd.getpwnam('router-policy-operator').pw_uid
    if not reader or not operator or reader == operator:
        raise PolicyRuntimeError('Policy runtime identities are not isolated.')
    generation = {'schema_version': 1, 'sequence': 1, 'floor_hash': profile['floor_sha256'],
                  'mapping_hash': mapping, 'ready': True}
    helper = {'schema_version': 1, 'mode': 'enforce',
              'profile': {'directory': contract['profile_directory'],
                          'sha256': profile['profile_sha256']},
              'generation_directory': contract['generation_directory'],
              'state_directory': contract['state_directory'],
              'nft_executable': contract['nft_executable'], 'reader_uid': reader,
              'operator_uid': operator, 'request_timeout_ms': 5000,
              'request_socket': '/run/router-policy-ipc/requests.sock',
              'status_socket': '/run/router-policy-ipc/status.sock',
              'expected_generation': generation}
    runtime = nat64_pin()
    if runtime is not None:
        helper['nat64_runtime'] = runtime
    atomic(CONFIG/'helper.json', helper)
    atomic(GENERATION/'generation.json', generation)


def install_guards(contract_path=CONTRACT):
    if os.geteuid() != 0:
        raise PolicyRuntimeError('Policy guard installation requires root.')
    contract = load_contract(contract_path)
    metadata(contract)
    wait_interfaces(contract)
    command([contract['nft_executable'], '-f', str(Path(contract['profile_directory'])/'guards.nft')])


def bootstrap(contract_path=CONTRACT):
    if os.geteuid() != 0:
        raise PolicyRuntimeError('Policy runtime requires root.')
    contract = load_contract(contract_path)
    for path in (ROOT, CONFIG, GENERATION, BINDINGS, COLLECTOR):
        private_directory(path, parents=path == ROOT)
    private_directory(Path(contract['state_directory']), parents=True)
    private_directory(ENROLLMENT.parent, parents=True)
    profile = metadata(contract)
    mapping = translation_hash(contract)
    publish_runtime(contract, profile, mapping)
    password = credential(contract)
    prepare_reader(contract, password)
    empty_bindings()
    if not ENROLLMENT.exists():
        if (Path(contract['state_directory'])/'state.json').exists():
            raise PolicyRuntimeError('Unacknowledged policy history prevents first enrolment.')
        atomic(ENROLLMENT, b'image-owner-first-install-v1\n')
        command([contract['helper_executable'], '-config-directory', str(CONFIG), '-initialize-state'])
    else:
        command([contract['recover_executable'], '-config-directory', str(CONFIG), '-timeout', '5s'])


def bindings_loop(contract_path=CONTRACT, interval=30):
    if os.geteuid() != 0:
        raise PolicyRuntimeError('Policy binding refresh requires root.')
    contract = load_contract(contract_path)
    private_directory(BINDINGS)
    private_directory(COLLECTOR)
    while True:
        try:
            refresh_bindings(contract)
        except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
            incomplete_bindings()
        time.sleep(interval)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('install-guards', 'bootstrap', 'bindings-loop'))
    args = parser.parse_args(arguments)
    try:
        if args.operation == 'install-guards':
            install_guards()
        elif args.operation == 'bootstrap':
            bootstrap()
        else:
            bindings_loop()
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print('policy-runtime: '+type(error).__name__+'; enforcement remains closed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
