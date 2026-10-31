#!/usr/bin/env python3
"""Exercise a selected helper's real observation IPC in an offline container.

The helper, profile compiler, recovery tool, generated binding producer and
nftables are real. Directory data and the empty client topology are synthetic.
A development candidate never qualifies the platform's pinned release. This is not a signed
image, private console, live directory, translator or lifecycle qualification.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time

from lanrith import components, config, policy_agent, policy_runtime
from lanrith.release import canonical, require
from test_extension_observations import OBSERVER, settings


ROOT = Path(__file__).resolve().parents[1]
HELPER = 'lanrith-policy-helper.service'
SOCKETS = ('lanrith-policy-helper-requests.socket', 'lanrith-policy-helper-status.socket')
DEPENDENCIES = ('lanrith-policy-bootstrap.service', 'lanrith-policy-bindings.service', 'lanrith-policy-reader.service')
COMMANDS = {'router-policy-helper', 'router-policy-check', 'router-policy-profile',
            'router-policy-recover', 'router-policy-status'}
OBSERVE = {'schema_version': 1, 'operation': 'observations', 'generation': '', 'offset': 0}
PROPOSAL = '/run/router-policy-ipc/requests.sock'
STATUS = '/run/router-policy-ipc/status.sock'
SOURCE_FILES = ('lanrith/policy_agent.py', 'lanrith/policy_runtime.py', 'lanrith/extension_observations.py',
                'tests/test_extension_observations.py', 'lanrith/integrations.py',
                'tests/test_policy_agent.py', 'tests/policy_observer_component_native.py')


def run(*args, check=True, timeout=30, **options):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, **options)
    require(not check or result.returncode == 0,
            'Native policy observer command failed: '+(result.stdout+result.stderr).decode(errors='replace')[-4096:])
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(package):
    selection = json.loads((ROOT/'build-inputs.json').read_bytes())['component_releases']['router-policy-agent']
    name = package.name
    require(name == 'router-policy-helper_'+selection['tag'].removeprefix('v')+'_amd64.deb' and not package.is_symlink() and
            package.is_file() and 0 < package.stat().st_size <= 64 << 20 and
            digest(package) == selection['files'][name], 'Policy helper package differs from its reviewed pin.')
    require(all(not (Path('/usr/bin')/command).exists() for command in COMMANDS),
            'Native observer fixture refuses existing component executables.')
    process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(package)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    extracted = {}
    try:
        reader = components.PayloadReader(process.stdout)
        with tarfile.open(fileobj=reader, mode='r|') as archive:
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/')
                require(not name.startswith('/') and '..' not in Path(name).parts and
                        (member.isfile() or member.isdir()), 'Unsafe component payload entry.')
                if not name.startswith('usr/bin/'):
                    continue
                command = name.removeprefix('usr/bin/')
                require(command in COMMANDS and command not in extracted and member.isfile() and
                        0 < member.size <= 16 << 20 and member.mode == 0o755,
                        'Unexpected component executable inventory.')
                data = archive.extractfile(member).read(member.size+1)
                require(len(data) == member.size, 'Incomplete component executable.')
                path = Path('/usr/bin')/command
                with path.open('xb') as output:
                    output.write(data)
                path.chmod(0o755)
                extracted[command] = hashlib.sha256(data).hexdigest()
        while reader.read(1 << 20):
            pass
        require(process.wait(timeout=20) == 0 and set(extracted) == COMMANDS and
                digest(package) == selection['files'][package.name], 'Component extraction did not match its pin.')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=20)
    return {'source_commit': selection['source_commit'], 'tag': selection['tag'],
            'package_sha256': selection['files'][package.name], 'executable_sha256': extracted,
            'current_release_security_admission': False}


def candidate(directory):
    """Development-only bytes never count as selected release qualification."""
    require(directory.is_absolute() and directory.resolve() == directory and directory.is_dir(),
            'Candidate directory must be canonical.')
    metadata = json.loads((directory/'candidate.json').read_bytes())
    require(set(metadata) == {'schema', 'source_commit', 'source_sha256', 'toolchain', 'executable_sha256',
                              'current_release_security_admission'} and metadata['schema'] == 1 and
            metadata['current_release_security_admission'] is False and
            set(metadata['executable_sha256']) == COMMANDS,
            'Invalid development candidate inventory.')
    for name, expected in metadata['executable_sha256'].items():
        path = directory/name
        require(path.is_file() and not path.is_symlink() and digest(path) == expected and
                not (Path('/usr/bin')/name).exists(), 'Candidate executable differs from its build inventory.')
        shutil.copyfile(path, Path('/usr/bin')/name)
        (Path('/usr/bin')/name).chmod(0o755)
    return {**metadata, 'development_candidate': True}


# Each subprocess actually changes kernel UID/GID. Sharing the socket group
# deliberately bypasses only filesystem exclusion, so SO_PEERCRED must enforce
# the reader boundary. No caller input becomes source code or a shell command.
CLIENT = r'''
import json,socket,struct,sys
path,body,raw=sys.argv[1:]
payload=bytes.fromhex(body)
def exact(sock,count):
 result=b''
 while len(result)<count:
  block=sock.recv(count-len(result))
  if not block:raise EOFError()
  result+=block
 return result
try:
 with socket.socket(socket.AF_UNIX) as sock:
  sock.settimeout(4);sock.connect(path)
  sock.sendall(payload if raw=='raw' else struct.pack('!I',len(payload))+payload)
  count=struct.unpack('!I',exact(sock,4))[0]
  assert 0<count<=512*1024
  response=json.loads(exact(sock,count))
 print(json.dumps({'reply':response}))
except (OSError,EOFError):
 print(json.dumps({'denied':True}))
'''


def request(path, value, *, uid=1801, gid=1801, raw=False):
    data = value if isinstance(value, bytes) else canonical(value)
    result = run('/usr/bin/python3', '-I', '-c', CLIENT, str(path), data.hex(), 'raw' if raw else 'framed',
                 user=uid, group=gid, extra_groups=[])
    return json.loads(result.stdout)


def state_identity():
    result = {str(path): digest(path) for parent in (policy_runtime.CONFIG, policy_runtime.GENERATION,
              Path('/var/lib/lanrith/policy-agent'), Path('/etc/router-policy-agent/profile'))
              for path in parent.rglob('*') if path.is_file()}
    def stable(value):
        if isinstance(value, dict):
            return {key: stable(item) for key, item in value.items()
                    if key not in ('handle', 'expires', 'packets', 'bytes')}
        return [stable(item) for item in value] if isinstance(value, list) else value
    rules = stable(json.loads(run('nft', '--json', 'list', 'ruleset').stdout))
    result['normalized_kernel_ruleset'] = hashlib.sha256(canonical(rules)).hexdigest()
    return result


def prepare_interfaces(value):
    """Supply real disposable attachment devices for native netdev guards."""
    names = []
    for interface in value['hardware']['interfaces'].values():
        name = interface['name']
        run('ip', 'link', 'add', name, 'type', 'dummy')
        run('ip', 'link', 'set', name, 'up')
        names.append(name)
    for network in value['networks'].values():
        name = network['name']
        if 'vlan' in network:
            parent = value['hardware']['interfaces'][network['interface']]['name']
            run('ip', 'link', 'add', 'link', parent, 'name', name, 'type', 'vlan', 'id', str(network['vlan']))
            names.append(name)
        run('ip', 'link', 'set', name, 'up')
    from lanrith import service_plane
    link = service_plane.topology(value)['host_link']
    run('ip', 'link', 'add', link, 'type', 'dummy')
    run('ip', 'link', 'set', link, 'up')
    names.append(link)
    return names


def qualify(package, output, *, candidate_directory=None):
    source_hashes = {name: digest(ROOT/name) for name in SOURCE_FILES}
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd' and
            (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists()) and
            not Path('/usr/share/lanrith/installed.json').exists(),
            'Real observer fixture requires an uninitialized disposable systemd container.')
    require({entry['ifname'] for entry in json.loads(run('ip', '-json', 'link').stdout)} == {'lo'},
            'Real observer fixture must have no external network.')
    require(output.is_absolute() and output.parent.is_dir() and not output.exists() and
            not output.is_symlink() and not policy_runtime.ROOT.exists(), 'Observer fixture state/output exists.')
    require((package is None) != (candidate_directory is None), 'Select exactly one pinned package or development candidate.')
    component = candidate(candidate_directory) if candidate_directory is not None else extract(package)
    units = Path('/run/systemd/system')
    names = (HELPER, *SOCKETS, *DEPENDENCIES)
    require(all(not (units/name).exists() for name in names), 'Observer unit overrides already exist.')
    for uid, name in ((1701, 'router-policy-reader'), (1702, 'router-policy-operator'), (1801, 'example-agent')):
        run('useradd', '--uid', str(uid), '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', name)
    value = settings()
    interfaces = prepare_interfaces(value)
    files = policy_agent.render(value, observer=OBSERVER)
    contract = json.loads(files['etc/router-policy-agent/runtime/runtime.json'])
    runtime_path = policy_runtime.CONTRACT
    require(not runtime_path.exists(), 'Observer core runtime contract already exists.')
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_path.write_bytes(canonical(contract))
    runtime_path.chmod(0o600)
    for path in (policy_runtime.ROOT, policy_runtime.CONFIG, policy_runtime.GENERATION,
                 policy_runtime.BINDINGS, policy_runtime.COLLECTOR,
                 Path(contract['state_directory']), Path(contract['profile_directory'])):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    # The selected compiler and real nftables build exactly the same synthetic
    # profile pipeline as finalization, confined to this container's netns.
    with tempfile.TemporaryDirectory(prefix='observer-profile.') as temporary:
        root = Path(temporary)
        firewall = root/'base.nft'
        firewall.write_text(config.render(value)['etc/nftables.conf'])
        run('nft', '-f', str(firewall))
        baseline, rules, profile_output = root/'baseline.json', root/'ruleset.json', root/'output'
        baseline.write_bytes(canonical(policy_agent.baseline(value)))
        rules.write_bytes(run('nft', '--json', 'list', 'ruleset').stdout)
        profile_output.mkdir(mode=0o700)
        run('/usr/bin/router-policy-profile', '-baseline', str(baseline), '-ruleset', str(rules),
            '-output-directory', str(profile_output))
        metadata = json.loads((profile_output/'router-profile-metadata.json').read_bytes())
        profile = (profile_output/'router-profile.json').read_bytes().removesuffix(b'\n')
        require(hashlib.sha256(profile).hexdigest() == metadata['profile_sha256'], 'Profile digest differs.')
        destination = Path(contract['profile_directory'])
        (destination/'profile.json').write_bytes(profile)
        (destination/'profile.json').chmod(0o400)
        shutil.copyfile(profile_output/'router-guards.nft', destination/'guards.nft')
        (destination/'guards.nft').chmod(0o400)
        run('nft', '-f', str(destination/'guards.nft'))
    policy_runtime.publish_runtime(contract, metadata, 'c'*64)
    policy_runtime.empty_bindings()
    run('/usr/bin/router-policy-helper', '-config-directory', str(policy_runtime.CONFIG), '-initialize-state')
    library = Path('/usr/lib/lanrith/lanrith')
    require(not library.exists(), 'Observer runtime library already exists.')
    library.mkdir(parents=True)
    for module in ('__init__.py', 'release.py', 'policy_runtime.py'):
        shutil.copyfile(ROOT/'lanrith'/module, library/module)
    wrapper = library.parent/'policy-runtime'
    wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                       'from lanrith.policy_runtime import main\nsys.exit(main())\n')
    wrapper.chmod(0o755)
    (units/HELPER).write_text(files['usr/lib/systemd/system/'+HELPER])
    for name in SOCKETS:
        shutil.copyfile(ROOT/'mkosi/base/mkosi.extra/usr/lib/systemd/system'/name, units/name)
    (units/DEPENDENCIES[0]).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    (units/DEPENDENCIES[1]).write_text(files['usr/lib/systemd/system/'+DEPENDENCIES[1]])
    (units/DEPENDENCIES[2]).write_text('[Service]\nType=exec\nExecStart=/usr/bin/sleep 600\n')
    checks, observed = [], {}
    try:
        require(all(digest(Path('/usr/bin')/name) == pinned for name, pinned in component['executable_sha256'].items()),
                'Native executable bytes changed after pinned extraction.')
        run('systemctl', 'daemon-reload')
        run('systemd-analyze', 'verify', *(str(units/name) for name in names))
        run('systemctl', 'start', HELPER, timeout=110)
        deadline = time.monotonic()+8
        while True:
            response = request(policy_runtime.OBSERVATIONS, OBSERVE)
            status = request(STATUS, {'schema_version': 1, 'operation': 'status'}, uid=1702, gid=1702)
            if (response.get('reply', {}).get('code') == 'unobserved' and
                    status.get('reply', {}).get('code') == '' and status['reply'].get('report') is not None):
                break
            if time.monotonic() >= deadline:
                states = {}
                for unit in (HELPER, DEPENDENCIES[1]):
                    fields = run('systemctl', 'show', '--property=Id,Result,ActiveState,SubState,NRestarts,ExecMainStartTimestampMonotonic', unit).stdout.decode()
                    states[unit] = dict(line.split('=', 1) for line in fields.splitlines() if '=' in line)
                binding = json.loads((policy_runtime.BINDINGS/'bindings.json').read_bytes())
                observed_at = datetime.fromisoformat(binding['observed_at'].replace('Z', '+00:00')).timestamp()
                start = int(states[HELPER]['ExecMainStartTimestampMonotonic'])/1e6
                failure = {'schema': 1, 'test': 'offline-pinned-policy-observer-component', 'result': 'fail',
                    'reason': 'enforcing helper did not become ready with generated binding producer',
                    'component': component, 'units': states, 'binding_generation': binding['generation'],
                    'binding_observed_at': binding['observed_at'], 'binding_records': len(binding['records']),
                    'binding_predates_latest_helper_exec': observed_at < time.time()-time.monotonic()+start,
                    'actual_policy_engine_ipc_qualified': False, 'private_image_qualified': False,
                    'source_sha256': {name: digest(ROOT/name) for name in ('lanrith/policy_runtime.py',
                        'lanrith/policy_agent.py', 'tests/test_policy_agent.py',
                        'tests/policy_observer_component_native.py')}}
                failure_path = output.with_suffix('.failure.json')
                with failure_path.open('xb') as stream:
                    stream.write(canonical(failure))
                raise ValueError('Real enforcing helper did not become ready; failure metadata retained.')
            time.sleep(.05)
        pid = run('systemctl', 'show', '--property=MainPID', '--value', HELPER).stdout.strip()
        def submit_empty():
            snapshot = {'schema_version': 1, 'directory': {'observed_at': datetime.now(timezone.utc).isoformat(),
                        'complete': True, 'groups': [], 'devices': []}}
            response = request(PROPOSAL, snapshot, uid=1701, gid=1701)
            require('reply' in response, 'Actual directory proposal did not receive a framed receipt.')
            receipt = response['reply']
            require(receipt['status'] == 'applied' and receipt['grant_count'] == 0,
                    'Real enforcing helper rejected the fresh synthetic empty directory.')
        submit_empty()
        response = request(policy_runtime.OBSERVATIONS, OBSERVE)['reply']
        snapshot = response['snapshot']
        require(response['code'] == '' and response['next_offset'] is None and snapshot['mode'] == 'enforce' and
                snapshot['complete'] is True and snapshot['total'] == 0 and snapshot['grants'] == [] and
                snapshot['writer_sequence'] == 1 and snapshot['floor_hash'] == metadata['floor_sha256'],
                'Real observation snapshot differs from the enforcing synthetic profile.')
        observed.update(generation=snapshot['generation'], floor_sha256=metadata['floor_sha256'],
                        baseline_sha256=snapshot['baseline_hash'], grant_count=0)
        checks.append('fresh-enforcing-compilation-observed')
        before = state_identity()
        for uid in (0, 1701, 1702, 1802):
            require(request(policy_runtime.OBSERVATIONS, OBSERVE, uid=uid, gid=1801) == {'denied': True},
                    'Wrong UID sharing the observation group received a reply.')
        checks.append('kernel-peer-uid-required-despite-shared-group')
        for operation in ('reset', 'status', 'submit', 'apply'):
            reply = request(policy_runtime.OBSERVATIONS, {**OBSERVE, 'operation': operation})['reply']
            require(reply['code'] == 'invalid_request' and reply['snapshot'] is None,
                    'Observation endpoint accepted a mutation/status operation.')
        for malformed in (b'{', canonical({**OBSERVE, 'directory': {}}), canonical({**OBSERVE, 'offset': -1})):
            require(request(policy_runtime.OBSERVATIONS, malformed)['reply']['code'] == 'invalid_request',
                    'Malformed observation was not rejected.')
        checks.append('mutation-unknown-fields-malformed-requests-rejected')
        require(request(policy_runtime.OBSERVATIONS, b'\x7f\xff\xff\xff', raw=True) == {'denied': True},
                'Oversized frame header was not rejected.')
        checks.append('oversized-frame-rejected-without-body')
        for path in (PROPOSAL, STATUS):
            require(request(path, OBSERVE) == {'denied': True}, 'Observation identity reached privileged IPC.')
        checks.append('observer-cannot-use-proposal-or-operator-sockets')
        for request_data, code in (({**OBSERVE, 'generation': 'a'*64}, 'generation_changed'),
                                   ({**OBSERVE, 'generation': snapshot['generation'], 'offset': 1}, 'invalid_request')):
            require(request(policy_runtime.OBSERVATIONS, request_data)['reply']['code'] == code,
                    'Observation generation/offset boundary differs.')
        checks.append('generation-and-page-bounds-enforced')
        require(before == state_identity(), 'Observation reads or rejected clients changed policy state.')
        checks.append('reads-and-rejections-preserve-durable-fence-and-kernel-state')
        # A partial frame blocks only the observation worker, for at most its
        # two-second request budget; the independent status endpoint stays live.
        partial = subprocess.Popen(['/usr/bin/python3', '-I', '-c',
            'import json,socket,time; s=socket.socket(socket.AF_UNIX);s.settimeout(2.8);'
            's.connect("/run/lanrith-policy-observations/observations.sock");'
            's.sendall(b"\\x00");print("ready",flush=True);started=time.monotonic();'
            'assert s.recv(1)==b"";elapsed=time.monotonic()-started;assert elapsed<2.6;'
            'print(json.dumps({"partial_client_seconds":elapsed}),flush=True);s.close()'],
            user=1801, group=1801, extra_groups=[], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            require(select.select([partial.stdout], [], [], 3)[0] and partial.stdout.readline() == b'ready\n',
                    'Partial observation client did not reach its connected state.')
            started = time.monotonic()
            status = request(STATUS, {'schema_version': 1, 'operation': 'status'}, uid=1702, gid=1702)
            require(status.get('reply', {}).get('code') == '' and time.monotonic()-started < 1.5,
                    'Stalled observer blocked the independent operator endpoint.')
            stdout, stderr = partial.communicate(timeout=4)
            require(partial.returncode == 0, 'Partial observation was not closed within its request deadline.')
            observed.update(json.loads(stdout))
        finally:
            if partial.poll() is None:
                partial.kill()
                partial.wait(timeout=3)
        require(request(policy_runtime.OBSERVATIONS, OBSERVE)['reply']['snapshot']['generation'] == snapshot['generation'],
                'Stalled client changed the observation generation.')
        checks.append('stalled-observer-bounded-and-independent-status-available')
        submit_empty()
        fresh = request(policy_runtime.OBSERVATIONS, OBSERVE)['reply']['snapshot']
        require(fresh['generation'] != snapshot['generation'] and
                request(policy_runtime.OBSERVATIONS, {**OBSERVE, 'generation': snapshot['generation']})['reply']['code'] == 'generation_changed',
                'An old observation generation survived a fresh actual compilation.')
        checks.append('stale-generation-rejected-after-new-compilation')
        require(run('systemctl', 'show', '--property=MainPID', '--value', HELPER).stdout.strip() == pid and
                run('systemctl', 'show', '--property=NRestarts', '--value', HELPER).stdout.strip() == b'0',
                'Rejected clients restarted the enforcing helper.')
        checks.append('enforcing-helper-stays-running-without-restart')
        # A producer's explicit negative interval seals permissions. Pausing
        # the real producer prevents its next complete publication racing this
        # controlled outage; no successful evidence timestamp is fabricated.
        binder_pid = int(run('systemctl', 'show', '--property=MainPID', '--value', DEPENDENCIES[1]).stdout)
        os.kill(binder_pid, signal.SIGSTOP)
        try:
            policy_runtime.incomplete_bindings()
            rejected = request(PROPOSAL, {'schema_version': 1, 'directory': {
                'observed_at': datetime.now(timezone.utc).isoformat(), 'complete': True, 'groups': [], 'devices': []}},
                uid=1701, gid=1701)['reply']
            require(rejected['status'] == 'rejected', 'Incomplete bindings admitted a directory request.')
            time.sleep(11)
            require(run('systemctl', 'show', '--property=MainPID', '--value', HELPER).stdout.strip() == pid and
                    run('systemctl', 'show', '--property=NRestarts', '--value', HELPER).stdout.strip() == b'0',
                    'An explicitly incomplete producer interval restarted the helper.')
            pending = request(STATUS, {'schema_version': 1, 'operation': 'status'}, uid=1702, gid=1702)['reply']
            require(pending['report']['permit_state'] == 'sealed', 'Pending evidence left application permission open.')
        finally:
            os.kill(binder_pid, signal.SIGCONT)
        deadline = time.monotonic()+40
        while not json.loads((policy_runtime.BINDINGS/'bindings.json').read_bytes())['complete']:
            require(time.monotonic() < deadline, 'Real binding producer did not recover.')
            time.sleep(.1)
        checks.append('real-producer-incomplete-interval-seals-without-helper-restart')
        cached_generation = request(policy_runtime.OBSERVATIONS, OBSERVE)['reply']['snapshot']['generation']
        run('systemctl', 'restart', HELPER, timeout=110)
        require(run('systemctl', 'show', '--property=MainPID', '--value', HELPER).stdout.strip() != pid,
                'Explicit helper restart did not start a new process.')
        require(request(policy_runtime.OBSERVATIONS, OBSERVE)['reply']['code'] == 'unobserved',
                'Helper restart restored a cached directory observation.')
        binding_after_restart = json.loads((policy_runtime.BINDINGS/'bindings.json').read_bytes())
        observed['binding_after_restart'] = binding_after_restart['observed_at']
        submit_empty()
        require(request(policy_runtime.OBSERVATIONS, OBSERVE)['reply']['snapshot']['generation'] != cached_generation,
                'Restart reused an earlier compilation generation.')
        checks.append('helper-restart-waits-for-real-post-start-evidence-without-restoring-grants')
        require(all(digest(Path('/usr/bin')/name) == pinned for name, pinned in component['executable_sha256'].items()),
                'Qualified native executable bytes no longer match their package.')
        if candidate_directory is not None:
            require(json.loads((candidate_directory/'candidate.json').read_bytes()) ==
                    {key: item for key, item in component.items() if key != 'development_candidate'},
                    'Development candidate inventory changed during qualification.')
    finally:
        run('systemctl', 'stop', *names, check=False)
        run('systemctl', 'reset-failed', *names, check=False)
        for name in names:
            (units/name).unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
        run('nft', 'flush', 'ruleset')
        for name in reversed(interfaces):
            run('ip', 'link', 'delete', name)
    require(source_hashes == {name: digest(ROOT/name) for name in SOURCE_FILES},
            'Native observer source changed during qualification.')
    result = {'schema': 1, 'test': ('offline-policy-observer-component-candidate' if candidate_directory else
                                  'offline-pinned-policy-observer-component'), 'result': 'pass',
        'assessed_at': datetime.now(timezone.utc).isoformat(), 'component': component,
        'checks': checks, 'observation': observed, 'actual_policy_engine_ipc_qualified': True,
        'selected_pinned_component_qualified': candidate_directory is None,
        'private_image_qualified': False, 'external_network': False,
        'limits': ['synthetic two-network profile and empty directory/bindings only',
                   'no nonempty grants, translator traffic, real directory or private publisher tested',
                   'no full signed image, persistent update/fallback or physical acceptance'],
        'source_sha256': source_hashes}
    with output.open('xb') as stream:
        stream.write(canonical(result))
    print('Enforcing policy helper passed native readiness, UID, operation, outage and restart checks; '
          'selected release qualified: '+str(candidate_directory is None)+'.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--package', type=Path)
    selection.add_argument('--candidate', type=Path)
    parser.add_argument('--result', required=True, type=Path)
    args = parser.parse_args()
    qualify(args.package, args.result, candidate_directory=args.candidate)
