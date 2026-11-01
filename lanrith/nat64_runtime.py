"""Publish retained NAT64 identities before starting an unprivileged translator."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import sys
import time

from . import nat64_allocations as allocations, nat64_packets, translation_runtime
from .release import canonical, read, require


def runtime_contract(manifest):
    """Load the narrow image contract; it contains no source configuration."""
    data = json.loads(read(Path('/etc/router-policy-agent/nat64-runtime/runtime.json'), 64*1024))
    require(isinstance(data, dict) and set(data) == {'schema_version', 'components'} and
            data['schema_version'] == 1 and isinstance(data['components'], list) and
            1 <= len(data['components']) <= 4, 'Invalid NAT64 runtime contract.')
    matches = [item for item in data['components'] if isinstance(item, dict) and
               item.get('id') == manifest['interface']]
    require(len(matches) == 1, 'NAT64 runtime contract omitted its component.')
    component = matches[0]
    legacy = {'id', 'status_directory', 'configuration_file', 'executable', 'username'}
    integrated = legacy | {'pending_family', 'pending_table', 'pending_set'}
    expected_executable = ('/usr/lib/lanrith/tayga-internal' if manifest['interface'] == 'nat64-internal'
                           else '/usr/sbin/tayga')
    require(set(component) in (legacy, integrated) and
            component['status_directory'] == '/run/lanrith-'+manifest['interface'] and
            component['configuration_file'] == component['status_directory']+'/tayga.conf' and
            component['executable'] == expected_executable and
            component['username'] == 'lanrith-'+manifest['interface'],
            'NAT64 runtime component changed.')
    if set(component) == integrated:
        require(component['pending_family'] == 'inet' and
                component['pending_table'] == 'router_policy_agent' and
                isinstance(component['pending_set'], str) and
                component['pending_set'].startswith('native_n64_') and
                component['pending_set'].endswith('_pending'), 'Invalid policy allocation source.')
    return component


def snapshot(component, suffix):
    family, table = 'inet', 'lanrith'
    name = nat64_packets.label({'interface': component['id']})+'_'+suffix
    if suffix == 'pending' and 'pending_set' in component:
        family, table, name = component['pending_family'], component['pending_table'], component['pending_set']
    data = translation_runtime.run('nft', '-j', 'list', 'set', family, table, name,
                                   json_output=True)
    entries = [entry['set'] for entry in data.get('nftables', []) if 'set' in entry]
    require(len(entries) == 1 and entries[0].get('type') == 'ipv6_addr', 'NAT64 allocation set changed.')
    result = []
    for entry in entries[0].get('elem', []):
        # Timeout sets use {"elem":{"val":...,"expires":...}}; permanent sets
        # use bare addresses. Expiration is never imported as a permission lease.
        if isinstance(entry, dict):
            entry = entry.get('elem', {}).get('val')
        require(isinstance(entry, str), 'Invalid pending NAT64 source.')
        result.append(entry)
    require(len(result) <= (4096 if suffix == 'pending' else 65534), 'NAT64 set exceeds its bound.')
    return result


def publish(manifest, component, current, pending, directory, runtime):
    """Durability precedes both daemon activation and the nft identity map."""
    updated = allocations.allocate(manifest, current, pending)
    configuration = allocations.configuration(manifest, updated)
    path = runtime/'tayga.conf'
    changed = updated != current or not path.exists() or read(path, 8*1024*1024) != configuration
    if changed:
        allocations.atomic_write(directory/'dynamic.map', allocations.encode(manifest, updated, int(time.time())))
        allocations.atomic_write(runtime/'tayga.conf', configuration, mode=0o644)
    name = nat64_packets.label(manifest)
    integrated = 'pending_set' in component
    if not integrated and (changed or set(snapshot(component, 'ready')) != set(updated)):
        subprocess.run(['nft', '-f', '-'], input=nat64_packets.client_chains(manifest, updated),
                       text=True, check=True, capture_output=True, timeout=30)
    return updated, changed


def kernel_uptime():
    """Use the helper's kernel boot clock, including time spent suspended."""
    return float(Path('/proc/uptime').read_text(encoding='ascii').split()[0])


def status(manifest, component=None):
    component = runtime_contract(manifest) if component is None else component
    translation_runtime.status(manifest)
    directory = Path(manifest['state_directory'])
    allocations.secure_state_directory(directory)
    current = allocations.load(manifest, directory)
    runtime = Path('/run/lanrith-'+manifest['interface'])
    configuration = read(runtime/'tayga.conf', 8*1024*1024)
    require(configuration == allocations.configuration(manifest, current),
            'NAT64 running configuration differs from retained source identities.')
    if 'pending_set' not in component:
        require(set(snapshot(component, 'ready')) == set(current),
                'NAT64 source identities are not installed.')
    observation = json.loads(read(runtime/'status.json', 4096))
    require(set(observation) == {'pid', 'start_ticks', 'monotonic', 'configuration_sha256'} and
            type(observation['pid']) is int and observation['pid'] > 1 and
            type(observation['monotonic']) in (int, float) and
            observation['configuration_sha256'] == hashlib.sha256(configuration).hexdigest() and
            0 <= kernel_uptime()-observation['monotonic'] < 4, 'NAT64 runtime observation is stale.')
    process = Path('/proc', str(observation['pid']))
    require(process.joinpath('stat').read_text().rsplit(') ', 1)[1].split()[19] == observation['start_ticks'],
            'NAT64 translator process identity changed.')
    fields = dict(line.split(':', 1) for line in process.joinpath('status').read_text().splitlines())
    uid = pwd.getpwnam('lanrith-'+manifest['interface']).pw_uid
    require(set(fields['Uid'].split()) == {str(uid)} and int(fields['CapEff'].strip(), 16) == 0,
            'NAT64 translator privileges differ from the required account.')
    binary = '/usr/lib/lanrith/tayga-internal' if manifest['interface'] == 'nat64-internal' else '/usr/sbin/tayga'
    expected = [binary, '--nodetach', '--config', str(runtime/'tayga.conf')]
    require(process.joinpath('cmdline').read_bytes().split(b'\0') == [part.encode() for part in expected]+[b''],
            'NAT64 translator command changed.')


def supervise(manifest, *, stop=None):
    translation_runtime.validate(manifest)
    name = manifest['interface']
    require(name in ('nat64', 'nat64-internal'), 'Not a NAT64 translator.')
    account = pwd.getpwnam('lanrith-'+name)
    component = runtime_contract(manifest)
    directory = Path(manifest['state_directory'])
    allocations.secure_state_directory(directory)
    runtime = Path('/run/lanrith-'+name)
    info = runtime.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
            'Unsafe NAT64 runtime directory.')
    lock = os.open(runtime/'allocator.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = allocations.load(manifest, directory)
        child = None
        stopping = False

        def shutdown(*unused):
            nonlocal stopping
            stopping = True

        def terminate():
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)

        if stop is None:
            signal.signal(signal.SIGTERM, shutdown)
            signal.signal(signal.SIGINT, shutdown)
        try:
            while not stopping and not (stop and stop()):
                current, changed = publish(manifest, component, current, snapshot(component, 'pending'),
                                           directory, runtime)
                if changed or child is None:
                    terminate()
                    binary = '/usr/lib/lanrith/tayga-internal' if name == 'nat64-internal' else '/usr/sbin/tayga'
                    child = subprocess.Popen([binary, '--nodetach', '--config', str(runtime/'tayga.conf')],
                                             user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                             stdin=subprocess.DEVNULL)
                require(child.poll() is None, 'NAT64 translator exited unexpectedly.')
                start_ticks = Path('/proc', str(child.pid), 'stat').read_text().rsplit(') ', 1)[1].split()[19]
                configuration_sha256 = hashlib.sha256(
                    allocations.configuration(manifest, current)).hexdigest()
                allocations.atomic_write(runtime/'status.json', canonical(
                    {'pid': child.pid, 'start_ticks': start_ticks, 'monotonic': kernel_uptime(),
                     'configuration_sha256': configuration_sha256}), mode=0o644)
                # A burst of new clients causes at most one restart per second.
                # Static mappings and both conntrack legs survive that restart.
                time.sleep(1)
        finally:
            terminate()
    finally:
        os.close(lock)


def main():
    require(len(sys.argv) in (2, 3) and sys.argv[-1] in ('nat64', 'nat64-internal') and
            (len(sys.argv) == 2 or sys.argv[1] == 'wait'), 'Unknown NAT64 operation.')
    manifest = json.loads(read(Path('/usr/share/lanrith', sys.argv[-1]+'.json'), 1024*1024))
    if len(sys.argv) == 2:
        supervise(manifest)
    else:
        deadline = time.monotonic()+30
        while True:
            try:
                status(manifest)
                break
            except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
                require(time.monotonic() < deadline, 'NAT64 did not reach verified readiness.')
                time.sleep(.1)


if __name__ == '__main__':
    main()
