"""Own the generated service attachment across interrupted starts and stops."""

from contextlib import contextmanager
from contextvars import ContextVar
import ctypes
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time


DIRECTORY = Path('/run/lanrith-services')
STATE = DIRECTORY / 'owner.json'
PIN = DIRECTORY / 'netns'
NETNS = Path('/run/netns')
CURRENT = Path('/proc/self/ns/net')
LOCK_FDS = ContextVar('service_lock_fds', default=())
CLONE_NEWNET = 0x40000000  # Linux uapi/linux/sched.h


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(arguments):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, pass_fds=LOCK_FDS.get(),
                          text=True, check=True, timeout=10).stdout


def identity(info):
    return [info.st_dev, info.st_ino]


def file_id(path):
    try:
        return identity(path.lstat())
    except FileNotFoundError:
        return None


@contextmanager
def descriptor(path, flags, mode=0o600):
    fd = os.open(path, flags, mode)
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def locked():
    DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    with descriptor(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) as directory:
        info = os.fstat(directory)
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe service ownership directory')
        end = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < end, 'Service attachment lifecycle is busy')
                time.sleep(.05)
        NETNS.mkdir(mode=0o755, exist_ok=True)
        info = NETNS.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe network namespace directory')
        # An ip or mount child that outlives a killed coordinator must finish
        # its mutation before the next invocation can reconcile this record.
        token = LOCK_FDS.set((directory,))
        try:
            yield
        finally:
            LOCK_FDS.reset(token)


def save(state):
    # One private staging file can be reused after an interrupted atomic write.
    stage = DIRECTORY / 'owner.new'
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(state, out)
    os.replace(stage, STATE)


def provenance(plane):
    return {'schema': 1, 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'parent': identity(CURRENT.stat()),
            'names': [plane[key] for key in ('namespace', 'host_link', 'service_link')]}


def read_state(plane):
    try:
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd) as stream:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= 4096, 'Unsafe service ownership record')
        state = json.load(stream)
    require(all(state.get(k) == v for k, v in provenance(plane).items())
            and state['ns'] != state['parent'], 'Service ownership belongs to a different lifecycle')
    return state


@contextmanager
def anonymous_namespace():
    # Python 3.11 lacks os.unshare and os.setns. Both libc calls take int arguments.
    libc = ctypes.CDLL(None, use_errno=True)
    with descriptor(CURRENT, os.O_RDONLY) as original:
        if libc.unshare(CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), 'Could not create an anonymous service namespace')
        try:
            yield
        finally:
            if libc.setns(original, CLONE_NEWNET) != 0:
                raise OSError(ctypes.get_errno(), 'Could not restore the parent network namespace')


def create(plane):
    state = provenance(plane)
    public = NETNS / plane['namespace']
    # Unnamed mount points and the anonymous namespace vanish automatically
    # until their identities have all been committed to protected state.
    with (descriptor(DIRECTORY, os.O_TMPFILE | os.O_RDWR) as pin_slot,
          descriptor(NETNS, os.O_TMPFILE | os.O_RDWR) as public_slot, anonymous_namespace()):
        state.update(ns=identity(CURRENT.stat()),
                     slots=[identity(os.fstat(pin_slot)), identity(os.fstat(public_slot))],
                     macs=['02:' + secrets.token_bytes(5).hex(':') for _ in range(2)],
                     indices=None, ready=False)
        save(state)
        # Supplying a dir_fd requests linkat with AT_SYMLINK_FOLLOW for
        # /proc/self/fd/N. Publication is exclusive, including after a collision.
        os.link(f'/proc/self/fd/{pin_slot}', PIN, src_dir_fd=pin_slot)
        run(['mount', '--no-canonicalize', '--bind', str(CURRENT), str(PIN)])
        os.link(f'/proc/self/fd/{public_slot}', public, src_dir_fd=public_slot)
        run(['mount', '--no-canonicalize', '--bind', str(PIN), str(public)])
    host, peer = plane['host_link'], plane['service_link']
    run(['ip', 'link', 'add', host, 'address', state['macs'][0], 'type', 'veth',
         'peer', 'name', peer, 'address', state['macs'][1], 'netns', str(PIN)])
    state['indices'] = [links()[host]['ifindex'], links(PIN)[peer]['ifindex']]
    save(state)
    return state


def links(namespace=None):
    prefix = ['nsenter', '--net='+str(namespace), '--'] if namespace else []
    rows = json.loads(run([*prefix, 'ip', '-j', '-d', 'link', 'show']))
    return {row['ifname']: row for row in rows}


def verified_pair(state, host, peer):
    if not host or not peer:
        return False
    pair = [host, peer]
    indices = [row['ifindex'] for row in pair]
    return (all(row.get('linkinfo', {}).get('info_kind') == 'veth' for row in pair) and
            [row.get('address') for row in pair] == state['macs'] and
            [row.get('link_index') for row in pair] == indices[::-1] and
            (state['indices'] is None or state['indices'] == indices))


def remove_handle(path, namespace, slot):
    actual = file_id(path)
    if actual == namespace:
        run(['umount', '--lazy', '--', str(path)])
        actual = file_id(path)
    require(actual in (None, slot), 'Foreign service namespace handle at '+str(path))
    if actual is not None:
        path.unlink(missing_ok=True)


def reconcile(plane, state, *, keep_ready=False):
    public = NETNS / plane['namespace']
    host, peer = plane['host_link'], plane['service_link']
    root_links = links()
    if state is None:
        require(file_id(public) is None and file_id(PIN) is None and host not in root_links,
                'Service attachment exists without an ownership record')
        return False

    handles = [PIN, public]
    handle_ids = [file_id(path) for path in handles]
    namespace = next((path for path, actual in zip(handles, handle_ids) if actual == state['ns']), None)
    service_links = links(namespace) if namespace else {}
    left, right = root_links.get(host), service_links.get(peer)
    verified = verified_pair(state, left, right)
    foreign_devices = set(service_links) - {'lo', peer}
    if (keep_ready and state['ready'] and verified and not foreign_devices and
            handle_ids == [state['ns'], state['ns']] and 'UP' in left['flags'] and 'UP' in right['flags']):
        return True

    problems = []
    if verified:
        # Use our peer in the pinned namespace. A concurrent replacement of
        # the public host name cannot cause us to delete the replacement.
        try:
            run(['nsenter', '--net='+str(namespace), '--', 'ip', 'link', 'del', 'dev', peer])
        except (OSError, subprocess.SubprocessError) as error:
            if peer in links(namespace):
                problems.append(str(error))
    elif left or right:
        problems.append('foreign or unverified service veth peer')
    # Dropping the last nsfs reference may destroy resident devices. Keep the
    # handles if a peer could not be removed or a foreign device remains.
    if foreign_devices or (right and problems):
        problems.append('unexpected or unremoved interface in owned service namespace')
    else:
        for path, slot in reversed(list(zip(handles, state['slots'], strict=True))):
            try:
                remove_handle(path, state['ns'], slot)
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                problems.append(str(error))
    require(not problems, ', '.join(problems))
    STATE.unlink()
    return False


def configure(plane):
    host, peer = plane['host_link'], plane['service_link']
    namespace = ['nsenter', '--net='+str(PIN), '--']
    local_ip = [*namespace, 'ip']
    # Deterministic link-local addresses avoid a DAD delay on the private pair.
    run(['ip', 'link', 'set', 'dev', host, 'addrgenmode', 'none'])
    run([*local_ip, 'link', 'set', 'dev', peer, 'addrgenmode', 'none'])
    run(['ip', '-6', 'address', 'add', 'fe80::1/64', 'dev', host, 'nodad'])
    run([*local_ip, '-6', 'address', 'add', 'fe80::2/64', 'dev', peer, 'nodad'])
    run([*local_ip, 'link', 'set', 'lo', 'up'])
    for endpoint in plane['host_addresses']:
        run(['ip', 'address', 'add', endpoint, 'dev', host, *(['nodad'] if ':' in endpoint else [])])
    for endpoint in plane['peer_addresses'] + [a+('/128' if ':' in a else '/32')
            for addresses in plane['endpoints'].values() for a in addresses]:
        run([*local_ip, 'address', 'add', endpoint, 'dev', peer, *(['nodad'] if ':' in endpoint else [])])
    run([*namespace, 'nft', '-f', '/etc/lanrith/services.nft'])
    run(['ip', 'link', 'set', host, 'up'])
    run([*local_ip, 'link', 'set', peer, 'up'])
    for gateway, source in zip(plane['defaults'], plane['default_sources'], strict=True):
        run([*local_ip, '-6' if ':' in gateway else '-4', 'route', 'add', 'default', 'via', gateway, 'src', source])
    for route in plane.get('dependency_routes', []):
        run([*local_ip, '-6' if ':' in route['via'] else '-4', 'route', 'add',
             route['to'], 'via', route['via'], 'src', route['source']])


def start(plane):
    with locked():
        if reconcile(plane, read_state(plane), keep_ready=True):
            return
        try:
            state = create(plane)
            configure(plane)
            state['ready'] = True
            save(state)
        except BaseException:
            reconcile(plane, read_state(plane))
            raise


def stop(plane):
    with locked():
        reconcile(plane, read_state(plane))


if __name__ == '__main__':
    plane = json.loads(Path('/usr/share/lanrith/service-plane.json').read_text())
    if sys.argv[1:] == ['start']:
        start(plane)
    elif sys.argv[1:] == ['stop']:
        stop(plane)
    else:
        raise SystemExit('Expected start or stop.')
