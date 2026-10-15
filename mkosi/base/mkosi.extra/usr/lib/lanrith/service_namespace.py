#!/usr/bin/env python3
"""Own the service namespace and its two veth pairs across interrupted starts."""

import contextlib
import ctypes
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


DIRECTORY = Path('/run/lanrith-service-namespace')
NETNS = Path('/run/netns')


class Conflict(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Conflict(message)


def identity(path):
    value = os.stat(path)
    return [value.st_dev, value.st_ino]


def run(*arguments):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=5)
    require(result.returncode == 0, ' '.join(arguments) + ': ' + result.stderr.strip())
    return result.stdout


def mount(source, target, flags):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(os.fsencode(source), os.fsencode(target), None, ctypes.c_ulong(flags), None):
        raise OSError(ctypes.get_errno(), 'Could not retain the owned service namespace')


def save(value):
    with tempfile.NamedTemporaryFile(mode='w', prefix='state.', dir=DIRECTORY, delete=False) as stream:
        try:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(stream.name, DIRECTORY / 'state.json')
        finally:
            Path(stream.name).unlink(missing_ok=True)


def read_state():
    try:
        descriptor = os.open(DIRECTORY / 'state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096,
                'Unsafe namespace ownership record')
        value = json.load(stream)
    require(set(value) == {'schema', 'parent', 'namespace', 'slot', 'namespace_id', 'pairs', 'ready'} and
            value['schema'] == 1 and value['parent'] == identity('/proc/self/ns/net'),
            'Namespace ownership belongs to another lifecycle or parent namespace')
    return value


def settings():
    return {key.removeprefix('lanrith_'): value for key, value in os.environ.items()
            if key.startswith('lanrith_')}


class Namespace:
    def __init__(self, configuration):
        self.config = configuration
        self.name = configuration['service_namespace']
        self.pairs = [(configuration['service_host_link'], configuration['service_namespace_link']),
                      (configuration['vpp_service_host_veth'], configuration['vpp_service_namespace_peer'])]
        names = [self.name, *(name for pair in self.pairs for name in pair)]
        require(len(names) == len(set(names)) and
                all(re.fullmatch(r'[a-z][a-z0-9-]{0,14}', name) for name in names),
                'Invalid or duplicate namespace/interface names')
        self.public = NETNS / self.name
        self.anchor = DIRECTORY / 'namespace'

    def ip(self, *arguments, namespace=False):
        with self.enter() if namespace else contextlib.nullcontext():
            return run('ip', *arguments)

    @contextlib.contextmanager
    def enter(self):
        original = os.open('/proc/self/ns/net', os.O_RDONLY)
        target = os.open(self.anchor, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.setns(target, os.CLONE_NEWNET)
            yield
        finally:
            os.setns(original, os.CLONE_NEWNET)
            os.close(target)
            os.close(original)

    def links(self, *, namespace=False):
        return {value['ifname']: value for value in json.loads(self.ip('-j', '-d', 'link', 'show', namespace=namespace))}

    def inspect(self, state):
        """Validate every owned identity before either reconciliation or removal."""
        require(state['namespace'] == self.name and [entry['names'] for entry in state['pairs']] ==
                [list(pair) for pair in self.pairs], 'Namespace ownership names differ from this configuration')
        require(not self.anchor.is_symlink(), 'Foreign symlink replaced the namespace anchor')
        anchor = identity(self.anchor) if self.anchor.exists() else None
        require(anchor in (None, state['slot'], state['namespace_id']), 'Foreign namespace replaced the owned anchor')
        mounted = anchor == state['namespace_id'] and anchor is not None
        if os.path.lexists(self.public):
            require(self.public.is_symlink() and os.readlink(self.public) == str(self.anchor),
                    'Foreign public service namespace')
            require(mounted, 'Published namespace lost its owned mount')
        roots = self.links()
        peers = self.links(namespace=True) if mounted else {}
        allowed = {name for pair in self.pairs for name in pair}
        require(set(peers) <= {'lo', *(pair[1] for pair in self.pairs)}, 'Foreign interface in service namespace')
        found = {}
        for pair in state['pairs']:
            for index, name in enumerate(pair['names']):
                occurrences = [(place, links[name]) for place, links in ((False, roots), (True, peers)) if name in links]
                require(len(occurrences) <= 1, 'Duplicate service link: ' + name)
                if not occurrences:
                    continue
                place, link = occurrences[0]
                require(link.get('linkinfo', {}).get('info_kind') == 'veth' and
                        link['address'] == pair['macs'][index] and (not place or index == 1),
                        'Foreign service link: ' + name)
                found[name] = (place, link)
            present = [name in found for name in pair['names']]
            require(present[0] == present[1], 'Owned veth peer is missing or was moved elsewhere')
            if all(present):
                for index, name in enumerate(pair['names']):
                    place, link = found[name]
                    other_place, other = found[pair['names'][1-index]]
                    require(link.get('link_index') == other['ifindex'] or
                            (place == other_place and link.get('link') == other['ifname']),
                            'Service link points at a foreign peer: ' + name)
        # A renamed owned link is not silently deleted through its other end.
        macs = {mac for pair in state['pairs'] for mac in pair['macs']}
        require(all(link['ifname'] in allowed for link in roots.values() if link.get('address') in macs),
                'Owned service link was renamed outside its declared interface names')
        return mounted, found

    def stop(self, state):
        if state is None:
            links = self.links()
            require(not os.path.lexists(self.public) and
                    not any(name in links for pair in self.pairs for name in pair),
                    'Service resources exist without an ownership record')
            # A kill before the first journal write can leave this empty file,
            # but cannot leave a mounted namespace or any published interface.
            if self.anchor.exists():
                info = self.anchor.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_size == 0 and info.st_uid == 0 and
                        not os.path.ismount(self.anchor), 'Unidentified namespace anchor')
                self.anchor.unlink()
            return
        mounted, found = self.inspect(state)
        for host, _ in self.pairs:
            if host in found:
                self.ip('link', 'delete', 'dev', host)
        if os.path.lexists(self.public):
            self.public.unlink()
        if mounted:
            # A diagnostic FD may still reference the now-disconnected
            # namespace. Detach only our verified mount, as ip netns del does;
            # the kernel releases the empty namespace when its last FD closes.
            run('umount', '--lazy', '--', str(self.anchor))
        self.anchor.unlink(missing_ok=True)
        (DIRECTORY / 'state.json').unlink()

    def create(self):
        self.stop(None)
        self.anchor.touch(mode=0o600, exist_ok=False)
        state = {'schema': 1, 'parent': identity('/proc/self/ns/net'), 'namespace': self.name,
                 'slot': identity(self.anchor), 'namespace_id': None, 'ready': False,
                 'pairs': [{'names': list(pair), 'macs': ['02:' + ':'.join(f'{b:02x}' for b in os.urandom(5))
                                                      for _ in pair]} for pair in self.pairs]}
        save(state)
        original = os.open('/proc/self/ns/net', os.O_RDONLY)
        created = None
        try:
            # No child PID is used as a readiness signal. Before publication a
            # process kill simply releases this anonymous namespace's last FD.
            os.unshare(os.CLONE_NEWNET)
            created = os.open('/proc/self/ns/net', os.O_RDONLY)
        finally:
            os.setns(original, os.CLONE_NEWNET)
            os.close(original)
        try:
            info = os.fstat(created)
            state['namespace_id'] = [info.st_dev, info.st_ino]
            save(state)
            mount('/proc/self/fd/' + str(created), self.anchor, 4096)  # MS_BIND
        finally:
            os.close(created)
        # Consumers retain their existing NetworkNamespacePath. The symlink
        # is published exclusively, after the namespace identity is recorded.
        self.public.symlink_to(self.anchor)
        for pair in state['pairs']:
            host, peer = pair['names']
            # MAC identities are part of the atomic veth creation request.
            # A kill before the peer move still leaves provably owned links.
            self.ip('link', 'add', host, 'address', pair['macs'][0], 'type', 'veth',
                    'peer', 'name', peer, 'address', pair['macs'][1])
            self.ip('link', 'set', peer, 'netns', self.name)
        return state

    def configure(self):
        c = self.config
        host, peer = self.pairs[0]
        vpp_host, vpp_peer = self.pairs[1]
        with self.enter():
            run('sysctl', '-qw', 'net.ipv4.ip_forward=0', 'net.ipv6.conf.all.forwarding=0')
        for version in ('4', '6'):
            self.ip('-' + version, 'address', 'replace', c[f'service_ipv{version}_host_cidr'], 'dev', host)
            self.ip('-' + version, 'address', 'replace', c[f'service_ipv{version}_namespace_cidr'], 'dev', peer, namespace=True)
            self.ip('-' + version, 'address', 'replace', c[f'vpp_service_ipv{version}_namespace_cidr'], 'dev', vpp_peer, namespace=True)
            for address in c[f'service_ipv{version}_addresses'].split():
                self.ip('-' + version, 'address', 'replace', address + ('/32' if version == '4' else '/128'), 'dev', 'lo', namespace=True)
        for interface in (host, vpp_host):
            self.ip('link', 'set', interface, 'up')
        for interface in ('lo', peer, vpp_peer):
            self.ip('link', 'set', interface, 'up', namespace=True)
        for version in ('4', '6'):
            self.ip('-' + version, 'route', 'replace', c[f'service_ipv{version}_prefix'],
                    'via', c[f'service_ipv{version}_namespace_address'], 'dev', host)
        roots, peers = self.links(), self.links(namespace=True)
        for namespace, interface, address, mac in (
                (False, host, c['service_ipv6_namespace_address'], peers[peer]['address']),
                (True, peer, c['service_ipv6_host_address'], roots[host]['address'])):
            self.ip('-6', 'neigh', 'replace', address, 'lladdr', mac, 'dev', interface,
                    'nud', 'permanent', namespace=namespace)
        for subnet in c['ipv4_client_subnets'].split():
            self.ip('route', 'replace', subnet, 'via', c['service_ipv4_host_address'], 'dev', peer, namespace=True)
        # After= on consumers must mean the fixed listener addresses are usable,
        # including completion (or explicit failure) of IPv6 duplicate checks.
        expected = [(False, host, [c['service_ipv6_host_cidr']]),
                    (True, peer, [c['service_ipv6_namespace_cidr']]),
                    (True, vpp_peer, [c['vpp_service_ipv6_namespace_cidr']]),
                    (True, 'lo', c['service_ipv6_addresses'].split())]
        deadline = time.monotonic() + 5
        while True:
            pending = False
            for namespace, interface, addresses in expected:
                values = json.loads(self.ip('-j', '-6', 'address', 'show', 'dev', interface, namespace=namespace))[0]['addr_info']
                for address in addresses:
                    wanted = ipaddress.IPv6Interface(address).ip
                    actual = next((value for value in values if ipaddress.IPv6Address(value['local']) == wanted), None)
                    require(actual is not None and not actual.get('dadfailed'), 'Service IPv6 address is absent or duplicate')
                    pending |= actual.get('tentative', False)
            if not pending:
                break
            require(time.monotonic() < deadline, 'Service IPv6 address readiness timed out')
            time.sleep(0.05)

    def start(self, state):
        if state is not None:
            mounted, links = self.inspect(state)
            ready = mounted and state['ready'] and all(peer in links and links[peer][0] for _, peer in self.pairs)
            if not ready:
                self.stop(state)
                state = None
        try:
            state = state or self.create()
            self.configure()
            state['ready'] = True
            save(state)
        except BaseException:
            # SIGKILL is handled by ExecStopPost or by the next invocation;
            # ordinary command failures also reconcile through the same owner.
            self.stop(read_state())
            raise


@contextlib.contextmanager
def locked():
    for directory, mode in ((DIRECTORY, 0o700), (NETNS, 0o755)):
        directory.mkdir(mode=mode, exist_ok=True)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe service namespace runtime directory')
    descriptor = os.open(DIRECTORY / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                'Unsafe service namespace lifecycle lock')
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, 'Service namespace lifecycle is busy')
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def main():
    require(os.geteuid() == 0 and sys.argv[1:] in (['start'], ['stop']), 'Usage: service_namespace.py start|stop (root only)')
    with locked():
        owner = Namespace(settings())
        state = read_state()
        if sys.argv[1] == 'start':
            owner.start(state)
        else:
            owner.stop(state)


if __name__ == '__main__':
    try:
        main()
    except (Conflict, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Service namespace: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
