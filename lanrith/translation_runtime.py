"""Create only the signed translator's TUN and routes; never grant permission."""

import errno
import fcntl
import hashlib
import ipaddress as ip
from itertools import islice
import json
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import sys

from .release import read, require


def run(*arguments, json_output=False):
    result = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=15)
    return json.loads(result.stdout) if json_output else result.stdout


def validate(manifest):
    require(isinstance(manifest, dict) and manifest.get('interface') in ('nat46', 'nat64', 'nat64-internal'),
            'Invalid translator manifest.')
    name = manifest['interface']
    component = 'nat46' if name == 'nat46' else 'nat64'
    expected_config = '/etc/tayga'+('' if name == 'nat64' else '-'+name)+'.conf'
    expected_state = '/var/lib/tayga'+('' if name == 'nat64' else '-'+name)
    if name == 'nat64-internal':
        expected_state += '/'+str(ip.ip_network(manifest['pool'])).replace('/', '-')
    require(manifest.get('component') == component and manifest.get('config') == expected_config and
            manifest.get('state_directory') == expected_state, 'Invalid translator paths.')
    require(hashlib.sha256(read(Path(manifest['config']), 1024*1024)).hexdigest() ==
            manifest.get('config_sha256'), 'Translator configuration differs from its signed manifest.')
    require(manifest['routes'] == [manifest['pool'], manifest['prefix']] and
            manifest['addresses'] == [manifest['ipv4']+'/32', manifest['ipv6']+'/128'] and
            ip.ip_network(manifest['pool']).version == 4 and ip.ip_network(manifest['prefix']).version == 6,
            'Translator routes differ from their manifest.')


def existing(manifest, uid):
    """Return the verified device index, or None when its name is absent."""
    name = manifest.get('interface', 'nat46')
    links = run('ip', '-d', '-j', 'link', 'show', json_output=True)
    for link in links:
        if link['ifname'] != name:
            continue
        info = link.get('linkinfo', {})
        data = info.get('info_data', {})
        require(info.get('info_kind') == 'tun' and data.get('type') == 'tun' and
                data.get('user') in (uid, 'lanrith-'+name) and data.get('persist') is True and
                link.get('ifalias') == 'lanrith-'+name+':'+manifest['config_sha256'],
                'Refusing an unowned or mismatched translation interface.')
        return link['ifindex']
    return None


def delete_index(index):
    # RTM_DELLINK takes the authenticated ifindex. A subsequent reuse of the
    # name cannot make this request target its replacement.
    info = struct.pack('=BxHiII', socket.AF_UNSPEC, 0, index, 0, 0)
    request = struct.pack('=IHHII', 16+len(info), 17, 5, 1, 0)  # REQUEST | ACK
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.settimeout(15)
        sock.sendto(request+info, (0, 0))
        reply = sock.recv(4096)
    length, kind, _, sequence, _ = struct.unpack_from('=IHHII', reply)
    require(20 <= length <= len(reply) and kind == 2 and sequence == 1, 'Invalid kernel link acknowledgement.')
    code, = struct.unpack_from('=i', reply, 16)
    if code and code != -errno.ENODEV:
        raise OSError(-code, os.strerror(-code))


def create_link(manifest, uid):
    # Match ip tuntap add's IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL. Publish
    # persistence only after ownership and alias are installed. An exception
    # before then closes the last descriptor and removes this new device.
    name = manifest['interface']
    with open('/dev/net/tun', 'rb+', buffering=0) as tun:
        fcntl.ioctl(tun, 0x400454ca, struct.pack('16sH', name.encode(), 0x9001))  # TUNSETIFF
        fcntl.ioctl(tun, 0x400454cc, uid)  # TUNSETOWNER
        index = socket.if_nametoindex(name)
        run('ip', 'link', 'set', 'dev', name, 'alias', 'lanrith-'+name+':'+manifest['config_sha256'])
        fcntl.ioctl(tun, 0x400454cb, 1)  # TUNSETPERSIST
    return index


def routes(prefix):
    family = '-'+str(ip.ip_network(prefix).version)
    return run('ip', family, '-j', 'route', 'show', 'table', 'main', 'exact', prefix, json_output=True)


def direct(row, prefix, name):
    # iproute2 omits defaults (boot protocol, main table and unicast type).
    v4 = ip.ip_network(prefix).version == 4
    attributes = {'dst', 'dev', 'scope', 'table', 'protocol', 'type', 'metric', 'flags', 'pref'}
    return (row.keys() <= attributes and row.get('dst') == prefix and row.get('dev') == name and
            row.get('table', 'main') in ('main', 254) and row.get('type', 'unicast') == 'unicast' and
            row.get('protocol', 'boot') == 'boot' and row.get('scope', 'global') == ('link' if v4 else 'global') and
            row.get('metric', 0) == (0 if v4 else 1024) and row.get('pref', 'medium') == 'medium' and
            set(row.get('flags', [])) <= {'linkdown'})


def owned_route(name, prefix):
    rows = routes(prefix)
    require(not rows or len(rows) == 1 and direct(rows[0], prefix, name),
            f'Conflicting translation route {prefix} on {name}.')
    return bool(rows)


def forwarding_cases(manifest):
    name = manifest['interface']
    pool = ip.ip_network(manifest['pool'])
    prefix = ip.ip_network(manifest['prefix']).network_address
    contexts = manifest.get('route_contexts', {})
    clients = contexts.get('clients') or [(None, None)]

    def embedded(address):
        return str(prefix+int(ip.IPv4Address(address)))

    for control in (manifest['ipv4'], manifest['ipv6']):
        yield control, None, None, 'local'
    if name == 'nat46':
        for entry in manifest['mappings'].values():
            server = entry['ipv6']
            for interface, source in clients:
                yield entry['ipv4'], interface, source, 'forward'
                ingress = contexts.get('servers', {}).get(server)
                yield embedded(source or '192.0.2.2'), ingress, server if ingress else None, 'return'
    else:
        peers = contexts.get('peers') or [(None, None)]
        targets = {str(pool.network_address+2), str(pool.network_address+pool.num_addresses//4)}
        active = manifest.get('source_allocations', {}).get('active', {})
        # Each peer needs both directions for every fixed mapping. Sample
        # other clients once per source range, then one client per later peer.
        targets = sorted(targets.union(active.values()))
        fixed = [context for context in clients if context[1] in active or context == clients[0]]
        for index, (ingress, peer) in enumerate(peers):
            destination = embedded(peer or ('192.0.0.9' if name == 'nat64' else '192.168.0.2'))
            selected = clients if index == 0 else fixed
            for interface, client in selected:
                yield destination, interface, client, 'forward'
            for target in targets:
                yield target, ingress, peer, 'return'


def effective_routes(manifest):
    # ip -batch emits one JSON array per command and stops at its first error.
    # Stream a bounded batch at a time even for a large static mapping set.
    name = manifest['interface']
    for family in (4, 6):
        selected = (case for case in forwarding_cases(manifest) if ip.ip_address(case[0]).version == family)
        while batch := list(islice(selected, 128)):
            commands = []
            for target, interface, source, _ in batch:
                command = 'route get '+str(ip.ip_address(target))
                if interface is not None:
                    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', interface) and
                            ip.ip_address(source).version == family, 'Invalid translator lookup context.')
                    command += ' from '+str(ip.ip_address(source))+' iif '+interface
                commands.append(command)
            result = subprocess.run(['ip', '-'+str(family), '-j', '-batch', '-'],
                                    input='\n'.join(commands)+'\n', capture_output=True, text=True, timeout=15)
            output = result.stdout.splitlines()
            for index, (target, interface, source, direction) in enumerate(batch):
                rows = json.loads(output[index]) if index < len(output) else []
                context = f' from {source} on {interface}' if interface else ''
                local = direction == 'local'
                require(len(rows) == 1 and rows[0].get('type', 'unicast') == ('local' if local else 'unicast')
                        and rows[0].get('dev') == ('lo' if local else name),
                        f'{name} {direction} lookup for {target}{context} failed.')
            result.check_returncode()


def status(manifest):
    validate(manifest)
    name = manifest['interface']
    require(existing(manifest, pwd.getpwnam('lanrith-'+name).pw_uid), 'Required translator interface is absent.')
    row = address_state(name)
    require('UP' in row['flags'], 'Required translator interface is down.')
    addresses = {entry['local']+'/'+str(entry['prefixlen']) for entry in row.get('addr_info', [])
                 if entry['scope'] == 'global'}
    require(addresses == set(manifest['addresses']), 'Translator control addresses differ from their manifest.')
    require(not any(entry.get('tentative') or entry.get('dadfailed') for entry in row.get('addr_info', [])),
            'Translator control address is not ready.')
    for prefix in manifest['routes']:
        require(owned_route(name, prefix), 'Required translator route is absent.')
    require(Path('/proc/sys/net/ipv4/conf', name, 'accept_local').read_text().strip() == '1',
            'Translator control-error source handling is unavailable.')
    effective_routes(manifest)


def address_state(name):
    row, = run('ip', '-j', 'address', 'show', 'dev', name, json_output=True)
    return row


def control_address(state, address):
    interface = ip.ip_interface(address)
    return next((entry for entry in state.get('addr_info', []) if entry['local'] == str(interface.ip)
                 and entry['prefixlen'] == interface.network.prefixlen and entry['scope'] == 'global'), None)


def restore_down(name):
    state = address_state(name)
    if 'UP' not in state['flags']:
        return
    # An administrative down event removes installed routes and normally
    # flushes IPv6 addresses. Preserve an unrelated writer's OS state.
    for family in ('-4', '-6'):
        rows = run('ip', family, '-j', 'route', 'show', 'table', 'all', 'dev', name, json_output=True)
        require(all(row.get('protocol') == 'kernel' for row in rows),
                'Another route now requires the interface to remain up.')
    addresses = [a for a in state.get('addr_info', []) if a['family'] == 'inet6']
    if not addresses:
        run('ip', 'link', 'set', 'dev', name, 'down')
        return
    require(all(a['scope'] == 'global' and a.get('valid_life_time') == 0xffffffff for a in addresses) and
            int(Path('/proc/sys/net/ipv6/conf/all/keep_addr_on_down').read_text()) >= 0,
            'Another IPv6 address requires the interface to remain up.')
    keep = Path('/proc/sys/net/ipv6/conf', name, 'keep_addr_on_down')
    prior = keep.read_text().strip()
    try:
        keep.write_text('1')
        run('ip', 'link', 'set', 'dev', name, 'down')
    finally:
        if keep.read_text().strip() == '1':
            keep.write_text(prior)


def setup(manifest, uid, index):
    name = manifest['interface']
    for prefix in manifest['routes']:
        owned_route(name, prefix)
    created = index is None
    if created:
        index = create_link(manifest, uid)
    # Undo only completed writes, comparing the current value before removal.
    undo = []
    try:
        require(existing(manifest, uid) == index, 'Translation interface changed during setup.')
        setting = Path('/proc/sys/net/ipv4/conf', name, 'accept_local')
        previous = setting.read_text().strip()
        if previous != '1':
            setting.write_text('1')
            undo.append(lambda: setting.write_text(previous) if setting.read_text().strip() == '1' else None)
        state = address_state(name)
        if 'UP' not in state['flags']:
            run('ip', 'link', 'set', 'dev', name, 'up')
            undo.append(lambda: restore_down(name))
        for address in manifest['addresses']:
            if control_address(state, address):
                continue
            version = ip.ip_interface(address).version
            args = ('ip', '-'+str(version), 'address')
            run(*args, 'add', address, 'dev', name, *(['nodad'] if version == 6 else []))
            def remove_address(address=address, args=args):
                entry = control_address(address_state(name), address)
                if (entry and 'peer' not in entry and entry.get('valid_life_time') == 0xffffffff
                        and entry.get('preferred_life_time') == 0xffffffff
                        and entry.get('label', name) == name and not entry.get('dynamic')):
                    run(*args, 'del', address, 'dev', name)
            undo.append(remove_address)
        for prefix in manifest['routes']:
            if owned_route(name, prefix):
                continue
            args = ('ip', '-'+str(ip.ip_network(prefix).version), 'route')
            try:
                run(*args, 'add', prefix, 'dev', name)
            except subprocess.CalledProcessError:
                if owned_route(name, prefix):
                    continue
                raise
            def remove_route(prefix=prefix, args=args):
                if any(direct(row, prefix, name) for row in routes(prefix)):
                    run(*args, 'del', prefix, 'dev', name, 'proto', 'boot',
                        'metric', '0' if args[1] == '-4' else '1024')
            undo.append(remove_route)
            require(owned_route(name, prefix), 'Translation route disappeared after creation.')
    except BaseException as error:
        actions = [lambda: delete_index(index)] if created else reversed(undo)
        for action in actions:
            try:
                if existing(manifest, uid) != index:
                    break
                action()
            except Exception as rollback:
                error.add_note(f'Translator rollback failed: {rollback}')
        raise


def configure(manifest, operation):
    validate(manifest)
    name = manifest['interface']
    uid = pwd.getpwnam('lanrith-'+name).pw_uid
    require(operation in ('start', 'stop'), 'Unknown translator operation.')
    # Both the unit and direct recovery invocations serialize this translator.
    directory = Path('/run/lanrith-translator-locks')
    directory.mkdir(mode=0o700, exist_ok=True)
    with (directory/name).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        index = existing(manifest, uid)
        if operation == 'stop':
            if index is not None:
                current = existing(manifest, uid)
                require(current in (None, index), 'Translation interface changed during stop.')
                if current is not None:
                    delete_index(index)
        else:
            setup(manifest, uid, index)


def reset_connections(manifest):
    """Retire only this component's two connection families during restart.

    Native TAYGA allocation state is untouched. Both original tuple directions
    are covered, so callbacks and SNAT replies cannot retain an earlier process's
    connection state. No global conntrack flush or allocation observation occurs.
    """
    validate(manifest)
    for prefix in (manifest['pool'], manifest['prefix']):
        family = 'ipv4' if ip.ip_network(prefix).version == 4 else 'ipv6'
        for field in ('--orig-src', '--orig-dst'):
            result = subprocess.run(['/usr/sbin/conntrack', '-D', '-f', family, field, prefix],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=2,
                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
            empty = (result.returncode == 1 and
                     result.stderr.strip().endswith(': 0 flow entries have been deleted.'))
            require(result.returncode == 0 or empty, 'Translator connection retirement failed.')


def main():
    require(len(sys.argv) in (2, 3) and sys.argv[1] in ('start', 'stop', 'reset'), 'Expected start, stop or reset.')
    name = sys.argv[2] if len(sys.argv) == 3 else 'nat46'
    require(name in ('nat46', 'nat64', 'nat64-internal'), 'Unknown translator.')
    manifest = json.loads(read(Path('/usr/share/lanrith', name+'.json'), 1024*1024))
    if sys.argv[1] == 'reset':
        reset_connections(manifest)
    else:
        configure(manifest, sys.argv[1])


if __name__ == '__main__':
    main()
