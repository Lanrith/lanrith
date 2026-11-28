#!/usr/bin/env python3
"""Exercise Avahi's selected D-Bus roles against an offline appliance filesystem."""

import argparse
from contextlib import ExitStack
import grp
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time


AVAHI = 'org.freedesktop.Avahi'
ROLES = {'root': 'status', 'admin': 'status', 'tcpdump': 'browse', 'www-data': 'publish',
         'discovery-bridge-collector': 'browse', 'discovery-bridge-publisher': 'publish',
         'daemon': 'none', 'nobody': 'none'}


def client(role):
    from jeepney import DBusAddress, DBusErrorResponse, MatchRule, new_method_call
    from jeepney.wrappers import unwrap_msg
    from jeepney.io.blocking import open_dbus_connection

    with open_dbus_connection('SYSTEM') as bus:
        owner, = bus.bus_proxy.GetNameOwner(AVAHI)
        assert bus.bus_proxy.GetConnectionUnixUser(owner) == (pwd.getpwnam('avahi').pw_uid,)
        assert bus.bus_proxy.GetId()[0]

        def call(interface, method, signature='', args=(), *, path='/', dest=owner, allow=True):
            address = DBusAddress(path, bus_name=dest, interface=AVAHI+'.'+interface)
            message = new_method_call(address, method, signature, args)
            try:
                reply = unwrap_msg(bus.send_and_get_reply(message, timeout=5))
            except DBusErrorResponse as ex:
                if allow or ex.name != 'org.freedesktop.DBus.Error.AccessDenied':
                    raise
                return
            assert allow, (role, interface, method)
            return reply

        for name in (owner, AVAHI):
            state = call('Server', 'GetState', dest=name, allow=role != 'none')
            if role != 'none':
                assert state == (2,)
        # A deliberately unimplemented method must be blocked by the bus, even for root.
        call('Server', 'FixtureUnlistedMethod', allow=False)
        index = socket.if_nametoindex('lan')
        browser = call('Server2', 'RecordBrowserPrepare', 'iisqqu',
                       (index, 0, 'lanrith-bus-fixture.local', 1, 1, 2), allow=role == 'browse')
        if browser:
            path, = browser
            rule = MatchRule(type='signal', path=path, interface=AVAHI+'.RecordBrowser')
            bus.bus_proxy.AddMatch(rule)
            with bus.filter(rule) as signals:
                call('RecordBrowser', 'Start', path=path)
                bus.recv_until_filtered(signals, timeout=8)
            call('RecordBrowser', 'Free', path=path)
        group = call('Server', 'EntryGroupNew', allow=role == 'publish')
        if group:
            path, = group
            call('EntryGroup', 'AddRecord', 'iiusqquay',
                 (index, 0, 0, 'lanrith-bus-fixture.local', 1, 1, 10, bytes([192, 0, 2, 25])), path=path)
            rule = MatchRule(type='signal', path=path, interface=AVAHI+'.EntryGroup', member='StateChanged')
            bus.bus_proxy.AddMatch(rule)
            with bus.filter(rule, bufsize=4) as signals:
                call('EntryGroup', 'Commit', path=path)
                while bus.recv_until_filtered(signals, timeout=8).body[0] != 2:
                    pass
            call('EntryGroup', 'Reset', path=path)
            call('EntryGroup', 'Free', path=path)


def isolated():
    # The outer fixture creates this mount and a network namespace with only lo.
    assert Path('/tmp/fixture/dbus_native.py').is_file() and socket.if_nameindex() == [(1, 'lo')]
    for args in (['link', 'set', 'lo', 'up'], ['link', 'add', 'lan', 'type', 'dummy'],
                 ['address', 'add', '192.0.2.1/24', 'dev', 'lan'], ['link', 'set', 'lan', 'multicast', 'on', 'up']):
        subprocess.run(['ip', *args], check=True)
    Path('/run/dbus').mkdir()
    messagebus = pwd.getpwnam('messagebus')
    os.chown('/run/dbus', messagebus.pw_uid, messagebus.pw_gid)
    Path('/run/avahi-daemon').mkdir()
    with ExitStack() as stack:
        def start(args, **identity):
            process = subprocess.Popen(args, **identity)
            stack.callback(process.wait, timeout=5)
            stack.callback(process.terminate)
            return process

        dbus = start(['dbus-daemon', '--system', '--nofork', '--nopidfile', '--nosyslog'],
                     user=messagebus.pw_uid, group=messagebus.pw_gid, extra_groups=[])
        for _ in range(100):
            if Path('/run/dbus/system_bus_socket').is_socket():
                break
            assert dbus.poll() is None
            time.sleep(0.05)
        avahi = start(['avahi-daemon', '--no-chroot', '--no-rlimits'])
        for _ in range(100):
            assert avahi.poll() is None
            state = subprocess.run(['busctl', '--auto-start=no', 'call', AVAHI, '/', AVAHI+'.Server', 'GetState'],
                                   capture_output=True, text=True, timeout=4)
            if state.stdout.strip() == 'i 2':
                break
            time.sleep(0.1)
        else:
            raise AssertionError('Avahi did not enter RUNNING state')
        assert 'nobody' in grp.getgrnam('netdev').gr_mem
        for user, role in ROLES.items():
            account = pwd.getpwnam(user)
            subprocess.run([sys.executable, '/tmp/fixture/dbus_native.py', '--client', role],
                           user=account.pw_uid, group=account.pw_gid,
                           extra_groups=os.getgrouplist(user, account.pw_gid), check=True, timeout=20)
        print('Avahi ownership, requested replies, signals, eight client identities and record withdrawal passed.')


def launch(root, library):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lanrith import config
    from test_discovery import declaration

    value = declaration()
    value['services']['discovery']['local_clients'] = {'admin': 'status', 'tcpdump': 'browse', 'www-data': 'publish'}
    files = config.render(value)
    with tempfile.TemporaryDirectory() as temporary:
        fixture = Path(temporary)
        fixture.chmod(0o755)
        shutil.copytree(library, fixture/'jeepney', ignore=shutil.ignore_patterns('__pycache__'))
        (fixture/'dbus_native.py').write_bytes(Path(__file__).read_bytes())
        group = (root/'etc/group').read_text().splitlines()
        for i, row in enumerate(group):
            if row.startswith('netdev:'):
                group[i] = ':'.join([*row.split(':')[:3], 'nobody'])
        (fixture/'group').write_text('\n'.join(group)+'\n')
        (fixture/'avahi.conf').write_text(files['etc/avahi/avahi-daemon.conf'])
        local = fixture/'system.d'
        shutil.copytree(root/'etc/dbus-1/system.d', local, symlinks=True)
        (local/'lanrith-avahi.conf').write_text(files['etc/dbus-1/system.d/lanrith-avahi.conf'])
        for path in (fixture/'dbus_native.py', fixture/'group', fixture/'avahi.conf', local/'lanrith-avahi.conf'):
            path.chmod(0o644)
        subprocess.run(['bwrap', '--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts',
                        '--hostname', 'lanrith-fixture', '--die-with-parent', '--cap-add', 'ALL', '--ro-bind', str(root), '/', '--dev', '/dev',
                        '--proc', '/proc', '--tmpfs', '/run', '--tmpfs', '/var', '--tmpfs', '/tmp',
                        '--symlink', '/run', '/var/run', '--ro-bind', str(fixture), '/tmp/fixture',
                        '--ro-bind', str(fixture/'group'), '/etc/group',
                        '--ro-bind', str(fixture/'avahi.conf'), '/etc/avahi/avahi-daemon.conf',
                        '--ro-bind', str(local), '/etc/dbus-1/system.d',
                        '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--setenv', 'PATH', '/usr/sbin:/usr/bin',
                        '--', '/usr/bin/python3', '/tmp/fixture/dbus_native.py', '--isolated'], check=True, timeout=90)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, help='extracted immutable appliance root')
    parser.add_argument('--jeepney', type=Path, help='test-only pure Python jeepney package directory')
    parser.add_argument('--client', choices=('none', 'status', 'browse', 'publish'))
    parser.add_argument('--isolated', action='store_true')
    args = parser.parse_args()
    if args.client:
        client(args.client)
    elif args.isolated:
        isolated()
    elif args.image and args.jeepney:
        launch(args.image.resolve(), args.jeepney.resolve())
    else:
        parser.error('supply --image and --jeepney')
