#!/usr/bin/python3
"""Measure synthetic DNS-SD publication using a supplied component in an empty network namespace."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import selectors
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.discovery import avahi_configuration

TYPE = '_fixture._tcp.local.'
INSTANCE = 'one.' + TYPE
HOST = 'fixture-alias.local.'
RECORDS = [(HOST, 1, '192.0.2.42'), (HOST, 28, '2001:db8::42'), (TYPE, 12, INSTANCE),
           (INSTANCE, 33, '0 0 8080 ' + HOST), (INSTANCE, 16, '"fixture"')]
EXPECTED = {(name, kind) for name, kind, _ in RECORDS}
SELECTED = {('lab'+str(i), family) for i in range(5) for family in (4, 6)}


def run(*args):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def dns_name(packet, offset):
    labels = []
    end = None
    for _ in range(128):
        length = packet[offset]
        if length == 0:
            return '.'.join(labels).lower()+'.', end or offset+1
        if length & 0xc0 == 0xc0:
            end = end or offset+2
            offset = struct.unpack_from('!H', packet, offset)[0] & 0x3fff
        else:
            labels.append(packet[offset+1:offset+1+length].decode('ascii', 'replace'))
            offset += length+1
    raise ValueError('DNS name exceeded its length bound')


def observations(frame):
    eth = frame[12:14]
    if eth == b'\x08\x00' and frame[23] == 17:
        family, udp = 4, 14+(frame[14] & 15)*4
    elif eth == b'\x86\xdd' and frame[20] == 17:
        family, udp = 6, 54
    else:
        return
    if frame[udp+2:udp+4] != struct.pack('!H', 5353):
        return
    dns = frame[udp+8:]
    if len(dns) < 12 or not dns[2] & 128:
        return
    questions, answers, authority, additional = struct.unpack_from('!4H', dns, 4)
    offset = 12
    for _ in range(questions):
        _, offset = dns_name(dns, offset)
        offset += 4
    for _ in range(answers+authority+additional):
        name, offset = dns_name(dns, offset)
        kind, _, ttl, length = struct.unpack_from('!HHIH', dns, offset)
        if (name, kind) in EXPECTED:
            yield family, (name, kind), ttl
        offset += 10+length


def capture(selector, began, *, goodbye=False, silent=False):
    seen = {scope: set() for scope in SELECTED}
    completed = {}
    deadline = began + (1.25 if silent else 9)
    while time.monotonic() < deadline:
        for key, _ in selector.select(max(0, min(.1, deadline-time.monotonic()))):
            packet, sender = key.fileobj.recvfrom(65535)
            if sender[2] == socket.PACKET_OUTGOING:
                continue
            for family, rr, ttl in observations(packet):
                scope = key.data, family
                assert scope in SELECTED, ('record on excluded peer', scope, rr)
                if silent:
                    assert ttl == 0, ('publication before fresh submission', scope, rr)
                elif (ttl == 0) == goodbye:
                    seen[scope].add(rr)
                    if seen[scope] == EXPECTED:
                        completed.setdefault(scope, round(time.monotonic()-began, 3))
        if not silent and len(completed) == len(SELECTED):
            print('goodbye' if goodbye else 'announcement', sorted(completed.items()), flush=True)
            return
    assert silent, {scope: EXPECTED-records for scope, records in seen.items() if records != EXPECTED}


def process(stack, *args, **kwargs):
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, **kwargs)
    def stop():
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=6)
    stack.callback(stop)
    return proc


def wait_for(path, proc):
    for _ in range(180):
        if proc.poll() is not None:
            raise RuntimeError(f'{proc.args[0]} exited with {proc.returncode}')
        if path.exists():
            return
        time.sleep(.05)
    raise TimeoutError(path)


def exercise(bridge):
    assert os.geteuid() == 0 and socket.if_nameindex() == [(1, 'lo')], 'requires isolated root and only loopback'
    account = pwd.getpwnam('nobody')
    with ExitStack() as stack:
        work = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        work.chmod(0o755)
        selector = stack.enter_context(selectors.DefaultSelector())
        interfaces = []
        sources = {}
        run('ip', 'link', 'set', 'lo', 'up')
        for i in range(6):
            lan, peer = f'lab{i}', f'peer{i}'
            run('ip', 'link', 'add', lan, 'type', 'veth', 'peer', 'name', peer)
            for iface in (lan, peer):
                run('ip', 'link', 'set', iface, 'up')
            run('ip', 'addr', 'add', f'10.90.{i}.1/24', 'dev', lan)
            run('ip', '-6', 'addr', 'add', f'fd00:90:{i}::1/64', 'dev', lan, 'nodad')
            listener = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
            listener.bind((peer, 0))
            selector.register(listener, selectors.EVENT_READ, lan)
            if i < 5:
                interfaces.append(dict(interface=lan, source=lan, families=[4, 6]))
                sources[lan] = [f'10.90.{i}.0/24', f'fd00:90:{i}::/64']

        bus, ipc, state = work/'bus', work/'producer', work/'identity.db'
        dbus = process(stack, 'dbus-daemon', '--session', '--nofork', '--nopidfile', '--address=unix:path='+str(bus))
        wait_for(bus, dbus)
        names = [i['interface'] for i in interfaces]
        profile = {'networks': {name: {'name': name} for name in names},
                   'services': {'discovery': {'networks': names}}}
        (work/'avahi.conf').write_text(avahi_configuration(profile))
        (work/'router.json').write_text(json.dumps(dict(enabled=True, interfaces=interfaces, sources=sources,
            alias_prefix='fixture-', bus_socket=str(bus), publisher_socket=str(ipc), state=str(state),
            producer_user=account.pw_name)))
        time.sleep(2)  # Allow link-local address DAD and topology notifications to finish.
        for epoch in range(2):
            daemon = process(stack, 'avahi-daemon', '--no-drop-root', '--no-chroot', '--no-rlimits',
                             '--file', work/'avahi.conf', env={**os.environ, 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path='+str(bus)})
            time.sleep(.6)
            publisher = process(stack, bridge, 'publisher', '--config', work/'router.json')
            wait_for(ipc, publisher)
            os.chown(ipc, 0, account.pw_gid)
            if epoch == 0:
                # Use the production schema initialized by the publisher.
                with sqlite3.connect(state) as db:
                    for name in (HOST, INSTANCE):
                        wire = b''.join(bytes([len(s)])+s.encode() for s in name.rstrip('.').split('.'))+b'\0'
                        db.execute('INSERT INTO identities VALUES(?,?,?,?,0)', (name,'lab0',wire,name))
                        db.execute('INSERT INTO reservations VALUES(?,?)', (wire,name))
            capture(selector, time.monotonic(), silent=True)
            with socket.socket(socket.AF_UNIX) as producer:
                os.setegid(account.pw_gid)
                os.seteuid(account.pw_uid)
                try:
                    # SO_PEERCRED is captured on connect. Grant only the fixture account access.
                    producer.connect(str(ipc))
                finally:
                    os.seteuid(0)
                    os.setegid(0)
                producer.settimeout(4)
                with producer.makefile('rwb',buffering=0) as stream:
                    generation = f'{epoch+1:032x}'
                    stream.write(f'RECEIPTS/1 {generation}\n'.encode())
                    protocol, echoed, remote = stream.readline().decode().split()
                    assert (protocol, echoed)==('RECEIPTS/1',generation)
                    began = time.monotonic()
                    groups=[dict(interface=socket.if_nametoindex(name),family=family,deadline=began+28,
                            records=[dict(name=name,type=kind,data=data,source='lab0',unique=kind!=12)
                                     for name,kind,data in RECORDS]) for name,family in sorted(SELECTED)]
                    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()

                    def submit(sequence):
                        stream.write(json.dumps(dict(boot=boot,sequence=sequence,issued=time.monotonic(),
                                                     groups=groups)).encode()+b'\n')
                        reply=json.loads(stream.readline())
                        assert (reply['sequence'],reply['collector'],reply['publisher'])==(sequence,generation,remote)
                        return reply['states']

                    submit(1)
                    capture(selector, began)
                    for seq in range(2,24):
                        if submit(seq)=='EE'*10:
                            break
                        time.sleep(.05)
                    else:
                        raise AssertionError('complete registration did not establish')
                    began = time.monotonic()
            capture(selector, began, goodbye=True)
            capture(selector, time.monotonic(), silent=True)
            daemon.terminate()
            daemon.wait(timeout=6)
            assert publisher.wait(timeout=6)!=0, 'Avahi owner loss retained publisher'
        print('Five dual-stack links, excluded peer, producer disconnect and fresh submission after owner restart passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bridge', type=Path, required=True)
    exercise(parser.parse_args().bridge.resolve(strict=True))
