#!/usr/bin/python3
"""Qualify the collector with a small Avahi object budget in an isolated systemd VM."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import time

from discovery_dns_native import CHILD, DEVICE, READER, announce, device_socket, prepare, qualify_source_ranges
from discovery_publisher_native import dns_name
from unbound_native import run


def limit_objects(_platform, _files):
    path = Path('/etc/avahi/avahi-daemon.conf')
    path.write_text(path.read_text().replace('[server]\n', '[server]\nobjects-per-client-max=8\n'))


def journal(unit):
    return run('journalctl', '-b', '-u', unit, '-o', 'cat', '--no-pager').stdout


def records():
    return [json.loads(line) for line in journal('discovery-bridge-collector').splitlines() if line.startswith('{')]


@contextmanager
def question_socket():
    with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/lan', 'rb') as lan:
        os.setns(lan.fileno(), 0)
        try:
            packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        finally:
            os.setns(original.fileno(), 0)
    with packet:
        packet.bind(('eth0', 0))
        yield packet


def wait_questions(packet, labels):
    missing = {label+'.local.' for label in labels}
    deadline = time.monotonic() + 5
    while missing:
        packet.settimeout(max(.01, deadline-time.monotonic()))
        frame = packet.recv(65535)
        udp = 14 + 4*(frame[14] & 15)
        if frame[23] == 17 and frame[udp+2:udp+4] == (5353).to_bytes(2):
            message = frame[udp+8:]
            if len(message) >= 12 and not message[2] & 128:
                offset = 12
                for _ in range(int.from_bytes(message[4:6], 'big')):
                    name, offset = dns_name(message, offset)
                    missing.discard(name)
                    offset += 4
        assert time.monotonic() < deadline, missing


def exercise(platform, bridge, collector):
    endpoints = prepare(platform, bridge, discovery_only=False, dns64=False, collector_scopes=True,
                        collector_binary=collector, install_profile=limit_objects)

    def query(label, *, check=True):
        return run('ip', 'netns', 'exec', 'lan', 'dig', '+tries=1', '+time=9', '-b', READER[0],
                   '@'+endpoints['discovery'][0], label+'.'+CHILD, 'A', check=check).stdout

    with device_socket() as peer:
        qualify_source_ranges(endpoints, peer)
        losses = sum(row.get('event') == 'discovery_epoch_lost' for row in records())
        start = run('systemctl', 'show', '-p', 'InvocationID', '--value', 'discovery-bridge-collector').stdout
        names = ['ordinary-'+str(index) for index in range(6)]
        with question_socket() as packet, ThreadPoolExecutor(max_workers=len(names)) as pool:
            queries = [pool.submit(query, name) for name in names]
            wait_questions(packet, names)
            clients = [row.split()[0] for row in run('busctl', '--system', '--no-pager', '--no-legend', 'list').stdout.splitlines()
                       if row.startswith(':') and 'discovery-bridge-collector.service' in row]
            warnings = journal('avahi-daemon')
            assert any(f"Too many objects for client '{client}'" in warnings for client in clients), clients
            announce(peer, *names)
            for task in queries:
                assert DEVICE in task.result()
        assert run('systemctl', 'show', '-p', 'InvocationID', '--value', 'discovery-bridge-collector').stdout == start
        assert sum(row.get('event') == 'discovery_epoch_lost' for row in records()) == losses
        counts = [row for row in records() if row.get('event') == 'catalog_counts']
        assert counts[-1]['submitted'] > 0, counts[-1]
        print('Six cold native lookups and the correlated catalog survived the package object limit.', flush=True)

        run('systemctl', 'restart', 'avahi-daemon')
        until = time.monotonic() + 25
        while time.monotonic() < until:
            answer = query(names[0], check=False)
            if 'status: NOERROR' in answer and 'ANSWER: 0' in answer:
                break
            assert DEVICE not in answer, answer
            time.sleep(.2)
        else:
            raise AssertionError('The recovered native authority did not return a fresh empty answer.')
        announce(peer, names[0])
        assert DEVICE in query(names[0])
        print('Restart withdrew old evidence. An independent fresh announcement restored the same native answer.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('platform', 'bridge', 'collector'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    try:
        exercise(args.platform, args.bridge, args.collector)
    except Exception:
        for unit in ('discovery-bridge-collector', 'discovery-bridge-publisher', 'avahi-daemon'):
            print(journal(unit)[-2200:], flush=True)
        raise
