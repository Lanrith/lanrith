#!/usr/bin/python3
"""Check discovery DNS with a real mDNS peer, parent, resolver chain and bridge in an offline VM."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import ipaddress as ip
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, service_runtime
from dns_migration_native import install
from test_authoritative import declaration
from unbound_native import network, run, upstream, write

PARENT = 'devices.example.test.'
CHILD = 'home.' + PARENT
READER = ('192.168.10.23', 'fd42:1234:5678:10::23')
ORDINARY = ('192.168.10.20', 'fd42:1234:5678:10::20')
DEVICE = '192.168.10.45'
DEVICE6 = 'fd42:1234:5678:10::45'


@contextmanager
def device_socket(address=ORDINARY[0], namespace='lan'):
    # A socket stays in its creation namespace. Prepare it before any timed queries.
    with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/'+namespace, 'rb') as lan:
        os.setns(lan.fileno(), 0)
        try:
            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        finally:
            os.setns(original.fileno(), 0)
    with peer:
        peer.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
        peer.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        peer.bind((address, 5353))
        yield peer


def announce(peer, *labels, ipv4=DEVICE, ipv6=None, reverse=False):
    """Publish fixture records on the isolated LAN with ordinary mDNS provenance."""
    def wire(name):
        return b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'

    def record(name, kind, payload):
        return wire(name) + struct.pack('!HHIH', kind, 1, 120, len(payload)) + payload

    records = []
    for label in labels:
        records.append(record(label+'.local', 1, socket.inet_aton(ipv4)))
        if reverse:
            name = '.'.join(reversed(ipv4.split('.')))+'.in-addr.arpa'
            records.append(record(name, 12, wire(label+'.local')))
        if ipv6:
            records.append(record(label+'.local', 28, socket.inet_pton(socket.AF_INET6, ipv6)))
    if 'printer' in labels:
        service = '_ipp._tcp.local'
        instance = 'printer.'+service
        records += [record(service, 12, wire(instance)),
                    record(instance, 33, struct.pack('!HHH', 0, 0, 631) + wire('printer.local')),
                    record(instance, 16, b'\x07fixture'),
                    record('printer.local', 28, socket.inet_pton(socket.AF_INET6, DEVICE6))]
    peer.sendto(struct.pack('!6H', 0, 0x8400, 0, len(records), 0, 0) + b''.join(records),
                ('224.0.0.251', 5353))


def prepare(platform, bridge, *, discovery_only, dns64, collector_scopes=False, collector_binary=None,
            configure=None, install_profile=None):
    assert os.geteuid() == 0 and run('systemd-detect-virt', '--vm').stdout.strip()
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    assert not Path('/usr/share/lanrith/installed.json').exists()
    for name in ('usr/sbin/ethtool', 'usr/sbin/unbound', 'usr/sbin/unbound-checkconf', 'usr/lib/systemd/system/unbound.service',
                 'usr/libexec/unbound-helper', 'usr/lib/sysusers.d/discovery-bridge.conf',
                 'usr/lib/tmpfiles.d/discovery-bridge.conf', 'usr/share/dbus-1/system.d/org.discovery-bridge.conf',
                 *('usr/lib/systemd/system/discovery-bridge-'+role+'.service' for role in ('dns', 'collector', 'publisher'))):
        shutil.copy2(platform/name, '/'+name)
    shutil.copy2(bridge, '/usr/bin/discovery-bridge')
    shutil.copytree(platform/'etc/unbound/unbound.conf.d', '/etc/unbound/unbound.conf.d', dirs_exist_ok=True)
    run('systemd-sysusers', 'discovery-bridge.conf')
    run('systemd-tmpfiles', '--create', 'discovery-bridge.conf')
    print(run('unbound', '-V').stdout.splitlines()[0], flush=True)

    value = declaration()
    value['translation'] = {'nat64': {'enabled': dns64}}
    value['services']['ntp'] = {'enabled': False}
    dns = value['services']['dns']
    dns['upstreams'] = ['198.51.100.20']
    authority = dns['authoritative']
    del authority['writers'], authority['zones']['example.test']
    authority['zones'][PARENT.rstrip('.')] = {'discovery_delegation': {'views': ['home'], 'publish_browse': True}}
    readers = [{'network': 'home', 'addresses': address} for address in READER]
    authority['direct_readers'] = readers
    value['services']['discovery'] = {'enabled': True, 'domain': PARENT.rstrip('.'), 'networks': ['home'],
                                      'alias_prefix': 'lab-', 'direct_readers': readers}
    if collector_scopes:
        value['networks']['home']['additional_subnets'] = ['2001:db8:88::/124']
        value['services']['discovery'].update(
            additional_sources=[{'network': 'home', 'addresses': '2001:db8:88::/124'}],
            exclude=['192.168.10.128/25', '2001:db8:88::8/125'], browse=['_ipp._tcp'])
    if discovery_only:
        del dns['authoritative'], value['services']['discovery']['direct_readers']
    if configure:
        configure(value)
    files = config.render(value)
    install({path: contents for path, contents in files.items() if path.startswith(
        ('etc/bind/', 'etc/unbound/', 'etc/discovery-bridge/', 'etc/avahi/', 'etc/dbus-1/', 'usr/share/lanrith/zones/',
         'etc/systemd/system/named.service.d/', 'etc/systemd/system/unbound.service.d/',
         'etc/systemd/system/discovery-bridge-', 'usr/lib/systemd/system/lanrith-dns',
         'usr/share/lanrith/authoritative.json', 'etc/nftables.conf', 'etc/lanrith/services.nft'))})
    write('/etc/unbound/unbound.conf.d/98-fixture.conf', 'server:\n  domain-insecure: "public.example.net."\n')
    library = Path('/usr/lib/lanrith/lanrith')
    library.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT/'lanrith/dns_runtime.py', library/'dns_runtime.py')
    network('lan', '192.168.10.1', ORDINARY[0])
    network('wan', '198.51.100.1', '198.51.100.20')
    # Veth TX offload exposes a partial checksum to the collector's raw packet socket.
    run('ethtool', '--offload', 'lan', 'tx', 'off')
    run('ip', 'netns', 'exec', 'lan', 'ethtool', '--offload', 'eth0', 'tx', 'off')
    run('ip', '-n', 'lan', 'addr', 'add', READER[0]+'/24', 'dev', 'eth0')
    run('ip', '-6', 'addr', 'add', 'fd42:1234:5678:10::1/64', 'dev', 'lan', 'nodad')
    if collector_scopes:
        run('ip', '-6', 'addr', 'add', '2001:db8:88::1/124', 'dev', 'lan', 'nodad')
        run('ip', '-n', 'lan', 'addr', 'add', '192.168.10.130/24', 'dev', 'eth0')
    for address in (READER[1], ORDINARY[1]):
        run('ip', '-n', 'lan', '-6', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad')
    run('ip', '-n', 'lan', '-6', 'route', 'add', 'default', 'via', 'fd42:1234:5678:10::1')
    if install_profile:
        install_profile(platform, files)
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    run('nft', '-f', '/etc/nftables.conf')
    plane = json.loads(files['usr/share/lanrith/service-plane.json'])
    service_runtime.start(plane)
    # The fixture creates its own interfaces and loads both generated firewalls before starting services.
    for unit in ('nftables', 'lanrith-services', 'systemd-networkd'):
        write(f'/run/systemd/system/{unit}.service',
              '[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n')
    collector_unit = '[Service]\nExecStartPre=\n'
    if collector_binary:
        shutil.copy2(collector_binary, '/usr/bin/fixture-collector')
        collector_unit += 'ExecStart=\nExecStart=/usr/bin/fixture-collector collector --config /etc/discovery-bridge/router.json\n'
    write('/run/systemd/system/discovery-bridge-collector.service.d/99-fixture.conf', collector_unit)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'dbus')
    units = ['discovery-bridge-dns', 'unbound']
    if not discovery_only:
        units.append('named')
    run('systemctl', 'start', *units)
    return plane['endpoints']


def qualify_source_ranges(endpoints, peer):
    def query(name, kind):
        return run('ip', 'netns', 'exec', 'lan', 'dig', '+tries=1', '+time=9', '-b', READER[0],
                   '@'+endpoints['discovery'][0], name+'.'+CHILD, kind).stdout

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready = run('ip', 'netns', 'exec', 'lan', 'dig', '+tries=1', '+time=1', '-b', READER[0],
                    '@'+endpoints['discovery'][0], CHILD, 'SOA', check=False)
        if 'status: NOERROR' in ready.stdout:
            break
        time.sleep(.2)
    else:
        raise RuntimeError('The discovery DNS listener did not answer its fixture SOA: '+ready.stdout)
    with device_socket('192.168.10.130') as excluded_peer:
        announce(excluded_peer, 'excluded-sender', ipv6='2001:db8:88::7')
    announce(peer, 'surviving', ipv4='192.168.10.127', ipv6='2001:db8:88::7')
    announce(peer, 'excluded-addresses', ipv4='192.168.10.128', ipv6='2001:db8:88::8')
    for kind, expected in [('A', '192.168.10.127'), ('AAAA', '2001:db8:88::7')]:
        result = query('surviving', kind)
        assert 'status: NOERROR' in result and expected in result, result
    with ThreadPoolExecutor(max_workers=3) as workers:
        queries = [workers.submit(query, label, kind) for label, kind in
                   [('excluded-sender', 'AAAA'), ('excluded-addresses', 'A'), ('excluded-addresses', 'AAAA')]]
        for task in queries:
            result = task.result()
            assert 'status: NOERROR' in result and 'ANSWER: 0' in result, result
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        announce(peer, 'printer')
        lines = run('journalctl', '-b', '-u', 'discovery-bridge-collector', '-o', 'cat').stdout.splitlines()
        counts = [json.loads(line) for line in lines if line.startswith('{')]
        if any(row.get('event') == 'catalog_counts' and row.get('submitted', 0) > 0 for row in counts):
            break
        time.sleep(.25)
    else:
        raise RuntimeError('The publisher did not acknowledge a nonempty collector frame.')
    print('A nonempty collector frame was acknowledged by the publisher.')
    print('Native queries retained both allowed addresses and withheld the excluded sender and address data.')


def qualify(endpoints, peer, *, discovery_only, dns64):
    child, managed = endpoints['discovery'], endpoints['dns']
    work = Path('/run/discovery-dns-fixture')
    work.mkdir()

    def query(address, name, kind, *, tcp=False, source=READER[0], port=53, seconds=35, short=False):
        return run('ip', 'netns', 'exec', 'lan', 'dig', '+tcp' if tcp else '+notcp', '+tries=1', f'+time={seconds}',
                   '+short' if short else '+comments', '-b', source, '-p', str(port), '@'+address, name, kind, check=False)

    if dns64:
        budgets = [('/etc/unbound/unbound.conf', '30000', '30000'), ('/etc/unbound/unbound-private.conf', '8000', '16000')]
    else:
        budgets = [('/etc/unbound/unbound.conf', '8000', '8000')]
    for file, tcp_ms, udp_ms in budgets:
        for key, expected in (('tcp-auth-query-timeout', tcp_ms), ('discard-timeout', udp_ms), ('infra-cache-min-rtt', '376')):
            assert run('unbound-checkconf', '-o', key, file).stdout.strip() == expected
        limits = {key: int(run('unbound-checkconf', '-o', key, file).stdout)
                  for key in ('wait-limit', 'num-queries-per-thread', 'incoming-num-tcp', 'outgoing-num-tcp')}
        assert all(count > 0 for count in limits.values())
        print(file, limits, flush=True)
    if discovery_only:
        assert run('systemctl', 'is-active', 'named', check=False).stdout.strip() == 'inactive'
        announce(peer, 'printer')
        announce(peer, 'only4', reverse=True)
        reverse = ip.ip_address('fd42:1234:5678:fd65::c0a8:a2d').reverse_pointer
        for index, address in enumerate(managed):
            for tcp in (False, True):
                for label, expected in (('only4', 'fd42:1234:5678:fd65::c0a8:a2d'), ('printer', DEVICE6)):
                    result = query(address, label+'.'+CHILD, 'AAAA', short=True, source=ORDINARY[index], tcp=tcp)
                    assert result.stdout.strip() == expected, result.stdout
                mapped = query(address, reverse, 'PTR', short=True, source=ORDINARY[index], tcp=tcp)
                assert mapped.stdout.strip() == 'only4.'+CHILD, mapped.stdout
                assert query(child[index], CHILD, 'SOA', source=READER[index], tcp=tcp, seconds=1).returncode != 0
        print('Private synthesis and native AAAA passed for IPv4/IPv6 and UDP/TCP without BIND or direct readers.')
        return

    # Only the parent is configured. Unbound must learn the child's NS and addresses from the referral.
    independent = work/'independent.conf'
    parent = endpoints['authoritative'][0]
    write(independent, f'server:\n  interface: 127.0.0.1@1053\n  outgoing-interface: {READER[0]}\n'
          '  do-ip6: no\n  chroot: ""\n  pidfile: ""\n  use-syslog: no\n  module-config: "iterator"\n'
          '  qname-minimisation: no\n  discard-timeout: 8000\n'
          f'  local-zone: "{PARENT}" transparent\n'
          f'stub-zone:\n  name: "{PARENT}"\n  stub-addr: {parent}\n')

    with ExitStack() as stack:
        job = subprocess.Popen(['ip', 'netns', 'exec', 'lan', 'unbound', '-d', '-p', '-c', independent])
        stack.callback(job.wait, timeout=5)
        stack.callback(job.terminate)
        upstream(work, stack, tls=False)
        for index, target in enumerate(child):
            for tcp in (False, True):
                result = query(target, CHILD, 'SOA', tcp=tcp, source=READER[index])
                assert 'status: NOERROR' in result.stdout and 'flags: qr aa' in result.stdout, result.stdout
                denied = query(target, CHILD, 'SOA', tcp=tcp, source=ORDINARY[index], seconds=1)
                assert denied.returncode != 0, denied.stdout
        print('Qualified declared and undeclared child ingress over both transports and address families.', flush=True)
        announce(peer, 'printer', 'only4')
        independent_client = {'source': '127.0.0.1', 'port': 1053}
        for address, options in (('127.0.0.1', independent_client), (managed[0], {})):
            instance = 'printer._ipp._tcp.'+CHILD
            for name, kind, expected in (('b._dns-sd._udp.'+PARENT, 'PTR', CHILD),
                    ('_ipp._tcp.'+CHILD, 'PTR', instance), (instance, 'SRV', '0 0 631 printer.'+CHILD),
                    (instance, 'TXT', '"fixture"'), ('printer.'+CHILD, 'A', DEVICE),
                    ('printer.'+CHILD, 'AAAA', DEVICE6)):
                result = query(address, name, kind, short=True, **options)
                assert result.stdout.strip().lower() == expected, (address, name, kind, result.stdout)
            print(f'DNS-SD resolution passed at {address}.', flush=True)
        if dns64:
            synthesized = query(managed[0], 'only4.'+CHILD, 'AAAA', short=True).stdout.strip()
            assert synthesized == 'fd42:1234:5678:fd65::c0a8:a2d', synthesized
        def ordinary_queries(suffix):
            time.sleep(1)
            for n in range(4):
                began = time.monotonic()
                result = query(managed[0], f'normal-{suffix}-{n}.public.example.net.', 'A', short=True)
                assert result.stdout.strip() == '93.184.216.34' and time.monotonic()-began < 2, result.stdout

        for address, label in ((child[0], 'direct'), (managed[0], 'recursive')):
            for tcp in (False, True):
                suffix = label + ('-tcp' if tcp else '-udp')
                positive = 'delayed-'+suffix
                with ThreadPoolExecutor(max_workers=4) as pool:
                    began = time.monotonic()
                    activity = [pool.submit(query, address, name+'.'+CHILD, kind, tcp=tcp)
                                for name, kind in ((positive, 'A'), ('silent-a-'+suffix, 'A'),
                                                   ('silent-aaaa-'+suffix, 'AAAA'))]
                    normal = pool.submit(ordinary_queries, suffix)
                    time.sleep(max(0, began+4.5-time.monotonic()))
                    announce(peer, positive)
                    delayed = activity[0].result()
                    assert 'status: NOERROR' in delayed.stdout and DEVICE in delayed.stdout, delayed.stdout
                    warm = time.monotonic()
                    assert query(address, positive+'.'+CHILD, 'A', tcp=tcp, short=True).stdout.strip() == DEVICE
                    assert time.monotonic()-warm < 2
                    for negative in activity[1:]:
                        result = negative.result()
                        assert ('status: NOERROR' in result.stdout and 'ANSWER: 0' in result.stdout and
                                any(row.split()[0] == CHILD and row.split()[3] == 'SOA'
                                    for row in result.stdout.splitlines() if len(row.split()) >= 4)), result.stdout
                    normal.result()
                    elapsed = time.monotonic()-began
                    assert 5 <= elapsed < 35
                    print(f'{suffix} first replies, warm hit and concurrent ordinary DNS passed in {elapsed:.2f}s', flush=True)
        run('systemctl', 'stop', 'discovery-bridge-dns')
        began = time.monotonic()
        result = query(managed[0], 'offline.'+CHILD, 'A')
        assert 'status: SERVFAIL' in result.stdout, result.stdout
        elapsed = time.monotonic()-began
        assert elapsed < 35
        print(f'Unavailable child returned SERVFAIL in {elapsed:.2f}s.', flush=True)
        assert CHILD not in (work/'plain.log').read_text(), 'Discovery question reached the public fixture.'
    print('Independent referral, real mDNS PTR/SRV/TXT/A/AAAA, exact ingress and bounded authority failure passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', type=Path)
    parser.add_argument('--bridge', type=Path)
    parser.add_argument('--collector-binary', type=Path)
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument('--discovery-only', action='store_true')
    profiles.add_argument('--no-dns64', action='store_true')
    profiles.add_argument('--collector-scopes', action='store_true')
    args = parser.parse_args()
    if args.platform and args.bridge:
        try:
            endpoints = prepare(args.platform, args.bridge, discovery_only=args.discovery_only,
                                dns64=not (args.no_dns64 or args.collector_scopes), collector_scopes=args.collector_scopes,
                                collector_binary=args.collector_binary)
            with device_socket() as peer:
                if args.collector_scopes:
                    qualify_source_ranges(endpoints, peer)
                else:
                    qualify(endpoints, peer, discovery_only=args.discovery_only, dns64=not args.no_dns64)
        except Exception:
            print(run('journalctl', '-b', '-u', 'discovery-bridge-dns', '-u', 'discovery-bridge-collector',
                      '-u', 'discovery-bridge-publisher', '-u', 'unbound', '-u', 'lanrith-dns64-private',
                      '-u', 'named', '-u', 'avahi-daemon', '-n', '60', '-o', 'cat', check=False).stdout, flush=True)
            raise
    else:
        parser.error('supply the immutable platform root and the pinned bridge executable')
