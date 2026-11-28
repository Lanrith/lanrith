"""Exercise compiled link readiness and routed LANs in a disposable systemd VM."""

import argparse
import json
import ipaddress
import socket
import struct
import sys
from pathlib import Path
import subprocess
import time

from lanrith import config, intent


def run(*args):
    return subprocess.check_output(args, text=True, timeout=45)


def namespaced(namespace, *args):
    return run('ip', 'netns', 'exec', namespace, *args)


def addresses(device):
    return {entry['local'] for entry in json.loads(run('ip', '-j', 'addr', 'show', device))[0]['addr_info']}


def peer_probe(peer, expression):
    return namespaced(peer, sys.executable, '-c', 'from networkd_native import *\n' + expression)


def router_advertisement():
    """Solicit and decode the current advertisement on the isolated client link."""
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sock:
        interface = socket.if_nametoindex('eth0')
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.settimeout(10)
        sock.sendto(struct.pack('!BBHI', 133, 0, 0, 0), ('ff02::2', 0, 0, interface))
        while True:
            packet = sock.recv(2048)
            if packet[0] == 134:
                break
    lifetime = struct.unpack_from('!H', packet, 6)[0]
    routes, pref64 = [], []
    offset = 16
    while offset < len(packet):
        kind, size = packet[offset:offset+2]
        assert size and offset + size*8 <= len(packet)
        option = packet[offset:offset+size*8]
        if kind == 24:
            prefix = ipaddress.IPv6Address(option[8:].ljust(16, b'\0'))
            routes.append(str(ipaddress.IPv6Network((prefix, option[2]))))
        if kind == 38:
            field = int.from_bytes(option[2:4], 'big')
            assert field & 7 == 0  # Both supported translators own /96 prefixes.
            pref64.append([str(ipaddress.IPv6Address(option[4:16]+bytes(4)))+'/96', field & ~7])
        offset += size*8
    print(json.dumps([lifetime, routes, pref64]))


def offer_slaac(flags, prefix):
    """Offer a standard PIO with M or O and listen for DHCPv6 on the upstream."""
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as ra, \
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as dhcp:
        interface = socket.if_nametoindex('eth0')
        ra.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        dhcp.bind(('::', 547))
        for group in ('ff02::1:2', 'ff05::1:3'):
            dhcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                            socket.inet_pton(socket.AF_INET6, group)+struct.pack('@I', interface))
        packet = struct.pack('!BBHBBHII', 134, 0, 0, 64, flags, 180, 0, 0)
        packet += struct.pack('!BBBBIII16s', 3, 4, 64, 0xc0, 120, 90, 0,
                              ipaddress.IPv6Network(prefix).network_address.packed)
        ra.sendto(packet, ('ff02::1', 0, 0, interface))
        dhcp.settimeout(4)
        try:
            data, peer = dhcp.recvfrom(2048)
        except TimeoutError:
            return
        raise AssertionError(('Unexpected DHCPv6 request', data[0], peer))


def qualify():
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert [row['ifname'] for row in json.loads(run('ip', '-j', 'link'))] == ['lo']
    value = config.load(Path('examples/minimal.yaml'))
    value['hardware']['interfaces']['oob'] = {'match': {'mac': '02:00:00:00:01:03'}}
    value['networks']['oob'] = {'interface': 'oob', 'role': 'management', 'ipv4': '192.0.2.0/24'}
    value['administration']['networks'] = ['oob']
    value['uplink'].update(ipv4='disabled', ipv6='static', addresses=['2001:db8:100::2/64'],
                           gateways=['2001:db8:100::1'], downstream_prefix='2001:db8:200::/48', delivery='routed')
    value['networks']['home']['addresses'].append('2001:db8:200:10::1/64')
    files = config.render(value)
    for path, contents in files.items():
        if (path.startswith('etc/systemd/network/') and path.endswith('.network') or
                path.startswith('etc/systemd/system/systemd-networkd-wait-online.service.d/') or
                path.startswith('etc/dbus-1/system.d/')):
            dest = Path('/')/path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(contents)
    for name, peer in [('lan', 'client'), ('wan', 'upstream'), ('oob', 'unplugged')]:
        run('ip', 'netns', 'add', peer)
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', peer)
    namespaced('client', 'ip', 'link', 'set', 'eth0', 'up')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'dbus.service')
    run('systemctl', 'reload', 'dbus.service')
    run('systemctl', 'start', 'systemd-networkd.service')
    begin = time.monotonic()
    try:
        run('systemctl', 'restart', 'systemd-networkd-wait-online.service')
    except subprocess.CalledProcessError:
        print(run('networkctl', 'list', '--no-pager'), flush=True)
        print(run('journalctl', '-u', 'systemd-networkd', '-u', 'systemd-networkd-wait-online',
                  '--no-pager', '-n', '60'), flush=True)
        raise
    assert '192.0.2.1' in addresses('oob') and '2001:db8:200:10::1' in addresses('lan')
    assert Path('/sys/class/net/wan/carrier').read_text().strip() == '0'
    print(f'LAN and isolated IPv4 management ready in {time.monotonic()-begin:.2f}s with WAN disconnected.', flush=True)

    manager = ('busctl', '--system', 'call', 'org.freedesktop.network1',
               '/org/freedesktop/network1', 'org.freedesktop.network1.Manager')
    ordinary = ('runuser', '-u', 'nobody', '--')
    assert 'lan' in run(*ordinary, *manager, 'ListLinks')
    link = Path('/sys/class/net/lan/ifindex').read_text().strip()
    rejected = subprocess.run([*ordinary, *manager, 'SetLinkNTP', 'ias', link, '0'],
                              capture_output=True, text=True, timeout=5)
    assert rejected.returncode and ('denied' in rejected.stderr.lower() or 'permitted' in rejected.stderr.lower()), rejected
    run(*manager, 'SetLinkNTP', 'ias', link, '0')
    run('systemctl', 'restart', 'systemd-networkd.service')
    run('systemctl', 'start', 'systemd-networkd-wait-online.service')
    assert 'lan' in run(*ordinary, *manager, 'ListLinks')
    print('Unprivileged status and ordinary networkd restart passed. Broker refused the unprivileged setter.', flush=True)

    namespaced('upstream', 'ip', 'link', 'set', 'eth0', 'up')
    namespaced('upstream', 'ip', '-6', 'address', 'add', '2001:db8:100::1/64', 'dev', 'eth0', 'nodad')
    namespaced('client', 'ip', '-6', 'address', 'add', '2001:db8:200:10::47/64', 'dev', 'eth0', 'nodad')
    namespaced('client', 'ip', '-6', 'route', 'replace', 'default', 'via', '2001:db8:200:10::1', 'dev', 'eth0')
    namespaced('upstream', 'ip', '-6', 'route', 'replace', '2001:db8:200:10::/64', 'via', '2001:db8:100::2')
    run('sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1')
    for _ in range(20):
        if '2001:db8:100::2' in addresses('wan'):
            break
        time.sleep(.3)
    Path('/tmp/networkd-forward.nft').write_text(files['etc/nftables.conf'])
    run('nft', '-f', '/tmp/networkd-forward.nft')
    for _ in range(2):
        namespaced('upstream', 'ip', '-6', 'neigh', 'flush', 'dev', 'eth0')
        namespaced('client', 'ping', '-6', '-I', '2001:db8:200:10::47', '-c', '1', '-w', '5', '2001:db8:100::1')
    print('Routed LAN client received replies after fresh upstream neighbor resolution.', flush=True)
    # Reuse the working route pair and change only the compiled LAN delivery guard.
    value['networks']['home']['ipv6_delivery'] = 'local'
    Path('/tmp/networkd-forward.nft').write_text(config.render(value)['etc/nftables.conf'])
    run('nft', '-f', '/tmp/networkd-forward.nft')
    denied = subprocess.run(['ip', 'netns', 'exec', 'client', 'ping', '-6', '-I',
                             '2001:db8:200:10::47', '-c', '1', '-w', '2', '2001:db8:100::1'],
                            capture_output=True, timeout=5)
    assert denied.returncode == 1
    print('The same routed client could no longer reach the WAN under local delivery.', flush=True)
    lifetime, _, prefixes = json.loads(peer_probe('client', 'router_advertisement()'))
    assert lifetime > 0 and prefixes == []

    # Transition the rendered LAN to local scope with one selected translator.
    value['networks']['home'].update(ipv6_delivery='local', pref64='nat64')
    value['translation'] = {'nat64': {'enabled': True}}
    value['uplink'].update(ipv6='ra', addresses=[], gateways=[])
    files = config.render(value)
    for path, contents in files.items():
        if 'pref64' in path:
            dest = Path('/')/path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(contents)
    # A disposable service supplies the translator's real systemd unit name.
    Path('/run/systemd/system/lanrith-nat64.service').write_text(
        '[Service]\nType=exec\nExecStart=/bin/sleep infinity\n')
    run('systemd-tmpfiles', '--create', '/usr/lib/tmpfiles.d/lanrith-pref64-nat64.conf')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'lanrith-nat64.service')
    run('systemctl', 'start', 'lanrith-pref64-nat64.service')
    for name in ('20-uplink.network', '40-home.network'):
        path = 'etc/systemd/network/'+name
        (Path('/')/path).write_text(files[path])
    run('networkctl', 'reload')
    run('networkctl', 'reconfigure', 'wan', 'lan')
    for _ in range(6):
        lifetime, routes, prefixes = json.loads(peer_probe('client', 'router_advertisement()'))
        if lifetime == 0:
            break
    assert lifetime == 0 and ['64:ff9b::/96', 1800] in prefixes, (lifetime, prefixes)
    for target in ('dns', 'ntp'):
        assert intent.service_addresses(config.normalize(value), target)[1]+'/128' in routes, routes
    run('systemctl', 'stop', 'lanrith-nat64.service')
    assert not Path('/run/systemd/network/40-home.network.d/60-lanrith-pref64.conf').exists()
    for _ in range(6):
        _, _, prefixes = json.loads(peer_probe('client', 'router_advertisement()'))
        if not any(life for _, life in prefixes):
            break
    assert not any(life for _, life in prefixes), prefixes
    run('systemctl', 'start', 'lanrith-nat64.service')
    for _ in range(6):
        _, _, prefixes = json.loads(peer_probe('client', 'router_advertisement()'))
        if ['64:ff9b::/96', 1800] in prefixes:
            break
    assert ['64:ff9b::/96', 1800] in prefixes
    print('On-wire service routes and PREF64 activation, stop and restoration passed.', flush=True)

    # Let packets reach the test server independently of the generated firewall.
    run('nft', 'flush', 'ruleset')
    for flags, cidr in [(0x80, '2001:db8:31::/64'), (0x40, '2001:db8:32::/64')]:
        peer_probe('upstream', f'offer_slaac({flags}, {cidr!r})')
        assert any(ipaddress.ip_address(addr) in ipaddress.ip_network(cidr) for addr in addresses('wan'))
    print('WAN accepted SLAAC under M and O advertisements without sending a DHCPv6 request.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--systemd', required=True, action='store_true')
    parser.parse_args()
    qualify()
