"""Downstream IPv6 PMTU checks for the offline translator systemd fixture."""

import errno
import ipaddress as ip
import json
import os
import socket
import struct
import subprocess
import time

import translation_reference as ref
from tun_policy_native import FOUR, SERVERS, SIX


def bound_socket(namespace, address, port, kind=socket.SOCK_DGRAM):
    with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/'+namespace, 'rb') as selected:
        os.setns(selected.fileno(), 0)
        try:
            fd = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, kind)
        finally:
            os.setns(original.fileno(), 0)
    fd.settimeout(2)
    fd.bind((address, port))
    return fd


def small_round_trip(sender, peer):
    sender.send(b'small request')
    assert peer.recv(256) == b'small request'
    peer.send(b'small reply')
    assert sender.recv(256) == b'small reply'


def fragmentation_needed(sender, gateway):
    # Linux IP_MTU_DISCOVER / IP_PMTUDISC_DO, IP_RECVERR and IP_MTU.
    sender.setsockopt(socket.IPPROTO_IP, 10, 2)
    sender.setsockopt(socket.IPPROTO_IP, 11, 1)
    assert sender.getsockopt(socket.IPPROTO_IP, 14) == 1500
    payload = b'ordinary UDP data '*80
    sender.send(payload)
    try:
        sender.recv(2048)
    except OSError as error:
        assert error.errno == errno.EMSGSIZE, repr(error)
    else:
        raise AssertionError('Expected fragmentation-needed on the IPv4 socket')
    data, ancillary, _, _ = sender.recvmsg(2048, 128, socket.MSG_ERRQUEUE)
    assert data and payload.startswith(data)
    message, = (entry for level, kind, entry in ancillary if (level, kind) == (socket.IPPROTO_IP, 11))
    number, origin, kind, code, _, mtu, _ = struct.unpack_from('=IBBBBII', message)
    assert (number, origin, kind, code, mtu) == (errno.EMSGSIZE, 2, 3, 4, 1260)
    assert socket.inet_ntoa(message[20:24]) == gateway
    assert sender.getsockopt(socket.IPPROTO_IP, 14) == mtu


def nat46_pmtu(manifest):
    command = ref.command
    backend_link = 'fd42:b0::'
    command('ip', 'netns', 'add', 'backend6')
    command('ip', '-n', 'p6', 'link', 'add', 'small', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'backend6')
    for namespace, device, suffix in (('p6', 'small', '1'), ('backend6', 'eth0', '2')):
        command('ip', '-n', namespace, 'link', 'set', device, 'mtu', '1280', 'up')
        command('ip', '-n', namespace, 'addr', 'add', backend_link+suffix+'/64', 'dev', device, 'nodad')
    command('ip', '-n', 'backend6', 'link', 'set', 'lo', 'up')
    command('ip', '-n', 'backend6', '-6', 'route', 'add', 'default', 'via', backend_link+'1')
    command('ip', '-n', 'p6', 'link', 'add', 'alternate', 'type', 'veth', 'peer', 'name', 'alternate', 'netns', 'c6')
    for namespace, suffix in (('p6', 'a001'), ('c6', 'a000')):
        command('ip', '-n', namespace, 'link', 'set', 'alternate', 'up')
        command('ip', '-n', namespace, 'addr', 'add', SIX+suffix+'/127', 'dev', 'alternate', 'nodad')
        command(*ref.inside(namespace, 'sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1'))

    prefix = manifest['prefix']
    embedded = str(ip.ip_network(prefix).network_address + int(ip.ip_address(FOUR)))
    command('ip', '-n', 'p6', '-6', 'route', 'add', prefix, 'via', SERVERS+'1', 'src', SERVERS+'2')
    ref.nft('table inet pmtu_observer {\n chain forward { type filter hook forward priority -2; policy accept;\n'
            + ''.join(f'iifname "{name}" oifname "{manifest["interface"]}" ip6 saddr {source} '
                      f'ip6 daddr {embedded} icmpv6 type packet-too-big counter\n'
                      for name, source in (('p6', SERVERS+'2'), ('c6', SIX+'a001')))
            + f'oifname "nat64-internal" ip6 daddr {embedded} icmpv6 type packet-too-big counter\n }}\n'
            + ' chain admitted { type filter hook forward priority 1; policy accept;\n'
              f'oifname "nat64-internal" ip6 daddr {embedded} icmpv6 type packet-too-big counter\n }}\n}}\n')
    for index, mode in enumerate(('client', 'owner callback', 'directory callback'), 1):
        mapping = manifest['mappings']['service'+str(index)]
        target, alias = mapping['ipv6'], mapping['ipv4']
        command('ip', '-n', 'p6', 'addr', 'del', target+'/64', 'dev', 'eth0')
        command('ip', '-n', 'backend6', 'addr', 'add', target+'/128', 'dev', 'lo', 'nodad')
        command('ip', '-n', 'p6', '-6', 'route', 'add', target+'/128', 'via', backend_link+'2')
        command('ip', '-6', 'route', 'add', target+'/128', 'via', SERVERS+'2', 'dev', 'p6')
        # Confirm that the moved endpoint and its new downstream hop answer
        # before the single-datagram PMTU and callback assertions begin.
        subprocess.run(ref.inside('p6', 'ping', '-6', '-n', '-I', 'small', '-c', '3',
                                  '-i', '0.2', '-W', '1', target),
                       check=True, capture_output=True, timeout=5)
        port = 0 if mode == 'client' else 22221+index
        with bound_socket('c4', FOUR, port) as sender, bound_socket('backend6', target, 11111) as peer:
            sender.connect((alias, 11111))
            peer.connect((embedded, sender.getsockname()[1]))
            if mode == 'directory callback':
                grant = f'{alias} . {FOUR} . udp . {port}'
                ref.nft(f'add element inet lanrith tp_grants4 {{ {grant} timeout 60s }}')
            if mode != 'client':
                peer.send(b'callback')
                assert sender.recv(256) == b'callback'
            small_round_trip(sender, peer)
            if mode == 'client':
                # A Linux route change alone cannot delegate the error to
                # the other running translator, even with a shared mark.
                command('ip', '-6', 'route', 'add', embedded+'/128', 'dev', 'nat64-internal')
                sender.setsockopt(socket.IPPROTO_IP, 10, 2)
                sender.send(b'x'*1400)
                sender.settimeout(.5)
                try:
                    sender.recv(2048)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError('Cross-translator PMTU was delivered')
                sender.settimeout(2)
                command('ip', '-6', 'route', 'del', embedded+'/128', 'dev', 'nat64-internal')
                time.sleep(1)
            if mode == 'owner callback':
                # Only the returning error takes c6. Regular mapped traffic
                # still enters through its declared attachment.
                command('ip', '-n', 'p6', '-6', 'route', 'replace', prefix, 'via', SIX+'a000', 'src', SIX+'a001')
            try:
                fragmentation_needed(sender, manifest['ipv4'])
            except Exception:
                print(command('nft', 'list', 'table', 'inet', 'pmtu_observer').stdout, flush=True)
                print(command('conntrack', '-L', '-f', 'ipv6', '-p', 'udp').stdout, flush=True)
                raise
            if mode == 'owner callback':
                command('ip', '-n', 'p6', '-6', 'route', 'replace', prefix, 'via', SERVERS+'1', 'src', SERVERS+'2')
            small_round_trip(sender, peer)
            if mode == 'directory callback':
                ref.nft(f'delete element inet lanrith tp_grants4 {{ {grant} }}')
                peer.send(b'after revocation')
                sender.settimeout(.3)
                try:
                    sender.recv(256)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError('A revoked directory callback was delivered')
        print(mode, 'received IPv4 type 3/code 4, MTU 1260, and completed a smaller transfer', flush=True)
    observed = json.loads(command('nft', '-j', 'list', 'table', 'inet', 'pmtu_observer').stdout)
    counts = [expression['counter']['packets'] for row in observed['nftables']
              for expression in row.get('rule', {}).get('expr', []) if 'counter' in expression]
    assert counts == [2, 1, 1, 0], counts
    print('Observed two PTBs on p6, one on alternate c6 and one rejected on the sibling TUN', flush=True)
