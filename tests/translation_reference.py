#!/usr/bin/env python3
"""Acceptance gate for stock TAYGA, conntrack and current directory grants.

Run only in a disposable, offline network namespace. This fixture deliberately
does not import Lanrith's existing translation/firewall implementations.
"""

import argparse
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import selectors
import subprocess
import sys
import tempfile
import time


SERVER = r'''
import selectors,socket,sys
s=selectors.DefaultSelector()
for address in sys.argv[2:]:
    family=socket.AF_INET6 if ':' in address else socket.AF_INET
    for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
        for port in (11111,22222,33333):
            fd=socket.socket(family,kind);fd.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6:fd.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            fd.bind((address,port))
            if kind==socket.SOCK_STREAM:fd.listen()
            fd.setblocking(False);s.register(fd,selectors.EVENT_READ,('listen' if kind==socket.SOCK_STREAM else 'udp'))
open(sys.argv[1],'x').close()
while True:
    for k,_ in s.select():
        fd=k.fileobj
        if k.data=='listen':
            client,_=fd.accept();client.setblocking(False);s.register(client,selectors.EVENT_READ,'tcp')
        elif k.data=='udp':
            data,peer=fd.recvfrom(4096);fd.sendto(data,peer)
        else:
            data=fd.recv(4096)
            if data:fd.sendall(data)
            else:s.unregister(fd);fd.close()
'''

CLIENT = r'''
import json,os,socket,struct,sys,time
target,source,port,proto=sys.argv[1:]
family=socket.AF_INET6 if ':' in target else socket.AF_INET
fd=socket.socket(family,socket.SOCK_RAW if proto=='icmp' else socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM,
                 (socket.IPPROTO_ICMPV6 if family==socket.AF_INET6 else socket.IPPROTO_ICMP) if proto=='icmp' else 0)
fd.settimeout(.35);fd.bind((source,0))
try:fd.connect((target,0 if proto=='icmp' else int(port)));print(json.dumps({'ready':True}),flush=True)
except OSError:print(json.dumps({'ready':False}),flush=True);sys.exit(0)
for sequence,line in enumerate(sys.stdin,1):
    token=line.strip().encode()+b'\n';ok=False;end=time.monotonic()+.35;data=b'';error=None
    try:
        packet=token
        if proto=='icmp':
            packet=struct.pack('!BBHHH',128 if family==socket.AF_INET6 else 8,0,0,os.getpid()&65535,sequence)+token
            padded=packet+b'\0'*(len(packet)%2)
            total=sum(struct.unpack('!%dH'%(len(padded)//2),padded))
            while total>>16:total=(total&65535)+(total>>16)
            packet=packet[:2]+struct.pack('!H',~total&65535)+packet[4:]
        fd.sendall(packet)
        while time.monotonic()<end:
            data+=fd.recv(4096)
            if token in data:ok=True;break
    except OSError as exc:error=str(exc)
    print(json.dumps({'ok':ok,'error':error}),flush=True)
fd.close()
'''


def command(*argv, data=None, check=True):
    result = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=2)
    if check and result.returncode:
        raise RuntimeError(f'{Path(argv[0]).name}: {result.stderr[-1200:]}')
    return result


def nft(text):
    command('nft', '-f', '-', data=text)


def inside(name, *argv):
    return ['nsenter', '--net=/run/netns/'+name, '--', *argv]


def await_file(path, process):
    end = time.monotonic()+2
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= end:
            raise RuntimeError('reference server failed to become ready')
        time.sleep(.01)


def peer(name, prefix):
    network = ipaddress.ip_network(prefix)
    router, client = network.network_address+1, network.network_address+2
    command('ip', 'netns', 'add', name)
    command('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
    flags = ['nodad'] if network.version == 6 else []
    command('ip', 'addr', 'add', f'{router}/{network.prefixlen}', 'dev', name, *flags)
    command('ip', 'link', 'set', name, 'up')
    command(*inside(name, 'ip', 'link', 'set', 'lo', 'up'))
    command(*inside(name, 'ip', 'addr', 'add', f'{client}/{network.prefixlen}', 'dev', 'eth0', *flags))
    command(*inside(name, 'ip', 'link', 'set', 'eth0', 'up'))
    command(*inside(name, 'ip', '-'+str(network.version), 'route', 'add', 'default', 'via', str(router)))
    return str(client)


def ipv6_ready():
    end = time.monotonic()+2
    while True:
        pending = False
        for name in (None, 'c6', 'p6', 'c4', 'p4'):
            argv = ['ip', '-6', '-j', 'addr', 'show']
            rows = json.loads(command(*(inside(name, *argv) if name else argv)).stdout)
            for row in rows:
                for address in row.get('addr_info', []):
                    assert not address.get('dadfailed'), 'reference duplicate IPv6 address'
                    pending |= bool(address.get('tentative'))
        if not pending:
            return
        assert time.monotonic() < end, 'reference IPv6 address readiness deadline'
        time.sleep(.01)


def start_translator(root, name, pool, prefix, mapping, executable, static_control=False):
    account = pwd.getpwnam('nobody')
    group = grp.getgrgid(account.pw_gid).gr_name
    state = root/(name+'-state')
    state.mkdir(mode=0o700)
    os.chown(state, account.pw_uid, account.pw_gid)
    config = root/(name+'.conf')
    config.write_text(f'tun-device {name}\nipv4-addr {pool}.1\nipv6-addr fd42:ff::{64 if name == "n64" else 46}\n'
                      f'prefix {prefix}\nmap {pool}.2 {mapping}\n'
                      +(f'map {pool}.3 fd42:100::3\nmap {pool}.4 fd42:100:0:0:8000::3\n'
                        if name == 'n64' and static_control else '')
                      +(f'dynamic-pool {pool}.0/24\ndata-dir {state}\n' if name == 'n64' else '')
                      +'udp-cksum-mode calc\n')
    command('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun', 'user', str(account.pw_uid))
    command('ip', 'link', 'set', name, 'up')
    command('ip', '-6', 'route', 'add', prefix, 'dev', name)
    command('ip', '-4', 'route', 'add', pool+'.0/24', 'dev', name)
    log = (root/(name+'.log')).open('w')
    child = subprocess.Popen([executable, '-d', '--config', str(config), '--user', account.pw_name,
                              '--group', group], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    log.close()
    return child


def rules(egress_scope=False, static_control=False):
    # Marks belong to each kernel connection only: 1=owner, 2=directory,
    # 3=translator transit. No packet mark or cross-family lifetime token.
    text = '''table inet reference {
 set grants4 {type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags timeout; timeout 30s;}
 set grants6 {type ipv6_addr . ipv6_addr . inet_proto . inet_service; flags timeout; timeout 30s;}
 set echo4 {type ipv4_addr . ipv4_addr; flags timeout; timeout 30s;}
 set echo6 {type ipv6_addr . ipv6_addr; flags timeout; timeout 30s;}
 chain fresh {
  meta nfproto ipv4 ct protocol icmp ct original ip saddr . ct original ip daddr @echo4 accept
  meta nfproto ipv6 ct protocol ipv6-icmp ct original ip6 saddr . ct original ip6 daddr @echo6 accept
  meta nfproto ipv4 ct original ip saddr . ct original ip daddr . ct protocol . ct original proto-dst @grants4 accept
  meta nfproto ipv6 ct original ip6 saddr . ct original ip6 daddr . ct protocol . ct original proto-dst @grants6 accept
  drop
 }
 chain owner { ct mark set 1 accept; }
 chain directory { ct mark set 2 jump fresh; }
 chain forward {type filter hook forward priority 0; policy drop;
  ct state invalid,untracked drop
  ct status & 512 != 0 drop
  iifname "c6" ip6 saddr != fd42:100::/64 drop
  iifname "p6" ip6 saddr != fd42:200::/64 drop
  iifname "c4" ip saddr != 192.0.2.0/24 drop
  iifname "p4" ip saddr != 198.51.100.0/24 drop
  iifname "n64" ip saddr != 10.250.0.0/24 drop
  iifname "n64" ip6 saddr != fd42:64::/96 drop
  iifname "n46" ip saddr != 10.251.0.2 drop
  iifname "n46" ip6 saddr != fd42:46::/96 drop
  ct mark 2 goto fresh
  ct state established,related ct mark {1,3} accept
  iifname "c6" ip6 saddr {fd42:100::2,fd42:100::3} ip6 daddr fd42:64::c633:6402 meta l4proto {tcp,udp} th dport 11111 goto owner
  iifname "n64" ip saddr 10.250.0.0/24 ip daddr 198.51.100.2 meta l4proto {tcp,udp} th dport 11111 ct mark set 3 accept
  iifname "p4" ip saddr 198.51.100.2 ip daddr 10.250.0.2 meta l4proto {tcp,udp} th dport 22222 goto directory
  iifname "n64" ip6 saddr fd42:64::c633:6402 ip6 daddr fd42:100::2 meta l4proto {tcp,udp} th dport 22222 goto directory
  iifname "c4" ip saddr 192.0.2.2 ip daddr 10.251.0.2 meta l4proto {tcp,udp} th dport 11111 goto owner
  iifname "n46" ip6 saddr fd42:46::c000:202 ip6 daddr fd42:200::2 meta l4proto {tcp,udp} th dport 11111 goto owner
  iifname "p6" ip6 saddr fd42:200::2 ip6 daddr fd42:46::c000:202 meta l4proto {tcp,udp} th dport 22222 goto directory
  iifname "n46" ip saddr 10.251.0.2 ip daddr 192.0.2.2 meta l4proto {tcp,udp} th dport 22222 goto directory
  iifname "c6" ip6 saddr {fd42:100::2,fd42:100::3} ip6 daddr fd42:64::c633:6402 icmpv6 type echo-request goto owner
  iifname "n64" ip saddr 10.250.0.0/24 ip daddr 198.51.100.2 icmp type echo-request ct mark set 3 accept
  iifname "p4" ip saddr 198.51.100.2 ip daddr 10.250.0.2 icmp type echo-request goto directory
  iifname "n64" ip6 saddr fd42:64::c633:6402 ip6 daddr fd42:100::2 icmpv6 type echo-request goto directory
  iifname "c4" ip saddr 192.0.2.2 ip daddr 10.251.0.2 icmp type echo-request goto owner
  iifname "n46" ip6 saddr fd42:46::c000:202 ip6 daddr fd42:200::2 icmpv6 type echo-request goto owner
  iifname "p6" ip6 saddr fd42:200::2 ip6 daddr fd42:46::c000:202 icmpv6 type echo-request goto directory
  iifname "n46" ip saddr 10.251.0.2 ip daddr 192.0.2.2 icmp type echo-request goto directory
 }
}
table ip reference_nat {
 chain post {type nat hook postrouting priority srcnat; policy accept;
  oifname "p4" ip saddr 10.250.0.0/24 masquerade
 }
}
'''
    if egress_scope:
        # Two owner permissions share one native dynamic pool. The first /65
        # may use p4; the second /65 may use p6. Both select the same encoded
        # IPv4 destination; Linux decides its actual route after translation.
        # No source assignment is supplied to this independent reference.
        text = text.replace(
            'ip6 saddr {fd42:100::2,fd42:100::3}',
            'ip6 saddr fd42:100::/64')
        text = text.replace('iifname "n64" ip saddr 10.250.0.0/24 ip daddr 198.51.100.2',
                            'iifname "n64" oifname {"p4","p6"} ip saddr 10.250.0.0/24 ip daddr 198.51.100.2')
        text = text.replace('oifname "p4" ip saddr 10.250.0.0/24 masquerade',
                            'oifname {"p4","p6"} ip saddr 10.250.0.0/24 masquerade')
    if static_control:
        # Positive control: with known source assignments a plain data set
        # suffices to retain each source's permitted physical egress.
        text = text.replace('table inet reference {', '''table inet reference {
 set egress4 {type ipv4_addr . ifname;
  elements = {10.250.0.2 . "p4",10.250.0.3 . "p4",10.250.0.4 . "p6"};}
''')
        text = text.replace('  ct mark 2 goto fresh',
                            '  iifname "n64" meta nfproto ipv4 ip saddr . oifname != @egress4 drop\n'
                            '  ct mark 2 goto fresh')
    return text


def grants(operation, protocol, timeout=30):
    text = 'flush set inet reference grants4\nflush set inet reference grants6\n'
    text += 'flush set inet reference echo4\nflush set inet reference echo6\n'
    if operation == 'allow':
        for family, entries in ((4, [('198.51.100.2', '10.250.0.2'), ('10.251.0.2', '192.0.2.2')]),
                                (6, [('fd42:64::c633:6402', 'fd42:100::2'), ('fd42:200::2', 'fd42:46::c000:202')])):
            if protocol == 'icmp':
                rows = ','.join(f'{a} . {b} timeout {timeout}s' for a,b in entries)
                text += f'add element inet reference echo{family} {{ {rows} }}\n'
            else:
                rows = ','.join(f'{a} . {b} . {protocol} . 22222 timeout {timeout}s' for a,b in entries)
                text += f'add element inet reference grants{family} {{ {rows} }}\n'
    nft(text)


class Flow:
    def __init__(self, name, target, source, port, protocol):
        self.child = subprocess.Popen(inside(name, sys.executable, '-u', '-c', CLIENT, target, source, str(port), protocol),
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.sequence = 0
        self.description = f'{name}: {source} -> {target}:{port}/{protocol}'
        self.ready = self.read().get('ready')

    def read(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            if not selector.select(2):
                raise AssertionError('reference client response deadline')
        line = self.child.stdout.readline()
        if not line:
            raise AssertionError('reference client exited: '+self.child.stderr.read()[-512:])
        return json.loads(line)

    def check(self, allowed):
        if not self.ready:
            assert not allowed, 'allowed reference TCP connection failed'
            return
        self.sequence += 1
        self.child.stdin.write(f'reference-{self.child.pid}-{self.sequence}\n')
        self.child.stdin.flush()
        result = self.read()
        assert result['ok'] == allowed, f'{self.description} expected allowed={allowed}: {result}'

    def close(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.wait(timeout=2)
        for stream in (self.child.stdin, self.child.stdout, self.child.stderr):
            stream.close()


def exercise(root, children, checks):
    def flow(name, target, source, port, protocol, allowed=True):
        obj = Flow(name, target, source, port, protocol)
        children.append(obj.child)
        obj.check(allowed)
        return obj

    for protocol in ('tcp', 'udp', 'icmp'):
        owners, callbacks = [], []
        for label, client, target, source in (
                ('nat64', 'c6', 'fd42:64::c633:6402', 'fd42:100::2'),
                ('nat64-dynamic', 'c6', 'fd42:64::c633:6402', 'fd42:100::3'),
                ('nat46', 'c4', '10.251.0.2', '192.0.2.2')):
            owners.append(flow(client, target, source, 11111, protocol))
            checks.append(label+' '+protocol+' owner request/reply')
            if protocol != 'icmp':
                denied = flow(client, target, source, 33333, protocol, False)
                denied.close()
                checks.append(label+' '+protocol+' undeclared port denied')
        for label, client, target, source in (
                ('nat64', 'p4', '10.250.0.2', '198.51.100.2'),
                ('nat46', 'p6', 'fd42:46::c000:202', 'fd42:200::2')):
            denied = flow(client, target, source, 22222, protocol, False)
            denied.close()
            checks.append(label+' '+protocol+' callback denied without grant')
        grants('allow', protocol)
        for label, client, target, source in (
                ('nat64', 'p4', '10.250.0.2', '198.51.100.2'),
                ('nat46', 'p6', 'fd42:46::c000:202', 'fd42:200::2')):
            callbacks.append(flow(client, target, source, 22222, protocol))
            checks.append(label+' '+protocol+' fresh callback request/reply')
        grants('deny', protocol)
        for obj in callbacks:
            obj.check(False)
            obj.close()
        for obj in owners:
            obj.check(True)
            obj.close()
        checks.append(protocol+' existing callbacks revoked; owner replies remain allowed')
        grants('allow', protocol, timeout=1)
        expiring = flow('p4', '10.250.0.2', '198.51.100.2', 22222, protocol)
        time.sleep(1.05)
        expiring.check(False)
        expiring.close()
        checks.append(protocol+' natural callback grant expiry')
        grants('deny', protocol)


def exercise_egress_scope(children):
    """Require source permission and actual egress to belong to the same rule.

    This is a normal trusted translator and legitimate route change. No forged
    translator packets, mark attacks or allocation manipulation are involved.
    """
    results = []
    for protocol in ('tcp', 'udp', 'icmp'):
        for source, interface, allowed in (
                ('fd42:100::3', 'p4', True),
                ('fd42:100:0:0:8000::3', 'p6', True),
                ('fd42:100:0:0:8000::3', 'p4', False),
                ('fd42:100::3', 'p6', False)):
            gateway = '198.51.100.2' if interface == 'p4' else '198.51.101.2'
            command('ip', '-4', 'route', 'replace', '198.51.100.2/32',
                    'via', gateway, 'dev', interface)
            obj = Flow('c6', 'fd42:64::c633:6402', source, 11111, protocol)
            children.append(obj.child)
            observed = obj.ready
            if observed:
                obj.sequence += 1
                obj.child.stdin.write(f'scope-{obj.child.pid}\n')
                obj.child.stdin.flush()
                observed = obj.read()['ok']
            obj.close()
            results.append({'protocol': protocol, 'source': source, 'actual_egress': interface,
                            'expected_allowed': allowed, 'observed_allowed': observed})
    print(json.dumps({'declared_policy': [
        {'from': 'fd42:100::/65', 'egress': 'p4', 'action': 'allow', 'authorization': 'owner'},
        {'from': 'fd42:100:0:0:8000::/65', 'egress': 'p6', 'action': 'allow', 'authorization': 'owner'}],
        'egress_scope': results}, sort_keys=True), flush=True)
    assert all(row['expected_allowed'] == row['observed_allowed'] for row in results), (
        'Source-specific egress policy is not preserved across the shared native dynamic pool')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tayga', required=True)
    parser.add_argument('--egress-scope', action='store_true',
                        help='Also require different source groups to retain their distinct egress permissions.')
    parser.add_argument('--static-egress-control', action='store_true',
                        help='Positive control with fixed source assignments and an ordinary egress set.')
    args = parser.parse_args()
    assert not args.static_egress_control or args.egress_scope, 'Control requires the egress matrix'
    assert os.geteuid() == 0 and Path('/dev/net/tun').is_char_device()
    assert {row['ifname'] for row in json.loads(command('ip', '-j', 'link').stdout)} == {'lo'}, 'Disposable namespace required'
    children, checks = [], []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        try:
            command('ip', 'link', 'set', 'lo', 'up')
            for name, prefix in (('c6', 'fd42:100::/64'), ('p6', 'fd42:200::/64'),
                                 ('c4', '192.0.2.0/24'), ('p4', '198.51.100.0/24')):
                address = peer(name, prefix)
                addresses = [address]
                if name == 'c6':
                    command(*inside(name, 'ip', '-6', 'addr', 'add', 'fd42:100::3/64', 'dev', 'eth0', 'nodad'))
                    addresses.append('fd42:100::3')
                    if args.egress_scope:
                        command(*inside(name, 'ip', '-6', 'addr', 'add',
                                        'fd42:100:0:0:8000::3/64', 'dev', 'eth0', 'nodad'))
                if name == 'p6' and args.egress_scope:
                    command('ip', '-4', 'addr', 'add', '198.51.101.1/24', 'dev', name)
                    command(*inside(name, 'ip', '-4', 'addr', 'add', '198.51.101.2/24', 'dev', 'eth0'))
                    command(*inside(name, 'ip', '-4', 'addr', 'add', '198.51.100.2/32', 'dev', 'eth0'))
                    command(*inside(name, 'ip', '-4', 'route', 'add', 'default', 'via', '198.51.101.1'))
                    addresses.append('198.51.100.2')
                ready = root/(name+'.ready')
                child = subprocess.Popen(inside(name, sys.executable, '-c', SERVER, str(ready), *addresses),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                children.append(child)
                await_file(ready, child)
            ipv6_ready()
            children.append(start_translator(root, 'n64', '10.250.0', 'fd42:64::/96', 'fd42:100::2',
                                             args.tayga, args.static_egress_control))
            children.append(start_translator(root, 'n46', '10.251.0', 'fd42:46::/96', 'fd42:200::2', args.tayga))
            observed_rules = []
            for line in rules(args.egress_scope, args.static_egress_control).splitlines():
                if 'policy ' not in line:
                    for verdict in ('accept', 'drop', 'goto', 'masquerade'):
                        line = line.replace(' '+verdict, ' counter '+verdict)
                observed_rules.append(line)
            nft('\n'.join(observed_rules)+'\n')
            if os.environ.get('REFERENCE_TRACE') == '1':
                trace = (root/'trace.log').open('w')
                children.append(subprocess.Popen(['nft', 'monitor', 'trace'], stdout=trace, stderr=trace))
                trace.close()
                nft('add table inet reference_trace\nadd chain inet reference_trace observe {type filter hook prerouting priority -301;policy accept;}\nadd rule inet reference_trace observe meta nftrace set 1\n')
            time.sleep(.1)
            assert all(child.poll() is None for child in children), 'Reference process failed at startup'
            exercise(root, children, checks)
            if args.egress_scope:
                exercise_egress_scope(children)
            print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks),
                              'static_egress_control': args.static_egress_control,
                              'witness_maps': 0, 'cross_family_metadata': False,
                              'custom_allocation_supervisor': False}, sort_keys=True))
        except Exception:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
            print(json.dumps({'completed_checks': checks}), file=sys.stderr)
            print(command('nft', 'list', 'ruleset', check=False).stdout, file=sys.stderr)
            for path in root.glob('*.log'):
                print(path.name+': '+path.read_text()[-18000:], file=sys.stderr)
            for path in root.glob('*-state/*'):
                print(path.name+': '+path.read_text()[-2048:], file=sys.stderr)
            raise
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
            for name in ('c6', 'p6', 'c4', 'p4'):
                command('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    main()
