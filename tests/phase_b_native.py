#!/usr/bin/env python3
"""Exercise core service isolation in a disposable container with no network.

Run with NET_ADMIN and SYS_ADMIN in a rootless container. Refuse an existing
network topology; never use this fixture on a router or the controller host.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build, config, service_runtime
from test_intent import minimal


def run(*argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)
    if result.returncode:
        raise RuntimeError(str(argv[:2])+': '+result.stderr)
    return result


def ns(name, *argv):
    return run('nsenter', '--net=/run/netns/'+name, '--', *argv)


def probe(namespace, address, port, allowed, protocol='tcp', user='', source='', source_port=0):
    program = '''
import socket,sys,os,pwd
address,port,protocol,user,source,source_port=sys.argv[1:]
if user:
 account=pwd.getpwnam(user);os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                socket.SOCK_DGRAM if protocol=='udp' else socket.SOCK_STREAM)
s.settimeout(.4)
try:
 if source:s.bind((source,int(source_port)))
 s.connect((address,int(port)))
 if protocol=='udp':s.send(b'test')
 s.recv(256)
except OSError:sys.exit(10)
'''
    result = subprocess.run(['nsenter', '--net=/run/netns/'+namespace, '--', 'python3', '-c', program,
                              address, str(port), protocol, user, source, str(source_port)], timeout=3, capture_output=True)
    if (result.returncode == 0) != allowed or result.returncode not in (0, 10):
        print(run('ip', '-j', 'route').stdout)
        print(ns('lanrith-services', 'ip', '-j', 'route').stdout)
        print(ns('lanrith-services', 'ss', '-lnptu').stdout)
        print(run('ip', '-j', 'neigh').stdout)
        print(ns('lanrith-services', 'ip', '-j', 'neigh').stdout)
        raise AssertionError(f'Unexpected {namespace} {address} {protocol}/{port} result: {result.returncode}')


SERVER = '''
import selectors,socket,sys
s=selectors.DefaultSelector()
for target in sys.argv[1:]:
 family=socket.AF_INET6 if ':' in target else socket.AF_INET
 for port in (53,123,8443):
  for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
   sock=socket.socket(family,kind)
   if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
   sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   sock.bind((target,port))
   if kind==socket.SOCK_STREAM:sock.listen()
   sock.setblocking(False);s.register(sock,selectors.EVENT_READ,kind)
while True:
 for key,_ in s.select():
  if key.data==socket.SOCK_STREAM:
   c,_=key.fileobj.accept();c.sendall(b'ok');c.close()
  else:
   data,a=key.fileobj.recvfrom(256);key.fileobj.sendto(b'ok',a)
'''


DHCP_CLIENT = '''
import json,socket,struct,sys,time
mode=sys.argv[1]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'eth0\\0')
s.bind(('',68))
# An unconfigured DHCP client receives packets below the IPv4 address filter.
receiver=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
receiver.bind(('eth0',0))
def exchange(index,kind,requested=None,server=None):
 xid=0x70680000+index*10+kind
 mac=bytes([2,0,0,0,1,index])
 packet=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0x8000,
                    bytes(4),bytes(4),bytes(4),bytes(4),mac,bytes(64),bytes(128))
 packet+=bytes([99,130,83,99,53,1,kind,61,7,1])+mac
 packet+=bytes([55,5,1,3,6,42,51])
 if requested:packet+=bytes([50,4])+socket.inet_aton(requested)
 if server:packet+=bytes([54,4])+server
 packet+=bytes([255])
 s.sendto(packet,('255.255.255.255',67))
 deadline=time.monotonic()+1.5
 while time.monotonic()<deadline:
  receiver.settimeout(deadline-time.monotonic())
  try:frame,_=receiver.recvfrom(4096)
  except TimeoutError:return None
  if len(frame)<42 or frame[12:14]!=b'\\x08\\x00' or frame[23]!=17:continue
  offset=14+(frame[14]&15)*4
  if frame[offset+2:offset+4]!=struct.pack('!H',68):continue
  reply=frame[offset+8:]
  if len(reply)<240 or reply[0]!=2 or reply[4:8]!=struct.pack('!I',xid):continue
  assert reply[236:240]==bytes([99,130,83,99])
  options={};offset=240
  while offset<len(reply):
   code=reply[offset];offset+=1
   if code==255:break
   if code==0:continue
   size=reply[offset];offset+=1
   options[code]=reply[offset:offset+size];offset+=size
  return socket.inet_ntoa(reply[16:20]),options
 if mode=='deny':return None
 raise AssertionError('No DHCP response')
if mode=='deny':
 assert exchange(1,1) is None
else:
 result=[]
 for index in range(1,5):
  offer=exchange(index,1);assert offer is not None
  address,options=offer;assert options[53]==bytes([2])
  answer=exchange(index,3,address,options[54]);assert answer is not None
  leased,options=answer;assert leased==address and options[53]==bytes([5])
  expected={1:'255.255.255.0',3:'192.168.10.1',6:'10.255.254.10',42:'10.255.254.40'}
  for code,target in expected.items():assert options[code]==socket.inet_aton(target),(code,options)
  assert 0<struct.unpack('!I',options[51])[0]<=3600
  result.append(address)
 assert len(set(result))==4
 assert set(result)=={'192.168.10.100','192.168.10.101','192.168.10.104','192.168.10.105'}
 assert exchange(5,1) is None,'DHCP allocated outside its exhausted pools'
 print(json.dumps(result))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gua', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert {item['ifname'] for item in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}, \
        'Refusing to use an existing network topology.'
    value = minimal()
    value['uplink'] = {'interface': 'wan', 'ipv4': {'address': '198.51.100.1/24', 'gateway': '198.51.100.2'},
                       'ipv6': 'disabled'}
    value['services'] = {'ntp': {'upstreams': ['198.51.100.2']}}
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    if args.gua:
        value['uplink']['ipv6'] = {'address': '2001:db8:200::2/48', 'gateway': '2001:db8:200::1',
                                   'downstream_prefix': '2001:db8:200::/48', 'delivery': 'on_link'}
        value['networks']['home']['ipv6']['gua'] = True
    value['networks']['home']['dhcp4']['pools'] = ['192.168.10.100-192.168.10.101',
                                                 '192.168.10.104-192.168.10.105']
    value['hardware']['interfaces']['guest'] = {'match': {'mac': '02:00:00:00:02:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.0.0/24', 'dns': False, 'ntp': False}
    value = config.normalize(value)
    files = config.render(value)
    processes = []
    checks = []
    with tempfile.TemporaryDirectory(prefix='phase-b-native.') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        for name, text in files.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        base = root/'base.tar'
        base.write_bytes(b'synthetic-assembly-input')
        build.assembly(value, base, root/'assembly', version='0.1.0', sequence=9)
        compiled = root/'assembly/mkosi.extra'
        Path('/etc/lanrith').mkdir(exist_ok=True)
        Path('/etc/lanrith/services.nft').write_text(files['etc/lanrith/services.nft'])
        for name, router, client in (('lan', '192.168.10.1/24', '192.168.10.2/24'),
                                      ('guest', '172.20.0.1/24', '172.20.0.2/24'),
                                      ('wan', '198.51.100.1/24', '198.51.100.2/24')):
            run('ip', 'netns', 'add', name+'-test')
            run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name+'-test')
            run('ip', 'address', 'add', router, 'dev', name)
            run('ip', 'link', 'set', name, 'up')
            ns(name+'-test', 'ip', 'address', 'add', client, 'dev', 'eth0')
            ns(name+'-test', 'ip', 'link', 'set', 'eth0', 'up')
            ns(name+'-test', 'ip', 'link', 'set', 'lo', 'up')
            ns(name+'-test', 'ip', 'route', 'add', 'default', 'via', router.split('/')[0])
        run('ip', '-6', 'address', 'add', 'fd42:1234:5678:10::1/64', 'dev', 'lan', 'nodad')
        ns('lan-test', 'ip', '-6', 'address', 'add', 'fd42:1234:5678:10::2/64', 'dev', 'eth0', 'nodad')
        ns('lan-test', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd42:1234:5678:10::1')
        if args.gua:
            run('ip', '-6', 'address', 'add', '2001:db8:200:10::1/64', 'dev', 'lan', 'nodad')
            ns('lan-test', 'ip', '-6', 'address', 'add', '2001:db8:200:10::2/64', 'dev', 'eth0', 'nodad')
            run('ip', '-6', 'address', 'add', '2001:db8:200::2/48', 'dev', 'wan', 'nodad')
            ns('wan-test', 'ip', '-6', 'address', 'add', '2001:db8:200::1/48', 'dev', 'eth0', 'nodad')
            run('ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:200::1', 'dev', 'wan')
        assert run('sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() == '1'
        assert run('sysctl', '-n', 'net.ipv6.conf.all.forwarding').stdout.strip() == '1'
        run('nft', '--check', '-f', str(root/'etc/nftables.conf'))
        run('nft', '-f', str(root/'etc/nftables.conf'))
        plane = json.loads(files['usr/share/lanrith/service-plane.json'])
        started = False
        try:
            service_runtime.start(plane)
            started = True
            checks.append('generated namespace and host firewalls loaded')
            # Use only the installed standard-library runtime, after removing a
            # disposable input file. The fixture has no systemd PID 1: unit
            # activation is checked separately; gateway inspection is real ip.
            owner_input = root/'owner.yaml'
            owner_input.write_text('schema: 1\n')
            owner_input.unlink()
            run('python3', '-I', '-S', '-c', """
import importlib, json, pathlib, sys
sys.path.insert(0, sys.argv[1])
for path in pathlib.Path(sys.argv[1], 'lanrith').glob('*.py'):
    importlib.import_module('lanrith.'+path.stem)
assert not any(name == 'yaml' or name.startswith('yaml.') for name in sys.modules)
assert not any(name in sys.modules for name in ('lanrith.config', 'lanrith.intent', 'lanrith.build'))
from lanrith import boot_health
from unittest.mock import patch
original = boot_health.command
def command(args):
    return 'active' if args[:2] == ['systemctl', 'is-active'] else original(args)
with patch.object(boot_health, 'command', command):
    boot_health.check(json.loads(pathlib.Path(sys.argv[2]).read_bytes()))
""", str(compiled/'usr/lib/lanrith'), str(compiled/'usr/share/lanrith/health.json'))
            checks.append('installed boot runtime imports and inspects real gateways without source YAML or compiler')

            run('unbound-checkconf', str(root/'etc/unbound/unbound.conf.d/lanrith.conf'))
            run('kea-dhcp4', '-t', str(root/'etc/kea/kea-dhcp4.conf'))
            run('chronyd', '-p', '-f', str(root/'etc/chrony/chrony.conf'))
            checks.append('Unbound Kea and Chrony native parsers')
            # A fixture intentionally offers extra ports on every service endpoint; the firewall
            # must still restrict each managed endpoint and network.
            server = subprocess.Popen(['nsenter', '--net=/run/netns/'+plane['namespace'], '--', 'python3', '-c', SERVER,
                                      *[a for addresses in plane['endpoints'].values() for a in addresses]],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(server)
            time.sleep(.2)
            for target in plane['endpoints']['dns']:
                probe('lan-test', target, 53, True)
                probe('lan-test', target, 53, True, 'udp')
                probe('lan-test', target, 8443, False)
            for target in plane['endpoints']['ntp']:
                probe('lan-test', target, 123, True, 'udp')
            probe('guest-test', plane['endpoints']['dns'][0], 53, False)
            probe('guest-test', plane['endpoints']['ntp'][0], 123, False, 'udp')
            probe('wan-test', plane['endpoints']['dns'][0], 53, False)
            probe('lan-test', '192.168.10.1', 53, False)
            checks.append('dual-stack services allowed; disabled LAN and WAN denied; extra ports denied')
            upstream = subprocess.Popen(['nsenter', '--net=/run/netns/wan-test', '--', 'python3', '-c', SERVER,
                                         '198.51.100.2'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(upstream)
            time.sleep(.2)
            probe(plane['namespace'], '198.51.100.2', 53, True, user='unbound', source=plane['endpoints']['dns'][0])
            probe(plane['namespace'], '198.51.100.2', 53, False, user='nobody', source=plane['endpoints']['dns'][0])
            probe(plane['namespace'], '198.51.100.2', 53, False, user='unbound', source=plane['endpoints']['ntp'][0])

            probe(plane['namespace'], '198.51.100.2', 53, True, 'udp', user='unbound',
                  source=plane['endpoints']['dns'][0], source_port=49555)
            for other in ('nobody', '_chrony'):
                probe(plane['namespace'], '198.51.100.2', 53, False, 'udp', user=other,
                      source=plane['endpoints']['dns'][0], source_port=49555)
            probe(plane['namespace'], '198.51.100.2', 123, True, 'udp', user='_chrony',
                  source=plane['endpoints']['ntp'][0], source_port=49556)
            probe(plane['namespace'], '198.51.100.2', 123, False, 'udp', user='unbound',
                  source=plane['endpoints']['ntp'][0], source_port=49556)
            checks.append('fresh and established socket traffic requires the package account and its assigned source; other users cannot reuse an admitted UDP tuple')
            server.terminate()
            server.communicate(timeout=5)
            processes.remove(server)
            # Run real Unbound, then query both managed address families.
            dns_path = root/'etc/unbound/unbound.conf.d/lanrith.conf'
            dns_path.write_text(dns_path.read_text()+
                '  local-zone: "phase-b.test." static\n  local-data: "phase-b.test. A 192.0.2.90"\n')
            daemon = subprocess.Popen(['nsenter', '--net=/run/netns/'+plane['namespace'], '--', 'unbound', '-d', '-p', '-c', str(dns_path)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(daemon)
            time.sleep(.4)
            for target in plane['endpoints']['dns']:
                answer = ns('lan-test', 'dig', '+time=1', '+tries=1', '+short', '@'+target, 'phase-b.test', 'A').stdout.strip()
                assert answer == '192.0.2.90', answer
            checks.append('real Unbound answers through all managed addresses')
            # Match the unit's private resolv.conf mount and package UID. A
            # client query must not depend on the controller's resolver or a
            # permissive service-subnet ACL in Unbound.
            resolver_path = root/'etc/lanrith/chrony-resolv.conf'
            resolver_path.write_text(resolver_path.read_text()+'options timeout:1 attempts:1\n')
            resolver_probe = '''
import os,pwd,socket,subprocess,sys
subprocess.run(['mount','--bind',sys.argv[1],'/etc/resolv.conf'],check=True)
account=pwd.getpwnam('_chrony')
os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
addresses=socket.getaddrinfo('phase-b.test',123,socket.AF_INET,socket.SOCK_DGRAM)
assert addresses and {item[4][0] for item in addresses}=={'192.0.2.90'}
'''
            ns(plane['namespace'], 'unshare', '--mount', '--propagation', 'private',
               'python3', '-c', resolver_probe, str(resolver_path))
            checks.append('the NTP package account resolves pool names through its generated private resolver')
            chrony = subprocess.Popen(['nsenter', '--net=/run/netns/'+plane['namespace'], '--', 'chronyd',
                                       '-x', '-d', '-f', str(root/'etc/chrony/chrony.conf')],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(chrony)
            time.sleep(.3)
            ntp_query = """
import socket,sys
address=sys.argv[1]
s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(2);s.sendto(bytes([0x23])+bytes(47),(address,123))
response,_=s.recvfrom(512)
assert len(response)>=48 and response[0]&7==4
"""
            for target in plane['endpoints']['ntp']:
                ns('lan-test', 'python3', '-c', ntp_query, target)
            checks.append('real Chrony serves all managed addresses through time redirection with clock control disabled')

            # Acquire leases with an unconfigured client, then restart the daemon
            # against its original database and confirm leases and gaps survive.
            ns('lan-test', 'ip', '-4', 'address', 'flush', 'dev', 'eth0')
            ns('lan-test', 'ip', '-4', 'route', 'add', '255.255.255.255/32', 'dev', 'eth0')
            # Package runtime directories normally created during systemd startup.
            Path('/run/kea').mkdir(parents=True, exist_ok=True)
            Path('/var/lib/kea').mkdir(parents=True, exist_ok=True)
            kea_path = str(root/'etc/kea/kea-dhcp4.conf')
            leases = None
            for attempt in range(2):
                kea = subprocess.Popen(['kea-dhcp4', '-c', kea_path],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                processes.append(kea)
                time.sleep(.3)
                assert kea.poll() is None, 'Kea did not start: '+kea.communicate()[0].decode()
                try:
                    acquired = json.loads(ns('lan-test', 'python3', '-c', DHCP_CLIENT, 'acquire').stdout)
                except Exception:
                    kea.terminate()
                    print(kea.communicate(timeout=5)[0].decode(), file=sys.stderr)
                    raise
                if leases is not None:
                    assert acquired == leases, 'DHCP leases changed after a daemon restart'
                leases = acquired
                ns('guest-test', 'python3', '-c', DHCP_CLIENT, 'deny')
                kea.terminate()
                kea.communicate(timeout=5)
                processes.remove(kea)
            checks.append('real DHCP leases include gateway DNS and NTP; pool gaps and leases survive restart; disabled LAN gets no offer')

        finally:
            for process in processes:
                process.terminate()
                process.communicate(timeout=5)
            if started:
                service_runtime.stop(plane)
    print(json.dumps({'result': 'pass', 'checks': checks, 'image_boot_qualified': False}, indent=2))


if __name__ == '__main__':
    main()
