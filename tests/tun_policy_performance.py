#!/usr/bin/env python3
"""Compare compiled TUN policy with the same stock TAYGA and source NAT.

Run only in an offline disposable namespace with compiled packet fixtures.
Alternating samples reduce order bias; raw measurements are always reported.
This measures the test host, not capacity or acceptance of physical hardware.
"""

import grp
import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import statistics
import subprocess
import sys
import tempfile
import time

import translation_reference as ref
from tun_policy_native import FOUR, SERVERS, SIX, WAN


SERVER = r'''
import selectors,socket,sys,threading,time
def tcp(address):
 family=socket.AF_INET6 if ':' in address else socket.AF_INET
 with socket.socket(family,socket.SOCK_STREAM) as listener:
  listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  listener.bind((address,11111));listener.listen()
  while True:
   fd,_=listener.accept()
   with fd:
    fd.settimeout(5); mode=fd.recv(1)
    if mode==b'U':
     total=0
     while data:=fd.recv(262144):total+=len(data)
     fd.sendall(str(total).encode())
    else:
     assert mode==b'D'
     data=b'x'*131072; end=time.monotonic()+1
     while time.monotonic()<end:fd.sendall(data)
def udp(address):
 family=socket.AF_INET6 if ':' in address else socket.AF_INET
 with socket.socket(family,socket.SOCK_DGRAM) as fd:
  fd.bind((address,11111))
  while True:
   data,peer=fd.recvfrom(2048);fd.sendto(data,peer)
for address in sys.argv[2:]:
 for handler in (tcp,udp):threading.Thread(target=handler,args=(address,),daemon=True).start()
time.sleep(.05);open(sys.argv[1],'x').close()
while True:time.sleep(1)
'''

CLIENT = r'''
import json,socket,struct,sys,time
target,source,direction=sys.argv[1:]
family=socket.AF_INET6 if ':' in target else socket.AF_INET
with socket.socket(family,socket.SOCK_STREAM) as fd:
 fd.settimeout(5);fd.bind((source,0));fd.connect((target,11111))
 fd.sendall(direction.encode()); start=time.monotonic();total=0
 if direction=='U':
  data=b'x'*131072
  while time.monotonic()-start<1:fd.sendall(data);total+=len(data)
  fd.shutdown(socket.SHUT_WR);reply=b''
  while block:=fd.recv(64):reply+=block
  assert int(reply)==total
 else:
  while data:=fd.recv(262144):total+=len(data)
 elapsed=time.monotonic()-start
 tcp_info=fd.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
 retransmissions=struct.unpack_from('I',tcp_info,100)[0]
with socket.socket(family,socket.SOCK_DGRAM) as fd:
 fd.settimeout(2);fd.bind((source,0));fd.connect((target,11111));samples=[]
 for i in range(220):
  data=i.to_bytes(4,'big');start=time.perf_counter_ns();fd.send(data);assert fd.recv(64)==data
  if i>=20:samples.append((time.perf_counter_ns()-start)/1000)
print(json.dumps({'mbps':total*8/elapsed/1000000,'udp_rtt_us':sorted(samples)[189],'tcp_retransmissions':retransmissions}))
'''


def main(root, tayga, rounds, diagnose=False):
    assert os.geteuid() == 0 and Path('/run/.containerenv').exists()
    assert {r['ifname'] for r in json.loads(ref.command('ip', '-j', 'link').stdout)} == {'lo'}
    components = {c['interface']: c for c in json.loads((root/'lab.json').read_text())['components']}
    children, samples = [], []
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o755)
        try:
            ref.command('ip', 'link', 'set', 'lo', 'up')
            for name, prefix in (('c6', SIX+'/64'), ('p6', SERVERS+'/64'),
                                 ('c4', '10.240.40.0/24'), ('p4', '93.184.216.0/24')):
                address = ref.peer(name, prefix)
                if name == 'c6':
                    ref.command(*ref.inside(name, 'ip', 'addr', 'add', SIX+'3/64', 'dev', 'eth0', 'nodad'))
                if name == 'p6':
                    address = SERVERS+'10'
                    ref.command(*ref.inside(name, 'ip', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad'))
                if name in ('p4', 'p6'):
                    ready = temporary/(name+'.ready')
                    child = subprocess.Popen(ref.inside(name, sys.executable, '-c', SERVER, str(ready), address),
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    children.append(child)
                    ref.await_file(ready, child)
            ref.ipv6_ready()
            account = pwd.getpwnam('nobody')
            for name, component in components.items():
                state = temporary/name
                state.mkdir(mode=0o700)
                os.chown(state, account.pw_uid, account.pw_gid)
                path = temporary/(name+'.conf')
                path.write_text(component['text'].replace(component['state_directory'], str(state)))
                ref.command('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun', 'user', str(account.pw_uid))
                ref.command('ip', 'link', 'set', name, 'up')
                for route in component['routes']:
                    ref.command('ip', '-'+str(ip.ip_network(route).version), 'route', 'add', route, 'dev', name)
                log = (temporary/(name+'.log')).open('w')
                child = subprocess.Popen([str(tayga), '-d', '--config', str(path), '--user', 'nobody',
                    '--group', grp.getgrgid(account.pw_gid).gr_name], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                log.close()
                children.append(child)
            time.sleep(.1)
            assert all(c.poll() is None for c in children)
            mac = json.loads(ref.command(*ref.inside('c4', 'ip', '-j', 'link', 'show', 'eth0')).stdout)[0]['address']
            variants = ('stock', 'policy', 'no-netdev', 'no-inet', 'conntrack-only', 'empty-netdev') if diagnose else ('stock', 'policy')
            if diagnose == 'inet':
                variants = ('stock', 'policy', 'no-source', 'no-identity', 'no-boundary', 'no-cleanup', 'no-access', 'constant-startup', 'no-invalid', 'flat-forward', 'flat-guards')
            for iteration in range(rounds):
                modes = variants if iteration % 2 == 0 else tuple(reversed(variants))
                for mode in modes:
                    ref.command('nft', '-f', str(root/'policy.nft'))
                    ref.command('nft', '-f', str(root/'identity-egress.nft'))
                    if mode == 'constant-startup':
                        rules = (root/'policy.nft').read_text()
                        assert rules.count('numgen inc mod 1 != @tp_started drop') == 1
                        replaced = temporary/'constant-startup.nft'
                        replaced.write_text(rules.replace('numgen inc mod 1 != @tp_started drop', 'meta mark & 0 != @tp_started drop'))
                        ref.command('nft', '-f', str(replaced))
                        ref.command('nft', '-f', str(root/'identity-egress.nft'))
                    if mode == 'no-invalid':
                        replaced = temporary/'no-invalid.nft'
                        replaced.write_text((root/'policy.nft').read_text().replace('ct state invalid drop', 'ct state invalid counter')
                            .replace('ct state invalid,untracked drop', 'ct state invalid,untracked counter'))
                        ref.command('nft', '-f', str(replaced))
                        ref.command('nft', '-f', str(root/'identity-egress.nft'))
                    if mode in ('stock', 'conntrack-only'):
                        # Preserve the identical generated Linux source NAT.
                        ref.nft('delete table inet lanrith\ndelete table netdev lanrith_identity\n')
                        if mode == 'conntrack-only':
                            ref.nft('table inet measurement { chain forward { type filter hook forward priority 0; '
                                    'policy accept; ct state invalid counter;\n }\n}\n')
                    else:
                        ref.nft('add element inet lanrith tp_started { 0 }\n'+
                            f'add element inet lanrith tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 90s }}\n'+
                            f'add element inet lanrith tp_dest4 {{ "c4" . {FOUR} timeout 90s }}\n'+
                            f'add element netdev lanrith_identity tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 90s }}\n')
                        if mode == 'no-netdev':
                            ref.nft('delete table netdev lanrith_identity')
                        if mode in ('no-inet', 'empty-netdev'):
                            ref.nft('delete table inet lanrith')
                        if mode == 'empty-netdev':
                            ref.nft('flush chain netdev lanrith_identity tp_identity')
                        for variant, chain in (('no-source', 'source_guard'), ('no-identity', 'tp_identity'),
                                               ('no-boundary', 'tp_boundary'), ('no-cleanup', 'tp_cleanup')):
                            if mode == variant:
                                ref.nft('flush chain inet lanrith '+chain)
                        if mode == 'no-access':
                            ref.nft('flush chain inet lanrith tp_access\nadd rule inet lanrith tp_access goto tp_owner\n')
                        if mode in ('flat-forward', 'flat-guards'):
                            ref.nft('flush chain inet lanrith forward\nadd rule inet lanrith forward accept\n')
                        if mode == 'flat-guards':
                            ref.nft('flush chain inet lanrith source_guard\nflush chain inet lanrith tp_cleanup\n')
                    ref.command('conntrack', '-F')
                    for name, component in components.items():
                        if name == 'nat46':
                            network, source, target = 'c4', FOUR, '10.251.0.2'
                        else:
                            network, source = 'c6', SIX+'3'
                            target = str(ip.ip_network(component['prefix']).network_address+int(ip.ip_address(WAN)))
                        for direction in (('U',) if diagnose else ('U', 'D')):
                            result = subprocess.run(ref.inside(network, sys.executable, '-c', CLIENT, target, source, direction),
                                check=True, capture_output=True, text=True, timeout=8)
                            samples.append({'iteration': iteration, 'mode': mode, 'component': name,
                                            'direction': direction, **json.loads(result.stdout)})
            comparisons = []
            for name in components:
                for direction in (('U',) if diagnose else ('U', 'D')):
                    group = [r for r in samples if r['component'] == name and r['direction'] == direction]
                    medians = {mode: {metric: statistics.median(r[metric] for r in group if r['mode'] == mode)
                        for metric in ('mbps', 'udp_rtt_us')} for mode in variants}
                    comparisons.append({'component': name, 'direction': direction, 'medians': medians,
                        'throughput_ratio': medians['policy']['mbps']/medians['stock']['mbps']})
            print(json.dumps({'test': 'compiled-tun-stock-tayga-comparison', 'samples': samples,
                'comparisons': comparisons, 'diagnostic_only': diagnose, 'hardware_qualified': False, 'runtime_yaml': False,
                'within_ten_percent': all(r['throughput_ratio'] >= .9 for r in comparisons)}, sort_keys=True))
        except Exception:
            print(json.dumps({'partial_samples': samples}), file=sys.stderr)
            raise
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
            for name in ('c6', 'p6', 'c4', 'p4'):
                ref.command('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    diagnostic = 'inet' if sys.argv[4:] == ['--diagnose-inet'] else sys.argv[4:] == ['--diagnose']
    main(Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]), diagnostic)
