#!/usr/bin/env python3
"""Qualify scoped host metrics in an offline disposable container namespace."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, metrics, router_metrics_runtime, service_runtime
from phase_b_native import run, ns
from test_intent import minimal


HTTP = '''
import json,socket,sys,os,pwd
address,source,request,user,port=sys.argv[1:]
if user:
 account=pwd.getpwnam(user);os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(3)
try:
 if source:s.bind((source,0))
 s.connect((address,int(port)));s.sendall(request.encode());s.shutdown(socket.SHUT_WR)
 data=b''
 while part:=s.recv(32768):
  data+=part
  assert len(data)<2*1024*1024
 print(json.dumps({'ok':data.startswith(b'HTTP/1.0 200') or data.startswith(b'HTTP/1.1 200'),
  'host_network':b'node_network_receive_bytes_total{device="hostproof0"}' in data,
  'router_health':b'lanrith_router_nftables_loaded 1' in data and b'lanrith_router_interface_present{interface="lan"} 1' in data,
  'bad_request':data.startswith(b'HTTP/1.0 400')}))
except OSError as error:
 print(type(error).__name__);sys.exit(10)
finally:s.close()
'''


def probe(namespace, target, allowed, source='', request='GET /metrics HTTP/1.0\r\n\r\n', bad=False, user='', port=9100):
    result = subprocess.run(['nsenter', '--net=/run/netns/'+namespace, '--', 'python3', '-c', HTTP,
                             target, source, request, user, str(port)], text=True, capture_output=True, timeout=8)
    if not allowed:
        assert result.returncode == 10, 'An undeclared collector reached the metrics listener.'
        return
    assert result.returncode == 0, 'Admitted metrics request failed: '+target+' '+source+' '+result.stdout[-1024:]+result.stderr[-1024:]
    data = json.loads(result.stdout)
    assert data['bad_request'] if bad else data['ok'] and data['host_network'] and data['router_health'], \
        'Proxy accepted a different request or exporter reported namespace network statistics.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exporter', type=Path, default=Path('/usr/bin/prometheus-node-exporter'))
    parser.add_argument('--exporter-sha256')
    parser.add_argument('--with-core-services', action='store_true')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and {a['ifname'] for a in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}, \
        'Refusing an existing network topology.'
    binary_sha = hashlib.sha256(args.exporter.read_bytes()).hexdigest()
    assert args.exporter_sha256 is None or args.exporter_sha256 == binary_sha, 'Reviewed exporter digest differs.'
    assert args.exporter == Path('/usr/bin/prometheus-node-exporter') or args.exporter_sha256 == binary_sha, \
        'An external fixture binary requires its reviewed digest.'
    value = minimal()
    value['uplink'] = {'interface': 'wan', 'ipv4': {'address': '198.51.100.1/24', 'gateway': '198.51.100.2'},
                       'ipv6': 'disabled'}
    value['services'] = {'dns': {'enabled': args.with_core_services},
                         'ntp': {'enabled': args.with_core_services}, 'dhcp4': {'enabled': False}}
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    value['hardware']['interfaces']['guest'] = {'match': {'mac': '02:00:00:00:02:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.0.0/24',
                                 'ipv6': {'subnet_id': 32, 'ra': False, 'gua': False}}
    value['routing'] = {'static_routes': [{'to': 'fd42:1234:5678:ffff::/64', 'network': 'home', 'on_link': True}]}
    value['observability'] = {'metrics': {'enabled': True, 'clients': [
        {'network': 'home', 'addresses': ['192.168.10.2/32', 'fd42:1234:5678:10::2/128']},
        {'addresses': 'fd42:1234:5678:ffff::56/128'}]}}
    value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any', 'authorization': 'owner'}]}
    value = config.normalize(value)
    files = config.render(value)
    settings = metrics.manifest(value)
    plane = json.loads(files['usr/share/lanrith/service-plane.json'])
    processes = []
    with tempfile.TemporaryDirectory(prefix='metrics-native.') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        for name, content in files.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        accounts = root/'accounts.conf'
        accounts.write_text('u prometheus - "Fixture exporter" /\nu lanrith-metrics - "Metrics proxy" /\n')
        run('systemd-sysusers', str(accounts))
        run('/usr/lib/systemd/systemd-sysctl', str(root/'etc/sysctl.d/90-lanrith-routing.conf'))
        if args.exporter == Path('/usr/bin/prometheus-node-exporter'):
            run('systemd-analyze', 'verify', '--man=no', str(root/'usr/lib/systemd/system/lanrith-metrics.service'),
                'prometheus-node-exporter.service', env={**os.environ, 'SYSTEMD_UNIT_PATH':
                str(root/'etc/systemd/system')+':'+str(root/'usr/lib/systemd/system')+
                ':/etc/systemd/system:/usr/lib/systemd/system'})
        Path('/etc/lanrith').mkdir(exist_ok=True)
        Path('/etc/lanrith/services.nft').write_text(files['etc/lanrith/services.nft'])
        for name, addresses in (
                ('lan', ['192.168.10.1/24', 'fd42:1234:5678:10::1/64']),
                ('guest', ['172.20.0.1/24', 'fd42:1234:5678:20::1/64']),
                ('wan', ['198.51.100.1/24'])):
            run('ip', 'netns', 'add', name+'-test')
            run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name+'-test')
            run('ip', 'link', 'set', name, 'up')
            ns(name+'-test', 'ip', 'link', 'set', 'lo', 'up')
            ns(name+'-test', 'ip', 'link', 'set', 'eth0', 'up')
            for address in addresses:
                from ipaddress import ip_interface
                local = ip_interface(address)
                peer = local.ip+1
                flags = ['nodad'] if local.version == 6 else []
                run('ip', 'address', 'add', address, 'dev', name, *flags)
                ns(name+'-test', 'ip', 'address', 'add', str(peer)+'/'+str(local.network.prefixlen), 'dev', 'eth0', *flags)
                ns(name+'-test', 'ip', '-'+str(local.version), 'route', 'add', 'default', 'via', str(local.ip))
        run('ip', 'link', 'add', 'hostproof0', 'type', 'dummy')
        run('ip', 'link', 'set', 'hostproof0', 'up')
        ns('lan-test', 'ip', 'address', 'add', '192.168.10.3/24', 'dev', 'eth0')
        for address in ('fd42:1234:5678:ffff::56/128', 'fd42:1234:5678:ffff::57/128'):
            ns('lan-test', 'ip', '-6', 'address', 'add', address, 'dev', 'eth0', 'nodad')
        run('ip', '-6', 'route', 'add', 'fd42:1234:5678:ffff::/64', 'dev', 'lan')
        run('nft', '-f', str(root/'etc/nftables.conf'))
        started = False
        try:
            service_runtime.start(plane)
            started = True
            # The root collector observes the host while the public proxy joins
            # the service namespace. Its textfile directory is not exporter-writable.
            output = router_metrics_runtime.OUTPUT
            output.parent.mkdir(parents=True, exist_ok=True)
            output.parent.chmod(0o755)
            os.chown(output.parent, 0, 0)
            router_metrics_runtime.publish(router_metrics_runtime.collect(metrics.router_manifest(value)))
            assert not subprocess.run(['setpriv', '--reuid=prometheus', '--regid=prometheus', '--clear-groups',
                'test', '-w', str(output.parent)], check=False).returncode == 0, 'Exporter can replace root health data.'
            exporter = subprocess.Popen([str(args.exporter), *metrics.exporter_arguments(value)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                user='prometheus', group='prometheus', extra_groups=(), env={**os.environ, 'GOMAXPROCS': '2'})
            processes.append(exporter)
            program = ('import asyncio,json,os,pwd; from lanrith.metrics_runtime import serve; '
                       'account=pwd.getpwnam("lanrith-metrics"); os.setgroups([]); '
                       'os.setgid(account.pw_gid); os.setuid(account.pw_uid); '
                       'asyncio.run(serve(json.loads(os.environ["FIXTURE_METRICS"])))')
            proxy = subprocess.Popen(['nsenter', '--net=/run/netns/'+plane['namespace'], '--', 'python3', '-c', program],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env={**os.environ, 'FIXTURE_METRICS': json.dumps(settings), 'PYTHONPATH': str(Path(__file__).resolve().parents[1])})
            processes.append(proxy)
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                assert proxy.poll() is None and exporter.poll() is None, 'Metrics daemon failed before readiness.'
                listing = ns(plane['namespace'], 'ss', '-lnt').stdout
                if all(('['+a+']' if ':' in a else a)+':9100' in listing for a in settings['listeners']):
                    break
                time.sleep(.05)
            else:
                raise AssertionError('Metrics proxy did not bind its generated listeners.')
            for target in settings['listeners']:
                source = '192.168.10.2' if ':' not in target else 'fd42:1234:5678:10::2'
                probe('lan-test', target, True, source)
                probe('guest-test', target, False)
                probe('wan-test', target, False)
            probe('lan-test', settings['listeners'][0], False, '192.168.10.3')
            probe('lan-test', settings['listeners'][1], True, 'fd42:1234:5678:ffff::56')
            probe('lan-test', settings['listeners'][1], False, 'fd42:1234:5678:ffff::57')
            for request in ('GET /debug/pprof/ HTTP/1.0\r\n\r\n', 'POST /metrics HTTP/1.0\r\n\r\n',
                            'GET /metrics HTTP/1.0\r\nContent-Length: 5\r\n\r\nhello'):
                probe('lan-test', settings['listeners'][0], True, '192.168.10.2', request, bad=True)
            probe('lan-test', settings['backend'], False, port=9101)
            probe(plane['namespace'], settings['backend'], False, user='nobody', source=settings['source'], port=9101)
            for target in settings['listeners']:
                probe(plane['namespace'], target, True)
                for user, feature in (('nobody', None), ('unbound', 'dns'), ('_chrony', 'ntp')):
                    source = next((a for a in plane['endpoints'].get(feature, [])
                                   if (':' in a) == (':' in target)), '')
                    probe(plane['namespace'], target, False, source, user=user)

            saturation = '''
import socket,sys,time
clients=[]
try:
 for _ in range(32):
  stream=socket.create_connection((sys.argv[1],9100),2)
  stream.sendall(b'GET /metrics HTTP/1.0\\r\\n');clients.append(stream)
 extra=socket.create_connection((sys.argv[1],9100),2);extra.settimeout(2)
 try:assert extra.recv(1)==b'','Proxy exceeded its client bound'
 except ConnectionResetError:pass
 extra.close()
finally:
 for stream in clients:stream.close()
'''
            ns('lan-test', 'python3', '-c', saturation, settings['listeners'][0])
            time.sleep(.2)
            probe('lan-test', settings['listeners'][0], True, '192.168.10.2')
            # Wrong physical ingress must not borrow the static-route exception.
            ns('guest-test', 'ip', '-6', 'address', 'add', 'fd42:1234:5678:ffff::56/128', 'dev', 'eth0', 'nodad')
            run('nft', '-f', '-', input='''
table inet metrics_fixture {
 counter spoof_arrived {}
 counter spoof_past_guard {}
 chain before_guard { type filter hook prerouting priority -301; policy accept;
  iifname "guest" ip6 saddr fd42:1234:5678:ffff::56 tcp dport 9100 counter name spoof_arrived
 }
 chain after_guard { type filter hook prerouting priority -299; policy accept;
  iifname "guest" ip6 saddr fd42:1234:5678:ffff::56 tcp dport 9100 counter name spoof_past_guard
 }
}
''')
            probe('guest-test', settings['listeners'][1], False, 'fd42:1234:5678:ffff::56')
            for name, positive in (('spoof_arrived', True), ('spoof_past_guard', False)):
                listing = json.loads(run('nft', '-j', 'list', 'counter', 'inet', 'metrics_fixture', name).stdout)
                packets = [item['counter']['packets'] for item in listing['nftables'] if 'counter' in item]
                assert len(packets) == 1 and (packets[0] > 0) == positive, \
                    'Wrong-ingress packet did not reach the physical guard or escaped its source check.'
            proxy.terminate()
            proxy.communicate(timeout=5)
            processes.remove(proxy)
            probe('lan-test', settings['listeners'][0], False, '192.168.10.2')
        finally:
            for process in processes:
                process.terminate()
                _, error = process.communicate(timeout=5)
                if process.returncode not in (0, -15):
                    print(error.decode()[-1024:], file=sys.stderr)
            if started:
                service_runtime.stop(plane)
    result = {'result': 'pass', 'private_image_qualified': False, 'external_network': False,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'collector_sha256': hashlib.sha256(Path(router_metrics_runtime.__file__).read_bytes()).hexdigest(),
        'exporter_sha256': binary_sha, 'checks': [
            'bounded root health collector reports host interfaces and active firewall through the real exporter',
            'exporter identity cannot write the root-owned health output directory',
            'real unprivileged exporter reports host interfaces rather than the proxy namespace',
            'IPv4 IPv6 and statically attached collectors require their exact network and source scopes',
            'guest WAN neighboring sources wrong ingress and arbitrary backend users are denied despite a wildcard owner rule',
            'unprivileged namespace accounts cannot bypass collector admission through loopback',
            'only bodyless GET /metrics reaches the fixed backend; debug methods and request bodies are refused',
            'partial-header clients are bounded to 32 connections and completed scrapes recover after they close',
            'metrics operates with DNS NTP '+('enabled' if args.with_core_services else 'disabled')+' and identity disabled; stopping its proxy removes the listener']}
    if args.result:
        args.result.write_text(json.dumps(result, sort_keys=True)+'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
