#!/usr/bin/env python3
"""Exercise generated BIND/Unbound policy with synthetic writers and journals."""

import base64
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import authoritative, config, dns_runtime, firewall, service_plane, service_runtime
from test_authoritative import declaration
from phase_b_native import run, ns


def main():
    assert os.geteuid() == 0 and Path('/run/.containerenv').exists()
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    value = declaration()
    value['networks']['home']['dhcp4'] = {'enabled': False}
    value['services']['ntp'] = {'enabled': False}
    value['hardware']['interfaces']['guest'] = {'name': 'guest', 'match': {'mac': '02:00:00:00:30:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.30.0/24', 'dns': False}
    value['translation'] = {'nat46': {'enabled': True, 'mappings': {
        'service-'+str(n): {'ipv4': '10.255.200.'+str(n+2), 'ipv6': 'fd42:1234:5678:10::'+str(n+30)}
        for n in range(6)}}}
    dns64_enabled = '--nat64' in sys.argv
    ipv6_upstream = '--ipv6-upstream' in sys.argv
    assert not ipv6_upstream or dns64_enabled
    if dns64_enabled:
        value['translation']['nat64'] = {'enabled': True}
        value['services']['dns']['upstreams'] = ['198.51.100.20']
        value['services']['dns']['authoritative']['zones']['example.test']['records'].update({
            'outside': {'CNAME': 'only4.example.net.'}})
        if ipv6_upstream:
            value['uplink']['ipv4'] = 'disabled'
            value['uplink']['ipv6'] = {'address': '2001:db8:feed::1/64', 'gateway': '2001:db8:feed::20'}
            value['services']['dns']['upstreams'] = ['2001:db8:feed::20']
    records = value['services']['dns']['authoritative']['zones']['example.test']['records']
    records.update({'service-'+str(n): {'A': {'alias': 'service-'+str(n)}, 'AAAA': {'alias': 'service-'+str(n)}}
                    for n in range(6)})
    value = config.normalize(value)
    # Exercise the DNS output while translation's separate packet runtime is
    # still gated. No translator is started or represented as qualified here.
    files = {**authoritative.render(value), **service_plane.render(value),
             'etc/nftables.conf': firewall.render(value)}
    processes, namespaces = [], []
    started = False
    with tempfile.TemporaryDirectory(prefix='lanrith-authoritative.') as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        for name, text in files.items():
            path = Path('/')/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        Path('/run/lanrith-dns').mkdir(mode=0o755)
        credentials = work/'credentials'
        credentials.mkdir(mode=0o700)
        for index, name in enumerate(('first', 'second')):
            secret = base64.b64encode(('synthetic-DNS-test-key-'+str(index)*16).encode()).decode()
            path = credentials/(name+'_tsig')
            path.write_text(secret)
            path.chmod(0o600)
            (work/(name+'.key')).write_text(f'key "{name}-key" {{ algorithm hmac-sha256; secret "{secret}"; }};')
        manifest = json.loads(files['usr/share/lanrith/authoritative.json'])
        dns_runtime.prepare(manifest, credentials, Path('/run/lanrith-dns'))
        if dns64_enabled:
            # Dynamic DNS writers can supply this value even though owner
            # seed declarations reject unspecified addresses.
            with Path('/var/cache/bind/db.example.test').open('a') as stream:
                stream.write('zero IN A 0.0.0.0\n')
        run('named-checkconf', '-z', '/etc/bind/named.conf')
        for zone in ('home.arpa', 'example.test'):
            run('named-checkzone', zone, '/usr/share/lanrith/zones/db.'+zone)
        run('unbound-checkconf', '/etc/unbound/unbound.conf.d/lanrith.conf')
        if dns64_enabled:
            run('unbound-checkconf', '/etc/unbound/unbound-private.conf')
        plane = service_plane.topology(value)
        try:
            for name, gateway, client in (('lan', '192.168.10.1/24', '192.168.10.20/24'),
                                          ('guest', '172.20.30.1/24', '172.20.30.20/24'),
                                          ('wan', '198.51.100.1/24', '198.51.100.20/24')):
                namespace = name+'-test'
                run('ip', 'netns', 'add', namespace)
                namespaces.append(namespace)
                run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', namespace)
                run('ip', 'addr', 'add', gateway, 'dev', name)
                run('ip', 'link', 'set', name, 'up')
                ns(namespace, 'ip', 'addr', 'add', client, 'dev', 'eth0')
                ns(namespace, 'ip', 'link', 'set', 'eth0', 'up')
                ns(namespace, 'ip', 'link', 'set', 'lo', 'up')
                ns(namespace, 'ip', 'route', 'add', 'default', 'via', gateway.split('/')[0])
            for address in ('192.168.10.21/24', '192.168.10.22/24'):
                ns('lan-test', 'ip', 'addr', 'add', address, 'dev', 'eth0')
            run('ip', '-6', 'addr', 'add', 'fd42:1234:5678:10::1/64', 'dev', 'lan', 'nodad')
            ns('lan-test', 'ip', '-6', 'addr', 'add', 'fd42:1234:5678:10::20/64', 'dev', 'eth0', 'nodad')
            ns('lan-test', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd42:1234:5678:10::1')
            if ipv6_upstream:
                run('ip', '-6', 'addr', 'add', '2001:db8:feed::1/64', 'dev', 'wan', 'nodad')
                ns('wan-test', 'ip', '-6', 'addr', 'add', '2001:db8:feed::20/64', 'dev', 'eth0', 'nodad')
                ns('wan-test', 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:feed::1')
            run('nft', '-f', '/etc/nftables.conf')
            service_runtime.start(plane)
            started = True

            def daemon(*args):
                log = work/(args[0]+'.log')
                with log.open('w') as stream:
                    child = subprocess.Popen(['nsenter', '--net=/run/netns/'+plane['namespace'], '--', *args],
                                             stdout=stream, stderr=stream)
                processes.append(child)
                time.sleep(.5)
                assert child.poll() is None, log.read_text()[-3000:]
                return child

            named = daemon('named', '-g', '-n', '1', '-u', 'bind', '-c', '/etc/bind/named.conf')
            if dns64_enabled:
                upstream = work/'upstream'
                upstream.mkdir()
                bind = pwd.getpwnam('bind')
                os.chown(upstream, bind.pw_uid, bind.pw_gid)
                (upstream/'db.example.net').write_text(
                    '$TTL 60\n@ IN SOA ns.example.net. hostmaster.example.net. (1 60 60 60 60)\n'
                    '@ IN NS ns.example.net.\nns IN A 198.51.100.20\n'
                    'only4 IN A 93.184.216.34\nnative IN AAAA 2001:4860::1\n'
                    'zero IN A 0.0.0.0\nrebind IN A 192.168.1.4\n')
                (upstream/'named.conf').write_text(
                    f'options {{ directory "{upstream}"; listen-on {{ 198.51.100.20; }}; '
                    f'listen-on-v6 {{ {"2001:db8:feed::20" if ipv6_upstream else "none"}; }}; '
                    f'pid-file "{upstream}/named.pid"; session-keyfile "{upstream}/session.key"; '
                    'recursion no; dnssec-validation no; allow-query { any; }; }; controls {};\n'
                    'zone "example.net" { type primary; file "db.example.net"; };\n')
                stream = (work/'upstream.log').open('w')
                processes.append(subprocess.Popen(['nsenter', '--net=/run/netns/wan-test', '--', 'named',
                    '-g', '-n', '1', '-u', 'bind', '-c', str(upstream/'named.conf')], stdout=stream, stderr=stream))
                stream.close()
                daemon('setpriv', '--reuid=unbound', '--regid=unbound', '--clear-groups',
                       'unbound', '-d', '-p', '-c', '/etc/unbound/unbound-private.conf')
            daemon('unbound', '-d', '-p', '-c', '/etc/unbound/unbound.conf.d/lanrith.conf')
            authority, resolver = plane['endpoints']['authoritative'], plane['endpoints']['dns']
            for target in authority+resolver:
                for n in range(6):
                    for kind, expected in (('A', '10.255.200.'+str(n+2)),
                                           ('AAAA', 'fd42:1234:5678:10::'+str(n+30))):
                        answer = ns('lan-test', 'dig', '+time=1', '+tries=1', '+short', '@'+target,
                                    f'service-{n}.example.test', kind).stdout.strip()
                        assert answer == expected, (target, kind, answer)
            if dns64_enabled:
                for target in resolver:
                    for name, expected in (
                            ('seeded.example.test', 'fd42:1234:5678:fd65::c000:214'),
                            ('only4.example.net', '64:ff9b::5db8:d822'),
                            ('outside.example.test', '64:ff9b::5db8:d822'),
                            ('native.example.net', '2001:4860::1')):
                        answer = ns('lan-test', 'dig', '+time=3', '+tries=1', '+short',
                                    '@'+target, name, 'AAAA').stdout.strip().splitlines()
                        assert expected in answer, (target, name, answer)
                    for name in ('zero.example.net', 'zero.example.test'):
                        for kind in ('A', 'AAAA'):
                            answer = ns('lan-test', 'dig', '+time=3', '+tries=1', '@'+target, name, kind).stdout
                            # DNS64's A subquery can turn the blocked zero
                            # answer into NODATA for AAAA rather than NXDOMAIN.
                            assert ('status: NXDOMAIN' in answer or
                                    (kind == 'AAAA' and 'status: NOERROR' in answer)), (name, kind, answer)
                            assert 'ANSWER: 0' in answer, (name, kind, answer)
                    answer = ns('lan-test', 'dig', '+time=3', '+tries=1', '+short',
                                '@'+target, 'rebind.example.net', 'AAAA').stdout.strip()
                    assert not answer, ('Private address leaked through public DNS64', answer)
                assert ns('lan-test', 'dig', '+time=1', '+tries=1', '+short',
                          '@'+resolver[0], 'only4.example.net', 'A').stdout.strip() == '93.184.216.34'
                print('DNS64 selected public and private prefixes, preserved native AAAA and CNAME scope, '
                      'suppressed zero addresses, and filtered public rebinding answers.')
            for namespace in ('guest-test', 'wan-test'):
                for target in (authority[0], resolver[0]):
                    denied = subprocess.run(['nsenter', '--net=/run/netns/'+namespace, '--', 'dig',
                                             '+time=1', '+tries=1', '@'+target, 'seeded.example.test'],
                                            capture_output=True, timeout=5)
                    assert denied.returncode != 0, 'Disabled network reached DNS.'

            def update(source, key, label, allowed, zone='example.test', *, tcp=True):
                request = (f'local {source}\nserver {authority[0]}\nzone {zone}\n'
                           f'update add {label}.{zone}. 300 A 192.0.2.99\nsend\n')
                argv = ['nsenter', '--net=/run/netns/lan-test', '--', 'nsupdate', '-t', '2']
                if tcp:
                    argv.append('-v')
                if key:
                    argv += ['-k', str(work/(key+'.key'))]
                result = subprocess.run(argv, input=request, text=True, capture_output=True, timeout=5)
                assert (result.returncode == 0) == allowed, (source, key, result.stderr)

            update('192.168.10.20', 'first', 'dynamic-first', True)
            update('192.168.10.21', 'second', 'dynamic-second', True)
            update('192.168.10.20', 'first', 'dynamic-udp', True, tcp=False)
            update('192.168.10.20', 'second', 'wrong-key', False)
            update('192.168.10.21', 'first', 'wrong-key', False)
            update('192.168.10.22', 'first', 'wrong-source', False)
            update('192.168.10.20', None, 'unsigned', False)
            update('192.168.10.20', None, 'unsigned-udp', False, tcp=False)
            update('192.168.10.20', 'first', 'wrong-zone', False, 'home.arpa')
            for source, key, allowed in (('192.168.10.20', 'first', True),
                                         ('192.168.10.21', 'second', False),
                                         ('192.168.10.21', 'first', False)):
                result = ns('lan-test', 'dig', '+time=1', '+tries=1', '-b', source, '-k',
                            str(work/(key+'.key')), '@'+authority[0], 'example.test', 'AXFR').stdout
                assert ('dynamic-first.example.test.' in result) == allowed, result
            # Kill rather than graceful shutdown: replay must use the durable
            # journal, and re-seeding must not replace any persistent contents.
            journal = Path('/var/cache/bind/db.example.test.jnl')
            assert journal.exists()
            named.kill()
            named.wait(timeout=5)
            processes.remove(named)
            previous = {p: p.read_bytes() for p in (journal, journal.with_suffix(''))}
            dns_runtime.prepare(manifest, credentials, Path('/run/lanrith-dns'))
            assert all(p.read_bytes() == data for p, data in previous.items())
            daemon('named', '-g', '-n', '1', '-u', 'bind', '-c', '/etc/bind/named.conf')
            for label in ('dynamic-first', 'dynamic-second', 'dynamic-udp'):
                answer = ns('lan-test', 'dig', '+time=1', '+tries=1', '+short',
                            '@'+authority[0], label+'.example.test', 'A').stdout.strip()
                assert answer == '192.0.2.99', answer
            print('BIND and Unbound served all six A/AAAA aliases over IPv4/IPv6; source-and-key '
                  'updates and the single AXFR writer passed; wrong sources, keys, unsigned updates, '
                  'wrong zones and disabled networks were denied; dynamic records survived journal replay.')
        except BaseException:
            for log in work.glob('*.log'):
                print(log.name, log.read_text()[-5000:])
            raise
        finally:
            for child in processes:
                child.terminate()
                child.wait(timeout=5)
            if started:
                service_runtime.stop(plane)
            for name in reversed(namespaces):
                run('ip', 'netns', 'del', name)


if __name__ == '__main__':
    main()
