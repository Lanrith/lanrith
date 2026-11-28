#!/usr/bin/python3
"""Exercise host resolution, private DNS availability and TLS in a disposable offline systemd guest."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, service_runtime
from test_authoritative import declaration


def run(*args, check=True):
    result = subprocess.run(args, timeout=45, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.stdout[-2000:]} {result.stderr[-2000:]}')
    return result


def write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def network(name, gateway, peer):
    run('ip', 'netns', 'add', name)
    run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
    run('ip', 'address', 'add', gateway+'/24', 'dev', name)
    run('ip', 'link', 'set', name, 'up')
    for args in (('link', 'set', 'lo', 'up'), ('address', 'add', peer+'/24', 'dev', 'eth0'),
                 ('link', 'set', 'eth0', 'up'), ('route', 'add', 'default', 'via', gateway)):
        run('ip', '-n', name, *args)


def certificate(work):
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=fixture CA',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', work/'ca.key', '-out', work/'ca.crt')
    run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=upstream.example',
        '-keyout', work/'server.key', '-out', work/'server.req')
    write(work/'extensions', 'subjectAltName=DNS:upstream.example\nextendedKeyUsage=serverAuth\n')
    run('openssl', 'x509', '-req', '-in', work/'server.req', '-CA', work/'ca.crt', '-CAkey', work/'ca.key',
        '-CAcreateserial', '-days', '2', '-extfile', work/'extensions', '-out', work/'server.crt')


def upstream(work, stack, tls, *, extra_zones=''):
    label = 'tls' if tls else 'plain'
    port = 853 if tls else 53
    path = work/(label+'.conf')
    write(path, f'server:\n  interface: 198.51.100.20@{port}\n  chroot: ""\n  username: ""\n'
          '  use-syslog: no\n  log-queries: yes\n  access-control: 0.0.0.0/0 allow\n'
          '  local-zone: "public.example.net." redirect\n'
          '  local-data: "public.example.net. 1 IN A 93.184.216.34"\n'
          +extra_zones+(f'  tls-port: 853\n  tls-service-key: "{work}/server.key"\n'
            f'  tls-service-pem: "{work}/server.crt"\n' if tls else ''))
    log = stack.enter_context((work/(label+'.log')).open('w'))
    child = subprocess.Popen(['ip', 'netns', 'exec', 'wan', 'unbound', '-d', '-p', '-c', str(path)],
                             stdout=log, stderr=log)
    stack.callback(child.wait, timeout=5)
    stack.callback(child.terminate)


def qualify(platform):
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert run('systemd-detect-virt', '--vm').stdout.strip()
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    assert not Path('/run/netns/lanrith-services').exists()
    if platform:
        # The VM provides its native tools and the signed platform as a separate read-only mount.
        for name in ('usr/sbin/unbound', 'usr/sbin/unbound-checkconf', 'usr/lib/systemd/system/unbound.service',
                     'usr/libexec/unbound-helper'):
            shutil.copyfile(platform/name, '/'+name)
        shutil.copytree(platform/'etc/unbound/unbound.conf.d', '/etc/unbound/unbound.conf.d', dirs_exist_ok=True)
    print(run('unbound', '-V').stdout.splitlines()[0], flush=True)
    value = declaration()
    value['translation'] = {'nat64': {'enabled': True}}
    dns = value['services']['dns']
    del dns['authoritative']['writers']
    zone = dns['authoritative']['zones']['example.test']
    zone['persistent'] = False
    zone['records']['restored'] = {'A': '192.0.2.44'}
    dns['authoritative']['zones']['7.27.172.in-addr.arpa'] = {'records': {}}
    dns['private_dns64_startup'] = 'independent'
    peer = {'address': '198.51.100.20', 'authentication_name': 'upstream.example'}
    dns['tls_forwarding'] = {'trust': 'system', 'upstreams': [peer]}
    value['hardware']['interfaces']['guest'] = {'name': 'guest', 'match': {'mac': '02:00:00:00:30:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.30.0/24', 'dns': False, 'ntp': False}
    files = config.render(value)
    for name, content in files.items():
        if (name.startswith('etc/unbound/') or name.startswith('etc/systemd/system/unbound.service.d/') or
                name.startswith('usr/share/lanrith/zones/') or name in (
                         'etc/bind/named.conf', 'etc/systemd/system/named.service.d/61-lanrith-dns64.conf',
                         'etc/nftables.conf', 'etc/lanrith/services.nft', 'etc/lanrith/chrony-resolv.conf',
                         'usr/lib/systemd/system/lanrith-dns64-private.service',
                         'usr/lib/systemd/system/lanrith-dns64-reverse.service')):
            write('/'+name, content)
    resolver = Path('/etc/resolv.conf')
    resolver.unlink(missing_ok=True)
    write(resolver, files['etc/resolv.conf'])
    for name in ('etc/unbound/unbound.conf.d/99-lanrith-runtime.conf',
                 'etc/systemd/system/unbound.service.d/30-lanrith-hardening.conf'):
        shutil.copyfile(ROOT/'mkosi/base/mkosi.extra'/name, '/'+name)
    work = Path('/run/unbound-fixture')
    work.mkdir()
    # Private zone failures use short retry intervals in the isolated network.
    write('/etc/unbound/unbound.conf.d/98-fixture.conf',
          'server:\n  domain-insecure: "public.example.net."\n  domain-insecure: "wkp.example.net."\n'
          '  domain-insecure: "ipv4only.arpa."\n  infra-cache-min-rtt: 50\n'
          '  infra-cache-max-rtt: 500\n  outbound-msg-retry: 1\n  infra-host-ttl: 2\n')
    units = Path('/etc/systemd/system')
    for name in ('lanrith-services', 'nftables'):
        write(units/(name+'.service'), '[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n')
    # Simulate the private authority preparation boundary by returning failure before its native start.
    write(units/'named.service', '[Service]\nType=simple\nNetworkNamespacePath=/run/netns/lanrith-services\n'
          'ExecStartPre=/usr/bin/test -f /run/unbound-fixture/ready\n'
          'ExecStart=/usr/sbin/named -g -n 1 -u bind -c /etc/bind/named.conf\n')
    Path('/run/named').mkdir(exist_ok=True)
    shutil.chown('/run/named', 'bind', 'bind')
    plane = json.loads(files['usr/share/lanrith/service-plane.json'])
    network('lan', '192.168.10.1', '192.168.10.20')
    network('guest', '172.20.30.1', '172.20.30.20')
    network('wan', '198.51.100.1', '198.51.100.20')
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1')
    run('nft', '-f', '/etc/nftables.conf')
    service_runtime.start(plane)
    certificate(work)
    ca = Path('/etc/ssl/certs/ca-certificates.crt')
    distro_ca = ca.read_bytes()
    ca.write_bytes(distro_ca+(work/'ca.crt').read_bytes())
    with ExitStack() as stack:
        upstream(work, stack, tls=False)
        upstream(work, stack, tls=True, extra_zones=(
            '  local-zone: "wkp.example.net." static\n'
            '  local-data: "global.wkp.example.net. 60 IN A 192.0.0.9"\n'
            '  local-data: "reserved.wkp.example.net. 60 IN A 250.1.2.3"\n'
            '  local-data: "literal.wkp.example.net. 60 IN AAAA 64:ff9b::fa01:203"\n'
            '  local-zone: "ipv4only.arpa." static\n'
            '  local-data: "ipv4only.arpa. 60 IN A 192.0.0.170"\n'
            '  local-data: "ipv4only.arpa. 60 IN A 192.0.0.171"\n'))
        run('systemctl', 'daemon-reload')
        assert run('unbound-checkconf', '-o', 'control-enable').stdout.strip() == 'no'
        run('systemctl', 'start', 'unbound')
        assert run('systemctl', 'is-failed', 'named.service', check=False).stdout.strip() == 'failed'
        target = plane['endpoints']['dns'][0]
        def query(label, *, namespace=None, tcp=False, check=True):
            prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
            return run(*prefix, 'dig', '+time=8', '+tries=1', '+tcp' if tcp else '+notcp', '@'+target,
                       label, 'A', check=check).stdout

        assert '93.184.216.34' in run('getent', 'ahostsv4', 'host.public.example.net').stdout
        for proto in (False, True):
            assert '93.184.216.34' in query(f'lan-{int(proto)}.public.example.net', namespace='lan', tcp=proto)
        # Verify that the TLS peer returns each original record, including
        # the records whose answers the public resolver suppresses.
        for label, kind, record in [('global.wkp.example.net', 'A', '192.0.0.9'),
                                    ('reserved.wkp.example.net', 'A', '250.1.2.3'),
                                    ('literal.wkp.example.net', 'AAAA', '64:ff9b::fa01:203')]:
            direct = run('ip', 'netns', 'exec', 'wan', 'dig', '+tls', '+short', '+time=3', '+tries=1',
                         '@198.51.100.20', '-p', '853', label, kind).stdout.split()
            assert direct == [record], (label, direct)
        for label, expected in [('global.wkp.example.net', {'64:ff9b::c000:9'}),
                                ('reserved.wkp.example.net', set()), ('literal.wkp.example.net', set()),
                                ('ipv4only.arpa', {'64:ff9b::c000:aa', '64:ff9b::c000:ab'})]:
            reply = run('ip', 'netns', 'exec', 'lan', 'dig', '+noall', '+comments', '+answer', '+time=8',
                        '+tries=1', '@'+target, label, 'AAAA').stdout
            permitted_rcodes = ('NOERROR',) if expected else ('NOERROR', 'SERVFAIL')
            assert any(f'status: {code},' in reply for code in permitted_rcodes), (label, reply)
            answers = {fields[-1] for row in reply.splitlines() if (fields := row.split())[3:4] == ['AAAA']}
            assert answers == expected, (label, reply)
        print('Public Unbound DNS64 global exception, reserved A/AAAA filtering and RFC 7050 discovery passed.', flush=True)
        for namespace in ('guest', 'wan'):
            result = run('ip', 'netns', 'exec', namespace, 'dig', '+time=1', '+tries=1', '@'+target,
                         'denied.public.example.net', 'A', check=False)
            assert result.returncode == 9, result.stdout
        assert not Path('/run/unbound.ctl').exists()
        for name in ('absent.example.test', '40.7.27.172.in-addr.arpa'):
            assert 'status: SERVFAIL,' in query(name)
        assert 'host.public.example.net.' in (work/'tls.log').read_text()
        for log in ('plain.log', 'tls.log'):
            recorded = (work/log).read_text()
            assert 'example.test.' not in recorded and '7.27.172.in-addr.arpa.' not in recorded
        (work/'ready').touch()
        run('systemctl', 'start', 'named')
        for _ in range(12):
            restored = query('restored.example.test')
            if '192.0.2.44' in restored:
                break
            time.sleep(1)
        else:
            raise AssertionError((restored, run('journalctl', '-b', '-u', 'named', '-u', 'lanrith-dns64-private',
                                                '-u', 'unbound', '-n', '60', '-o', 'cat').stdout))
        run('systemctl', 'reload', 'unbound')
        for index in range(6):
            reloaded = query(f'reloaded-{index}.public.example.net')
            if '93.184.216.34' in reloaded:
                break
            time.sleep(1)
        else:
            raise AssertionError((reloaded, run('journalctl', '-b', '-u', 'unbound', '-n', '60', '-o', 'cat').stdout,
                                  (work/'tls.log').read_text()[-2000:]))
        run('systemctl', 'restart', 'unbound')
        assert not Path('/run/unbound.ctl').exists()
        run('ip', 'netns', 'exec', plane['namespace'], 'unshare', '--mount', '--propagation', 'private',
            '/bin/sh', '-ec', 'mount --bind /etc/lanrith/chrony-resolv.conf /etc/resolv.conf\n'
            'exec setpriv --reuid=_chrony --regid=_chrony --clear-groups getent ahostsv4 chrony.public.example.net')
        print('passed host NSS, LAN UDP/TCP, guest and WAN denial, chrony, control, private outage and recovery', flush=True)
        for name in ('wrong-name', 'unknown-issuer'):
            peer['authentication_name'] = 'other.example' if name == 'wrong-name' else 'upstream.example'
            if name == 'unknown-issuer':
                ca.write_bytes(distro_ca)
            path = 'etc/unbound/unbound.conf.d/lanrith.conf'
            write('/'+path, config.render(value)[path])
            run('systemctl', 'restart', 'unbound')
            assert 'status: SERVFAIL,' in query(name+'.public.example.net')
        assert 'public.example.net.' not in (work/'plain.log').read_text()
        print('passed matching TLS identity, wrong name, untrusted issuer, zero plaintext queries', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', type=Path, help='read-only subject root in the disposable VM')
    args = parser.parse_args()
    qualify(args.platform)
