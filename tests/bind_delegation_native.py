#!/usr/bin/python3
"""Resolve DNS-SD through a generated parent and synthetic child in an offline VM."""

from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import authoritative, config, discovery, intent, service_plane
from dns_migration_native import install, run
from test_authoritative import declaration

PARENT = 'devices.example.test'
CHILD = 'home.'+PARENT+'.'


def main():
    assert sys.argv[1:] == ['--isolated-systemd'] and os.geteuid() == 0
    assert run('systemd-detect-virt', '--vm').stdout.strip()
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    assert not Path('/usr/share/lanrith/installed.json').exists()
    value = declaration()
    authority = value['services']['dns']['authoritative']
    del authority['writers'], authority['zones']['example.test']
    diagnostic = '192.168.10.23'
    authority['direct_readers'] = [{'network': 'home', 'addresses': diagnostic}]
    authority['zones'][PARENT] = {'discovery_delegation': {'views': ['home'], 'publish_browse': True}}
    value['hardware']['interfaces']['guest'] = {'name': 'guest', 'match': {'mac': '02:00:00:00:30:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.30.0/24'}
    value['services']['discovery'] = {'enabled': True, 'domain': PARENT, 'networks': ['home', 'guest'],
                                      'views': {'home': 'home', 'other': 'guest'}, 'default_view': 'home',
                                      'alias_prefix': 'lab-'}
    value = config.normalize(value)
    server = intent.service_addresses(value, 'authoritative')
    resolver = intent.service_addresses(value, 'dns')
    proxy = intent.service_addresses(value, 'discovery')
    install(authoritative.render(value))
    library = Path('/usr/lib/lanrith/lanrith')
    library.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__).resolve().parents[1]/'lanrith/dns_runtime.py', library/'dns_runtime.py')
    for unit in ('lanrith-services', 'nftables'):
        install({f'run/systemd/system/{unit}.service':
                 '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n'})
    run('ip', 'netns', 'add', service_plane.NAMESPACE)
    ns = ['ip', 'netns', 'exec', service_plane.NAMESPACE]
    run(*ns, 'ip', 'link', 'set', 'lo', 'up')
    for addr in [*server, *resolver, *proxy, diagnostic]:
        run(*ns, 'ip', 'addr', 'add', addr+('/128' if ':' in addr else '/32'), 'dev', 'lo')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'named')
    pid = run('systemctl', 'show', 'named', '-p', 'MainPID', '--value').stdout.strip()
    opts = run('nsenter', '-t', pid, '-m', 'findmnt', '-n', '-T', '/var/cache/bind', '-o', 'VFS-OPTIONS')
    assert 'ro' in opts.stdout.strip().split(','), opts.stdout
    run('named-checkconf', '-z')
    work = Path('/run/lanrith-delegation-fixture')
    work.mkdir()
    shutil.chown(work, 'bind', 'bind')
    target = 'discovery-proxy.'+PARENT+'.'
    instance = 'printer._ipp._tcp.'+CHILD
    device = 'printer.'+CHILD
    (work/'child.db').write_text(
        f'$ORIGIN {CHILD}\n$TTL 60\n@ IN SOA {target} hostmaster.{CHILD} (1 300 300 300 60)\n'
        f'@ IN NS {target}\n_ipp._tcp IN PTR {instance}\n{instance} IN SRV 0 0 631 {device}\n'
        f'{instance} IN TXT "fixture"\n{device} IN A 192.0.2.45\n')
    (work/'child.conf').write_text(
        f'options {{ directory "{work}"; listen-on {{ {proxy[0]}; }}; listen-on-v6 {{ {proxy[1]}; }}; '
        'pid-file none; recursion no; notify no; dnssec-validation no; }; controls {};\n'
        f'zone "{CHILD}" {{ type primary; file "child.db"; }};\n')
    # The independent resolver knows the parent and learns the child from its referral.
    (work/'independent.conf').write_text(
        f'server:\n  interface: 127.0.0.1@1053\n  outgoing-interface: {diagnostic}\n'
        '  do-ip6: no\n  chroot: ""\n  pidfile: ""\n  use-syslog: no\n  module-config: "iterator"\n'
        f'  local-zone: "home.arpa." nodefault\n  local-zone: "{PARENT}." transparent\n'
        f'stub-zone:\n  name: "{PARENT}."\n  stub-addr: {server[0]}\n')
    managed = service_plane.render(value)['etc/unbound/unbound.conf.d/lanrith.conf']
    (work/'managed.conf').write_text(managed+discovery.resolver_configuration(value))

    def query(target_address, name, kind, *flags, port=53):
        return run(*ns, 'dig', '+time=2', '+tries=1', *flags, '-b', diagnostic if port == 53 else '127.0.0.1',
                   '-p', str(port), '@'+target_address, name, kind, check=False).stdout.strip()

    def wait_server(target_address, name, port=53):
        deadline = time.monotonic()+12
        while ' SOA ' not in ' '.join(query(target_address, name, 'SOA', '+noall', '+answer', port=port).split()):
            assert time.monotonic() < deadline, query(target_address, name, 'SOA', port=port)
            time.sleep(.1)

    with ExitStack() as stack:
        def daemon(*args):
            job = subprocess.Popen([*ns, *args], stdout=sys.stdout, stderr=sys.stderr)
            stack.callback(job.wait, timeout=5)
            stack.callback(job.terminate)

        daemon('named', '-g', '-n', '1', '-u', 'bind', '-c', str(work/'child.conf'))
        wait_server(proxy[0], CHILD)
        assert ' aa;' in query(proxy[0], CHILD, 'SOA', '+norecurse', '+noall', '+comments')
        referral = query(server[0], device, 'A', '+norecurse', '+noall', '+authority')
        assert referral.split()[-2:] == ['NS', target], referral
        for kind, address in zip(('A', 'AAAA'), proxy):
            assert query(server[0], target, kind, '+short') == address
        assert 'status: NXDOMAIN' in query(server[0], 'absent.other.'+PARENT+'.', 'A', '+norecurse')
        daemon('unbound', '-d', '-p', '-c', str(work/'independent.conf'))
        daemon('unbound', '-d', '-p', '-c', str(work/'managed.conf'))
        wait_server('127.0.0.1', PARENT, port=1053)
        wait_server(resolver[0], PARENT)
        for address, port in (('127.0.0.1', 1053), (resolver[0], 53)):
            domains = query(address, 'b._dns-sd._udp.'+PARENT, 'PTR', '+short', port=port).splitlines()
            assert CHILD in domains and (('other.'+PARENT+'.' in domains) == (port == 53)), domains
            assert query(address, 'db._dns-sd._udp.'+PARENT, 'PTR', '+short', port=port) == CHILD
            for name, kind, expected in (('_ipp._tcp.'+CHILD, 'PTR', instance), (instance, 'TXT', '"fixture"'),
                                         (instance, 'SRV', '0 0 631 '+device), (device, 'A', '192.0.2.45')):
                assert query(address, name, kind, '+short', port=port) == expected, (address, name, kind)
    print('Parent referral and glue, scoped DNS-SD and static sandbox passed with independent and managed resolvers.')


if __name__ == '__main__':
    main()
