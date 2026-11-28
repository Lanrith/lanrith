#!/usr/bin/env python3
"""Exercise retained zones and their pre-start DNS migration in a disposable VM."""

import atexit
import base64
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import authoritative, config, intent
from test_authoritative import declaration

PROJECT = Path(__file__).resolve().parents[1]
ZONE = 'example.test'
STATE = Path('/var/cache/bind/db.'+ZONE)
JOURNAL = STATE.with_name(STATE.name+'.jnl')
MIGRATE = 'lanrith-dns-migrate.service'
KEY = Path('/run/dns-fixture.key')


def run(*args, check=True, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=35, **kwargs)


def install(files):
    for name, content in files.items():
        path = Path('/')/name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(content)


def main():
    assert sys.argv[1:] == ['--isolated-systemd'] and os.geteuid() == 0
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    suite = run('python3', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_authoritative.py', check=False)
    assert suite.returncode == 0, suite.stderr
    print(run('named', '-v').stdout.strip(), suite.stderr, flush=True)
    value = declaration()
    zones = value['services']['dns']['authoritative']['zones']
    zones['fresh.test'] = {'persistent': True, 'records': {'@': {'A': '192.0.2.70'}}, 'fixed_records': ['@']}
    zones['hosted.branch.example.test'] = {'records': {'server': {'A': '192.0.2.71'}}}
    zone = zones[ZONE]
    zone['records'].update({'retired': {'A': '192.0.2.8'}, 'host.oldpath': {'A': '192.0.2.80'}})
    del value['services']['dns']['authoritative']['writers']['first']['grants']
    old = config.normalize(value)
    server = intent.service_addresses(old, 'authoritative')[0]
    resolver = intent.service_addresses(old, 'dns')[0]
    clients = ['192.168.10.20', '192.168.10.21']
    namespace = 'lanrith-services'
    run('ip', 'netns', 'add', namespace)
    ns = ['ip', 'netns', 'exec', namespace]
    run(*ns, 'ip', 'link', 'set', 'lo', 'up')
    for address in [*clients, server, resolver]:
        run(*ns, 'ip', 'addr', 'add', address+'/32', 'dev', 'lo')
    bind = pwd.getpwnam('bind')
    STATE.parent.mkdir(exist_ok=True, parents=True)
    os.chown(STATE.parent, bind.pw_uid, bind.pw_gid)
    assert not os.path.lexists(STATE) and not os.path.lexists(JOURNAL)
    install(authoritative.render(old))
    library = Path('/usr/lib/lanrith/lanrith')
    library.mkdir(exist_ok=True, parents=True)
    for name in ('dns_runtime.py', 'dns_migration.py'):
        shutil.copyfile(PROJECT/'lanrith'/name, library/name)
    # Supply the generated named dependency edges with the isolated loopback
    # namespace and a no-op firewall fixture. Packet admission is tested elsewhere.
    for name in ('lanrith-services', 'nftables'):
        install({f'run/systemd/system/{name}.service':
                 '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n'})
    for name, key in (('first', 'synthetic first publisher'), ('second', 'synthetic second publisher')):
        secret = base64.b64encode(key.encode()).decode()
        line = next(l for l in Path('/usr/lib/systemd/system/lanrith-dns-state.service').read_text().splitlines()
                    if l.startswith('LoadCredential='+name+'_tsig:'))
        source = Path(line.split(':', 1)[1])
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(secret)
        source.chmod(0o600)
        if name == 'first':
            KEY.write_text(f'key "first-key" {{ algorithm hmac-sha256; secret "{secret}"; }};')
            KEY.chmod(0o600)
    run('systemctl', 'daemon-reload')

    def systemctl(*args):
        result = run('systemctl', *args, check=False)
        if result.returncode:
            for unit in ('lanrith-dns-state', MIGRATE, 'named'):
                print(run('journalctl', '-u', unit, '-b', '--no-pager', '-n', '15').stdout, flush=True)
            raise AssertionError((args, result.stderr))

    def update(cmds, source=clients[0], *, allowed=True):
        request = '\n'.join([f'local {source}', 'server '+server, 'zone '+ZONE, *cmds, 'send', ''])
        result = run(*ns, 'nsupdate', '-v', '-k', str(KEY), input=request, check=False)
        assert (result.returncode == 0) == allowed, result.stderr
        if not allowed and source == clients[0]:
            assert 'REFUSED' in result.stderr, result.stderr

    def query(name, kind, target=server):
        return run(*ns, 'dig', '+time=2', '+tries=1', '+short', '-b', clients[0],
                   '@'+target, name+'.'+ZONE+'.' if name else ZONE+'.', kind).stdout.strip()

    systemctl('start', 'named')
    assert run(*ns, 'dig', '+short', '-b', clients[0], '@'+server, 'fresh.test.', 'A').stdout.strip() == '192.0.2.70'
    public_pid = run('systemctl', 'show', '-p', 'MainPID', '--value', 'named').stdout.strip()
    status = dict(line.split(':', 1) for line in Path('/proc/'+public_pid+'/status').read_text().splitlines()
                  if ':' in line)
    assert set(map(int, status['Uid'].split())) == {bind.pw_uid}
    assert int(status['CapBnd'], 16) == int(status['CapEff'], 16) == 1 << 10
    assert status['NoNewPrivs'].strip() == '1'
    for path, expected in (('/run/named', 'rw'), (str(STATE), 'rw'),
                           ('/run/lanrith-dns/keys.conf', 'ro'), ('/usr/share/lanrith/zones', 'ro')):
        options = run('nsenter', '-t', public_pid, '-m', 'findmnt', '-n', '-T', path, '-o', 'VFS-OPTIONS')
        assert expected in options.stdout.strip().split(','), (path, options.stdout)
    print('named UID', bind.pw_uid, 'CapBnd', status['CapBnd'].strip(), 'CapEff', status['CapEff'].strip(),
          'NoNewPrivs', status['NoNewPrivs'].strip(), flush=True)
    systemctl('reload', 'named')
    for transport in ('+tcp', '+notcp'):
        assert run(*ns, 'dig', transport, '+short', '-b', clients[0], '@'+server,
                   'seeded.'+ZONE, 'A').stdout.strip() == '192.0.2.20'
    unbound_conf = Path('/run/dns-fixture-unbound.conf')
    unbound_conf.write_text(
        f'server:\n  interface: {resolver}\n  access-control: 192.168.10.0/24 allow\n'
        '  chroot: ""\n  username: ""\n  use-syslog: no\n  pidfile: ""\n'
        '  module-config: "iterator"\n  cache-max-negative-ttl: 3\n'
        f'  local-zone: "{ZONE}." transparent\n  outgoing-interface: {resolver}\n'
        f'stub-zone:\n  name: "{ZONE}."\n  stub-addr: {server}\n')
    resolver_process = subprocess.Popen([*ns, 'unbound', '-d', '-p', '-c', str(unbound_conf)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(resolver_process.terminate)
    limit = time.monotonic()+10
    while run(*ns, 'dig', '+time=1', '+tries=1', '+short', '-b', clients[0],
              '@'+resolver, 'seeded.'+ZONE, 'A', check=False).stdout.strip() != '192.0.2.20':
        assert resolver_process.poll() is None and time.monotonic() < limit
        time.sleep(.1)
    negative = run(*ns, 'dig', '+time=2', '+tries=1', '+noall', '+comments', '-b', clients[0],
                   '@'+resolver, 'service.'+ZONE, 'AAAA')
    assert 'status: NXDOMAIN' in negative.stdout, negative.stdout
    update(['update add publisher.example.test. 60 TXT "retained"',
            'update add alias.example.test. 60 CNAME publisher.example.test.'])
    assert query('alias', 'CNAME') == 'publisher.example.test.'
    update(['update add oldpath.example.test. 60 NS ns1.home.arpa.'])
    assert JOURNAL.is_file()
    print('named cgroup during publication', run('systemctl', 'show', '-p', 'MemoryCurrent', '-p',
                                                'MemoryPeak', 'named').stdout.strip(), flush=True)
    # Simulate an interrupted primary: this backup contains a genuine unflushed
    # journal. Stop the restarting package service before restoring the pair.
    pair = {path: path.read_bytes() for path in (JOURNAL, STATE)}
    assert b'publisher' not in pair[STATE]
    systemctl('stop', 'named', MIGRATE, 'lanrith-dns-state')
    for path, data in pair.items():
        path.write_bytes(data)
        os.chown(path, bind.pw_uid, bind.pw_gid)
        path.chmod(0o640)
    STATE.unlink()
    failed = run('systemctl', 'start', 'named', check=False)
    assert failed.returncode and not STATE.exists() and JOURNAL.read_bytes() == pair[JOURNAL]
    assert 'Incomplete DNS restore for example.test' in run('journalctl', '-u', 'lanrith-dns-state').stdout
    STATE.write_bytes(pair[STATE])
    os.chown(STATE, bind.pw_uid, bind.pw_gid)
    STATE.chmod(0o640)
    run('named-checkzone', '-j', ZONE, str(STATE))
    # A matching address can still be hidden by a delegation in its saved parent.
    zone['fixed_records'] = ['host.oldpath']
    install(authoritative.render(config.normalize(value)))
    systemctl('daemon-reload')
    assert run('systemctl', 'start', 'named', check=False).returncode
    assert 'for oldpath.example.test. NS.' in run('journalctl', '-b', '-u', MIGRATE).stdout
    install(authoritative.render(old))
    systemctl('daemon-reload')
    systemctl('start', 'named')
    update(['update delete oldpath.example.test. NS'])
    systemctl('stop', 'named', MIGRATE, 'lanrith-dns-state')
    # A release adopting a previous seed must verify its current journaled value.
    zone['fixed_records'] = ['SEEDED']
    zone['records']['seeded'] = {'A': '192.0.2.22'}
    install(authoritative.render(config.normalize(value)))
    systemctl('daemon-reload')
    assert run('systemctl', 'start', 'named', check=False).returncode
    assert 'Fixed DNS addresses or delegation conflict' in run('journalctl', '-b', '-u', MIGRATE).stdout
    zone['fixed_records'] += ['service', 'host.lab']
    zone['records']['host.lab'] = {'A': '192.0.2.45'}
    zone['records'].update({'seeded': {'A': '192.0.2.22'}, 'service': {'AAAA': '2001:db8::53'},
                            'alias': {'AAAA': '2001:db8::99'}})
    zone['records']['owned-alias'] = {'CNAME': 'publisher.example.test.'}
    del zone['records']['retired']
    zone['managed_rrsets'] = {'host.lab': {'A': {'previous': []}},
                              'owned-alias': {'CNAME': {'previous': []}},
                              'service': {'AAAA': {'previous': []}},
                              'seeded': {'A': {'previous': ['192.0.2.20']}},
                              'retired': {'A': {'previous': ['192.0.2.8'], 'remove': True}},
                              'alias': {'AAAA': {'previous': []}}}
    files = authoritative.render(config.normalize(value))
    install(files)
    # Run the syntax checker with a disposable key in a temporary copy. It
    # cannot read the real key outside the migration unit's private mount.
    checkconf = Path('/run/dns-fixture-check.conf')
    checkconf.write_text(files['etc/bind/lanrith-migration.conf'].replace('/var/lib/bind/migration.key', str(KEY)))
    checked = run('named-checkconf', str(checkconf), check=False)
    assert checked.returncode == 0, (checked.stdout, checked.stderr)
    run('systemctl', 'daemon-reload')
    failed = run('systemctl', 'start', 'named', check=False)
    assert failed.returncode and run('systemctl', 'is-active', 'named', check=False).returncode
    details = run('journalctl', '-b', '-u', MIGRATE).stdout
    assert 'prerequisite conflict in zone example.test' in details, details
    dumped = run('named-checkzone', '-j', '-D', '-o', '-', ZONE, str(STATE)).stdout
    assert '192.0.2.20' in dumped and '192.0.2.8' in dumped and '2001:db8::53' not in dumped
    del zone['managed_rrsets']['alias']
    del zone['records']['alias']
    install(authoritative.render(config.normalize(value)))
    # Pause the client after the real server acknowledged its atomic write.
    # Killing the whole service here leaves the primary's journal for a retry.
    wrapper = Path('/run/dns-fixture-pause')
    real_client = Path('/run/dns-fixture-nsupdate')
    shutil.copy('/usr/bin/nsupdate', real_client)
    wrapper.write_text(
        '#!/usr/bin/python3\nimport os, pathlib, signal, subprocess, sys, time\n'
        'data = sys.stdin.buffer.read()\n'
        f'rc = subprocess.run([{str(real_client)!r}, *sys.argv[1:]], input=data).returncode\n'
        'if rc == 0 and b"\\nupdate " in data:\n'
        '    os.kill(os.getppid(), signal.SIGSTOP)\n'
        '    pathlib.Path("/var/lib/bind/acknowledged").touch()\n'
        '    time.sleep(30)\nsys.exit(rc)\n')
    wrapper.chmod(0o755)
    dropin = Path('/run/systemd/system')/(MIGRATE+'.d')/'90-fixture.conf'
    dropin.parent.mkdir()
    dropin.write_text(f'[Service]\nBindReadOnlyPaths={wrapper}:/usr/bin/nsupdate\n')
    systemctl('daemon-reload')
    systemctl('start', '--no-block', 'named')
    marker = Path('/run/lanrith-dns-migrate/acknowledged')
    limit = time.monotonic()+25
    while not marker.is_file():
        assert time.monotonic() < limit, run('journalctl', '-u', MIGRATE, '-n', '10').stdout
        time.sleep(.1)
    pid = run('systemctl', 'show', '-p', 'MainPID', '--value', MIGRATE).stdout.strip()
    assert os.readlink(f'/proc/{pid}/ns/net') != os.readlink('/proc/1/ns/net')
    links = json.loads(run('nsenter', '-t', pid, '-n', 'ip', '-j', 'link', 'show').stdout)
    assert [link['ifname'] for link in links] == ['lo']
    status = Path(f'/proc/{pid}/status').read_text()
    assert 'CapEff:\t0000000000000000' in status and f'Uid:\t{bind.pw_uid}\t' in status
    assert run('systemctl', 'is-active', '--quiet', 'named', check=False).returncode != 0
    denied = run('nsenter', '-t', pid, '-n', 'nsupdate', '-v', '-t', '2', '-k',
                 '/run/lanrith-dns-migrate/migration.key', check=False,
                 input='server 127.0.0.1 1053\nzone example.test.\n'
                       'update add ordinary.example.test. 60 TXT "outside-scope"\nsend\n')
    assert denied.returncode != 0 and 'REFUSED' in denied.stderr, denied.stderr
    systemctl('kill', '--signal=SIGKILL', MIGRATE)
    systemctl('stop', MIGRATE, 'named')
    dropin.unlink()
    systemctl('daemon-reload')
    run('named-checkzone', '-j', ZONE, str(STATE))
    systemctl('start', 'named')
    assert not Path('/run/lanrith-dns-migrate/migration.key').exists()
    assert query('service', 'AAAA') == '2001:db8::53'
    limit = time.monotonic()+8
    while query('service', 'AAAA', resolver) != '2001:db8::53':
        assert time.monotonic() < limit
        time.sleep(.2)
    assert query('seeded', 'A') == '192.0.2.22' and not query('retired', 'A')
    assert query('publisher', 'TXT') == '"retained"'
    assert query('alias', 'CNAME') == 'publisher.example.test.'
    update(['update add ordinary.example.test. 60 TXT "ok"'])
    update(['update add service.example.test. 60 AAAA 2001:db8::54'], allowed=False)
    update(['update add service.example.test. 60 CNAME elsewhere.example.test.'], allowed=False)
    assert query('service', 'AAAA') == '2001:db8::53'
    update(['update add owned-alias.example.test. 60 A 192.0.2.66'], allowed=False)
    assert query('owned-alias', 'CNAME') == 'publisher.example.test.'
    for command in ('update delete SeEdEd.example.test.',
                    'update add seeded.example.test. 60 AAAA 2001:db8::45',
                    'update add HOST.LAB.example.test. 60 CNAME other.example.test.',
                    'update add lab.example.test. 60 NS ns1.home.arpa.',
                    'update add lab.example.test. 60 DNAME other.example.test.',
                    'update add example.test. 60 NS other.example.test.',
                    'update add hosted.branch.example.test. 60 NS other.example.test.',
                    'update add branch.example.test. 60 DNAME other.example.test.'):
        update(['update add partial.example.test. 60 TXT "partial"', command], allowed=False)
        assert not query('partial', 'TXT')
    assert query('host.lab', 'A') == '192.0.2.45'
    update(['update add brand-new.example.test. 60 CAA 0 issue "example.net"'])
    assert 'example.net' in query('brand-new', 'CAA')
    update(['update add other.example.test. 60 TXT "no"'], source=resolver, allowed=False)
    update(['update add other.example.test. 60 TXT "no"'], source=clients[1], allowed=False)
    xfr = run(*ns, 'dig', '+time=2', '+tries=1', '-b', clients[0], '-k', str(KEY),
              '@'+server, ZONE, 'AXFR').stdout
    assert 'ordinary.example.test.' in xfr
    update(['update add example.test. 60 A 192.0.2.40'])
    assert query('', 'A') == '192.0.2.40'
    serial = query('', 'SOA').split()[2]
    # Abrupt stop after successful changes exercises real BIND journal replay.
    systemctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'named')
    systemctl('stop', 'named', MIGRATE, 'lanrith-dns-state')
    systemctl('start', 'named')
    assert query('', 'SOA').split()[2] == serial
    assert query('ordinary', 'TXT') == '"ok"' and query('alias', 'CNAME') == 'publisher.example.test.'
    assert query('seeded', 'A') == '192.0.2.22'
    systemctl('stop', 'named', MIGRATE, 'lanrith-dns-state')
    zone['records']['@'] = {'A': '192.0.2.41'}
    zone['fixed_records'].append('@')
    zone['managed_rrsets']['@'] = {'A': {'previous': ['192.0.2.40']}}
    install(authoritative.render(config.normalize(value)))
    systemctl('start', 'named')
    assert query('', 'A') == '192.0.2.41' and query('', 'NS') == 'ns1.home.arpa.'
    update(['update add example.test. 60 A 192.0.2.42'], allowed=False)
    value['services']['dns']['authoritative']['writers']['first']['grants'] = []
    install(authoritative.render(config.normalize(value)))
    systemctl('restart', 'named')
    update(['update add inventory.example.test. 60 TXT "transfer-only"'], allowed=False)
    transfer = run(*ns, 'dig', '+time=2', '+tries=1', '-b', clients[0], '-k', str(KEY),
                   '@'+server, ZONE, 'AXFR').stdout
    assert 'ordinary.example.test.' in transfer and 'inventory.example.test.' not in transfer
    print('Real BIND pair restore, conflict gate, scoped publisher, retained RRsets, '
          'interrupted primary and idempotent second startup passed.', flush=True)


if __name__ == '__main__':
    main()
