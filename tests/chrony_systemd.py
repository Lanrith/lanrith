#!/usr/bin/python3
"""Exercise the generated time service and both firewalls in a disposable VM without a NIC."""

import fcntl
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, service_runtime
from unbound_native import network, run, write


WAN4 = '198.51.100.20'
WAN6 = '2001:db8:1::20'
WORK = Path('/run/chrony-fixture')
NS = ['ip', 'netns', 'exec', 'lanrith-services']
CONTROL = [*NS, 'chronyc', '-h', '/run/chrony/chronyd.sock', '-n', '-c']
SOURCE = {'type': 'pool', 'address': 'v6.clock.test', 'family': 'ipv6', 'maxsources': 1}


def stamp(seconds):
    return struct.pack('!Q', int((seconds+2208988800) * 2**32))


def peer():
    # This synthetic reference advances independently of CLOCK_REALTIME in the guest.
    origin = time.time()-time.monotonic()
    mux = selectors.DefaultSelector()
    for target in (WAN4, WAN6, '2001:db8:1::21'):
        sock = socket.socket(socket.AF_INET6 if ':' in target else socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((target, 123))
        mux.register(sock, selectors.EVENT_READ, target)
    (WORK/'ready').touch()
    while True:
        for key, _ in mux.select():
            packet, address = key.fileobj.recvfrom(2048)
            if len(packet) < 48 or packet[0] & 7 != 3 or (WORK/'withdraw').exists():
                continue
            now = origin+time.monotonic()
            header = struct.pack('!BBBbII4s', 0x24, 3, packet[2], -20, 65, 65, b'TEST')
            key.fileobj.sendto(header+stamp(now-1)+packet[40:48]+stamp(now)+stamp(now), address)


def query(target, local, count):
    sock = socket.socket(socket.AF_INET6 if ':' in target else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((local, 0))
    sock.settimeout(0.15 if count > 1 else 2)
    replies = []
    for _ in range(count):
        sent = stamp(time.time())
        sock.sendto(bytes([0x23])+bytes(39)+sent, (target, 123))
        try:
            packet, address = sock.recvfrom(2048)
        except TimeoutError:
            continue
        assert address[0] == target and len(packet) >= 48 and packet[24:32] == sent
        replies.append(packet[1])
    print(json.dumps(replies))


def wait(probe, seconds=25):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        observed = probe()
        if observed:
            return observed
        time.sleep(.4)
    raise AssertionError(f'fixture deadline {probe!r}')


def ctl(*args):
    return run(*CONTROL, *args).stdout.strip()


def state(key):
    return run('systemctl', 'show', '-P', key, 'chrony').stdout.strip()


def selected():
    # Type=exec precedes the daemon's bind(2), including across bounded restarts.
    report = run(*CONTROL, 'sources', check=False)
    if report.returncode:
        return []
    return [row.split(',')[2] for row in report.stdout.splitlines() if row.startswith('^,*,')]


def client(target, local='192.168.10.20', count=1):
    return json.loads(run('ip', 'netns', 'exec', 'lan', 'python3', __file__, 'query', target, local, str(count)).stdout)


def zone():
    # Sign zone data at the good reference time. A stale RTC is before RRSIG inception.
    os.chdir(WORK)
    key = run('dnssec-keygen', '-a', 'ECDSAP256SHA256', '-n', 'ZONE', '-f', 'KSK', 'clock.test').stdout.strip()
    write('zone', '$ORIGIN clock.test.\n$TTL 10\n@ IN SOA ns hostmaster 1 60 60 60 10\n'
          '@ IN NS ns\nns IN A '+WAN4+'\nv6 IN AAAA '+WAN6+'\nv6 IN AAAA 2001:db8:1::21\n'
          'v4 IN A '+WAN4+'\nsynth IN A 192.0.2.99\n')
    run('dnssec-signzone', '-n', '1', '-S', '-z', '-o', 'clock.test', 'zone')
    write('named.conf', 'options { directory "'+str(WORK)+'"; listen-on { '+WAN4+'; }; '
          'listen-on-v6 { none; }; recursion no; dnssec-validation no; empty-zones-enable no; pid-file "named.pid"; }; controls {}; '
          'zone "clock.test" { type primary; file "zone.signed"; };')
    return str(WORK/(key+'.key'))


def qualify():
    assert Path('/proc/1/comm').read_text().strip() == 'systemd' and run('systemd-detect-virt', '--vm').stdout.strip()
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert {r['ifname'] for r in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    platform = Path('/opt/fixture-platform')
    assert (platform/'usr/sbin/chronyd').is_file()
    run('systemctl', 'stop', 'chrony')
    for path in ('usr/sbin/chronyd', 'usr/bin/chronyc', 'usr/lib/systemd/system/chrony.service'):
        shutil.copyfile(platform/path, '/'+path)
    print(run('chronyd', '-v').stdout.strip(), flush=True)
    assert '+SCFILTER' in run('chronyd', '-v').stdout
    WORK.mkdir()
    network('wan', '198.51.100.1', WAN4)
    network('lan', '192.168.10.1', '192.168.10.20')
    run('ip', '-n', 'lan', 'addr', 'add', '192.168.10.21/24', 'dev', 'eth0')
    for name, gateway, addr in [('wan', '2001:db8:1::1', WAN6), ('lan', 'fd42:1000:1000:10::1', 'fd42:1000:1000:10::20')]:
        run('ip', '-6', 'addr', 'add', gateway+'/64', 'dev', name, 'nodad')
        run('ip', '-n', name, 'addr', 'add', addr+'/64', 'dev', 'eth0', 'nodad')
        run('ip', '-n', name, '-6', 'route', 'add', 'default', 'via', gateway)
    run('ip', '-n', 'wan', '-6', 'addr', 'add', '2001:db8:1::21/64', 'dev', 'eth0', 'nodad')
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    value = config.load(ROOT/'examples/minimal.yaml')
    value['networks']['home']['ntp'] = True
    ntp = value['services']['ntp']
    ntp['enabled'] = True
    ntp['upstreams'] = [SOURCE, {'type': 'server', 'address': 'v4.clock.test', 'family': 'ipv6'},
                        {'type': 'server', 'address': 'synth.clock.test', 'family': 'ipv6'}]
    ntp['ratelimit'] = {'interval': 3, 'burst': 8, 'leak': 2}
    value['services']['dns']['upstreams'] = [WAN4]
    files = config.render(value)
    plane = json.loads(files['usr/share/lanrith/service-plane.json'])
    local, local6 = plane['endpoints']['ntp'][:2]
    for name in ('etc/lanrith/chrony-resolv.conf', 'etc/lanrith/services.nft', 'etc/nftables.conf',
                 'etc/systemd/system/chrony.service.d/60-lanrith-services.conf'):
        write('/'+name, files[name])
    for name in ('10-lanrith-firewall.conf', '30-lanrith-hardening.conf'):
        unit = 'etc/systemd/system/chrony.service.d/'+name
        write('/'+unit, (ROOT/'mkosi/base/mkosi.extra'/unit).read_text())
    library_dir = Path('/usr/lib/x86_64-linux-gnu')
    write('/etc/systemd/system/chrony.service.d/90-fixture-image-abi.conf', '[Service]\n'
          f'BindReadOnlyPaths={platform}{library_dir}:{library_dir}\n'
          f'BindReadOnlyPaths={platform}/etc/nsswitch.conf:/etc/nsswitch.conf\n')
    for name in ('nftables', 'lanrith-services'):
        write('/etc/systemd/system/'+name+'.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    run('systemctl', 'daemon-reload')
    run('nft', '-f', '/etc/nftables.conf')
    service_runtime.start(plane)
    anchor = zone()
    # Use a local DNS64 validator with a trust anchor for the signed isolated zone.
    write(WORK/'resolver', files['etc/unbound/unbound.conf.d/lanrith.conf'].replace('forward-zone:', '''
  chroot: ""
  username: "unbound"
  use-syslog: no
  val-log-level: 2
  module-config: "dns64 validator iterator"
  trust-anchor-file: "'''+anchor+'''"
  local-zone: "test." nodefault
  do-not-query-localhost: no
  dns64-prefix: 64:ff9b::/96
forward-zone:'''))
    # Force the synthetic prefix away from the WAN, as on the reviewed deployment.
    run('ip', '-6', 'route', 'add', 'unreachable', '64:ff9b::/96')
    def launch(namespace, *cmd):
        return subprocess.Popen(['ip', 'netns', 'exec', namespace, *cmd], stdout=subprocess.DEVNULL)
    launch('wan', 'named', '-g', '-n', '1', '-c', str(WORK/'named.conf'))
    resolver = launch('lanrith-services', 'unbound', '-d', '-p', '-c', str(WORK/'resolver'))
    launch('wan', 'python3', __file__, 'peer')
    wait(lambda: (WORK/'ready').exists())
    def dig(name):
        return run(*NS, 'dig', '@127.0.0.1', '+time=1', '+tries=1', name+'.clock.test', 'AAAA', check=False).stdout
    wait(lambda: WAN6 in dig('v6'))
    assert 'flags: qr rd ra ad;' in dig('v6')
    assert '64:ff9b::c000:263' in dig('synth')
    # A separate A-only DNS lookup will use a signed zone with DNS64 disabled below.
    resolver.terminate()
    resolver.wait(timeout=5)
    write(WORK/'resolver', (WORK/'resolver').read_text().replace('module-config: "dns64 validator iterator"',
                                                             'module-config: "validator iterator"'))
    resolver = launch('lanrith-services', 'unbound', '-d', '-p', '-c', str(WORK/'resolver'))
    wait(lambda: WAN6 in dig('v6'))
    assert 'ANSWER: 0' in dig('v4')
    def apply_ntp():
        text = config.render(value)['etc/chrony/chrony.conf']
        write('/etc/chrony/chrony.conf', text)
        assert run('chronyd', '-p', '-f', '/etc/chrony/chrony.conf').stdout.splitlines() == text.splitlines()

    limits = ntp.pop('ratelimit')
    apply_ntp()
    ntp['ratelimit'] = limits
    apply_ntp()
    run('systemctl', 'start', 'chrony')
    wait(lambda: selected() and int(ctl('activity').split(',')[-1]) >= 2)
    print('A-only names unresolved under ipv6 restriction', ctl('activity'), ctl('sources'), flush=True)
    run('systemctl', 'stop', 'chrony')
    run('systemctl', 'reset-failed', 'chrony')
    reference = time.time()-time.monotonic()
    resolver.terminate()
    resolver.wait(timeout=5)
    time.clock_settime(time.CLOCK_REALTIME, time.time()-86400*30)
    # hwclock is optional on the native-tools disk. Write the emulated RTC directly.
    stale = time.gmtime()
    rtc_value = struct.pack('9i', stale.tm_sec, stale.tm_min, stale.tm_hour, stale.tm_mday, stale.tm_mon-1,
                            stale.tm_year-1900, 0, 0, 0)
    with open('/dev/rtc0', 'rb', buffering=0) as rtc:
        fcntl.ioctl(rtc, 0x4024700a, rtc_value)  # RTC_SET_TIME on the x86-64 test image
    assert Path('/sys/class/rtc/rtc0/date').read_text().strip() == time.strftime('%Y-%m-%d', stale)
    resolver = launch('lanrith-services', 'unbound', '-d', '-p', '-c', str(WORK/'resolver'))
    wait(lambda: 'status: SERVFAIL' in dig('v6'))
    run('systemctl', 'start', 'chrony')
    time.sleep(2)
    assert not selected() and ctl('tracking').endswith('Not synchronised')
    assert int(ctl('activity').split(',')[-1]) >= 1
    print('stale clock, signed DNS refused, named sources unselected', flush=True)
    ntp['upstreams'].append({'type': 'server', 'address': WAN4})
    ntp['require_numeric_source'] = True
    apply_ntp()
    first = time.monotonic()
    run('systemctl', 'restart', 'chrony')
    wait(lambda: selected() == [WAN4] and abs(time.time()-reference-time.monotonic()) < 2)
    print('numeric recovery seconds', round(time.monotonic()-first, 2), 'tracking', ctl('tracking'), flush=True)
    assert client(local) == [4] and client(local6, 'fd42:1000:1000:10::20') == [4]
    assert client(WAN4) == [3]
    # Ordinary policy denies the LAN's ULA egress to the WAN.
    assert not client(WAN6, 'fd42:1000:1000:10::20')
    # Restore named acquisition and exercise a synthesized unreachable target alongside native v6.
    resolver.terminate()
    resolver.wait(timeout=5)
    write(WORK/'resolver', (WORK/'resolver').read_text().replace('module-config: "validator iterator"',
                                                             'module-config: "dns64 validator iterator"')
)
    resolver = launch('lanrith-services', 'unbound', '-d', '-p', '-c', str(WORK/'resolver'))
    wait(lambda: WAN6 in dig('v6'))
    ntp['upstreams'] = [SOURCE, {'type': 'server', 'address': 'synth.clock.test', 'family': 'ipv6'}]
    ntp['require_numeric_source'] = False
    apply_ntp()
    run('systemctl', 'reset-failed', 'chrony')
    run('systemctl', 'restart', 'chrony')
    remote = wait(lambda: next((s for s in selected() if s in (WAN6, '2001:db8:1::21')), None))
    wait(lambda: '64:ff9b::c000:263' in ctl('sources'))
    print('named acquisition', ctl('sources'), ctl('ntpdata', remote), flush=True)
    def retained():
        rows = [r.split(',') for r in ctl('sources').splitlines()]
        return (sum(r[2] in (WAN6, '2001:db8:1::21') for r in rows) == 1 and
                any(r[2] == '64:ff9b::c000:263' and r[1] == '?' and int(r[5]) == 0 for r in rows))
    wait(retained)
    details = ctl('ntpdata', remote).split(',')
    assert details[0] == remote and details[2:4] == ['123', local6], details
    # Accelerate only the selected isolated test peer. Keep normal poll limits in all rendered files.
    ctl('minpoll', remote, '0')
    ctl('maxpoll', remote, '0')
    ctl('burst', '4/4', remote)
    wait(lambda: float(ctl('tracking').split(',')[9]) < 10000, 50)
    (WORK/'withdraw').touch()
    time.sleep(.5)
    old = ctl('tracking').split(',')
    time.sleep(3)
    held = ctl('tracking').split(',')
    assert held[3] == old[3]
    wait(lambda: all(int(line.split(',')[5]) == 0 for line in ctl('sources').splitlines()), 45)
    (WORK/'withdraw').unlink()
    wait(lambda: selected() and ctl('tracking').split(',')[3] != held[3], 40)
    print('withdrawn and restored tracking', old, held, ctl('tracking'), flush=True)
    baseline = int(ctl('serverstats').split(',')[1])
    responses = len(client(local, count=32))
    drops = int(ctl('serverstats').split(',')[1])-baseline
    print('rate limit, replies to 32 requests', responses, 'dropped counter delta', drops, flush=True)
    assert 0 < responses < 32 and drops > 0
    assert client(local, '192.168.10.21') == [4]
    client_state = WORK/'client'
    client_state.mkdir()
    shutil.chown(client_state, '_chrony', '_chrony')
    check = run('ip', 'netns', 'exec', 'lan', 'chronyd', '-Q', '-t', '10',
                'server '+local+' iburst maxsamples 1', 'bindacqaddress 192.168.10.21',
                'pidfile '+str(client_state/'client.pid'))
    assert 'System clock wrong by' in check.stderr
    value['networks']['home']['ntp_intercept'] = True
    write('/etc/nftables.conf', config.render(value)['etc/nftables.conf'])
    run('nft', '-f', '/etc/nftables.conf')
    assert client(WAN4, '192.168.10.21') == [4]
    assert client(WAN6, 'fd42:1000:1000:10::20') == [4]
    pid = state('MainPID')
    for name in ('libc.so.6', 'libseccomp.so.2', 'ld-linux-x86-64.so.2'):
        pinned = platform/library_dir.relative_to('/')/name
        runtime = Path('/proc', pid, 'root')/library_dir.relative_to('/')/name
        assert pinned.samefile(runtime), name
    assert '-F 1' in state('ExecStart') and 'Seccomp:\t2' in Path('/proc', pid, 'status').read_text()
    run('systemctl', 'reset-failed', 'chrony')
    assert 'Loaded seccomp filter (level 1)' in run('journalctl', '-b', '-u', 'chrony', '-o', 'cat').stdout
    run('systemctl', 'kill', '--signal=SIGKILL', '--kill-whom=main', 'chrony')
    wait(lambda: state('MainPID') not in ('0', pid) and state('ActiveState') == 'active')
    wait(lambda: selected() and client(WAN4, '192.168.10.21') == [4])
    run('systemctl', 'stop', 'chrony')
    time.sleep(3)
    assert state('ActiveState') == 'inactive' and state('MainPID') == '0'
    assert not client(WAN4, '192.168.10.21')
    run('systemctl', 'reset-failed', 'chrony')
    def start_count():
        return run('journalctl', '-b', '-u', 'chrony', '-o', 'cat').stdout.count('chronyd version ')

    before = start_count()
    write('/etc/chrony/chrony.conf', 'invalid_fixture_config\n')
    run('systemctl', 'start', 'chrony', check=False)
    wait(lambda: state('ActiveState') == 'failed' and start_count() == before+3)
    apply_ntp()
    refused = run('systemctl', 'start', 'chrony', check=False)
    assert refused.returncode and start_count() == before+3 and state('MainPID') == '0'
    print('Three configuration failures, next valid start refused inside the limit', flush=True)
    run('systemctl', 'reset-failed', 'chrony')
    run('systemctl', 'start', 'chrony')
    wait(lambda: selected() and client(WAN4, '192.168.10.21') == [4])
    print('Deliberate stop, reset after bounded retries and client reply passed', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['peer']:
        peer()
    elif sys.argv[1:2] == ['query']:
        query(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    else:
        try:
            qualify()
        except Exception:
            if Path('/proc/1/comm').read_text().strip() == 'systemd' and WORK.is_dir():
                print(run('journalctl', '-b', '-u', 'chrony', '-n', '35', '-o', 'cat').stdout, flush=True)
                for report in ('activity', 'sources', 'tracking'):
                    print(report, run(*CONTROL, report, check=False).stdout, flush=True)
            raise
