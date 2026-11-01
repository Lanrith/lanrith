#!/usr/bin/env python3
"""Exercise generated dnstap units and packaged Unbound in an offline systemd guest."""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import build, config, dns_observations as generation, dns_qualification, service_plane
from lanrith.release import file_record, require
from test_extension_network import manifest as extension_manifest


def run(*args, check=True, timeout=20):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(not check or result.returncode == 0,
            'DNS fixture command failed: '+result.stderr.decode(errors='replace')[-2048:])
    return result


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def question(identifier=1234, kind=1):
    return struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0)+b'\x06answer\x07fixture\x04test\0'+struct.pack('!HH', kind, 1)


def query(family, transport, count=1):
    # Called only through ip-netns-exec in the synthetic service namespace.
    endpoint = ('::1', 53) if family == 6 else ('127.0.0.1', 53)
    maximum = 0.
    with socket.socket(socket.AF_INET6 if family == 6 else socket.AF_INET,
                       socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.connect(endpoint)
        for index in range(count):
            raw = question(1234+index % 60000, 28 if family == 6 else 1)
            started = time.monotonic()
            if transport == 'tcp':
                client.sendall(struct.pack('!H', len(raw))+raw)
                def receive(size):
                    result = b''
                    while len(result) < size:
                        part = client.recv(size-len(result))
                        require(part, 'DNS fixture TCP closed early.')
                        result += part
                    return result
                reply = receive(struct.unpack('!H', receive(2))[0])
            else:
                client.send(raw)
                reply = client.recv(65536)
            maximum = max(maximum, time.monotonic()-started)
            require(reply[:2] == raw[:2] and reply[3] & 15 == 0 and struct.unpack('!H', reply[6:8])[0] == 1,
                    'DNS fixture answer differs.')
    print(json.dumps({'queries': count, 'maximum_seconds': maximum}))


def qualify(result, base):
    require(os.geteuid() == 0 and Path('/run/systemd/system').is_dir() and
            (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists()) and
            b'systemd' in Path('/proc/1/cmdline').read_bytes() and
            not Path('/usr/share/lanrith/installed.json').exists(),
            'DNS fixture requires an uninitialized disposable systemd container.')
    require({entry['ifname'] for entry in json.loads(run('ip', '-json', 'link').stdout)} == {'lo'},
            'DNS fixture must have no external network.')
    failed = {line.split()[0] for line in run('systemctl', '--failed', '--no-legend', '--plain').stdout.decode().splitlines()}
    require(failed <= {'proc-sys-fs-binfmt_misc.automount', 'sys-kernel-config.mount',
                       'sys-kernel-debug.mount', 'sys-kernel-tracing.mount'}, 'Unexpected initial failed units.')
    if failed:
        run('systemctl', 'reset-failed', *sorted(failed))
    require(not result.exists() and result.parent.is_dir(), 'DNS result must be new.')
    subject = file_record(base)
    with tempfile.TemporaryDirectory(prefix='dns-executables.', dir='/run') as temporary:
        candidates = Path(temporary)
        base_binaries = dns_qualification.binaries(base, destination=candidates)
        for name in dns_qualification.BINARIES:
            target = Path('/')/name
            require(not target.is_symlink(), 'Fixture executable must be ordinary.')
            shutil.copyfile(candidates/target.name, target)
            target.chmod(0o755)
    version = run('/usr/sbin/unbound', '-V').stdout.decode()
    selected_version = [line.split('=', 1)[1] for line in (ROOT/'builders/unbound-source.lock').read_text().splitlines()
                        if line.startswith('UNBOUND_UPSTREAM_VERSION=')]
    require(len(selected_version) == 1 and '--enable-dnstap' in version and
            version.splitlines()[0] == 'Version '+selected_version[0],
            'Selected native resolver differs or lacks dnstap.')
    units = Path('/etc/systemd/system')
    require(not (units/generation.SOCKET).exists(), 'DNS fixture already initialized.')
    run('mount', '--make-shared', '/run')
    run('ip', 'netns', 'add', service_plane.NAMESPACE)
    checks, traffic = [], []
    with tempfile.TemporaryDirectory(prefix='dns-observer-native.') as temporary:
        root = Path(temporary)
        value = config.load(ROOT/'examples/minimal.yaml')
        value['extensions'] = ['example-observer']
        generated = config.render(value)
        observer = {'user': 'example-agent', 'uid': 1801, 'gid': 1801}
        extension = root/'extension'
        extension.mkdir()
        pin = extension_manifest(extension, observations=[{'service': 'dns', 'user': 'example-agent'}])
        base = root/'accounts.tar'
        with tarfile.open(base, 'w') as archive:
            for name in ('etc/passwd', 'etc/group'):
                data = (Path('/')/name).read_bytes()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        build.assembly(value, base, root/'assembly', version='0.1.0', sequence=9,
                       integrations={'example-observer': (extension, pin)})
        tree = root/'assembly/mkosi.extra'
        assembly_sha256 = {name: sha(tree/name) for name in (*generation.render(observer),
            'etc/passwd', 'etc/group', 'usr/lib/lanrith/lanrith/dns_metadata.py',
            'usr/lib/lanrith/lanrith/dns_observations_runtime.py')}
        for name in ('etc/passwd', 'etc/group'):
            shutil.copyfile(tree/name, Path('/')/name)
        shutil.copytree(tree/'usr/lib/lanrith/lanrith', '/usr/lib/lanrith/lanrith', dirs_exist_ok=True)
        for name in generation.render(observer):
            target = Path('/')/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tree/name, target)
            target.chmod(0o755 if name.endswith('/dns-observations-runtime') else 0o644)
        (units/'lanrith-services.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
        (units/'nftables.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
        # Namespace/firewall creation is synthetic. Preserve the selected package
        # unit, generated namespace binding, hardening and actual tap configuration.
        dropin = units/'unbound.service.d'
        dropin.mkdir(exist_ok=True)
        for name in ('30-lanrith-hardening.conf',):
            shutil.copyfile(ROOT/'mkosi/base/mkosi.extra/etc/systemd/system/unbound.service.d'/name, dropin/name)
        (dropin/'60-lanrith-services.conf').write_text(generated['etc/systemd/system/unbound.service.d/60-lanrith-services.conf'])
        conf = Path('/etc/unbound/unbound.conf.d')
        conf.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/'mkosi/base/mkosi.extra/etc/unbound/unbound.conf.d/99-lanrith-runtime.conf', conf/'99-lanrith-runtime.conf')
        (conf/'lanrith.conf').write_text(generated[generation.RESOLVER])
        (conf/'98-native-fixture.conf').write_text('server:\n  module-config: "iterator"\n'
            '  local-zone: "fixture.test." static\n'
            '  local-data: "answer.fixture.test. 120 IN A 203.0.113.7"\n'
            '  local-data: "answer.fixture.test. 120 IN AAAA 2001:db8::7"\n')
        Path('/etc/unbound/unbound.conf').write_text('include: "/etc/unbound/unbound.conf.d/*.conf"\n')
        anchor = Path('/var/lib/unbound/root.key')
        anchor.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile('/usr/share/dns/root.key', anchor)
        unbound = pwd.getpwnam('unbound')
        os.chown(anchor, unbound.pw_uid, unbound.pw_gid)
        namespace = '--net=/run/netns/'+service_plane.NAMESPACE
        run('nsenter', namespace, 'ip', 'link', 'set', 'lo', 'up')
        for endpoint in service_plane.topology(value)['endpoints']['dns']:
            run('nsenter', namespace, 'ip', 'address', 'add', endpoint+('/32' if ':' not in endpoint else '/128'), 'dev', 'lo')
        Path('/run/unbound').mkdir(mode=0o750, exist_ok=True)
        run('/usr/sbin/unbound-checkconf')
        run('systemctl', 'daemon-reload')
        run('systemd-analyze', 'verify', str(units/generation.SERVICE), str(units/generation.SOCKET))
        run('systemctl', 'start', generation.SOCKET)
        # No genuine producer is connected yet: rejection cannot be explained
        # by the single-peer connection limit.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.connect('/run/lanrith-dns-tap.sock')
            peer.settimeout(5)
            require(peer.recv(1) == b'', 'Collector accepted a root peer instead of Unbound.')
        run('systemctl', 'start', 'unbound.service', timeout=35)

        def queries(family=4, transport='udp', count=1):
            record = json.loads(run('nsenter', namespace,
                '/usr/bin/python3', '-B', str(Path(__file__).resolve()), '--query', str(family), transport, str(count), timeout=30).stdout)
            traffic.append({'family': family, 'transport': transport, **record})
            return record

        def records():
            return [json.loads(line) for line in Path('/run/lanrith-dns-observations/events.jsonl').read_bytes().splitlines()]

        def until(predicate, seconds=25):
            deadline = time.monotonic()+seconds
            while True:
                try:
                    if predicate():
                        return
                except (OSError, ValueError):
                    pass
                require(time.monotonic() < deadline, 'DNS native observation deadline exceeded.')
                time.sleep(.2)

        for family in (4, 6):
            for transport in ('udp', 'tcp'):
                queries(family, transport)
        until(lambda: len(records()) >= 8)
        observations = records()
        query_times = {r['transaction']: r['observed_ns'] for r in observations if r['phase'] == 'query'}
        clock_deltas = [r['query_observed_ns']-query_times[r['transaction']] for r in observations
                        if r['phase'] == 'response' and r['query_observed_ns'] is not None and r['transaction'] in query_times]
        require([r['sequence'] for r in observations] == list(range(1, len(observations)+1)) and
                len({r['producer_epoch'] for r in observations}) == 1 and
                all(r['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
                    ((type(r['query_observed_ns']) is int and r['query_observed_ns'] <= r['observed_ns']) or
                     (r['phase'] == 'response' and r['query_observed_ns'] is None and r['latency_ms'] is None)) for r in observations),
                'DNS record producer identity, ordinal or query time differs.')
        require({(r['client_ip'], r['protocol'], r['phase']) for r in observations} >=
                {(ip, protocol, phase) for ip in ('127.0.0.1', '::1') for protocol in ('udp', 'tcp') for phase in ('query', 'response')},
                'Native DNS observations omit a transport/family/phase.')
        require(any(r['answer_records'] and r['answer_records'][0]['value'] == '203.0.113.7' for r in observations) and
                any(r['answer_records'] and r['answer_records'][0]['value'] == '2001:db8::7' for r in observations),
                'Native DNS answer metadata differs.')
        checks += ['packaged-unbound-dnstap', 'generated-unit-verification', 'ipv4-ipv6-udp-tcp-client-query-response']
        pid = run('systemctl', 'show', '--property=MainPID', '--value', generation.SERVICE).stdout.decode().strip()
        status = dict(line.split(':', 1) for line in Path('/proc/'+pid+'/status').read_text().splitlines())
        collector_uid = int(status['Uid'].split()[0])
        require(collector_uid not in (0, 1801, unbound.pw_uid) and int(status['CapEff'], 16) == 0 and
                int(status['CapBnd'], 16) == 0 and status['NoNewPrivs'].strip() == '1', 'DNS collector authority differs.')
        require(run('systemctl', 'show', '--property=MemoryMax', '--value', generation.SERVICE).stdout.strip() == b'67108864',
                'DNS collector memory bound differs.')
        checks += ['dedicated-nonroot-uid-no-capabilities-resource-bound']
        tap = Path('/run/lanrith-dns-tap.sock').stat()
        require((tap.st_uid, tap.st_gid, tap.st_mode & 0o777) == (unbound.pw_uid, unbound.pw_gid, 0o600), 'Tap custody differs.')
        access = root/'role.py'
        access.write_text('import pathlib,socket\n'
            'p=pathlib.Path("/run/lanrith-dns-observations/events.jsonl");assert p.read_bytes()\n'
            'for target in (p,p.parent/"forbidden"):\n'
            ' try: target.open("ab").close()\n'
            ' except PermissionError: pass\n'
            ' else: raise AssertionError("reader can write")\n'
            's=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n'
            'try:s.connect("/run/lanrith-dns-tap.sock")\n'
            'except PermissionError:pass\n'
            'else:raise AssertionError("reader can forge producer")\n')
        root.chmod(0o755)
        run('setpriv', '--reuid=1801', '--regid=1801', '--clear-groups', '/usr/bin/python3', str(access))
        outsider = run('setpriv', '--reuid=1802', '--regid=1802', '--clear-groups',
            '/usr/bin/python3', '-c', 'from pathlib import Path;Path("/run/lanrith-dns-observations/events.jsonl").read_bytes()', check=False)
        require(outsider.returncode != 0 and b'PermissionError' in outsider.stderr, 'Outsider read DNS metadata.')
        checks += ['reader-metadata-only-no-write-no-producer-socket']
        health = Path('/run/lanrith-dns-observations/health.json')
        until(lambda: json.loads(health.read_bytes())['rejected'] >= 1)
        before = json.loads(health.read_bytes())
        checks += ['kernel-peer-uid-rejects-forged-producer']
        run('systemctl', 'kill', '--signal=STOP', generation.SERVICE)
        stalled = queries(count=5000)
        require(stalled['maximum_seconds'] < 2., 'DNS blocked on stalled collector.')
        run('systemctl', 'kill', '--signal=CONT', generation.SERVICE)
        checks += ['dns-survives-stalled-reader-5000-queries']
        restarted_at = time.time_ns()
        manifest = Path('/')/generation.CONFIG
        original_manifest = manifest.read_bytes()
        manifest.write_text(json.dumps({'schema': 1, 'record_schema': 1, 'observer': {**observer, 'uid': 1802}}))
        run('systemctl', 'kill', '--signal=KILL', generation.SERVICE)
        time.sleep(6)
        require(run('systemctl', 'show', '--property=NRestarts', '--value', generation.SERVICE).stdout.strip() != b'0',
                'Collector did not restart after crash.')
        require(run('systemctl', 'is-failed', '--quiet', generation.SERVICE, check=False).returncode != 0,
                'Optional collector entered the global failed-unit set.')
        queries()
        run('systemctl', 'start', 'systemd-boot-check-no-failures.service')
        checks += ['collector-failure-keeps-dns-and-global-boot-check-usable']
        manifest.write_bytes(original_manifest)
        until(lambda: json.loads(health.read_bytes())['producer_epoch'] != before['producer_epoch'])
        def reconnected():
            queries()
            return any(r['phase'] == 'response' and r['observed_ns'] >= restarted_at for r in records())
        until(reconnected)
        checks += ['collector-restart-epoch-and-reconnect']
        run('systemctl', 'stop', generation.SERVICE, generation.SOCKET)
        for family in (4, 6):
            for transport in ('udp', 'tcp'):
                queries(family, transport)
        checks += ['dns-survives-absent-collector-and-socket']
        run('systemctl', 'stop', 'unbound.service')
        for name in generation.render(observer):
            (Path('/')/name).unlink()
        run('systemctl', 'daemon-reload')
        Path('/run/unbound').mkdir(mode=0o750, exist_ok=True)
        run('/usr/sbin/unbound-checkconf')
        run('systemctl', 'start', 'unbound.service', timeout=35)
        queries()
        require(not Path('/run/lanrith-dns-tap.sock').exists() and
                not Path('/run/lanrith-dns-observations').exists(), 'Disabled DNS observation endpoint remains.')
        checks += ['disabled-selection-removes-endpoint-and-keeps-dns']
        run('systemctl', 'stop', 'unbound.service', 'lanrith-services.service')
        run('ip', 'netns', 'delete', service_plane.NAMESPACE)
        record = {'schema': 1, 'result': 'pass', 'assessed_at': datetime.now(timezone.utc).isoformat(),
                  'scope': 'Offline systemd component; generated units and actual packaged resolver; synthetic namespace/firewall/local zone',
                  'checks': checks, 'traffic': traffic, 'collector_uid': collector_uid,
                  'query_response_clock_deltas_ns': clock_deltas,
                  'test': 'offline-dns-observations', 'filesystem_sha256': subject['sha256'],
                  'base_binaries_sha256': base_binaries, 'effective_capabilities': int(status['CapEff'], 16),
                  'bounding_capabilities': int(status['CapBnd'], 16), 'no_new_privileges': status['NoNewPrivs'].strip() == '1',
                  'unbound_version': version, 'unbound_sha256': sha(Path('/usr/sbin/unbound')),
                  'unbound_checkconf_sha256': sha(Path('/usr/sbin/unbound-checkconf')),
                  'assembly_sha256': assembly_sha256,
                  'source_sha256': dns_qualification.implementation(ROOT),
                  'external_network': False, 'private_image_qualified': False, 'image_boot_qualified': False}
        result.write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')
        print(json.dumps({'result': 'pass', 'checks': len(checks)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--result', type=Path)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--query', nargs=3)
    args = parser.parse_args()
    if args.query:
        query(int(args.query[0]), args.query[1], int(args.query[2]))
    else:
        require(args.result is not None and args.base is not None, 'Result and base are required.')
        qualify(args.result, args.base)


if __name__ == '__main__':
    main()
