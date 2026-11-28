"""Run on a disposable systemd guest with the audited platform mounted read-only."""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import threading
import time

from lanrith import config, directory_runtime, router_metrics_runtime as metrics
from test_directory import fixture


def run(*args, data=None):
    return subprocess.run(args, input=data, text=True, stdout=subprocess.PIPE, check=True, timeout=40).stdout


def main():
    platform = Path('/opt/fixture-platform')
    assert platform.is_mount() and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not Path('/run/netns/lanrith-services').exists()
    files = config.render(fixture())
    manifest = json.loads(files['usr/share/lanrith/router-metrics.json'])
    lib = Path('/usr/lib/lanrith')
    (lib/'lanrith').mkdir(parents=True, exist_ok=True)
    for module in ('__init__', 'release', 'router_metrics_runtime', 'ntp_health_runtime', 'directory_runtime', 'policy_runtime'):
        shutil.copyfile(Path('lanrith')/(module+'.py'), lib/'lanrith'/(module+'.py'))
    wrapper = lib/'router-metrics'
    wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                       'from lanrith.router_metrics_runtime import main\nfrom resource import getrusage,RUSAGE_SELF,RUSAGE_CHILDREN\n'
                       'result=main()\nif not sys.argv[1:]:\n'
                       '    usage=[getrusage(role) for role in (RUSAGE_SELF,RUSAGE_CHILDREN)]\n'
                       '    open("/var/lib/node_exporter/textfile_collector/fixture-cpu","w").write('
                       'str(sum(r.ru_utime+r.ru_stime for r in usage)))\nsys.exit(result)\n')
    wrapper.chmod(0o755)
    run('systemd-sysusers', '-', data='u router-policy-operator -\nu router-policy-reader -\nu lanrith-directory-health -\nu lanrith-metrics -\n')
    shutil.copy(platform/'usr/bin/router-policy-status', '/usr/bin/router-policy-status')
    target = Path('/run/systemd/system')
    for name, contents in files.items():
        if name.startswith('usr/lib/systemd/system/lanrith-router-') or name.endswith('80-lanrith-metrics.conf'):
            path = target/Path(name).name if name.endswith(('.service', '.socket', '.timer')) else Path('/'+name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
    path = metrics.MANIFEST
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest))
    # Supply the surrounding services and the helper's read-only status response.
    for unit in ('lanrith-services', 'lanrith-policy-helper'):
        (target/(unit+'.service')).write_text('[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n')
    # The pinned reader emits a JSON line on stderr. Exercise that stream
    # through the genuine service account, journald and collector sandbox.
    reader = 'lanrith-policy-reader.service'
    (target/reader).write_text('[Service]\nUser=router-policy-reader\nGroup=router-policy-reader\n'
        'StandardError=journal\nExecStart=/bin/sh -c "cat /run/fixture-attempt >&2; exec sleep infinity"\n')
    def attempt(outcome):
        Path('/run/fixture-attempt').write_text(json.dumps({'schema_version': 1, 'outcome': outcome,
            'grant_count': 0, 'denial_count': 0})+'\n')
        run('systemctl', 'restart', reader)
        for _ in range(30):
            try:
                if metrics.reader_attempt(time.monotonic()+2)[0] == outcome:
                    return
            except (OSError, ValueError):
                pass
            time.sleep(.1)
        raise AssertionError('Synthetic reader journal entry unavailable.')
    directory_runtime.MANIFEST.write_text(files['usr/share/lanrith/directory-health.json'])
    ca = Path(directory_runtime.load()['ca_file'])
    ca.parent.mkdir(parents=True, exist_ok=True)
    run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-days', '2', '-subj', '/CN=Synthetic', '-keyout', '/run/fixture-ca.key', '-out', str(ca))
    run('systemctl', 'daemon-reload')
    attempt('applied')
    run('systemctl', 'start', 'lanrith-services.service', 'lanrith-policy-helper.service',
        'lanrith-router-policy-status.socket', 'lanrith-router-service-hooks.socket')
    run('ip', 'netns', 'add', 'lanrith-services')
    for hook in manifest['hooks']['host']:
        if device := hook.get('dev'):
            run('ip', 'link', 'add', device, 'type', 'dummy')
    run('nft', '-f', '-', data=files['etc/nftables.conf']+'\n'+files['usr/lib/lanrith-build/policy-egress.nft'])
    run('ip', 'netns', 'exec', 'lanrith-services', 'nft', '-f', '-', data=files['etc/lanrith/services.nft'])
    run('mount', '--bind', '/var', '/var')
    metrics.OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    metrics.OUTPUT.write_text('prior_boot 1\n')
    run('systemd-tmpfiles', '--boot', '--remove', '/usr/lib/tmpfiles.d/80-lanrith-metrics.conf')
    assert not metrics.OUTPUT.exists()
    proof = target/'lanrith-router-metrics.service.d'
    proof.mkdir()
    (proof/'fixture.conf').write_text('[Service]\nExecStartPost=/bin/sh -c "findmnt -n -M / -o VFS-OPTIONS >'
                                    ' /var/lib/node_exporter/textfile_collector/root-options"\n')
    run('systemctl','daemon-reload')
    report = dict(schema_version=1, mode='enforce', helper_state='ready', permit_state='last_application',
                  last_failure='', baseline_hash='a'*64, baseline_generation='synthetic', last_compiled_at='2026-01-01T00:00:00Z',
                  directory_age_ms=1000, decision_age_ms=1000, apply_age_ms=1000, last_grant_count=0, last_denial_count=0,
                  last_binding_count=0, remaining_grant_count=0, next_expiry_ms=None, rules=[], rules_truncated=False,
                  denial_codes=[], clock_state='usable', floor_state='unverified', kernel_tuple_count=None, writer_sequence=None)
    endpoint = Path('/run/router-policy-ipc/status.sock')
    endpoint.parent.mkdir(exist_ok=True)
    operator = pwd.getpwnam('router-policy-operator')
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(endpoint))
        os.chown(endpoint, 0, operator.pw_gid)
        endpoint.chmod(0o660)
        listener.listen(2)
        listener.settimeout(15)

        def collect():
            replies = []
            def respond():
                with listener.accept()[0] as connection, connection.makefile('rb') as stream:
                    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    request = json.loads(stream.read(struct.unpack('!I', stream.read(4))[0]))
                    assert request == {'schema_version': 1, 'operation': 'status'} and uid == operator.pw_uid
                    payload = json.dumps({'schema_version': 1, 'code': '', 'report': report}).encode()
                    connection.sendall(struct.pack('!I',len(payload))+payload)
                    replies.append(True)
            worker = threading.Thread(target=respond)
            worker.start()
            run('systemctl', '--job-mode=ignore-dependencies', 'start', 'lanrith-router-metrics.service')
            worker.join()
            text = metrics.OUTPUT.read_text()
            print(json.dumps({'bytes': len(text.encode()), 'host_collector_cpu_seconds':
                float((metrics.OUTPUT.parent/'fixture-cpu').read_text()),
                'duration_seconds': float(next(line.split()[1] for line in text.splitlines()
                    if line.startswith('lanrith_router_metrics_collection_duration_seconds ')))}), flush=True)
            assert replies
            return text

        text = collect()
        assert 'rw' in run('findmnt','-n','-M','/','-o','VFS-OPTIONS').strip().split(',')
        assert 'ro' in (metrics.OUTPUT.parent/'root-options').read_text().strip().split(',')
        assert 'lanrith_router_mount_read_only 0\n' in text and 'lanrith_router_var_mounted_rw 1\n' in text
        assert 'lanrith_router_firewall_startup_barrier_closed 1\n' in text
        assert 'lanrith_router_policy_directory_age_seconds 1.0\n' in text
        assert 'lanrith_router_policy_reader_latest_attempt{outcome="applied"} 1\n' in text
        assert 'lanrith_router_policy_reader_attempt_timestamp_seconds ' in text
        assert 'lanrith_router_directory_trust_certificate_not_after_seconds{sha256="' in text
        assert 'lanrith_router_policy_status_query_timestamp_seconds ' in text
        hooks = [line for line in text.splitlines() if line.startswith('lanrith_router_firewall_hook_present{')]
        assert len(hooks) == sum(map(len, manifest['hooks'].values())) and all(row.endswith(' 1') for row in hooks)
        run('nft', 'delete', 'table', 'ip', 'lanrith_nat')
        run('nft', 'add', 'element', 'inet', 'lanrith', 'tp_started', '{ 0 }')
        run('ip', 'netns', 'del', 'lanrith-services')
        report['directory_age_ms'] = 120000
        attempt('submission_failed')
        text = collect()
        assert 'lanrith_router_policy_reader_latest_attempt{outcome="submission_failed"} 1\n' in text
        assert 'outcome="applied"' not in text
        assert 'lanrith_router_nftables_loaded 1\n' in text
        assert 'table="lanrith_nat"} 0\n' in text and 'lanrith_router_firewall_startup_barrier_closed 0\n' in text
        assert 'lanrith_router_metrics_query_success{collector="firewall_hooks_services"} 0\n' in text
        assert 'namespace="services"' not in text and 'lanrith_router_policy_directory_age_seconds 120.0\n' in text
    print('Systemd mount descriptor, nft hook inventories, namespace outage, startup barrier, operator IPC and boot cleanup passed.')


if __name__ == '__main__':
    main()
