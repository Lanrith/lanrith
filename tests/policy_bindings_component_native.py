#!/usr/bin/env python3
"""Offline nonempty generated binding-producer integration, using candidate bytes.

Real helper IPC, nftables, systemd journal provenance, VLAN placement and Kea
queries are exercised. The accounting service emits synthetic events, directory
proposals are synthetic and leases are seeded before Kea starts. This does not
qualify RADIUS authentication, LDAP, DHCP packets, translators or any image.
"""

import argparse
import copy
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import config, policy_agent, policy_runtime
from lanrith.release import canonical, require
import policy_observer_component_native as base
from test_radius import declaration

MAC = '02:00:00:00:22:79'
IP = '192.168.22.120'
COLLECTOR = 'router-policy-collector'


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def wait(predicate, seconds=45):
    end = time.monotonic()+seconds
    while True:
        value = predicate()
        if value: return value
        require(time.monotonic() < end, 'Nonempty binding fixture deadline expired.')
        time.sleep(.2)


def snapshot():
    placement = {'schema_version': 1, 'kind': 'placement', 'vlan_role': 'devices'}
    access = {'schema_version': 1, 'kind': 'access', 'vlan_role': 'devices', 'temporary': False, 'rules': [
        {'id': 'https', 'direction': 'from_device', 'peer': {'addresses': ['10.244.0.50/32']},
         'protocol': 'tcp', 'destination_ports': [443], 'reason': 'synthetic offline integration'}]}
    return {'schema_version': 1, 'directory': {'observed_at': datetime.now(timezone.utc).isoformat(),
        'complete': True, 'groups': [
            {'id': 'placement', 'name': 'Synthetic devices', 'is_network': True, 'policy': json.dumps(placement)},
            {'id': 'access', 'name': 'Synthetic HTTPS', 'is_network': True, 'policy': json.dumps(access)}],
        'devices': [{'id': 'synthetic-device', 'mac': MAC, 'active': True, 'group_ids': ['placement', 'access']}]}}


ACCOUNTING = r'''import json,time
start=int(time.time())
while True:
 now=int(time.time()); duration=now-start
 value={"received_at":now,"mac":"020000002279","nas_source":"192.168.10.40",
 "nas_reported_ipv4":"192.168.10.40","nas_port":"5","nas_port_type":"Ethernet",
 "nas_port_id_hex":"65746835","session_id_hex":"6e61746976652d66697874757265",
 "status":"Start" if duration==0 else "Interim-Update","event_time":"",
 "delay_seconds":"0","session_seconds":str(duration),"ipv4":"192.168.22.120",
 "ipv6_addresses":"","ipv6_prefixes":"","interface_id":"","vlan_reported_hex":"3232"}
 print("radius-policy-accounting-v1 "+json.dumps(value,separators=(",",":")),flush=True)
 time.sleep(10)
'''


def qualify(candidate, collector_sha, output, *, configure=None, observer=None, observe_stage=None,
            prepare_interfaces=None, prepare_ruleset=None, after_profile=None):
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd' and
        Path('/run/.containerenv').exists() and not Path('/usr/share/lanrith/installed.json').exists(),
        'Require an uninitialized disposable systemd container.')
    require({row['ifname'] for row in json.loads(base.run('ip', '-j', 'link').stdout)} == {'lo'} and
        not output.exists() and output.is_absolute() and output.parent.is_dir(), 'Fixture topology/output exists.')
    sources = {name: sha(ROOT/name) for name in (*base.SOURCE_FILES, 'lanrith/kea_runtime.py',
        'tests/policy_bindings_component_native.py', 'tests/test_radius.py')}
    require(isinstance(collector_sha, str) and re.fullmatch('[0-9a-f]{64}', collector_sha) and
        sha(candidate/COLLECTOR) == collector_sha and not (Path('/usr/bin')/COLLECTOR).exists(),
        'Candidate collector hash differs.')
    component = base.candidate(candidate)
    shutil.copyfile(candidate/COLLECTOR, Path('/usr/bin')/COLLECTOR)
    (Path('/usr/bin')/COLLECTOR).chmod(0o755)
    # Trusted companion fixtures can observe the same lifecycle through their
    # own admitted-style reader. These hooks are Python-only test composition;
    # no runtime command, directory input or CLI option can select executable code.
    # A companion may supply a disposable packet topology and the final native
    # ruleset after its own extension wiring. The same finalization compiler then
    # binds that ruleset; the normalized baseline is never replaced by the hook.
    observer = dict(base.OBSERVER if observer is None else observer)
    require(observer['uid'] == observer['gid'] == 1801, 'Fixture observer identity differs.')
    for uid, name in ((1701, 'router-policy-reader'), (1702, 'router-policy-operator'), (1801, observer['user'])):
        base.run('useradd', '--uid', str(uid), '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', name)
    value = declaration()
    if configure is not None: value = configure(value)
    value['networks']['devices']['dhcp4']['id'] = 22
    value = config.normalize(value)
    interfaces = base.prepare_interfaces(value) if prepare_interfaces is None else prepare_interfaces(copy.deepcopy(value))
    for network in value['networks'].values():
        for address in network['addresses']:
            base.run('ip', 'address', 'add', address, 'dev', network['name'], *(['nodad'] if ':' in address else []))
    files = config.render(value)
    files.update(policy_agent.render(value, observer=observer))
    library = Path('/usr/lib/lanrith/lanrith'); require(not library.exists(), 'Runtime library exists.')
    library.mkdir(parents=True)
    for name in ('__init__.py', 'release.py', 'policy_runtime.py', 'kea_runtime.py'):
        shutil.copyfile(ROOT/'lanrith'/name, library/name)
    wrapper = library.parent/'policy-runtime'
    wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                       'from lanrith.policy_runtime import main\nsys.exit(main())\n'); wrapper.chmod(0o755)
    ruleset = files['etc/nftables.conf'] if prepare_ruleset is None else prepare_ruleset(copy.deepcopy(value), dict(files))
    require(isinstance(ruleset, str) and 0 < len(ruleset.encode()) <= 8*1024*1024,
            'Companion native ruleset is missing or oversized.')
    contract = json.loads(files['etc/router-policy-agent/runtime/runtime.json'])
    require(contract['binding_collector']['subnet_id'] == 22, 'Generated DHCP scope differs.')
    policy_runtime.CONTRACT.parent.mkdir(parents=True, exist_ok=True)
    policy_runtime.CONTRACT.write_bytes(canonical(contract)); policy_runtime.CONTRACT.chmod(0o600)
    for path in (policy_runtime.ROOT, policy_runtime.CONFIG, policy_runtime.GENERATION,
                 policy_runtime.BINDINGS, policy_runtime.COLLECTOR,
                 Path(contract['state_directory']), Path(contract['profile_directory'])):
        path.mkdir(mode=0o700, parents=True, exist_ok=True); path.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix='nonempty-profile.') as temporary:
        work = Path(temporary)
        (work/'base.nft').write_text(ruleset)
        base.run('nft', '-f', str(work/'base.nft'))
        (work/'baseline.json').write_bytes(canonical(policy_agent.baseline(value)))
        (work/'ruleset.json').write_bytes(base.run('nft', '-j', 'list', 'ruleset').stdout)
        destination = work/'profile'; destination.mkdir(mode=0o700)
        base.run('/usr/bin/router-policy-profile', '-baseline', str(work/'baseline.json'),
            '-ruleset', str(work/'ruleset.json'), '-output-directory', str(destination))
        metadata = json.loads((destination/'router-profile-metadata.json').read_bytes())
        profile = (destination/'router-profile.json').read_bytes().removesuffix(b'\n')
        require(hashlib.sha256(profile).hexdigest() == metadata['profile_sha256'], 'Profile digest differs.')
        parent = Path(contract['profile_directory'])
        (parent/'profile.json').write_bytes(profile); (parent/'profile.json').chmod(0o400)
        shutil.copyfile(destination/'router-guards.nft', parent/'guards.nft'); (parent/'guards.nft').chmod(0o400)
        base.run('nft', '-f', str(parent/'guards.nft'))
    # A trusted companion may now install/start generated service dependencies
    # using the actual completed profile. No runtime CLI or source intent can
    # select this hook, and the baseline, floor and guard artifacts stay pinned.
    if after_profile is not None:
        after_profile(copy.deepcopy(value), dict(files), copy.deepcopy(contract), dict(metadata))
    policy_runtime.publish_runtime(contract, metadata, 'c'*64)
    policy_runtime.empty_bindings()
    base.run('/usr/bin/router-policy-helper', '-config-directory', str(policy_runtime.CONFIG), '-initialize-state')
    units = Path('/run/systemd/system')
    names = (base.HELPER, *base.SOCKETS, *base.DEPENDENCIES, 'kea-dhcp4-server.service', 'freeradius.service')
    for name in (base.HELPER, base.DEPENDENCIES[1]):
        (units/name).write_text(files['usr/lib/systemd/system/'+name])
    for name in base.SOCKETS:
        shutil.copyfile(ROOT/'mkosi/base/mkosi.extra/usr/lib/systemd/system'/name, units/name)
    (units/base.DEPENDENCIES[0]).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    (units/base.DEPENDENCIES[2]).write_text('[Service]\nType=exec\nExecStart=/usr/bin/sleep 600\n')
    accounting = Path('/run/synthetic-accounting.py'); accounting.write_text(ACCOUNTING); accounting.chmod(0o644)
    (units/'freeradius.service').write_text('[Service]\nType=exec\nUser=freerad\nGroup=freerad\n'
        'ExecStart=/usr/bin/python3 -I /run/synthetic-accounting.py\nSyslogIdentifier=freeradius\n'
        'StandardOutput=journal\nStandardError=journal\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n')
    account = pwd.getpwnam('_kea')
    path = Path('/etc/kea/kea-dhcp4.conf'); path.write_text(files['etc/kea/kea-dhcp4.conf'])
    os.chown(path, 0, account.pw_gid); path.chmod(0o640)
    dropin = units/'kea-dhcp4-server.service.d'; dropin.mkdir()
    hardening = 'mkosi/base/mkosi.extra/etc/systemd/system/kea-dhcp4-server.service.d/30-lanrith-hardening.conf'
    shutil.copyfile(ROOT/hardening, dropin/'30-lanrith-hardening.conf')
    (dropin/'60-lanrith-control.conf').write_text(files['etc/systemd/system/kea-dhcp4-server.service.d/60-lanrith-control.conf'])
    state = Path('/var/lib/kea'); state.mkdir(exist_ok=True)
    os.chown(state, account.pw_uid, account.pw_gid); state.chmod(0o750)
    expiry = int(time.time())+600
    lease = {'address': IP, 'hwaddr': MAC, 'client_id': '', 'valid_lifetime': '3600', 'expire': str(expiry),
        'subnet_id': '22', 'fqdn_fwd': '0', 'fqdn_rev': '0', 'hostname': 'synthetic-binding', 'state': '0', 'user_context': ''}
    path = state/'kea-leases4.csv'
    with path.open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(lease), lineterminator='\n'); writer.writeheader(); writer.writerow(lease)
    os.chown(path, account.pw_uid, account.pw_gid); path.chmod(0o600)
    checks, observed, paused = [], {}, None
    def bindings(): return json.loads((policy_runtime.BINDINGS/'bindings.json').read_bytes())
    # The generated helper admits a five-second processing budget. The test
    # client must allow that complete budget plus reply delivery; this never
    # changes the server deadline, evidence freshness or authorization lease.
    def submit(): return base.request(base.PROPOSAL, snapshot(), uid=1701, gid=1701,
                                      response_timeout=7).get('reply', {})
    def observe(): return base.request(policy_runtime.OBSERVATIONS, base.OBSERVE).get('reply', {})
    try:
        base.run('systemctl', 'daemon-reload')
        base.run('systemctl', 'start', 'systemd-journald.service')
        # The base boot dependencies are deliberately not an image boot test.
        base.run('systemctl', '--job-mode=ignore-dependencies', 'start', 'kea-dhcp4-server.service')
        base.run('systemctl', 'start', base.HELPER, timeout=110)
        pid = base.run('systemctl', 'show', '--property=MainPID', '--value', base.HELPER).stdout.strip()
        initial = submit()
        require(initial.get('status') == 'applied' and initial['grant_count'] == 0,
            'First directory enrollment must be deny-only without ownership evidence: '+
            json.dumps({'receipt': initial, 'binding': bindings(), 'status': base.request(base.STATUS,
                {'schema_version': 1, 'operation': 'status'}, uid=1702, gid=1702)}, sort_keys=True))
        require(policy_runtime.cohort(contract) == [MAC], 'Actual helper did not persist the enrolled cohort.')
        checks.append('directory-enrollment-persists-nonempty-cohort-without-ownership-or-permission')
        wait(lambda: bindings()['complete'] and bindings()['records'])
        first = bindings(); record, = first['records']; address, = record['addresses']
        require(record['mac'] == MAC and record['interface'] == 'lan.22' and record['vlan'] == 22 and
            address['ip'] == IP and address['source'] == 'kea_dhcp4', 'Actual collected binding differs.')
        checks.append('generated-producer-joins-real-journal-kea-and-vlan-placement')
        applied = submit()
        require(applied.get('status') == 'applied' and applied['grant_count'] > 0,
            'Fresh independent ownership and directory evidence did not admit the exact grant: '+
            json.dumps({'receipt': applied, 'status': base.request(base.STATUS,
                {'schema_version': 1, 'operation': 'status'}, uid=1702, gid=1702)}, sort_keys=True))
        grant = observe()['snapshot']
        require(grant['complete'] and grant['total'] > 0, 'Actual nonempty policy observation missing.')
        observed.update(binding=first, grant_snapshot=grant)
        checks.append('fresh-directory-and-collected-ownership-produce-nonempty-enforcing-observation')
        if observe_stage is not None: observe_stage('applied', value, files)
        # Pause the real daemon while preserving its dependency state. An
        # explicit unit stop would also stop its Requires= dependents.
        paused = int(base.run('systemctl', 'show', '--property=MainPID', '--value', 'kea-dhcp4-server.service').stdout)
        os.kill(paused, signal.SIGSTOP)
        wait(lambda: not bindings()['complete'])
        denied = submit()
        require(denied.get('status') == 'rejected', 'Missing Kea evidence admitted a directory request.')
        # A source query can consume its full deadline. Keep it stalled long
        # enough to cover helper supervision and the collector's own negative
        # publication, rather than only the runtime wrapper's first marker.
        negative_markers = []
        for _ in range(12):
            time.sleep(1)
            negative = bindings()
            if not negative['complete']:
                require(negative['schema_version'] == 1 and negative['generation'] and
                    negative['observed_at'] != '0001-01-01T00:00:00Z' and negative['records'] == [],
                    'Native collector emitted a malformed incomplete envelope.')
                if len(negative['generation']) == 64: negative_markers.append(negative)
            require(base.run('systemctl', 'show', '--property=MainPID', '--value', base.HELPER).stdout.strip() == pid and
                base.run('systemctl', 'show', '--property=NRestarts', '--value', base.HELPER).stdout.strip() == b'0',
                'A stalled source or collector negative publication restarted the enforcing helper.')
        require(negative_markers, 'Actual native collector negative publication was not observed.')
        observed['collector_negative_markers'] = negative_markers
        checks.append('native-collector-negative-marker-retains-loader-contract-through-source-deadline')
        checks.append('kea-source-loss-invalidates-complete-export-and-denies-directory-request')
        if observe_stage is not None: observe_stage('incomplete', value, files)
        os.kill(paused, signal.SIGCONT); paused = None
        wait(lambda: bindings()['complete'] and bindings()['records'])
        require(base.run('systemctl', 'show', '--property=MainPID', '--value', base.HELPER).stdout.strip() == pid,
            'Evidence source recovery restarted the enforcing helper.')
        status = base.request(base.STATUS, {'schema_version': 1, 'operation': 'status'}, uid=1702, gid=1702)['reply']
        require(status['report']['permit_state'] == 'sealed', 'Recovered ownership restored a cached directory grant.')
        if observe_stage is not None: observe_stage('bindings-recovered', value, files)
        require(submit().get('grant_count', 0) > 0, 'Fresh directory confirmation did not restore permission.')
        if observe_stage is not None: observe_stage('directory-reconfirmed', value, files)
        checks.append('recovered-producer-needs-fresh-directory-confirmation-without-helper-restart')
    except BaseException:
        try:
            diagnostic = {'result': 'failure-diagnostic-only', 'bindings': bindings(),
                'links': json.loads(base.run('ip', '-d', '-j', 'link').stdout)}
            output.with_suffix('.failure.json').write_bytes(canonical(diagnostic))
        except Exception:
            pass  # Preserve the original failure if its diagnostic read fails.
        raw = base.run('journalctl', '--no-pager', '-n', '60', '-u', base.HELPER, '-u', base.DEPENDENCIES[1],
            '-u', 'kea-dhcp4-server.service', check=False).stdout
        sys.stderr.buffer.write(raw[-16000:])  # Only isolated synthetic data.
        raise
    finally:
        if paused is not None: os.kill(paused, signal.SIGCONT)
        base.run('systemctl', 'stop', *names, check=False)
        for name in names:
            (units/name).unlink(missing_ok=True)
        shutil.rmtree(dropin)
        base.run('systemctl', 'daemon-reload')
        base.run('nft', 'flush', 'ruleset')
        for name in reversed(interfaces): base.run('ip', 'link', 'delete', name)
    require(sources == {name: sha(ROOT/name) for name in sources} and sha(candidate/COLLECTOR) == collector_sha,
        'Source or candidate collector changed during qualification.')
    result = {'schema': 1, 'result': 'pass', 'test': 'offline-nonempty-generated-policy-bindings',
        'assessed_at': datetime.now(timezone.utc).isoformat(), 'checks': checks, 'observed': observed,
        'component': component, 'collector_sha256': collector_sha, 'source_sha256': sources,
        'external_network': False, 'private_image_qualified': False, 'selected_pinned_component_qualified': False,
        'limits': ['synthetic two-network topology, directory proposals and accounting service',
            'real Kea serves a lease seeded before startup; no DHCP packets or RADIUS/LDAP authentication',
            'development component bytes only; no release/package admission',
            'no application packets, translators, complete image boot, upgrade/fallback or physical acceptance']}
    with output.open('xb') as stream: stream.write(canonical(result))
    print(json.dumps({'result': 'pass', 'checks': len(checks)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--collector-sha256', required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    qualify(args.candidate, args.collector_sha256, args.result)
