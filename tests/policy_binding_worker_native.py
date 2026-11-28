#!/usr/bin/env python3
"""Exercise both package-selected binding graphs in a disposable systemd guest."""
import argparse
import ast
import csv
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import config, policy_runtime as runtime
from kea_control_systemd_native import stage
from policy_bindings_component_native import ACCOUNTING, MAC
from policy_observer_component_native import prepare_interfaces
from test_radius import declaration


def run(*args):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL, timeout=60)


def finalize():
    source = ROOT/'scripts/finalize-image.py'
    node = next(n for n in ast.parse(source.read_text()).body if isinstance(n, ast.FunctionDef)
                and n.name == 'finalize_binding_worker')
    scope = {'os': os, 'stat': stat, 'subprocess': subprocess}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), scope)
    scope['finalize_binding_worker'](Path('/'))


def status():
    path = runtime.BINDINGS/'bindings.json'
    with path.open('rb') as stream:
        return (json.load(stream), json.loads(os.getxattr(stream.fileno(), runtime.STATUS_ATTRIBUTE)))


def sample(previous, outcome):
    end = time.monotonic()+50
    while time.monotonic() < end:
        try:
            snapshot, metadata = status()
        except (FileNotFoundError, OSError):
            time.sleep(.1)
            continue
        if snapshot['generation'] != previous and metadata['outcome'] == outcome:
            return snapshot, metadata
        time.sleep(.1)
    run('journalctl', '--no-pager', '-n', '45', '-u', 'lanrith-policy-bindings',
        '-u', 'lanrith-policy-evidence@*', '-u', 'lanrith-kea-leases')
    raise AssertionError('Missing publication '+outcome)


def fixture(compatible, worker):
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert [row['ifname'] for row in json.loads(subprocess.check_output(['ip','-j','link']))] == ['lo']
    assert compatible.is_file() and worker.is_file()
    value = declaration()
    value['networks']['devices']['dhcp4']['id'] = 22
    value = config.normalize(value)
    files = config.render(value)
    account = stage(files)
    prepare_interfaces(value)
    for network in value['networks'].values():
        for address in network['addresses']:
            run('ip', 'addr', 'add', address, 'dev', network['name'], *(['nodad'] if ':' in address else []))
    run('groupadd', '--system', 'lanrith-kea-lease-readers')
    state = Path('/var/lib/kea')
    state.mkdir(exist_ok=True)
    os.chown(state, account.pw_uid, account.pw_gid)
    lease = {'address':'192.168.22.120','hwaddr':MAC,'client_id':'','valid_lifetime':3600,
        'expire':int(time.time())+1200,'subnet_id':22,'fqdn_fwd':0,'fqdn_rev':0,'hostname':'',
        'state':0,'user_context':''}
    csv_path = state/'kea-leases4.csv'
    with csv_path.open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=lease, lineterminator="\n")
        writer.writeheader()
        writer.writerow(lease)
    os.chown(csv_path, account.pw_uid, account.pw_gid)
    runtime.CONTRACT.parent.mkdir(parents=True, exist_ok=True)
    runtime.CONTRACT.write_text(files[str(runtime.CONTRACT).lstrip('/')])
    runtime.CONTRACT.chmod(0o600)
    contract = runtime.load_contract()
    for path in (runtime.ROOT,runtime.BINDINGS,runtime.COLLECTOR,Path(contract['state_directory'])):
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    runtime.atomic(Path(contract['state_directory'])/'state.json', {
        'schema_version':2,'cohort_macs':[MAC],'classified_ipv4':[],'classified_ipv6':[],
        'ledger':{},'last_directory_observed_at':None,'directory_hash':''})
    library = Path('/usr/lib/lanrith/lanrith')
    for name in ('__init__.py','policy_runtime.py'):
        shutil.copyfile(ROOT/'lanrith'/name, library/name)
    wrapper = library.parent/'policy-runtime'
    wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                       'from lanrith.policy_runtime import main\nsys.exit(main())\n')
    wrapper.chmod(0o755)
    units = Path('/etc/systemd/system')
    name = 'lanrith-policy-bindings.service'
    (units/name).write_text(files['usr/lib/systemd/system/'+name])
    dropin = 'etc/systemd/system/'+name+'.d/65-lanrith-kea.conf'
    target = Path('/')/dropin
    target.parent.mkdir(exist_ok=True)
    target.write_text(files[dropin])
    (units/'lanrith-policy-bootstrap.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    event = Path('/run/fixture-accounting.py')
    # Exceed one native journal page before the enrolled Start. The legacy
    # collector sees closed unrelated sessions, and the worker must paginate
    # and reach the authenticated tail before it can publish the one owner.
    prelude = """ if duration==0:
  other = dict(value, mac="020000002278", ipv4="192.168.22.121", status="Stop")
  for sequence in range(260):
   other["session_id_hex"] = format(4096+sequence, "04x")
   print("radius-policy-accounting-v1 "+json.dumps(other,separators=(",",":")),flush=True)
"""
    event.write_text(ACCOUNTING.replace(' print("radius-policy-accounting-v1 ', prelude+' print("radius-policy-accounting-v1 '))
    (units/'freeradius.service').write_text('[Service]\nType=exec\nUser=freerad\nGroup=freerad\n'
        'ExecStart=/usr/bin/python3 -I /run/fixture-accounting.py\nSyslogIdentifier=freeradius\n'
        'StandardOutput=journal\n')
    executable = Path(contract['collector_executable'])
    shutil.copy(compatible,executable)
    finalize()
    assert target.exists() and not (units/name.replace('bindings.service','evidence.socket')).exists()
    run('systemctl','daemon-reload')
    run('systemctl','start','kea-dhcp4-server.service')
    run('systemctl','start','lanrith-kea-leases.service','freeradius.service')
    run('systemctl','start',name)
    first,_ = sample('', 'complete')
    assert [r['mac'] for r in first['records']] == [MAC], first
    run('systemctl','stop',name)
    shutil.copy(worker,executable)
    marker = Path('/usr/share/router-policy-agent/binding-worker-v1')
    marker.parent.mkdir(exist_ok=True)
    marker.write_text('binding-worker-v1\n')
    finalize()
    assert not target.exists()
    run('systemctl','daemon-reload')
    run('systemctl','start',name)
    new,success = sample(first['generation'],'complete')
    assert [r['mac'] for r in new['records']] == [MAC], new
    checkpoint = Path('/run/lanrith-policy-evidence/accounting-v1.json')
    assert checkpoint.stat().st_uid == pwd.getpwnam('lanrith-policy-evidence').pw_uid
    assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600
    denied = subprocess.run(['runuser','-u','lanrith-policy-evidence','--','/usr/bin/python3','-c',
        'import socket;s=socket.socket(socket.AF_UNIX);s.connect("/run/lanrith-policy-evidence.sock")'],
        capture_output=True)
    assert denied.returncode != 0
    for path in (Path(contract['state_directory'])/'state.json', Path('/run/kea/kea4-ctrl-socket'),
                 runtime.BINDINGS/'bindings.json'):
        access = subprocess.run(['runuser', '-u', 'lanrith-policy-evidence', '--', 'test', '-r', str(path)])
        assert access.returncode != 0, path
    # Restart the supervisor to sample immediately; the previous snapshot and
    # the worker's runtime checkpoint survive process exit.
    run('systemctl','restart',name)
    deadline = time.monotonic()+25
    while time.monotonic()<deadline:
        current,meta=status()
        assert current['complete'] and current['records'] and meta['outcome']=='complete'
        if meta['last_success']!=success['last_success']:
            break
        time.sleep(.05)
    else:
        raise AssertionError('No successful second worker pass')
    prior_success = meta['last_success']
    pid = int(subprocess.check_output(['systemctl','show','-P','MainPID','kea-dhcp4-server.service']))
    os.kill(pid,signal.SIGSTOP)
    try:
        run('systemctl','restart',name)
        failed, negative = sample(current['generation'],'lease')
        assert not failed['complete'] and failed['records']==[] and negative['last_success']==prior_success
    finally:
        os.kill(pid,signal.SIGCONT)
    run('systemctl','restart',name)
    result,_ = sample(failed['generation'],'complete')
    assert [r['mac'] for r in result['records']] == [MAC]
    print('Pinned staged collector and socket-activated evidence worker passed DHCP, journal, VLAN, checkpoint, denial and recovery checks.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compatible',type=Path)
    parser.add_argument('worker',type=Path)
    args = parser.parse_args()
    try:
        fixture(args.compatible,args.worker)
    except BaseException:
        subprocess.run(['journalctl','--no-pager','--all','-n','60','-u','kea-dhcp4-server','-u','lanrith-kea-leases','-u','lanrith-policy-bindings','-u','lanrith-policy-evidence@*'])
        raise
