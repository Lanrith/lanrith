"""Compose the kernel packet fixture with actual build/account/systemd wiring."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import tarfile
import time

from lanrith import build, config, firewall_observations as generation
from test_extension_network import manifest


DIRECTORY = Path('/run/lanrith-firewall-observations')


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, timeout=8)
    if check and result.returncode:
        sys.stderr.buffer.write((result.stdout+result.stderr)[-8192:])
        result.check_returncode()
    return result


def wait(probe, seconds=20):
    deadline = time.monotonic()+seconds
    while True:
        value = probe()
        if value:
            return value
        assert time.monotonic() < deadline, 'Generated firewall observer deadline expired.'
        time.sleep(.1)


def health():
    try:return json.loads((DIRECTORY/'health.json').read_bytes())
    except (FileNotFoundError, json.JSONDecodeError):return None


class Receiver:
    def __init__(self, value, baseline, root):
        assert Path('/proc/1/comm').read_text().strip() == 'systemd'
        self.root, self.baseline, self.returncode = root, baseline, None
        # Rootless containers cannot mount these host-kernel pseudo filesystems.
        # Quarantine only their pre-existing failures, before testing any unit.
        # Never clear an observer/core failure to satisfy the real boot check.
        failed = run('systemctl', '--failed', '--no-legend', '--plain', '--no-pager').stdout.decode()
        self.preexisting_failures = sorted(line.split()[0] for line in failed.splitlines() if line.strip())
        self.exclusions = sorted({'sys-kernel-config.mount', 'sys-kernel-debug.mount', 'sys-kernel-tracing.mount',
                                  'proc-sys-fs-binfmt_misc.automount'})
        assert set(self.preexisting_failures) <= set(self.exclusions), failed
        run('systemctl', 'mask', '--runtime', *self.exclusions)
        run('systemctl', 'reset-failed', *self.exclusions)
        value = copy.deepcopy(value)
        value['extensions'] = ['example-observer']
        extension = root/'extension'
        extension.mkdir()
        pin = manifest(extension, observations=[{'service': 'firewall', 'user': 'example-agent'}])
        base = root/'accounts.tar'
        with tarfile.open(base, 'w') as archive:
            for name in ('etc/passwd', 'etc/group'):
                data = (Path('/')/name).read_bytes()
                item = tarfile.TarInfo(name)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
        assert config.render(value)[generation.RULESET] == baseline
        build.assembly(value, base, root/'assembly', version='0.1.0', sequence=9,
                       integrations={'example-observer': (extension, pin)})
        tree = root/'assembly/mkosi.extra'
        self.files = generation.render({'user': 'example-agent', 'uid': 1801, 'gid': 1801}, baseline)
        names = [*self.files, 'etc/passwd', 'etc/group',
                 *['usr/lib/lanrith/lanrith/'+name for name in
                   ('firewall_observations_runtime.py', 'firewall_metadata.py', 'observation_spool.py')]]
        self.assembly = {name: hashlib.sha256((tree/name).read_bytes()).hexdigest() for name in names}
        for name in ('etc/passwd', 'etc/group'):
            shutil.copyfile(tree/name, Path('/')/name)
        shutil.copytree(tree/'usr/lib/lanrith/lanrith', '/usr/lib/lanrith/lanrith', dirs_exist_ok=True)
        for name in self.files:
            target = Path('/')/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tree/name, target)
            target.chmod(0o755 if name.endswith('/firewall-observations-runtime') else 0o644)
        hidden = Path('/etc/systemd/system')/(generation.SERVICE+'.d')
        hidden.mkdir()
        (hidden/'90-fixture.conf').write_text('[Service]\nInaccessiblePaths=/source /output\n')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'nftables.service')
        wait(health)
        self.pid = int(run('systemctl', 'show', '--property=MainPID', '--value', generation.SERVICE).stdout)
        status = dict(line.split(':', 1) for line in Path(f'/proc/{self.pid}/status').read_text().splitlines())
        user = pwd.getpwnam(generation.ACCOUNT)
        assert set(status['Uid'].split()) == {str(user.pw_uid)} and user.pw_uid != 0
        caps = {key: status[key].strip() for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd', 'NoNewPrivs')}
        assert all(int(caps[key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'))
        assert int(caps['CapBnd'], 16) == 1 << 12 and caps['NoNewPrivs'] == '1'
        for prop, expected in (('MemoryMax', b'67108864'), ('TasksMax', b'8')):
            assert run('systemctl', 'show', '--property='+prop, '--value', generation.SERVICE).stdout.strip() == expected
        clone = ['setpriv', '--reuid='+str(user.pw_uid), '--regid=1801', '--clear-groups', '--bounding-set=-all', '--no-new-privs']
        assert run(*clone, 'nft', 'add', 'table', 'inet', 'forbidden', check=False).returncode != 0
        probe = 'import sys;sys.path.insert(0,"/usr/lib/lanrith");from lanrith.firewall_metadata import kernel_listener;kernel_listener()'
        assert run(*clone, 'python3', '-I', '-c', probe, check=False).returncode != 0
        role = {'uid': user.pw_uid, 'capabilities': caps, 'port': None,
                'fixture_kernel_mount_exclusions': self.exclusions,
                'preexisting_fixture_failures': self.preexisting_failures,
                'firewall_write_denied': True, 'reconfiguration_denied': True,
                'denial_probe_scope': 'same-UID capability-empty child; actual main PID capability fields independently verified'}
        (root/'ready.json').write_text(json.dumps(role))
        self.initial_epoch = health()['producer_epoch']

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if not Path(f'/proc/{self.pid}').exists():
            return 1
        values = []
        for name in ('events.jsonl.2', 'events.jsonl.1', 'events.jsonl'):
            path = DIRECTORY/name
            if not path.exists():
                continue
            data = path.read_bytes()
            for line in data[:data.rfind(b'\n')+1].splitlines():
                values.append(json.loads(line))
        (self.root/'rows.json').write_text(json.dumps(values))
        return None

    def send_signal(self, signum):
        if self.returncode is None:
            os.kill(self.pid, signum)

    def terminate(self):
        run('systemctl', 'stop', generation.SERVICE)
        self.returncode = 0

    def wait(self, timeout):
        return self.returncode

    def communicate(self):
        return b'', run('journalctl', '-u', generation.SERVICE, '--no-pager', '-n', '15').stdout[-8192:]

    def qualify_lifecycle(self, udp):
        run('systemctl', 'start', generation.SERVICE)
        wait(lambda: (value if (value := health()) and value['producer_epoch'] != self.initial_epoch else None))
        before = health()['producer_epoch']
        pid = int(run('systemctl', 'show', '--property=MainPID', '--value', generation.SERVICE).stdout)
        os.kill(pid, signal.SIGKILL)
        wait(lambda: (value if (value := health()) and value['producer_epoch'] != before else None))
        udp('192.0.2.1', 54321)
        udp('192.0.2.1', 23456, allowed=True)
        wait(lambda: (DIRECTORY/'events.jsonl').exists())
        role = 'from pathlib import Path\np=Path("/run/lanrith-firewall-observations/events.jsonl");assert p.read_bytes()\n'
        role += 'assert Path("/run/lanrith-firewall-observations/health.json").read_bytes()\n'
        role += 'for target in (p,p.parent/"forbidden"):\n try:target.open("ab").close()\n except PermissionError:pass\n else:raise AssertionError("reader can write metadata")\n'
        guard = Path('/var/lib/lanrith/credentials/firewall-fixture-guard')
        guard.parent.mkdir(parents=True, exist_ok=True)
        guard.parent.chmod(0o700)
        guard.write_text('SYNTHETIC_PRIVATE_GUARD')
        guard.chmod(0o600)
        role += 'try:Path("/var/lib/lanrith/credentials/firewall-fixture-guard").read_bytes()\nexcept PermissionError:pass\nelse:raise AssertionError("reader can read credentials")\n'
        run('setpriv', '--reuid=1801', '--regid=1801', '--clear-groups', '--bounding-set=-all', '--no-new-privs', 'python3', '-I', '-c', role)
        outsider = run('setpriv', '--reuid=1802', '--regid=1802', '--clear-groups', '--bounding-set=-all', '--no-new-privs',
                      'python3', '-I', '-c', 'from pathlib import Path;Path("/run/lanrith-firewall-observations/events.jsonl").read_bytes()', check=False)
        assert outsider.returncode != 0 and b'PermissionError' in outsider.stderr
        contract = Path('/')/generation.CONFIG
        valid = contract.read_bytes()
        contract.write_text('{"schema":2}')
        restart_count = int(run('systemctl', 'show', '--property=NRestarts', '--value', generation.SERVICE).stdout)
        run('systemctl', 'kill', '--signal=KILL', generation.SERVICE)
        wait(lambda: run('systemctl', 'show', '--property=ExecMainStatus', '--value', generation.SERVICE).stdout.strip() == b'1' and
             int(run('systemctl', 'show', '--property=NRestarts', '--value', generation.SERVICE).stdout) > restart_count, seconds=30)
        assert run('systemctl', 'is-failed', '--quiet', generation.SERVICE, check=False).returncode != 0
        run('systemctl', 'start', 'systemd-boot-check-no-failures.service')
        assert run('systemctl', 'is-active', 'nftables.service').stdout.strip() == b'active'
        udp('192.0.2.1', 54321)
        udp('192.0.2.1', 23456, allowed=True)
        contract.write_bytes(valid)
        run('systemctl', 'stop', generation.SERVICE)
        for name in self.files:
            if name != generation.RULESET:
                (Path('/')/name).unlink()
        (Path('/etc/systemd/system')/(generation.SERVICE+'.d')/'90-fixture.conf').unlink()
        Path('/etc/nftables.conf').write_text(self.baseline)
        run('systemctl', 'daemon-reload')
        run('nft', '-f', '/etc/nftables.conf')
        assert not DIRECTORY.exists()
        udp('192.0.2.1', 54321)
        udp('192.0.2.1', 23456, allowed=True)
        return ['actual build-allocated account, curated runtime and generated resource-bound systemd unit',
                'admitted reader can read but not write; unrelated capability-empty UID cannot read',
                'forced process loss changes producer epoch and resumes metadata',
                'invalid collector contract preserves firewall, allowed/denied packets and actual global boot check',
                'disabled endpoint removes metadata/activation and preserves default-deny and permitted forwarding']
