#!/usr/bin/env python3
"""Qualify an experimental root-disabled image on a disposable VM disk."""
import argparse
from contextlib import ExitStack
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time

from lanrith import build, config, release
from qualify_bound_observation_vm import require_matching_base
from vm import Guest, PROJECT, boot, factory_medium, image, regular, run, stop, upload


def diagnostic_image(value, base, initrd, work, secret, *, diagnose):
    """Include synthetic, fixed-category SSH diagnostics before signing."""
    assembly = work/'image-9'
    identity = build.assembly(value, base, assembly, version='0.1.0', sequence=9,
                              certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
    if diagnose:
        tree = assembly/'mkosi.extra'
        dropin = tree/'etc/systemd/system/ssh.service.d/99-qualification.conf'
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text('[Unit]\nOnFailure=lanrith-ssh-diagnostic.service\n')
        helper = tree/'usr/lib/lanrith/qualification-ssh-diagnostic'
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text('''import subprocess\nr = subprocess.run(["journalctl", "--no-pager", "-b", "-u", "ssh.service"], capture_output=True, text=True, timeout=20)\ns = r.stdout.lower()\nfor category, text in (("no-hostkey", "no hostkeys available"), ("hostkey-load", "unable to load host key"), ("permission", "permission denied"), ("operation", "operation not permitted"), ("bad-config", "bad configuration option"), ("privsep", "privilege separation"), ("missing-file", "no such file or directory"), ("status-203", "status=203/exec"), ("status-226", "status=226/namespace"), ("namespace", "failed to set up mount namespacing"), ("status-255", "status=255"), ("core-dump", "core-dump"), ("upload-path", "/var/tmp/lanrith-update"), ("hostkey-path", "/var/lib/lanrith/ssh-host-keys"), ("sshd-path", "/usr/sbin/sshd"), ("sshd-runtime-path", "/run/sshd"), ("config-path", "/etc/ssh"), ("sshd-session", "sshd-session"), ("library", "error while loading shared libraries"), ("fatal", "fatal:"), ("sandbox", "sandbox"), ("seccomp", "seccomp"), ("chroot", "chroot"), ("rexec", "rexec"), ("exec-error", "exec of"), ("error", "error:"), ("failed", "failed"), ("closed", "closed"), ("signal", "signal"), ("not-found", "not found"), ("exit", "exited"), ("refused", "refused"), ("bad", "bad "), ("uids", "uids"), ("key-exchange", "kex_exchange"), ("maxstartups", "maxstartups"), ("broken-pipe", "broken pipe"), ("invalid", "invalid"), ("connection", "connection"), ("preauth", "preauth"), ("ssh-auth", "sshd-auth"), ("signal-31", "signal 31"), ("signal-11", "signal 11"), ("signal-6", "signal 6"), ("signal-4", "signal 4"), ("signal-9", "signal 9"), ("bad-syscall", "bad system call"), ("sigsys", "sigsys"), ("monitor", "monitor"), ("authenticated", "authenticated"), ("killed", "killed"), ("recv-error", "ssh_msg_recv")):\n    if text in s: print("LANRITH_QA_SSH_"+category, flush=True)\nprint("LANRITH_QA_SSH_failure", flush=True)\n''')
        unit = tree/'usr/lib/systemd/system/lanrith-ssh-diagnostic.service'
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text('[Unit]\nDescription=Synthetic SSH failure category\nAfter=ssh.service\n'
                        '[Service]\nType=oneshot\nStandardOutput=journal+console\n'
                        'ExecStart=/usr/bin/python3 -I /usr/lib/lanrith/qualification-ssh-diagnostic\n')
        probe = tree/'usr/lib/systemd/system/lanrith-ssh-session-diagnostic.service'
        probe.write_text('[Unit]\nDescription=Synthetic SSH session failure category\nAfter=ssh.service\n'
                         '[Service]\nType=oneshot\nExecStartPre=/bin/sleep 45\nStandardOutput=journal+console\n'
                         'ExecStart=/usr/bin/python3 -I /usr/lib/lanrith/qualification-ssh-diagnostic\n')
        wants = tree/'usr/lib/systemd/system/multi-user.target.wants/lanrith-ssh-session-diagnostic.service'
        wants.parent.mkdir(parents=True, exist_ok=True)
        wants.symlink_to('../lanrith-ssh-session-diagnostic.service')
    build.run(assembly)
    update = work/'update-9'
    build.update_payload(assembly, identity, update)
    release.sign(update, secret/'test.key')
    release.verify(update, secret/'test.crt', purpose='update', image_id='lanrith')
    return assembly, identity, update


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--direct', action='store_true', help='boot without factory installer')
    parser.add_argument('--diagnose', action='store_true', help='include synthetic SSH diagnostics')
    parser.add_argument('--update', action='store_true', help='also exercise one signed operator A/B update')
    args = parser.parse_args()
    base, initrd = regular(args.base), regular(args.initrd_base)
    matched = require_matching_base(base)
    work = args.work
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Qualification requires a new disposable workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': ('synthetic-root-disabled-operator-update' if args.update else
                                    'synthetic-root-disabled-first-boot-only'), 'result': 'fail',
              'synthetic_operator_update_passed': False, 'physical_homelab_qualified': False, 'direct_boot': args.direct, 'test_only_diagnostics': args.diagnose,
              'automatic_fallback_qualified': False, 'branch_overlay_files_matched': matched,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-rootless.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Rootless Test', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(secret/'ssh'))
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            (secret/'serial.hash').write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
            (secret/'serial.hash').chmod(0o600)
            agent = subprocess.Popen(['ssh-agent', '-D', '-a', str(secret/'agent.sock')],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            resources.callback(stop, agent)
            deadline = time.monotonic()+15
            while not (secret/'agent.sock').exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            run('ssh-add', str(secret/'ssh'), env={**os.environ, 'SSH_AUTH_SOCK': str(secret/'agent.sock')})
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-lanrith-qa-disk'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8'}
            value['administration']['root_access'] = 'disabled'
            value['administration']['serial'] = {'enabled': False}
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            assembly, identity, update = diagnostic_image(value, base, initrd, work, secret, diagnose=args.diagnose)
            target = work/'synthetic-target.raw'
            if args.direct:
                shutil.copyfile(assembly/'output/lanrith_9.raw', target)
                with target.open('r+b') as stream:
                    stream.truncate(40*1024**3)
                medium = None
            else:
                with target.open('xb') as stream:
                    stream.truncate(40*1024**3)
                medium = factory_medium(assembly, identity, update, work, secret)
            guest = Guest(work/'guest', secret, target, medium=medium, tpm=True)
            try:
                if not args.direct:
                    print('Rootless VM: installing signed synthetic image.', flush=True)
                    guest.start()
                    event = guest.expect_any([rb'Type ERASE-AND-INSTALL .* to continue: ',
                                              rb'(?:You are in|Entering) emergency mode'])
                    release.require(event == 0, 'Synthetic installer entered emergency mode.')
                    guest.serial.sendall(b'ERASE-AND-INSTALL /dev/disk/by-id/virtio-lanrith-qa-disk\r')
                    guest.expect(rb'Installation read-back passed')
                    guest.wait_shutdown(); guest.close(); guest.medium = None
                boot(guest, first=True, root_access=False)
                print('Rootless VM: checking operator boundaries.', flush=True)
                root_ssh = guest.ssh_arguments('id -u', agent=False)
                root_ssh[-2] = 'root@127.0.0.1'
                login = subprocess.run(root_ssh, stdin=subprocess.DEVNULL, capture_output=True,
                                       env=guest.environment, timeout=30)
                release.require(login.returncode != 0, 'Synthetic image accepted root SSH login.')
                probe = r'''set -eu
test "$(id -u)" -ne 0
! id -nG | tr ' ' '\n' | grep -qx sudo
test "$(awk -F: '$1 == "root" {print $7}' /etc/passwd)" = /usr/sbin/nologin
for path in /usr/bin/sudo /usr/bin/sudoedit /usr/bin/su /bin/su /etc/sudoers /etc/sudoers.d; do
  test ! -e "$path" && test ! -L "$path"
done
grep -qx 'AllowAgentForwarding no' /etc/ssh/sshd_config.d/00-lanrith.conf
test "$(systemctl show --property NoNewPrivileges --value ssh.service)" = yes
grep -Eq '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
grep -Eq '^CapEff:[[:space:]]*0+$' /proc/self/status
for command in 'sudo -n id' 'su -c id' 'systemd-run --quiet --wait /usr/bin/id' \
  'systemctl restart ssh.service' 'lanrith-runtime accept 9'; do
  if sh -c "$command" >/dev/null 2>&1; then exit 77; fi
done
test ! -e /etc/lanrith/config.yaml
! find /usr/share/lanrith /usr/lib/lanrith -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .
mkdir -m 0700 /var/tmp/lanrith-update/rootless-probe
rmdir /var/tmp/lanrith-update/rootless-probe
lanrith-image status >/dev/null
'''
                release.require(guest.ssh('sh -c '+shlex.quote(probe), success=False).returncode == 0,
                                'Synthetic rootless operator boundary failed.')
                deadline = time.monotonic()+180
                while time.monotonic() < deadline:
                    status = json.loads(guest.ssh('lanrith-image status', agent=False).stdout)
                    if (status.get('accepted') or {}).get('deployment_sequence') == 9:
                        break
                    time.sleep(2)
                else:
                    raise release.ReleaseError('Synthetic operator did not observe the accepted image.')
                report.update(result='pass', checks=([] if args.direct else ['signed-factory-install'])+['secure-boot',
                    'root-disabled-first-boot', 'operator-ssh', 'root-ssh-denied', 'operator-status', 'no-sudo-or-su',
                    'session-no-new-privileges', 'session-effective-capabilities-empty',
                    'runtime-source-yaml-absent'])
                if args.update:
                    report['result'] = 'fail'
                    machine_identity = guest.ssh('cat /etc/machine-id', agent=False).stdout
                    guest.ssh("printf synthetic-persistent-state > /var/tmp/lanrith-update/qualification-state", agent=False)
                    print('Rootless VM: building and uploading the next signed image.', flush=True)
                    candidate_assembly, _, candidate = image(value, base, initrd, work, secret, 10)
                    shutil.rmtree(candidate_assembly)
                    destination = upload(guest, candidate, operator=True)
                    digest = destination.rsplit('/', 1)[1]
                    triggered = guest.ssh('lanrith-image trigger '+digest, agent=False, success=False, timeout=1200)
                    if triggered.returncode != 0 and guest.process.poll() is None:
                        try:
                            guest.process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            status = json.loads(guest.ssh('lanrith-image status', agent=False).stdout)
                            record = status.get('operation') or {}
                            report['operator_phase'] = record.get('phase')
                            report['operator_error'] = record.get('error')
                            raise release.ReleaseError('Synthetic operator trigger returned before reboot.') from None
                    guest.process.wait(timeout=180)
                    guest.close()
                    boot(guest, root_access=False)
                    deadline = time.monotonic()+240
                    while time.monotonic() < deadline:
                        status = json.loads(guest.ssh('lanrith-image status', agent=False).stdout)
                        if (status.get('operation') or {}).get('phase') == 'accepted':
                            break
                        time.sleep(2)
                    else:
                        raise release.ReleaseError('Synthetic operator update did not complete.')
                    release.require((status.get('accepted') or {}).get('deployment_sequence') == 10,
                                    'Synthetic operator accepted the wrong image.')
                    release.require(guest.ssh('cat /etc/machine-id', agent=False).stdout == machine_identity,
                                    'Synthetic machine identity changed during the update.')
                    release.require(guest.ssh('cat /var/tmp/lanrith-update/qualification-state', agent=False).stdout ==
                                    b'synthetic-persistent-state', 'Synthetic operator state changed during the update.')
                    release.require(guest.ssh('lanrith-image trigger '+digest, agent=False,
                                              success=False).returncode != 0,
                                    'Synthetic operator accepted a replay.')
                    report['checks'] += ['signed-operator-upload', 'operator-triggered-reboot',
                                         'ab-candidate-accepted', 'operator-replay-rejected',
                                         'machine-identity-retained', 'synthetic-operator-state-retained']
                    report['synthetic_operator_update_passed'] = True
                    report['result'] = 'pass'
            except release.ReleaseError:
                report['sanitized_observation'] = json.loads(guest.diagnostic())
                raise
            finally:
                guest.close()
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic root-disabled first boot passed.')


if __name__ == '__main__':
    main()
