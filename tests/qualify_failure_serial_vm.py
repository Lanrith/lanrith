#!/usr/bin/env python3
"""Exercise gated fallback after a synthetic initrd failure on disposable disks.

A nonexportable test image overrides both qualification constants. This drill
never grants fallback authority to production images or proves TPM compatibility.
"""

import argparse
import ast
from contextlib import ExitStack
import datetime
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time

from vm import Guest, PROJECT, STATE, boot, check_state, factory_medium, image, regular, root, run, stop, upload
from lanrith import build, config, release


def console_hook(automatic):
    """Separate automatic-fallback drills from manual serial-selection drills."""
    if type(automatic) is not bool:
        raise ValueError('Invalid synthetic console mode.')
    if automatic:
        return ("_automatic=console.automatic_fallback\n"
                "def _observed_automatic():\n"
                " print('VM automatic console fallback entered',flush=True)\n"
                " return _automatic()\n"
                "console.automatic_fallback=_observed_automatic\n")
    return 'console.automatic_fallback=lambda: False  # Manual-selection fixture only.\n'


def synthetic_state_override():
    """Isolate console handoff; this deliberately does not test TPM compatibility."""
    return ('\n# Synthetic VM only: state compatibility is not qualified by this drill.\n'
            'def observe_rollback_compatibility(installed):\n'
            " return {'scope':'rollback-compatibility-observation','authorized_to_boot':False}\n")


def require_matching_base(base):
    """Reject a base whose branch-owned runtime files differ from this source.

    This is a synthetic-fixture preflight, not package approval or release
    admission. It prevents testing one branch with another branch's helpers.
    """
    source = PROJECT/'mkosi/base/mkosi.extra'
    expected = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).digest()
                for path in source.rglob('*') if path.is_file() and not path.is_symlink()}
    release.require(expected, 'Synthetic base overlay is empty.')
    seen = set()
    with tarfile.open(base, 'r|*') as archive:
        for item in archive:
            name = item.name.removeprefix('./')
            if name not in expected:
                continue
            release.require(name not in seen and item.isfile() and item.uid == item.gid == 0 and
                            item.size <= 16*1024*1024, 'Synthetic base overlay is ambiguous.')
            seen.add(name)
            release.require(hashlib.sha256(archive.extractfile(item).read()).digest() == expected[name],
                            'Synthetic base differs from branch runtime files.')
    release.require(seen == set(expected), 'Synthetic base omits branch runtime files.')
    return len(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--corrupt-fallback', action='store_true',
                        help='Corrupt only the disposable accepted root and require recovery hold')
    parser.add_argument('--stall-fallback', action='store_true',
                        help='Stall only the disposable fallback verifier and require bounded recovery hold')
    parser.add_argument('--automatic-console', action='store_true',
                        help='Exercise automatic fallback from the authenticated serial emergency entry')
    args = parser.parse_args()
    release.require(not (args.corrupt_fallback and args.stall_fallback), 'Synthetic fault modes are exclusive.')
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    matched_files = require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Qualification requires a new disposable workspace.')
    release.require(shutil.disk_usage(work.parent).free >= (32+25+4)*1024**3,
                    'Serial qualification requires the full 32 GiB disk budget, reserve and margin.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'synthetic-failed-initrd-serial-fallback-only', 'result': 'fail',
              'physical_homelab_qualified': False, 'automatic_fallback_qualified': False,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    report['branch_overlay_files_matched'] = matched_files
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-bound-vm.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Bound VM', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(secret/'ssh'))
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable-passphrase', salt=salt, n=32768, r=8, p=1,
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
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['serial'] = {'enabled': True, 'tty': 'ttyS0'}
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            assembly, identity, first = image(value, base, initrd, work, secret, 9)
            disk = work/'installed.raw'
            with disk.open('xb') as stream:
                stream.truncate(32*1024**3)
            medium = factory_medium(assembly, identity, first, work, secret)
            guest = Guest(work/'guest', secret, disk, medium=medium, tpm=True)
            try:
                print('Bound VM: installing synthetic accepted image.', flush=True)
                guest.start()
                event = guest.expect_any([rb'Type ERASE-AND-INSTALL .* to continue: ',
                                          rb'(?:You are in|Entering) emergency mode'])
                release.require(event == 0, 'Synthetic installer entered emergency mode.')
                guest.serial.sendall(b'ERASE-AND-INSTALL /dev/disk/by-id/virtio-lanrith-qa-disk\r')
                guest.expect(rb'Installation read-back passed')
                guest.wait_shutdown(); guest.close(); guest.medium = None
                # Preserve the independent signed release, but remove test-only
                # factory image copies after the installer has shut down.
                medium.unlink()
                shutil.rmtree(work/'factory')
                shutil.rmtree(assembly)
                boot(guest, first=True)
                guest.ssh('sudo lanrith-runtime accept 9')
                program = ('import json,sys;sys.path.insert(0,"/usr/lib/lanrith");'
                           'from lanrith import update;print(json.dumps(update.geometry("/dev/vda")))')
                rows = json.loads(root(guest, 'python3 -I -c '+__import__('shlex').quote(program)).stdout)
                esps = [r for r in rows if r.get('type') == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
                release.require(len(esps) == 1 and isinstance(esps[0].get('uuid'), str),
                                'Synthetic installed ESP is ambiguous.')
                root(guest, """set -eu
mkdir -p /var/lib/lanrith/qualification-state /var/lib/kea
systemctl stop kea-dhcp4-server.service
printf 'address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\\n192.168.10.123,02:00:00:00:02:01,,3600,4102444800,1,0,0,synthetic,0,\\n' > /var/lib/kea/kea-leases4.csv
printf synthetic-credential > /var/lib/lanrith/qualification-state/credentials
printf synthetic-enrollment > /var/lib/lanrith/qualification-state/enrollment
chmod 0600 /var/lib/lanrith/qualification-state/*
logger -t lanrith-qualification synthetic-persistent-state
journalctl --sync
systemctl start kea-dhcp4-server.service
""")
                guest.ready()
                state_before = root(guest, STATE).stdout
                lease = json.loads(state_before.splitlines()[3])
                release.require('192.168.10.123' in lease, 'Synthetic DHCP lease was not seeded.')
                root(guest, 'printf synthetic-bound-state > /var/lib/lanrith/bound-probe')
                before = root(guest, 'sha256sum /var/lib/lanrith/bound-probe; cat /etc/machine-id').stdout
                print('Bound VM: building signed candidate with fallback binding.', flush=True)
                second = work/'image-10'
                candidate = build.assembly(value, base, second, version='0.1.0', sequence=10,
                    certificate=secret/'test.crt', private_key=secret/'test.key', serial_hash=secret/'serial.hash',
                    initrd_base=initrd, fallback_release=first,
                    fallback_disk_by_id='/dev/disk/by-id/virtio-lanrith-qa-disk', fallback_esp_uuid=esps[0]['uuid'])
                overlay = second/'mkosi.images/initrd/mkosi.extra'
                # Override only this disposable signed test image; the source and
                # normal builds retain their hard-disabled gates.
                module = overlay/'usr/lib/lanrith/lanrith/early_failure.py'
                source = module.read_text()
                release.require(source.count('FALLBACK_AUTHENTICATION_QUALIFIED = False') == 1 and
                                source.count('ROLLBACK_COMPATIBILITY_QUALIFIED = False') == 1,
                                'Synthetic qualification gates differ.')
                source = source.replace('FALLBACK_AUTHENTICATION_QUALIFIED = False',
                                        'FALLBACK_AUTHENTICATION_QUALIFIED = True')
                source = source.replace('ROLLBACK_COMPATIBILITY_QUALIFIED = False',
                                        'ROLLBACK_COMPATIBILITY_QUALIFIED = True')
                source += synthetic_state_override()
                if args.stall_fallback:
                    release.require(source.count('def failed_boot(installed):\n') == 1,
                                    'Synthetic fallback entry differs.')
                    source = source.replace('def failed_boot(installed):\n',
                        'def failed_boot(installed):\n    import time; time.sleep(120)\n', 1)
                    factory_module = overlay/'usr/lib/lanrith/lanrith/factory.py'
                    factory_source = factory_module.read_text()
                    release.require(factory_source.count('FALLBACK_DEADLINE_SECONDS = 900') == 1,
                                    'Synthetic fallback deadline differs.')
                    factory_module.write_text(factory_source.replace('FALLBACK_DEADLINE_SECONDS = 900',
                                                                      'FALLBACK_DEADLINE_SECONDS = 3', 1))
                module.write_text(source)
                from lanrith import recovery_failure_build
                recovery_failure_build.FAILURE_CONSOLE_BUILD_QUALIFIED = True # synthetic image only
                recovery_failure_build.prepare(second, credential=secret/'serial.hash', tty='ttyS0', base=base, initrd_base=initrd)
                # Test-only bounded diagnostics: never print exception text,
                # input, credentials or raw console data.
                entry = overlay/'usr/bin/lanrith-failure-console'
                entry.write_text("""#!/usr/bin/python3 -I
import re,sys
from pathlib import Path
sys.path.insert(0,'/usr/lib/lanrith')
from lanrith import recovery_failure_console as console,recovery_select,release
original=recovery_select.select_bound
def diagnosed(*args,**kwargs):
    try: return original(*args,**kwargs)
    except Exception as error:
        category='release' if isinstance(error,release.ReleaseError) else ('os' if isinstance(error,OSError) else 'other')
        allowed={'recovery_select.py','early_failure.py','recovery_inputs.py','repair.py','factory.py','update.py','release.py'}
        location='unknown'; trace=error.__traceback__
        while trace is not None:
            code=trace.tb_frame.f_code; module=Path(code.co_filename).name
            if module in allowed and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',code.co_name):
                location=module+':'+code.co_name+':'+str(trace.tb_lineno)
            trace=trace.tb_next
        number=0; cause=error
        for _ in range(4):
            if isinstance(cause,OSError) and type(cause.errno) is int and 1<=cause.errno<=4095:
                number=cause.errno; break
            cause=cause.__cause__ or cause.__context__
            if cause is None: break
        command='unknown'
        if isinstance(error,release.ReleaseError):
            match=re.fullmatch(r'Update command (?:could not start|failed): (bootctl|cryptsetup|dd|dmsetup|findmnt|lsblk|mount|sfdisk|sync|systemctl|udevadm|umount)',str(error))
            if match: command=match.group(1)
        print('Synthetic serial selection diagnostic: '+category+' '+location+' errno='+str(number)+' command='+command,flush=True)
        raise
recovery_select.select_bound=diagnosed
sys.exit(console.main())
""")
                entry_text = entry.read_text()
                release.require(entry_text.count('sys.exit(console.main())') == 1,
                                'Synthetic console entry differs.')
                hook = console_hook(args.automatic_console)
                entry.write_text(entry_text.replace('sys.exit(console.main())', hook+'sys.exit(console.main())'))
                selector = overlay/'usr/lib/lanrith/lanrith/recovery_select.py'
                selector_text = selector.read_text()
                release.require(selector_text.count('OPERATOR_SELECTION_QUALIFIED = False') == 1,
                                'Synthetic selection gate differs.')
                selector.write_text(selector_text.replace('OPERATOR_SELECTION_QUALIFIED = False',
                                                          'OPERATOR_SELECTION_QUALIFIED = True'))
                failure_unit = overlay/'usr/lib/systemd/system/lanrith-initrd-failure.service'
                failure_text = failure_unit.read_text()
                release.require(failure_text.count('ExecStart=/usr/bin/lanrith-factory failed') == 1,
                                'Synthetic failure unit differs.')
                failure_unit.write_text(failure_text.replace('ExecStart=/usr/bin/lanrith-factory failed',
                                                             'ExecStart=/usr/bin/false', 1))
                unit = overlay/'usr/lib/systemd/system/lanrith-factory.service'
                with unit.open('a') as stream:
                    stream.write('ExecStartPre=/usr/bin/false\n')
                build.run(second)
                update = work/'update-10'
                build.update_payload(second, candidate, update)
                release.sign(update, secret/'test.key')
                release.verify(update, secret/'test.crt', purpose='update', image_id='lanrith')
                uploaded = upload(guest, update)
                guest.ssh('sudo lanrith-runtime promote '+uploaded, timeout=900)
                guest.poweroff()
                shutil.rmtree(second)
                shutil.rmtree(update)
                if args.corrupt_fallback:
                    # The VM is stopped and this is the new, disposable regular
                    # file created above. Change one byte in the accepted root,
                    # after verifying it against the signed prior release.
                    release.require(disk == work/'installed.raw' and disk.is_file() and not disk.is_symlink(),
                                    'Synthetic target disk is unsafe.')
                    table = json.loads(run('sfdisk', '--json', str(disk)))['partitiontable']
                    roots = [part for part in table['partitions'] if part.get('name') == 'l_9_root']
                    release.require(table.get('sectorsize') == 512 and len(roots) == 1 and
                                    type(roots[0].get('start')) is int and roots[0]['start'] > 0 and
                                    type(roots[0].get('size')) is int and roots[0]['size'] > 2,
                                    'Synthetic fallback partition is ambiguous.')
                    manifest = release.verify(first, secret/'test.crt', purpose='update', image_id='lanrith')
                    artifact = next(item for item in manifest['artifacts'] if item['role'] == 'root')
                    expected_uuid = artifact['name'].removeprefix('lanrith_9_').removesuffix('.root.raw')
                    release.require(roots[0].get('type', '').lower() == '4f68bce3-e8cd-4db1-96e7-fbcaf984b709' and
                                    roots[0].get('uuid', '').lower() == expected_uuid,
                                    'Synthetic fallback root differs from its signed identity.')
                    with (first/artifact['name']).open('rb') as signed:
                        signed.seek(1024)
                        expected = signed.read(1)
                    with disk.open('r+b') as raw:
                        offset = roots[0]['start']*512+1024
                        raw.seek(offset)
                        actual = raw.read(1)
                        release.require(len(actual) == 1 and actual == expected,
                                        'Synthetic fallback byte differs before fault injection.')
                        raw.seek(offset)
                        raw.write(bytes([actual[0]^1]))
                        raw.flush(); os.fsync(raw.fileno())
                    report['fault'] = 'one-signed-fallback-root-byte-corrupted'
                print('Fallback VM: injecting initrd failure into signed candidate.', flush=True)
                guest.start()
                if args.automatic_console:
                    event = guest.expect_any([rb'VM automatic console fallback entered', rb'Recovery passphrase: '])
                    release.require(event == 0, 'Synthetic automatic console fallback did not start.')
                    if args.corrupt_fallback or args.stall_fallback:
                        diagnostic = (rb'Automatic fallback diagnostic: verification early_failure\.py:observe_bound_fallback:[0-9]+'
                                      if args.corrupt_fallback else
                                      rb'Automatic fallback diagnostic: os factory\.py:expired:[0-9]+')
                        guest.expect(diagnostic)
                        guest.expect(rb'Recovery passphrase: ')
                        guest.serial.sendall(b'wrong-passphrase\r')
                        guest.expect(rb'Authentication failed\.')
                        guest.expect(rb'Recovery passphrase: ')
                        guest.serial.sendall(b'disposable-passphrase\r')
                        guest.expect(rb'Failure recovery: status, fallback, reboot, exit\.')
                        guest.expect(rb'failure-recovery> ')
                        guest.serial.sendall(b'reboot\r')
                        guest.expect(rb'Select a fallback in this session before rebooting\.')
                        time.sleep(10)
                        release.require(guest.process.poll() is None,
                                        'Rejected automatic fallback unexpectedly rebooted.')
                        fault_checks = (['confirmed-fallback-byte-corruption',
                                         'automatic-fallback-rejected-corruption'] if args.corrupt_fallback else
                                        ['test-only-stalled-verifier', 'test-only-short-deadline',
                                         'automatic-fallback-deadline'])
                        report.update(result='pass', checks=['test-only-gate-override',
                            'synthetic-state-compatibility-override', 'signed-factory-install',
                            'signed-bound-candidate', 'automatic-console-fallback-entered', *fault_checks,
                            'serial-authentication-wrong-secret-denied', 'authenticated-menu-available',
                            'reboot-without-selection-denied', 'recovery-hold-observed'])
                        return
                else:
                    event = guest.expect_any([rb'Recovery passphrase: ', rb'Entering emergency mode'])
                    release.require(event == 0, 'Synthetic failure console did not prompt.')
                    guest.serial.sendall(b'wrong-passphrase\r')
                    guest.expect(rb'Authentication failed\.')
                    guest.expect(rb'Recovery passphrase: ')
                    guest.serial.sendall(b'disposable-passphrase\r')
                    guest.expect(rb'Failure recovery: status, fallback, reboot, exit\.')
                    guest.expect(rb'failure-recovery> ')
                    guest.serial.sendall(b'fallback\r')
                    event = guest.expect_any([rb'Type the deployment number to confirm: ',
                                              rb'Fallback selection failed\.'])
                    if event != 0: report['diagnostic'] = json.loads(guest.last_diagnostic)
                    release.require(event == 0, 'Synthetic serial fallback preflight failed.')
                    guest.serial.sendall(b'9\r')
                    event = guest.expect_any([rb'Fallback selected once\.', rb'Fallback selection failed\.'])
                    if event != 0: report['diagnostic'] = json.loads(guest.last_diagnostic)
                    release.require(event == 0, 'Synthetic serial fallback selection failed.')
                    guest.expect(rb'failure-recovery> ')
                    release.require(guest.process.poll() is None, 'Synthetic serial selection rebooted without request.')
                    guest.serial.sendall(b'reboot\r')
                if args.stall_fallback:
                    guest.expect(rb'Automatic fallback diagnostic: os factory\.py:expired:[0-9]+')
                    guest.expect(rb'Automatic fallback unavailable; holding for recovery\.')
                    time.sleep(10)
                    release.require(guest.process.poll() is None,
                                    'Synthetic timeout did not remain in recovery hold.')
                    report.update(result='pass', checks=['test-only-gate-override', 'signed-factory-install',
                        'signed-bound-candidate', 'test-only-stalled-verifier', 'test-only-short-deadline',
                        'emergency-fallback-deadline', 'recovery-hold-observed'])
                    return
                if args.corrupt_fallback:
                    tree = ast.parse((PROJECT/'lanrith/early_failure.py').read_text())
                    locations = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call) and
                                 isinstance(node.func, ast.Name) and node.func.id == 'require' and
                                 len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and
                                 node.args[1].value == 'Fallback partition differs from binding.']
                    release.require(len(locations) == 1, 'Synthetic integrity check is ambiguous.')
                    location = ('Automatic fallback diagnostic: verification early_failure.py:'
                                'observe_bound_fallback:'+str(locations[0])).encode()
                    guest.expect_any([rb'Fallback partition differs from binding\.', re.escape(location)])
                    guest.expect(rb'Automatic fallback unavailable; holding for recovery\.')
                    time.sleep(10)
                    release.require(guest.process.poll() is None,
                                    'Synthetic rejection did not remain in recovery hold.')
                    report.update(result='pass', checks=['test-only-gate-override', 'signed-factory-install',
                        'signed-bound-candidate', 'confirmed-fallback-byte-corruption',
                        'actual-failure-handler-rejected-corruption', 'recovery-hold-observed'])
                    return
                deadline = time.monotonic()+600
                while guest.process.poll() is None and time.monotonic() < deadline:
                    if b'Automatic fallback unavailable; holding for recovery.' in guest.buffer:
                        report['diagnostic'] = json.loads(guest.diagnostic())
                        raise release.ReleaseError('Synthetic fallback entered recovery hold.')
                    time.sleep(0.2)
                if guest.process.poll() is None:
                    report['diagnostic'] = json.loads(guest.diagnostic())
                    raise release.ReleaseError('Synthetic fallback did not reboot.')
                diagnostic = json.loads(guest.diagnostic())
                release.require(any(event.get('event') == 'SHUTDOWN' and event.get('reason') == 'guest-reset'
                                    for event in diagnostic['qmp_events']),
                                'Synthetic failed candidate did not request a reboot: '+json.dumps(diagnostic))
                guest.close()
                print('Fallback VM: booting the accepted prior image.', flush=True)
                boot(guest)
                current = json.loads(guest.ssh('sudo lanrith-runtime status').stdout)
                release.require(current['deployment_sequence'] == 9, 'Synthetic fallback did not boot prior image.')
                after = root(guest, 'sha256sum /var/lib/lanrith/bound-probe; cat /etc/machine-id').stdout
                release.require(before == after, 'Synthetic persistent state or identity changed.')
                check_state(guest, state_before, 'Fallback changed synthetic persistent state.')
                guest.poweroff()
                selection_checks = (['automatic-console-fallback-entered'] if args.automatic_console else
                                    ['serial-authentication-wrong-secret-denied', 'serial-confirmed-one-shot-fallback',
                                     'explicit-operator-reboot'])
                report.update(result='pass', checks=['test-only-gate-override','signed-factory-install',
                    'signed-bound-candidate','synthetic-state-compatibility-override',
                    'injected-initrd-failure', *selection_checks,
                    'accepted-prior-image-booted','state-preserved', 'ssh-identity-retained',
                    'dhcp-lease-retained','persistent-journal-retained'])
            finally:
                guest.close()
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic serial fallback passed.')


if __name__ == '__main__':
    main()
