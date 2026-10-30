"""Assemble dedicated recovery media with no factory installation entry point.

Ordinary factory and update exports remain prohibited. The recovery export has
its own signed release purpose and explicit target and operation bindings."""

import json
import os
from pathlib import Path
import shutil
import stat

from . import recovery_console, release


WRAPPER = '''#!/usr/bin/python3 -I
import sys,time
sys.path.insert(0,"/usr/lib/lanrith")
try:
    from lanrith.recovery_console import main
    from lanrith.release import ReleaseError
    try:
        main()
    except ReleaseError as error:
        if str(error) == "UEFI Secure Boot is not enabled.":
            print("Recovery unavailable: Secure Boot is disabled.", flush=True)
        else:
            print("Recovery console unavailable. Restart verified recovery media.", flush=True)
except Exception:
    print("Recovery console unavailable. Restart verified recovery media.", flush=True)
print("Recovery session ended. Restart verified recovery media.", flush=True)
while True:
    time.sleep(60)
'''
HOLD = '''#!/usr/bin/python3 -I
import time
print("Recovery environment unavailable. Restart verified recovery media.", flush=True)
while True:
    time.sleep(60)
'''


RESTORE_RECOVERY_BUILD_QUALIFIED = False
RESTORE_MODULES = ('recovery_backup_preflight.py', 'recovery_backup_auth.py', 'recovery_backup_files.py',
                   'recovery_backup_verity.py', 'recovery_backup_device.py', 'recovery_restore_layout.py', 'recovery_restore_target.py',
                   'recovery_restore_transaction.py', 'recovery_restore.py')


def prepare(destination, *, disk_by_id, credential, state_uuid=None, offline_inputs=None, offline_backup=None,
            operations=None):
    """Replace factory provisioning with a constrained console in a scratch build."""
    release.require(offline_backup is None or RESTORE_RECOVERY_BUILD_QUALIFIED or
                    isinstance(operations, list) and {'backup', 'restore'} <= set(operations),
                    'Offline restore recovery image is not qualified.')
    release.require(isinstance(destination, Path) and destination.is_absolute() and
                    destination.resolve() == destination and destination.is_dir() and not destination.is_symlink(),
                    'Recovery workspace must be a canonical directory.')
    release.require(isinstance(credential, Path) and credential.is_absolute() and
                    credential.resolve() == credential and not credential.is_symlink(),
                    'Recovery credential must be a protected file.')
    descriptor = os.open(credential, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        release.require(stat.S_ISREG(before.st_mode) and (before.st_uid == os.geteuid() or os.geteuid() == 0) and
                        before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                        0 < before.st_size <= 512, 'Recovery credential must be a protected file.')
        stored = stream.read(513)
        after = os.fstat(stream.fileno())
        current = credential.stat()
        def fingerprint(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                    value.st_ctime_ns, value.st_mode, value.st_uid, value.st_nlink)
        release.require(fingerprint(before) == fingerprint(after) == fingerprint(current) and
                        len(stored) == before.st_size, 'Recovery credential changed during read.')
    try:
        encoded = stored.decode('ascii')
    except UnicodeDecodeError:
        raise release.ReleaseError('Invalid recovery credential format.') from None
    release.require(recovery_console.HASH.fullmatch(encoded) is not None,
                    'Invalid recovery credential format.')
    installed = json.loads(release.read(destination/'mkosi.extra/usr/share/lanrith/installed.json', 65536),
                           object_pairs_hook=release.unique)
    value = {'schema': 1, 'tty': installed['boot']['recovery_console'],
             'image_id': installed['image_id'], 'disk_by_id': disk_by_id}
    if state_uuid is not None:
        value['state_uuid'] = state_uuid.lower() if isinstance(state_uuid, str) else state_uuid
    if offline_inputs is not None:
        value['offline_inputs'] = {name: item.lower() if name.endswith('_uuid') and isinstance(item, str) else item
                                   for name, item in offline_inputs.items()} if isinstance(offline_inputs, dict) else offline_inputs
    if offline_backup is not None:
        value['offline_backup'] = {name: item.lower() if name in ('state_uuid', 'state_partuuid', 'backup_partuuid') and isinstance(item, str) else item
                                   for name, item in offline_backup.items()} if isinstance(offline_backup, dict) else offline_backup
    if operations is not None:
        value['operations'] = operations
    value = recovery_console.policy(value)
    root = destination/'mkosi.images/initrd/mkosi.extra'
    library = root/'usr/lib/lanrith/lanrith'
    units = root/'usr/lib/systemd/system'
    release.require(all(path.is_dir() and not path.is_symlink() for path in (root, library, units)) and
                    all((library/name).is_file() and not (library/name).is_symlink() for name in
                        ('__init__.py', 'release.py', 'update.py', 'repair.py', 'factory.py')) and
                    (destination/'mkosi.extra/usr/share/lanrith/owner.crt').is_file(),
                    'Recovery assembly lacks its independent verified-root prerequisites.')
    marker = destination/'RECOVERY-ASSEMBLY'
    # Create the export barrier first; leave it in place on any later error.
    with marker.open('xb') as stream:
        stream.write(b'Dedicated recovery assembly; ordinary exports forbidden.\n')
    marker.chmod(0o600)
    shutil.copyfile(Path(__file__).with_name('recovery_console.py'), library/'recovery_console.py')
    shutil.copyfile(Path(__file__).with_name('recovery_state.py'), library/'recovery_state.py')
    shutil.copyfile(Path(__file__).with_name('recovery_inputs.py'), library/'recovery_inputs.py')
    modules = list(RESTORE_MODULES) if offline_backup is not None else []
    if modules or operations:
        modules.append('recovery_authority.py')
    if operations and 'repair' in operations:
        modules.append('recovery_slot.py')
    if modules:
        for name in modules:
            source, target = Path(__file__).with_name(name), library/name
            release.require(source.is_file() and not target.exists() and not target.is_symlink(),
                            'Recovery restore module is unavailable or already installed.')
            shutil.copyfile(source, target)
    metadata = root/'usr/share/lanrith'
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata/'recovery-console.json').write_bytes(release.canonical(value))
    secret = metadata/'recovery-console.hash'
    descriptor = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(stored)
    binary = root/'usr/bin/lanrith-recovery'
    binary.write_text(WRAPPER)
    binary.chmod(0o755)
    hold = root/'usr/bin/lanrith-recovery-hold'
    hold.write_text(HOLD)
    hold.chmod(0o755)
    (units/'lanrith-factory.service').write_text(
        '[Unit]\nDescription=Authenticated recovery console\nDefaultDependencies=no\n'
        'Requires=initrd-root-fs.target\nAfter=initrd-root-fs.target systemd-udev-trigger.service\n'
        'Before=initrd-udevadm-cleanup-db.service initrd-cleanup.service initrd-switch-root.target shutdown.target\n'
        'Conflicts=shutdown.target\nOnFailure=emergency.target\nOnFailureJobMode=isolate\n'
        '[Service]\nType=oneshot\nExecStart=/usr/bin/lanrith-recovery\n'
        f'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{value["tty"]}\n'
        'TTYReset=yes\nTTYVHangup=no\nTimeoutStartSec=infinity\nLimitCORE=0\nNoNewPrivileges=yes\n')
    emergency = units/'emergency.service.d/60-lanrith-recovery.conf'
    emergency.write_text('[Service]\nType=exec\nExecStart=\nExecStart=/usr/bin/lanrith-recovery-hold\n'
                         'StandardInput=null\nStandardOutput=journal+console\nStandardError=journal+console\n')
    # The recovery initrd has no callable destructive installer entry point.
    (root/'usr/bin/lanrith-factory').unlink()
    return value
