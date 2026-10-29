"""Assemble an authenticated fixed-command serial menu in a signed initrd.

The ordinary builder enables this for steady-state images with an explicitly
supplied recovery credential. Legacy migration integration remains gated."""
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile

from . import release


FAILURE_CONSOLE_BUILD_QUALIFIED = False
MODULES = ('recovery_inputs.py', 'recovery_console.py', 'recovery_select.py',
           'recovery_failure_console.py')


BOOTCTL = 'usr/bin/bootctl'


def archive_members(archive, names):
    """Read only bounded, uniquely named, root-owned admitted archive entries."""
    release.require(isinstance(archive, Path) and archive.is_absolute() and archive.resolve() == archive and
                    archive.is_file() and not archive.is_symlink(), 'Invalid admitted archive.')
    result = {}
    with tarfile.open(archive, 'r|*') as source:
        for item in source:
            name = item.name.removeprefix('./')
            if name not in names:
                continue
            release.require(name not in result and item.isfile() and item.uid == item.gid == 0 and
                            0 < item.size <= 16*1024*1024 and not item.mode & 0o022 and
                            (name != BOOTCTL or bool(item.mode & 0o111)),
                            'Unsafe or ambiguous admitted boot utility.')
            stream = source.extractfile(item)
            release.require(stream is not None, 'Admitted boot utility is unavailable.')
            data = stream.read(item.size+1)
            release.require(len(data) == item.size, 'Admitted boot utility is truncated.')
            result[name] = data
    release.require(set(result) == set(names), 'Admitted boot utility or library is missing.')
    return result


def admitted_bootctl(base, initrd_base):
    """Bind the boot utility to identical system libraries in both archives."""
    data = archive_members(base, {BOOTCTL})[BOOTCTL]
    release.require(len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01' and
                    int.from_bytes(data[18:20], 'little') == 62,
                    'Admitted boot utility architecture is unsupported.')
    systemd = set(re.findall(rb'libsystemd-shared-[0-9]{1,4}\.so(?=\x00)', data))
    crypto = set(re.findall(rb'libcrypto\.so\.[0-9]{1,4}(?=\x00)', data))
    release.require(len(systemd) == len(crypto) == 1, 'Boot utility library identity is ambiguous.')
    libraries = {'usr/lib/x86_64-linux-gnu/systemd/'+next(iter(systemd)).decode('ascii'),
                 'usr/lib/x86_64-linux-gnu/'+next(iter(crypto)).decode('ascii'),
                 'usr/lib/x86_64-linux-gnu/libc.so.6'}
    main = archive_members(base, libraries)
    initrd = archive_members(initrd_base, libraries)
    release.require(all(main[name] == initrd[name] for name in libraries),
                    'Boot utility libraries differ between admitted archives.')
    return data


def prepare(workspace, *, credential, tty, base, initrd_base, emergency_dropin='60-lanrith-recovery.conf',
            library_prefix='usr/lib/lanrith', steady=False):
    """Install the serial menu only in an already assembled, private workspace."""
    release.require(FAILURE_CONSOLE_BUILD_QUALIFIED or steady is True,
                    'Failure console image integration is not qualified.')
    release.require(isinstance(workspace, Path) and workspace.is_absolute() and workspace.is_dir() and
                    not workspace.is_symlink() and workspace.resolve() == workspace and
                    isinstance(credential, Path) and credential.is_absolute() and
                    credential.resolve() == credential and credential.is_file() and not credential.is_symlink() and
                    isinstance(tty, str) and re.fullmatch(r'(?:tty(?:S|AMA|USB|ACM)|hvc)[0-9]{1,3}', tty) and
                    isinstance(emergency_dropin, str) and
                    re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.conf', emergency_dropin) and
                    isinstance(library_prefix, str) and
                    re.fullmatch(r'usr/lib/[A-Za-z0-9][A-Za-z0-9_-]{0,63}', library_prefix),
                    'Invalid failure console build input.')
    descriptor = os.open(credential, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        release.require(stat.S_ISREG(info.st_mode) and (info.st_uid == os.geteuid() or os.geteuid() == 0) and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 512,
                        'Invalid private failure console credential.')
        credential_data = stream.read(513)
        after = os.fstat(stream.fileno())
        current = credential.stat()
        def fingerprint(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                    value.st_ctime_ns, value.st_mode, value.st_uid, value.st_nlink)
        release.require(fingerprint(info) == fingerprint(after) == fingerprint(current) and
                        len(credential_data) == info.st_size and
                        re.fullmatch(rb'scrypt:32768:8:1:[0-9a-f]{32}:[0-9a-f]{64}\n?', credential_data),
                        'Invalid private failure console credential.')
    bootctl_data = admitted_bootctl(base, initrd_base)
    root = workspace/'mkosi.images/initrd/mkosi.extra'
    library = root/library_prefix/'lanrith'
    emergency = root/'usr/lib/systemd/system/emergency.service.d'/emergency_dropin
    release.require(library.is_dir() and not library.is_symlink() and emergency.is_file() and
                    not emergency.is_symlink() and
                    'ExecStart=/usr/bin/lanrith-factory emergency\n' in emergency.read_text(),
                    'Failure console requires an assembled initrd.')
    for name in MODULES:
        source, destination = Path(__file__).with_name(name), library/name
        release.require(source.is_file() and not destination.exists() and not destination.is_symlink(),
                        'Failure console module is unavailable or already installed.')
    settings = root/'usr/share/lanrith'
    release.require(settings.is_dir() and not settings.is_symlink(), 'Failure console settings are unavailable.')
    policy, digest = settings/'failure-console.json', settings/'failure-console.hash'
    release.require(not policy.exists() and not digest.exists() and not policy.is_symlink() and not digest.is_symlink(),
                    'Failure console settings already exist.')
    entry = root/'usr/bin/lanrith-failure-console'
    bootctl = root/BOOTCTL
    release.require(not entry.parent.is_symlink() and not entry.exists() and not entry.is_symlink() and
                    not bootctl.exists() and not bootctl.is_symlink(),
                    'Failure console entry or directory is unsafe.')
    for name in MODULES:
        shutil.copyfile(Path(__file__).with_name(name), library/name)
    policy.write_bytes(release.canonical({'schema': 1, 'tty': tty}))
    descriptor = os.open(digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(credential_data)
    entry.parent.mkdir(parents=True, exist_ok=True)
    bootctl.write_bytes(bootctl_data)
    bootctl.chmod(0o755)
    entry.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,'+repr('/'+library_prefix)+')\n'
                     'from lanrith.recovery_failure_console import main\nsys.exit(main())\n')
    entry.chmod(0o755)
    emergency.write_text('[Service]\nType=exec\nExecStart=\nExecStart=/usr/bin/lanrith-failure-console\n'
                         'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\n'
                         f'TTYPath=/dev/{tty}\nTTYReset=yes\nTTYVHangup=no\nTimeoutStartSec=infinity\n')
