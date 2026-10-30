#!/usr/bin/env python3
"""Apply and verify the build-time operator root-access policy."""

import argparse
import os
from pathlib import Path
import shutil
import stat


REMOVED = (
    'usr/bin/sudo', 'usr/bin/sudoedit', 'usr/bin/su', 'bin/su',
    'etc/sudoers', 'etc/sudoers.d', 'etc/pam.d/sudo', 'etc/pam.d/sudo-i',
    'etc/pam.d/su', 'etc/pam.d/su-l', 'etc/security/authorized_keys',
    'etc/security/admin.serial-passphrase.hash', 'root/.ssh',
    'usr/lib/lanrith/verify-serial-passphrase', 'usr/lib/lanrith/serial-idle-watchdog',
)


def _remove(root, relative):
    path = root/relative
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _rewrite_database(path, transform):
    if not path.is_file() or path.is_symlink():
        raise ValueError('Root-access account database is unavailable or unsafe.')
    output = []
    for line in path.read_text().splitlines():
        fields = line.split(':')
        transform(fields)
        output.append(':'.join(fields))
    path.write_text('\n'.join(output)+'\n')


def _lock_root(root):
    seen = False

    def passwd(fields):
        nonlocal seen
        if fields[0] == 'root':
            if len(fields) != 7 or fields[2] != '0':
                raise ValueError('Root account record is malformed.')
            fields[6] = '/usr/sbin/nologin'
            seen = True

    _rewrite_database(root/'etc/passwd', passwd)
    if not seen:
        raise ValueError('Root account record is missing.')

    seen = False

    def shadow(fields):
        nonlocal seen
        if fields[0] == 'root':
            if len(fields) != 9:
                raise ValueError('Root shadow record is malformed.')
            fields[1] = '!'
            seen = True

    _rewrite_database(root/'etc/shadow', shadow)
    if not seen:
        raise ValueError('Root shadow record is missing.')


def _remove_sudo_membership(root, username):
    for name in ('group', 'gshadow'):
        def transform(fields):
            if fields[0] == 'sudo':
                if len(fields) != 4:
                    raise ValueError('Sudo group record is malformed.')
                fields[-1] = ','.join(member for member in fields[-1].split(',')
                                      if member and member != username)
        _rewrite_database(root/'etc'/name, transform)
    sysusers = root/'usr/lib/sysusers.d'
    if not sysusers.is_dir() or sysusers.is_symlink():
        raise ValueError('System-user declarations are unavailable or unsafe.')
    for path in sysusers.glob('*.conf'):
        if path.is_symlink() or not path.is_file():
            raise ValueError('System-user declaration is unsafe.')
        lines = []
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[:3] == ['m', username, 'sudo']:
                continue
            lines.append(line)
        path.write_text('\n'.join(lines)+'\n')


def _strip_file_privileges(root):
    for path in root.rglob('*'):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            path.chmod(stat.S_IMODE(info.st_mode) & ~(stat.S_ISUID | stat.S_ISGID))
        if 'security.capability' in os.listxattr(path, follow_symlinks=False):
            os.removexattr(path, 'security.capability', follow_symlinks=False)


def verify_root_access_disabled(root, username):
    for relative in REMOVED:
        path = root/relative
        if path.exists() or path.is_symlink():
            raise ValueError('Disabled root access retained an elevation path.')
    passwd = [line.split(':') for line in (root/'etc/passwd').read_text().splitlines()]
    uid_zero = [fields for fields in passwd if len(fields) == 7 and fields[2] == '0']
    if len(uid_zero) != 1 or uid_zero[0][0] != 'root' or uid_zero[0][6] != '/usr/sbin/nologin':
        raise ValueError('Disabled root access retained a login-capable UID 0 account.')
    shadow = {fields[0]: fields[1] for line in (root/'etc/shadow').read_text().splitlines()
              if len(fields := line.split(':')) == 9}
    if shadow.get('root') not in ('!', '*', '!*'):
        raise ValueError('Disabled root access retained an unlockable root password.')
    for name in ('group', 'gshadow'):
        for line in (root/'etc'/name).read_text().splitlines():
            fields = line.split(':')
            if fields[0] == 'sudo' and username in fields[-1].split(','):
                raise ValueError('Administrator remains a sudo group member.')
    for path in root.rglob('*'):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError('Disabled root access retained a privileged executable mode.')
        if 'security.capability' in os.listxattr(path, follow_symlinks=False):
            raise ValueError('Disabled root access retained a file capability.')


def protect_password_databases(root):
    """Optional daemons authenticate through their integrations, not Unix hashes."""
    for name in ('group', 'gshadow'):
        def transform(fields):
            if fields[0] == 'shadow':
                if len(fields) != 4:
                    raise ValueError('Shadow group record is malformed.')
                fields[3] = ''
                if name == 'gshadow':
                    fields[2] = ''
        _rewrite_database(root/'etc'/name, transform)
    for path in (root/'usr/lib/sysusers.d').glob('*.conf'):
        if path.is_symlink() or not path.is_file():
            raise ValueError('System-user declaration is unsafe.')
        lines = [line for line in path.read_text().splitlines()
                 if not (len(fields := line.split()) >= 3 and fields[0] == 'm' and fields[2] == 'shadow')]
        path.write_text('\n'.join(lines)+'\n')
    for name in ('shadow', 'gshadow', 'shadow-', 'gshadow-'):
        path = root/'etc'/name
        if not path.exists() and not path.is_symlink():
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError('Password database is unavailable or unsafe.')
        path.chmod(0o600)


def apply_root_access(root, username, mode):
    """Remove every general operator elevation path when selected at build time."""
    if mode not in ('enabled', 'disabled'):
        raise ValueError('Unknown root-access finalization policy.')
    protect_password_databases(root)
    if mode == 'enabled':
        return
    _lock_root(root)
    _remove_sudo_membership(root, username)
    for relative in REMOVED:
        _remove(root, relative)
    _strip_file_privileges(root)
    verify_root_access_disabled(root, username)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('username')
    args = parser.parse_args()
    apply_root_access(args.root, args.username, 'disabled')
    print('Rootless administration policy applied and verified.')


if __name__ == '__main__':
    main()
