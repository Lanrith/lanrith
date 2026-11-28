"""Authenticated fixed-command serial menu for a failed signed initrd.

Automatic and manually selected fallback use the same signed image and state
checks. The menu grants no shell or arbitrary command execution."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

from . import factory, recovery_console, recovery_select, release
from .factory import automatic_fallback


POLICY = Path('/usr/share/lanrith/failure-console.json')
CREDENTIAL = Path('/usr/share/lanrith/failure-console.hash')


def wait_for_reboot():
    """Do not admit a competing selection after a successful reboot request."""
    while True:
        time.sleep(60)


def policy(value):
    release.require(isinstance(value, dict) and set(value) == {'schema', 'tty'} and
                    type(value['schema']) is int and value['schema'] == 1 and
                    isinstance(value['tty'], str) and
                    recovery_console.TERMINAL.fullmatch(value['tty']),
                    'Invalid failure console policy.')
    return value


def fixed_menu(*, read_command, write, select, reboot, eligibility):
    """Provide fixed status, confirmed fallback selection and explicit reboot."""
    selected = None
    reason = eligibility()
    guidance = ('Use the bootloader menu on the firmware console for manual recovery, '
                'or boot independently signed recovery media on its prepared terminal.\n')
    if reason:
        write('Failure recovery: status, exit.\n'+reason+' '+guidance)
    else:
        write('Failure recovery: status, fallback, reboot, exit. No shell is available.\n')
    for _ in range(32):
        command = read_command()
        if not isinstance(command, str) or len(command) > 32:
            write('Invalid command.\n')
            return
        if command == 'exit':
            return
        if command == 'status':
            if selected:
                write('One-shot fallback selected.\n')
            else:
                reason = eligibility()
                write(reason+' '+guidance if reason else 'Use fallback to verify the bound previous release.\n')
        elif command == 'fallback':
            if selected:
                write('Fallback already selected. Use reboot or exit.\n')
                continue
            reason = eligibility()
            if reason:
                write(reason+' '+guidance)
                continue
            try:
                def confirm(sequence, digest):
                    release.require(type(sequence) is int and 1 <= sequence <= 999999999 and
                                    isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest),
                                    'Invalid fallback confirmation.')
                    write('Select deployment '+str(sequence)+' once. Image SHA-256: '+digest+'\n')
                    write('Type the deployment number to confirm: ')
                    return read_command()
                result = select(confirm)
                release.require(isinstance(result, dict) and type(result.get('sequence')) is int and
                                result.get('default_changed') is False and result.get('automatic_reboot') is False,
                                'Invalid fallback selection result.')
                selected = result
                write('Fallback selected once. Use reboot to start it.\n')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                selected = None
                write('Fallback selection failed. Check the recovery state before rebooting.\n')
        elif command == 'reboot':
            if not selected:
                write('Select a fallback in this session before rebooting.\n')
                continue
            write('Requesting reboot to the selected fallback.\n')
            try:
                reboot(selected)
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                write('Reboot request failed. The one-shot selection may still be pending.\n')
                continue
            return
        else:
            write('Unknown command.\n')
    write('Session limit reached.\n')


def main():
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Failure console requires the signed initrd.')
    factory.secure_boot()
    if automatic_fallback():
        return wait_for_reboot()
    value = policy(json.loads(recovery_console.protected_file(POLICY, 4096, private=False),
                              object_pairs_hook=release.unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number.'))))
    tty = Path('/dev')/value['tty']
    identity = tty.stat()
    release.require(stat.S_ISCHR(identity.st_mode) and sys.stdin.isatty() and sys.stdout.isatty() and
                    os.fstat(sys.stdin.fileno()).st_rdev == identity.st_rdev and
                    os.fstat(sys.stdout.fileno()).st_rdev == identity.st_rdev,
                    'Failure console requires the configured physical terminal.')
    stored = recovery_console.protected_file(CREDENTIAL, 512, private=True).decode('ascii')
    release.require(recovery_console.HASH.fullmatch(stored) is not None, 'Failure credential is invalid.')
    for _ in range(3):
        secret = recovery_console.secret_from_tty(sys.stdin.buffer, sys.stdout)
        try:
            admitted = recovery_console.verify_secret(secret, stored)
        finally:
            for index in range(len(secret)):
                secret[index] = 0
        if admitted:
            def read_command():
                sys.stdout.write('failure-recovery> ')
                sys.stdout.flush()
                line = sys.stdin.readline(34)
                return line.rstrip('\r\n') if line.endswith('\n') else None
            fixed_menu(read_command=read_command, write=sys.stdout.write,
                       select=lambda confirm: recovery_select.select_bound(confirm=confirm),
                       reboot=recovery_select.reboot_selected, eligibility=recovery_select.unavailable_reason)
            return 0
        sys.stdout.write('Authentication failed.\n')
        sys.stdout.flush()
    sys.stdout.write('Recovery session closed.\n')
    return 1
