#!/usr/bin/env python3
"""Check canonical unit lookup and D-Bus aliases in a disposable systemd guest."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build
from test_discovery import declaration


NETWORKD = 'systemd-networkd.service'
AVAHI = 'avahi-daemon.service'
HOSTNAMED = 'systemd-hostnamed.service'
ALIASES = {NETWORKD: 'dbus-org.freedesktop.network1.service', AVAHI: 'dbus-org.freedesktop.Avahi.service',
           HOSTNAMED: 'dbus-org.freedesktop.hostname1.service'}


def state(command, expected, status=0):
    result = subprocess.run(['systemctl', *command], text=True, capture_output=True, timeout=10)
    if (result.returncode, result.stdout.strip()) != (status, expected):
        subprocess.run(['systemctl', 'show', '-p', 'Id,Names,LoadError,LoadState,FragmentPath,UnitFileState',
                        command[-1]], check=False)
        raise AssertionError((command, result))


def main():
    assert sys.argv[1:] == ['--disposable-systemd'], 'requires a disposable PID 1 fixture'
    assert Path('/run/systemd/system').is_dir() and 'rdinit=/fixture-init' in Path('/proc/cmdline').read_text()
    # basic.target has already pulled in Debian's unmasked listening sockets. Release
    # their units before simulating a profile assembled with different activation.
    subprocess.run(['systemctl', 'stop', 'avahi-daemon.socket', AVAHI,
                    'systemd-hostnamed.socket', HOSTNAMED], check=True)
    platform = Path('/opt/fixture-platform')
    etc = Path('/etc/systemd/system')
    vendor = Path('/usr/lib/systemd/system')
    # Copy only the fixture's three vendor units, their aliases and the selected socket.
    for unit in (*ALIASES, 'avahi-daemon.socket'):
        shutil.copyfile(platform/vendor.relative_to('/')/unit, vendor/unit)
    for unit, alias in ALIASES.items():
        (etc/alias).unlink(missing_ok=True)
        (etc/alias).symlink_to(vendor/unit)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        base = directory/'base.tar'
        base.write_bytes(b'synthetic assembly input')
        for enabled in (False, True):
            value = declaration()
            value['services']['discovery']['enabled'] = enabled
            workspace = directory/str(enabled)
            build.assembly(value, base, workspace, sequence=1, version='0.1.32')
            for unit in (*ALIASES, 'avahi-daemon.socket'):
                (etc/unit).unlink(missing_ok=True)
                (etc/unit).symlink_to(vendor/unit if unit == NETWORKD else '/dev/null')
            for alias in ALIASES.values():
                rendered = workspace/'mkosi.extra/etc/systemd/system'/alias
                if rendered.is_symlink():
                    (etc/alias).unlink(missing_ok=True)
                    (etc/alias).symlink_to(rendered.readlink())
            for unit in (NETWORKD, AVAHI):
                target = vendor/'multi-user.target.wants'/unit
                target.unlink(missing_ok=True)
                source = workspace/'mkosi.extra'/target.relative_to('/')
                if source.is_symlink():
                    target.symlink_to(source.readlink())
            subprocess.run([workspace/'mkosi.postinst'], check=True, env={**os.environ, 'BUILDROOT': '/'})
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            for unit, alias in ALIASES.items():
                loaded = unit == NETWORKD or (unit == AVAHI and enabled)
                status = 0 if loaded else 1
                state(['is-enabled', unit], 'enabled' if loaded else 'masked', status)
                state(['is-enabled', alias], 'alias' if loaded else 'masked', status)
                for name in (unit, alias):
                    state(['show', '-p', 'LoadState', '--value', name], 'loaded' if loaded else 'masked')
                    state(['show', '-p', 'FragmentPath', '--value', name], str(vendor/unit if loaded else etc/name))
            state(['show', '-p', 'LoadState', '--value', 'avahi-daemon.socket'], 'loaded' if enabled else 'masked')
    print('PID 1 resolved canonical networkd, the selected Avahi unit, and disabled aliases in both profiles.')


if __name__ == '__main__':
    main()
