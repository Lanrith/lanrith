#!/usr/bin/env python3
"""Check post-acceptance optional startup in a disposable offline systemd guest."""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build, config
from lanrith.release import canonical, file_record, require


ROOT = Path(__file__).resolve().parents[1]
UNIT = 'example-optional.service'
STARTER = 'lanrith-extension-start.service'
OBSERVER = 'lanrith-observation.service'
TARGET = 'boot-complete.target'
GATE = 'systemd-boot-check-no-failures.service'
CORE = 'example-core-failure.service'


def command(*args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    require(not check or result.returncode == 0,
            'Synthetic extension native command failed: '+result.stderr.decode(errors='replace')[-2048:])
    return result


def qualify(result):
    require(os.geteuid() == 0 and Path('/run/systemd/system').is_dir() and
            (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists()) and
            b'systemd' in Path('/proc/1/cmdline').read_bytes() and
            not Path('/usr/share/lanrith/installed.json').exists(),
            'Extension fixture requires an uninitialized disposable systemd container.')
    require({entry['ifname'] for entry in json.loads(command('ip', '-json', 'link').stdout)} == {'lo'},
            'Extension fixture must have no external network.')
    failed = {line.split()[0] for line in command('systemctl', '--failed', '--no-legend', '--plain').stdout.decode().splitlines()}
    container_mounts = {'proc-sys-fs-binfmt_misc.automount', 'sys-kernel-config.mount',
                        'sys-kernel-debug.mount', 'sys-kernel-tracing.mount'}
    require(failed <= container_mounts, 'Extension fixture already has unexpected failed units.')
    if failed:
        # An offline container cannot mount these host-owned kernel surfaces.
        # Clear only their fixture startup failures, never arbitrary failures.
        command('systemctl', 'reset-failed', *sorted(failed))
    require(not result.exists() and result.parent.is_dir(), 'Extension result must be new.')
    directory = Path('/etc/systemd/system')
    names = (UNIT, STARTER, OBSERVER, TARGET, CORE)
    require(all(not (directory/name).exists() and not (directory/name).is_symlink() for name in names),
            'Extension fixture unit override already exists.')
    with tempfile.TemporaryDirectory(prefix='lanrith-extension-systemd.') as temporary:
        work = Path(temporary)
        extension = work/'extension'
        unit = extension/'root/usr/lib/systemd/system'/UNIT
        unit.parent.mkdir(parents=True)
        unit.write_text('[Unit]\nDescription=Synthetic optional failure\n'
                        '[Service]\nType=oneshot\nUser=nobody\nExecStart=/usr/bin/false\n')
        unit.chmod(0o644)
        record = file_record(unit)
        record.pop('name')
        metadata = {'schema': 1, 'id': 'example-extension', 'features': [], 'health_units': [],
                    'start_units': [UNIT], 'files': {'usr/lib/systemd/system/'+UNIT: {**record, 'mode': 0o644}}}
        encoded = canonical(metadata)
        (extension/'extension.json').write_bytes(encoded)
        base = work/'base.tar'
        with tarfile.open(base, 'w') as archive:
            for name, data in {'etc/passwd': b'root:*:0:0:root:/root:/bin/sh\n',
                               'etc/group': b'root:x:0:\n'}.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        value = config.load(ROOT/'examples/minimal.yaml')
        value['extensions'] = ['example-extension']
        build.assembly(value, base, work/'assembly', version='0.1.0', sequence=9,
                       integrations={'example-extension': (extension, hashlib.sha256(encoded).hexdigest())})
        generated = work/'assembly/mkosi.extra/usr/lib/systemd/system'
        try:
            shutil.copyfile(generated/STARTER, directory/STARTER)
            shutil.copyfile(unit, directory/UNIT)
            (directory/TARGET).write_text('[Unit]\nDescription=Synthetic core acceptance boundary\n'
                'Requires='+GATE+'\nAfter='+GATE+'\n')
            # Keep the actual observer's oneshot lifecycle and dependencies;
            # replace only its platform/hardware-dependent observation command.
            (directory/OBSERVER).write_text((generated/OBSERVER).read_text().replace(
                'ExecStart=/usr/bin/lanrith-runtime publish', 'ExecStart=/usr/bin/true'))
            (directory/CORE).write_text('[Unit]\nDescription=Synthetic mandatory core failure\n'
                '[Service]\nType=oneshot\nExecStart=/usr/bin/false\n')
            command('systemctl', 'daemon-reload')
            command('systemd-analyze', 'verify', str(directory/STARTER), str(directory/UNIT),
                    str(directory/OBSERVER), str(directory/TARGET))
            command('systemctl', 'start', STARTER)
            deadline = time.monotonic()+5
            while command('systemctl', 'is-failed', '--quiet', UNIT, check=False).returncode != 0:
                require(time.monotonic() < deadline, 'Optional failure was not observed.')
                time.sleep(0.05)
            for name in (GATE, TARGET, STARTER):
                command('systemctl', 'is-active', '--quiet', name)
            require(command('systemctl', 'show', '--property=Result', '--value', OBSERVER).stdout.strip() == b'success',
                    'Accepted-observation fixture did not complete.')
            # The generated starter must run only after the native gate and
            # the accepted-observation job have completed.
            def stamp(name, field):
                return int(command('systemctl', 'show', '--property='+field, '--value', name).stdout)
            require(0 < stamp(OBSERVER, 'ExecMainExitTimestampMonotonic') <=
                    stamp(STARTER, 'ExecMainStartTimestampMonotonic') <=
                    stamp(UNIT, 'ExecMainStartTimestampMonotonic'), 'Optional startup preceded acceptance.')
            command('systemctl', 'stop', STARTER, OBSERVER, TARGET, GATE)
            command('systemctl', 'reset-failed', UNIT)
            require(command('systemctl', 'start', CORE, check=False).returncode != 0,
                    'Synthetic core failure unexpectedly passed.')
            require(command('systemctl', 'start', TARGET, check=False).returncode != 0,
                    'The native global failure gate admitted a core failure.')
            require(command('systemctl', 'is-active', '--quiet', TARGET, check=False).returncode != 0,
                    'Core acceptance remained active after the required check failed.')
        finally:
            command('systemctl', 'stop', *names, GATE, check=False)
            command('systemctl', 'reset-failed', *names, GATE, check=False)
            for name in names:
                (directory/name).unlink(missing_ok=True)
            command('systemctl', 'daemon-reload')
    from policy_observer_native import qualify as qualify_policy_observer
    policy_observer = qualify_policy_observer()
    report = {'schema': 1, 'test': 'offline-systemd-optional-extension', 'result': 'pass',
              'policy_observer': policy_observer,
              'assessed_at': datetime.now(timezone.utc).isoformat(), 'private_image_qualified': False,
              'container_only_mount_failures_reset': sorted(failed),
              'checks': ['generated-unit-verification', 'optional-failure-after-core-acceptance',
                         'accepted-observation-precedes-startup', 'core-failure-still-blocks-acceptance'],
              'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                               ('lanrith/build.py', 'lanrith/extensions.py', 'lanrith/extension_network.py',
                                'tests/extensions_native.py', 'tests/test_extension_network.py')}}
    with result.open('xb') as stream:
        stream.write(canonical(report))
    print('Native optional extension startup and mandatory failure gate passed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', required=True, type=Path)
    qualify(parser.parse_args().result)


if __name__ == '__main__':
    main()
