#!/usr/bin/env python3
"""Qualify exact base nft userspace and generated observer service in a disposable offline systemd container."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import firewall_qualification
from lanrith.release import canonical, file_record, read, require, unique


def command(runtime, *args, timeout=30, check=True):
    result = subprocess.run([runtime, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(not check or result.returncode == 0, 'Firewall qualification container operation failed.')
    return result


def qualify(project, builder, base, result, *, runtime='docker'):
    require(runtime in ('docker', 'podman') and isinstance(builder, str) and builder and
            not builder.startswith('-') and not any(char.isspace() for char in builder), 'Invalid Firewall gate runtime.')
    require(project.is_absolute() and project.resolve() == project and project.is_dir() and
            base.is_absolute() and base.resolve() == base and base.is_file() and
            result.is_absolute() and result.parent.resolve() == result.parent and result.parent.is_dir() and
            result.name == 'firewall-qualification.json' and not result.exists() and not result.is_symlink() and
            all(':' not in str(path) for path in (project, base, result)), 'Firewall gate needs canonical inputs and a new result.')
    require(0 < base.stat().st_size <= 32*1024**3, 'Firewall gate base size bound.')
    subject, sources = file_record(base), firewall_qualification.implementation(project)
    # Reject malformed allocation/link metadata before starting a container.
    expected = firewall_qualification.subject(base)[firewall_qualification.NFT]
    image = command(runtime, 'image', 'inspect', '--format', '{{.Id}}', builder).stdout.decode('ascii').strip().removeprefix('sha256:')
    require(re.fullmatch(r'[0-9a-f]{64}', image), 'Firewall builder identity differs.')
    nonce = uuid.uuid4().hex
    name = 'lanrith-firewall-qualification-'+nonce
    container, report = None, None
    with tempfile.TemporaryDirectory(prefix='.firewall-native-', dir=result.parent) as temporary:
        stage = Path(temporary)
        intermediate = stage/'native.json'
        try:
            args = ['run', '--detach', '--name', name, '--label', 'io.lanrith.firewall-gate='+nonce,
                '--pull=never', '--network=none', '--privileged', '--cgroupns=private', '--memory=1g', '--pids-limit=256',
                '--tmpfs=/run', '--tmpfs=/tmp',
                '--env', 'LANRITH_FIXTURE_OUTER_NET='+str(os.stat('/proc/self/ns/net').st_ino),
                '--env', 'LANRITH_FIXTURE_OUTER_MNT='+str(os.stat('/proc/self/ns/mnt').st_ino), '-v', str(project)+':/source:ro',
                '-v', str(base)+':/subject/base.tar.gz:ro', '-v', str(stage)+':/output']
            if runtime == 'podman':
                args.append('--systemd=always')
            args += ['sha256:'+image, '/usr/lib/systemd/systemd', '--system', '--unit=basic.target', '--log-target=console']
            launched = command(runtime, *args).stdout.decode('ascii').strip()
            require(re.fullmatch(r'[0-9a-f]{64}', launched), 'Firewall container identity differs.')
            container = launched
            deadline = time.monotonic()+60
            while command(runtime, 'exec', container, 'systemctl', 'is-active', '--quiet', 'basic.target', timeout=5, check=False).returncode:
                require(time.monotonic() < deadline, 'Firewall fixture systemd readiness expired.')
                time.sleep(.2)
            native = command(runtime, 'exec', container, 'python3', '-B', '/source/tests/firewall_metadata_native.py', '--service',
                '--base', '/subject/base.tar.gz', '--result', '/output/native.json', timeout=300, check=False)
            if native.returncode:
                sys.stderr.buffer.write((native.stdout+b'\n'+native.stderr)[-16384:])
            require(native.returncode == 0, 'Firewall native qualification failed.')
            report = json.loads(read(intermediate, 262144), object_pairs_hook=unique)
            require(report.get('filesystem_sha256') == subject['sha256'] and
                    report.get('nft_sha256') == expected and report.get('base_userspace_sha256') ==
                    firewall_qualification.subject(base, report.get('builder_libraries_sha256', {})) and report.get('source_sha256') == sources,
                    'Firewall fixture describes another base or source tree.')
            require(file_record(base) == subject and firewall_qualification.implementation(project) == sources,
                    'Firewall qualification inputs changed during execution.')
        finally:
            if container is None:
                inspected = command(runtime, 'inspect', '--format', '{{json .Config.Labels}}', name, check=False)
                if inspected.returncode == 0:
                    require(json.loads(inspected.stdout, object_pairs_hook=unique).get('io.lanrith.firewall-gate') == nonce,
                            'Firewall cleanup identity differs.')
                    container = name
            if container is not None:
                command(runtime, 'rm', '--force', container)
    require(report is not None, 'Firewall qualification report is absent.')
    report.update(container_cleanup='removed', builder_image_sha256=image, container_runtime=runtime)
    firewall_qualification.validate(report, subject['sha256'], project=project)
    descriptor, temporary = tempfile.mkstemp(prefix='.firewall-report-', dir=result.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(report))
            stream.flush()
            os.fsync(stream.fileno())
        require(not result.exists() and not result.is_symlink(), 'Firewall result appeared during qualification.')
        os.replace(temporary, result)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builder', required=True)
    parser.add_argument('--runtime', choices=('docker', 'podman'), default='docker')
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    qualify(Path(__file__).resolve().parents[1], args.builder, args.base, args.result, runtime=args.runtime)
    print('Native Firewall qualification, exact base executable binding and cleanup passed.')


if __name__ == '__main__':
    main()
