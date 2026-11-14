#!/usr/bin/env python3
"""Run the native credential gate in an isolated, disposable systemd container."""

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
from lanrith.release import canonical, read, require, unique


def command(runtime, *args, timeout=30, check=True):
    result = subprocess.run([runtime, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(not check or result.returncode == 0, 'Native credential container operation failed.')
    return result


def wait_systemd(runtime, container):
    deadline = time.monotonic()+60
    while True:
        remaining = deadline-time.monotonic()
        require(remaining > 0, 'Credential gate systemd readiness deadline expired.')
        try:
            if command(runtime, 'exec', container, 'systemctl', 'is-active', '--quiet', 'basic.target',
                       timeout=min(5, remaining), check=False).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        remaining = deadline-time.monotonic()
        require(remaining > 0, 'Credential gate systemd readiness deadline expired.')
        try:
            inspected = command(runtime, 'inspect', '--format', '{{json .State}}', container,
                                timeout=min(5, remaining), check=False)
        except subprocess.TimeoutExpired:
            inspected = None
        if inspected is not None and inspected.returncode == 0:
            state = json.loads(inspected.stdout, object_pairs_hook=unique)
            require(state.get('Running') is True, 'Credential gate systemd container exited before readiness.')
        # An observation failure is not an exited container. Recheck this same
        # handle until ready, authoritatively stopped, or the bounded deadline.
        time.sleep(1)


def qualify(project, builder, result, *, runtime='docker'):
    require(runtime in ('docker', 'podman') and isinstance(builder, str) and builder and
            not builder.startswith('-') and not any(c.isspace() for c in builder), 'Invalid credential gate runtime.')
    require(project.is_absolute() and project.resolve() == project and project.is_dir() and
            result.is_absolute() and result.parent.resolve() == result.parent and result.parent.is_dir() and
            result.name == 'credential-qualification.json' and not result.exists() and not result.is_symlink() and
            ':' not in str(project) and ':' not in str(result), 'Credential gate needs a new canonical result path.')
    image = command(runtime, 'image', 'inspect', '--format', '{{.Id}}', builder).stdout.decode('ascii').strip()
    image = image.removeprefix('sha256:')
    require(re.fullmatch(r'[0-9a-f]{64}', image), 'Credential gate builder identity is invalid.')
    nonce = uuid.uuid4().hex
    name = 'lanrith-credentials-'+nonce
    intermediate = result.parent/('.credentials-'+nonce+'.json')
    require(not intermediate.exists() and not intermediate.is_symlink(), 'Credential gate staging result exists.')
    container = None
    report = None
    try:
        # No daemon socket, owner input, key, physical disk or host cgroup bind
        # enters the fixture. Its private cgroup namespace is writable only
        # within the new container's subtree.
        args = ['run', '--detach', '--name', name, '--label', 'io.lanrith.credential-gate='+nonce,
            '--network', 'none', '--privileged', '--cgroupns=private', '--memory=512m',
            '--tmpfs', '/run', '--tmpfs', '/tmp', '-v', str(project)+':/source:ro',
            '-v', str(result.parent)+':/output']
        if runtime == 'podman':
            args.append('--systemd=always')
        args += ['sha256:'+image, '/usr/lib/systemd/systemd', '--system', '--unit=basic.target', '--log-target=console']
        # The unique name is retained before launch so a timeout after daemon
        # creation still has a bounded, label-verified cleanup path.
        launched = command(runtime, *args).stdout.decode('ascii').strip()
        require(re.fullmatch(r'[0-9a-f]{64}', launched), 'Credential gate container identity is invalid.')
        container = launched
        wait_systemd(runtime, container)
        native = command(runtime, 'exec', '-e', 'PYTHONPATH=/source:/source/tests', container, 'python3', '-B',
                '/source/tests/credentials_native.py', '--result', '/output/'+intermediate.name, timeout=240, check=False)
        if native.returncode:
            # This fixture contains synthetic inputs only. Retain bounded
            # native diagnostics instead of hiding its failed assertion.
            sys.stderr.buffer.write((native.stdout+b'\n'+native.stderr)[-16384:])
        require(native.returncode == 0, 'Native credential fixture failed.')
        report = json.loads(read(intermediate, 262144), object_pairs_hook=unique)
        require(report.get('result') == 'pass' and report.get('test') == 'offline-systemd-credential-provisioning',
                'Native credential fixture did not pass.')
    finally:
        if container is None:
            # A launch may have timed out after creating the named container.
            inspected = command(runtime, 'inspect', '--format', '{{json .Config.Labels}}', name, check=False)
            if inspected.returncode == 0:
                labels = json.loads(inspected.stdout, object_pairs_hook=unique)
                require(labels.get('io.lanrith.credential-gate') == nonce,
                        'Credential fixture cleanup identity differs.')
                container = name
        try:
            if container is not None:
                command(runtime, 'rm', '--force', container)
        finally:
            intermediate.unlink(missing_ok=True)
    require(report is not None, 'Native credential report is unavailable.')
    report.update(container_cleanup='removed', builder_image_sha256=image, container_runtime=runtime)
    descriptor, temporary = tempfile.mkstemp(prefix='.credential-report-', dir=result.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(report))
            stream.flush()
            os.fsync(stream.fileno())
        require(not result.exists() and not result.is_symlink(), 'Credential gate result appeared during qualification.')
        os.replace(temporary, result)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builder', required=True)
    parser.add_argument('--runtime', choices=('docker', 'podman'), default='docker')
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    qualify(Path(__file__).resolve().parents[1], args.builder, args.result, runtime=args.runtime)
    print('Native credential qualification and fixture cleanup passed.')


if __name__ == '__main__':
    main()
