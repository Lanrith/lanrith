#!/usr/bin/env python3
"""Qualify the exact base detector in an isolated container and verify cleanup."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import ids_qualification
from lanrith.release import canonical, file_record, read, require, unique


def command(runtime, *args, timeout=30, check=True):
    value = subprocess.run([runtime, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(not check or value.returncode == 0, 'Native IDS container operation failed.')
    return value


def qualify(project, builder, base, result, *, runtime='docker'):
    require(runtime in ('docker', 'podman') and isinstance(builder, str) and builder and
            not builder.startswith('-') and not any(char.isspace() for char in builder), 'Invalid IDS gate runtime.')
    require(project.is_absolute() and project.resolve() == project and project.is_dir() and
            base.is_absolute() and base.resolve() == base and base.is_file() and
            result.is_absolute() and result.parent.resolve() == result.parent and result.parent.is_dir() and
            result.name == 'ids-qualification.json' and not result.exists() and not result.is_symlink() and
            all(':' not in str(path) for path in (project, base, result)),
            'IDS gate requires canonical base input and a new result path.')
    require(0 < base.stat().st_size <= 32*1024**3, 'IDS gate base exceeds the input size limit.')
    subject, sources = file_record(base), ids_qualification.implementation(project)
    require(subject['size'] <= 32*1024**3, 'IDS gate base exceeds the input size limit.')
    image = command(runtime, 'image', 'inspect', '--format', '{{.Id}}', builder).stdout.decode('ascii').strip()
    image = image.removeprefix('sha256:')
    require(re.fullmatch(r'[0-9a-f]{64}', image), 'IDS gate builder identity is invalid.')
    nonce = uuid.uuid4().hex
    name = 'lanrith-ids-qualification-'+nonce
    staging = tempfile.TemporaryDirectory(prefix='.ids-native-', dir=result.parent)
    stage = Path(staging.name)
    intermediate = stage/'native.json'
    require(not intermediate.exists() and not intermediate.is_symlink(), 'IDS gate staging result already exists.')
    container, report = None, None
    try:
        args = ['run', '--detach', '--name', name, '--label', 'io.lanrith.ids-gate='+nonce,
                '--pull=never', '--network', 'none', '--cap-add=NET_ADMIN', '--cap-add=SYS_ADMIN', '--cap-add=NET_RAW',
                '--security-opt=seccomp=unconfined', '--security-opt=apparmor=unconfined',
                '--memory=768m', '--pids-limit=128',
                '--tmpfs', '/run', '--tmpfs', '/tmp', '-v', str(project)+':/source:ro',
                '-v', str(base)+':/subject/base.tar.gz:ro', '-v', str(stage)+':/output',
                'sha256:'+image, '/usr/bin/sleep', '600']
        launched = command(runtime, *args).stdout.decode('ascii').strip()
        require(re.fullmatch(r'[0-9a-f]{64}', launched), 'IDS gate container identity is invalid.')
        container = launched
        native = command(runtime, 'exec', container, 'python3', '-B', '/source/tests/ids_native.py',
                         '--base', '/subject/base.tar.gz', '--result', '/output/'+intermediate.name,
                         timeout=240, check=False)
        if native.returncode:
            sys.stderr.buffer.write((native.stdout+b'\n'+native.stderr)[-16384:])
        require(native.returncode == 0, 'Native IDS fixture failed.')
        report = json.loads(read(intermediate, 262144), object_pairs_hook=unique)
        require(report.get('filesystem_sha256') == subject['sha256'] and
                report.get('implementation_sha256') == sources,
                'Native IDS fixture describes different base or source inputs.')
        require(file_record(base) == subject and ids_qualification.implementation(project) == sources,
                'IDS qualification inputs changed during execution.')
    finally:
        try:
            if container is None:
                inspected = command(runtime, 'inspect', '--format', '{{json .Config.Labels}}', name, check=False)
                if inspected.returncode == 0:
                    labels = json.loads(inspected.stdout, object_pairs_hook=unique)
                    require(labels.get('io.lanrith.ids-gate') == nonce, 'IDS fixture cleanup identity differs.')
                    container = name
            if container is not None:
                command(runtime, 'rm', '--force', container)
        finally:
            try:
                intermediate.unlink(missing_ok=True)
            finally:
                staging.cleanup()
    require(report is not None, 'Native IDS report is unavailable.')
    report.update(container_cleanup='removed', builder_image_sha256=image, container_runtime=runtime)
    ids_qualification.validate(report, subject['sha256'], project=project)
    descriptor, temporary = tempfile.mkstemp(prefix='.ids-report-', dir=result.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(report))
            stream.flush()
            os.fsync(stream.fileno())
        require(not result.exists() and not result.is_symlink(), 'IDS result appeared during qualification.')
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
    print('Native IDS qualification, exact base executable binding and fixture cleanup passed.')


if __name__ == '__main__':
    main()
