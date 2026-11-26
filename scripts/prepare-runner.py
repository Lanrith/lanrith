#!/usr/bin/env python3
"""Reclaim unused SDKs on a disposable hosted runner and record its disk budget."""

import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build_resources

MINIMUM_FREE_BYTES = 60 * 1024**3
CONSUMER_FREE_BYTES = 32 * 1024**3
# Fixed SDK paths only. Go, Python, Node actions, Docker, the source checkout,
# package artifacts and authenticated build caches are never cleanup targets.
UNUSED_SDKS = (
    '/usr/local/lib/android',
    '/usr/share/dotnet',
    '/opt/ghc',
    '/opt/hostedtoolcache/CodeQL',
    '/usr/share/swift',
    '/usr/local/.ghcup',
)


def prepare(profile='platform'):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.environ.get('RUNNER_OS') != 'Linux'):
        raise RuntimeError('SDK cleanup requires a disposable GitHub-hosted Linux runner.')
    if profile not in ('platform', 'isolated-consumer'):
        raise RuntimeError('Unknown runner resource profile.')
    if profile == 'isolated-consumer' and (os.environ.get('GITHUB_REPOSITORY') !=
            'Lanrith/config-template-qualification' or os.environ.get('GITHUB_JOB') != 'image'):
        raise RuntimeError('Consumer disk preparation is restricted to the isolated image job.')
    minimum = CONSUMER_FREE_BYTES if profile == 'isolated-consumer' else MINIMUM_FREE_BYTES
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    report = temporary/'runner-disk.json'
    if not temporary.is_dir() or report.is_symlink():
        raise RuntimeError('Runner disk diagnostics require a regular file in RUNNER_TEMP.')
    record = {
        'schema': 1, 'kind': 'hosted-runner-disk-preparation', 'result': 'fail',
        'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'profile': profile, 'minimum_free_bytes': minimum, 'cleanup_paths': list(UNUSED_SDKS),
        'runner': {key: os.environ[key] for key in ('ImageOS', 'ImageVersion', 'RUNNER_OS',
            'RUNNER_ARCH', 'RUNNER_ENVIRONMENT', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB')
            if key in os.environ},
    }

    def observe():
        usage = shutil.disk_usage(temporary)
        return {'path': str(temporary), 'total_bytes': usage.total,
                'used_bytes': usage.used, 'free_bytes': usage.free}

    try:
        record['before'] = observe()
        print(f"Runner disk before SDK cleanup: {record['before']['free_bytes']/1024**3:.2f} GiB free.", flush=True)
        subprocess.run(['sudo', 'rm', '-rf', '--one-file-system', '--', *UNUSED_SDKS], check=True)
        record['after'] = observe()
        available = record['after']['free_bytes']
        print(f'Runner disk after SDK cleanup: {available/1024**3:.2f} GiB free; {minimum/1024**3:.2f} GiB required.', flush=True)
        if available < minimum:
            raise RuntimeError(f'Insufficient runner disk: {available/1024**3:.2f} GiB free after SDK cleanup; '
                               f'at least {minimum/1024**3:.2f} GiB is required before downloading build artifacts.')
        record['build_resources'] = build_resources.prepare()
        record['result'] = 'pass'
        return record
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        record['error'] = str(error)[:2000]
        raise
    finally:
        record['completed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report.write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('platform', 'isolated-consumer'), default='platform')
    args = parser.parse_args()
    try:
        prepare(args.profile)
    except (OSError, KeyError, subprocess.SubprocessError, RuntimeError) as error:
        print(f'::error::{error}', file=sys.stderr)
        raise SystemExit(1)
