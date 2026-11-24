#!/usr/bin/env python3
"""Assemble the isolated consumer canary with disposable keys and publish only a report."""
import argparse
import datetime
import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, release, trust


def qualification(owner, output):
    release.require(os.environ.get('GITHUB_REPOSITORY') == 'Lanrith/config-template-qualification',
                    'Disposable image qualification is restricted to the isolated canary repository.')
    release.require(not any(value for name, value in os.environ.items() if name.startswith('LANRITH_') and
                    name.endswith(('_KEY', '_CERTIFICATE', '_PASSPHRASE_HASH'))),
                    'The isolated canary must not receive deployment credentials.')
    release.require(Path('/dev/shm').is_mount(), 'Canary keys require private tmpfs.')
    spec = importlib.util.spec_from_file_location('canary_consumer', ROOT/'scripts/consumer.py')
    consumer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumer)
    with tempfile.TemporaryDirectory(prefix='lanrith-canary.', dir=os.environ['RUNNER_TEMP']) as temporary, \
            tempfile.TemporaryDirectory(prefix='lanrith-canary-keys.', dir='/dev/shm') as private:
        work, keys = Path(temporary), Path(private)
        copied = work/'owner'
        shutil.copytree(owner, copied, symlinks=True, ignore=shutil.ignore_patterns('.git'))
        release.require(not any(p.is_symlink() for p in copied.rglob('*')), 'Canary configuration contains a symlink.')
        for name in ('boot', 'evidence'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1',
                '-subj', '/CN=Lanrith disposable canary '+name, '-keyout', str(keys/(name+'.key')),
                '-out', str(copied/'trust'/(name+'.crt'))], check=True, capture_output=True)
        # These keys are generated for this test only. No image or private key is
        # uploaded, and this code cannot authorize a deployable owner release.
        os.environ['LANRITH_SIGNING_PROFILE'] = 'repository'
        bundle = work/'platform'
        request = consumer.preflight(copied, bundle)
        request_path = work/'request.json'
        request_path.write_bytes(release.canonical(request))
        selection = trust.lock(copied/'platform.lock')
        subprocess.run(['docker', 'pull', selection['builder']+'@sha256:'+selection['builder_digest']], check=True)
        (bundle/'signing-admission.json').write_bytes(release.canonical({
            'request': request, 'admitted_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'assessment_sha256': release.file_record(bundle/'security-assessment.json')['sha256']
                if (bundle/'security-assessment.json').exists() else None}))
        os.environ['LANRITH_BOOT_KEY'] = (keys/'boot.key').read_text()
        os.environ['LANRITH_BOOT_CERTIFICATE'] = (copied/'trust/boot.crt').read_text()
        if config.load(copied/'config.yaml')['administration']['serial']['enabled']:
            os.environ['LANRITH_SERIAL_PASSPHRASE_HASH'] = subprocess.run(
                ['openssl', 'passwd', '-6', '-stdin'], input=secrets.token_hex(32)+'\n',
                capture_output=True, text=True, check=True).stdout.strip()
        try:
            consumer.assemble(copied, bundle, request_path, work/'image')
        finally:
            for name in ('LANRITH_BOOT_KEY', 'LANRITH_BOOT_CERTIFICATE', 'LANRITH_SERIAL_PASSPHRASE_HASH'):
                os.environ.pop(name, None)
        deployment = release.read(work/'image/deployment.json', 1024*1024)
        output.write_bytes(release.canonical({'schema': 1, 'kind': 'isolated-consumer-qualification', 'result': 'pass',
            'repository': os.environ['GITHUB_REPOSITORY'], 'source_commit': os.environ['GITHUB_SHA'],
            'workflow_commit': os.environ['LANRITH_WORKFLOW_COMMIT'], 'platform_version': selection['version'],
            'platform_lock_sha256': request['platform_lock_sha256'], 'configuration_sha256': request['configuration_sha256'],
            'deployment_record_sha256': __import__('hashlib').sha256(deployment).hexdigest(),
            'deployable': False, 'signing_authority': 'disposable-per-run',
            'run_url': 'https://github.com/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    qualification(args.owner.resolve(), args.output.resolve())
