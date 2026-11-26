#!/usr/bin/env python3
"""Assemble the isolated consumer canary with disposable keys and publish only a report."""
import argparse
import datetime
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, release, trust


def require_assembly_space(owner, bundle, work):
    """Budget authenticated expanded inputs and verified outputs after the pull."""
    expanded = 0
    entries = 0
    for name in ('lanrith-base.tar.gz', 'lanrith-initrd-base.tar.gz'):
        with tarfile.open(bundle/name, 'r|gz') as archive:
            for member in archive:
                entries += 1
                release.require(member.size >= 0 and entries <= 200000, 'Canary filesystem inventory exceeds its bound.')
                expanded += member.size
                release.require(expanded <= 16*1024**3, 'Canary expanded filesystems exceed their disk budget.')
    storage = config.load(owner/'config.yaml')['hardware']['storage']
    # mkosi staging trees, raw disk plus its two verified split-payload copies,
    # and 4 GiB for metadata, initrd scratch and the runner. Installed /var and
    # the spare slot are provisioned on hardware, not in the factory image.
    payload = (storage['root_mib'] + max(64, storage['root_mib']//16) + storage['esp_mib'])*1024**2
    required = 3*expanded + 3*payload + 4*1024**3
    available = shutil.disk_usage(work).free
    print(f'Consumer assembly disk: {available/1024**3:.2f} GiB free; {required/1024**3:.2f} GiB required.', flush=True)
    release.require(available >= required, 'Insufficient disk for authenticated consumer inputs and output bounds.')
    return {'expanded_input_bytes': expanded, 'payload_bound_bytes': payload,
            'required_bytes': required, 'available_bytes': available}


def disposable_serial_hash():
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(secrets.token_bytes(32), salt=salt, n=32768, r=8, p=1,
                             dklen=32, maxmem=64*1024*1024)
    return 'scrypt:32768:8:1:'+salt.hex()+':'+derived.hex()


def disposable_authorities(owner, keys, *, tpm_required):
    authorities = {'boot': 3072, 'evidence': 3072}
    if tpm_required:
        authorities['pcr'] = 2048
    for name, bits in authorities.items():
        key = keys/(name+'.key')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:'+str(bits), '-nodes', '-sha256', '-days', '1',
            '-subj', '/CN=Lanrith disposable canary '+name, '-keyout', str(key),
            '-out', str(owner/'trust'/(name+'.crt'))], check=True, capture_output=True)
        key.chmod(0o600)
    return authorities


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
        authorities = disposable_authorities(copied, keys,
            tpm_required=config.load(copied/'config.yaml')['hardware']['boot'].get('tpm', 'required') == 'required')
        # These keys are generated for this test only. No image or private key is
        # uploaded, and this code cannot authorize a deployable owner release.
        os.environ['LANRITH_SIGNING_PROFILE'] = 'repository'
        bundle = work/'platform'
        request = consumer.preflight(copied, bundle)
        request_path = work/'request.json'
        request_path.write_bytes(release.canonical(request))
        selection = trust.lock(copied/'platform.lock')
        subprocess.run(['docker', 'pull', selection['builder']+'@sha256:'+selection['builder_digest']], check=True)
        require_assembly_space(copied, bundle, work)
        (bundle/'signing-admission.json').write_bytes(release.canonical({
            'request': request, 'admitted_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'assessment_sha256': release.file_record(bundle/'security-assessment.json')['sha256']
                if (bundle/'security-assessment.json').exists() else None}))
        os.environ['LANRITH_BOOT_KEY'] = (keys/'boot.key').read_text()
        os.environ['LANRITH_BOOT_CERTIFICATE'] = (copied/'trust/boot.crt').read_text()
        if 'pcr' in authorities:
            os.environ['LANRITH_PCR_KEY'] = (keys/'pcr.key').read_text()
            os.environ['LANRITH_PCR_CERTIFICATE'] = (copied/'trust/pcr.crt').read_text()
        if config.load(copied/'config.yaml')['administration']['serial']['enabled']:
            os.environ['LANRITH_SERIAL_PASSPHRASE_HASH'] = disposable_serial_hash()
        try:
            # Both signed payloads are assembled and verified. The canary only
            # needs their deployment record, so avoid duplicating large archives.
            consumer.assemble(copied, bundle, request_path, work/'image', archive_images=False)
        finally:
            for name in ('LANRITH_BOOT_KEY', 'LANRITH_BOOT_CERTIFICATE', 'LANRITH_SERIAL_PASSPHRASE_HASH',
                         'LANRITH_PCR_KEY', 'LANRITH_PCR_CERTIFICATE'):
                os.environ.pop(name, None)
        deployment = release.read(work/'image/deployment.json', 1024*1024)
        output.write_bytes(release.canonical({'schema': 1, 'kind': 'isolated-consumer-qualification', 'result': 'pass',
            'repository': os.environ['GITHUB_REPOSITORY'], 'source_commit': os.environ['GITHUB_SHA'],
            'workflow_commit': os.environ['LANRITH_WORKFLOW_COMMIT'], 'platform_version': selection['version'],
            'platform_lock_sha256': request['platform_lock_sha256'], 'configuration_sha256': request['configuration_sha256'],
            'deployment_record_sha256': hashlib.sha256(deployment).hexdigest(),
            'deployable': False, 'signing_authority': 'disposable-per-run',
            'run_url': 'https://github.com/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    qualification(args.owner.resolve(), args.output.resolve())
