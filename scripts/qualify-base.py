#!/usr/bin/env python3
"""Bind successful native evidence and the reviewed build-platform assessment."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.release import canonical, document, file_record, read, require, unique
from lanrith.assessment import REQUIREMENTS, REVIEWED_WORKFLOWS, validate_platform

CHECKS = {
    'tpm2-ab': {'factory-install-readback', 'secure-boot', 'dm-verity', 'tpm2-state-encryption',
        'recovery-enrollment', 'ssh-pam-administration', 'automatic-boot-observation',
        'optional-services-inactive', 'one-shot-upgrade',
        'fallback-protection', 'unaccepted-reboot-fallback', 'explicit-acceptance', 'replay-rejection',
        'tamper-rejection', 'interrupted-staging', 'failed-health-fallback', 'populated-state-upgrade-and-rollback',
        'initrd-provisioning-failure-boundary', 'firewall-listener-failure-boundary',
        'unprivileged-control-boundary'},
    'manual-encryption': {'secure-boot', 'dm-verity', 'manual-state-encryption', 'recovery-enrollment',
        'ssh-pam-administration', 'automatic-boot-observation', 'persistent-state-reboot',
        'optional-services-inactive', 'unprivileged-control-boundary'},
    'rootless-administration': {'secure-boot', 'dm-verity', 'tpm2-state-encryption', 'recovery-enrollment',
        'automatic-boot-observation', 'unprivileged-ssh-administration', 'root-login-absent',
        'elevation-tools-absent', 'privileged-file-paths-absent', 'source-configuration-absent',
        'unprivileged-upload-staging'},
}


def value(path):
    return json.loads(read(path, 4*1024*1024), object_pairs_hook=unique)


def publish(path, data):
    # Container-created evidence can be root-owned and read-only to this job.
    # Replace it inside the job-owned output directory without changing ownership
    # or making the original evidence writable.
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def qualify(directory, project, environment, *, now=None):
    assessment = validate_platform(project)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    native = value(directory/'native-qualification.json')
    require(native.get('schema') == 1 and native.get('result') == 'pass' and
            native.get('test') == 'x86-64-uefi-factory-ab', 'Native UEFI qualification did not pass.')
    for field, name in (('filesystem_sha256', 'lanrith-base.tar.gz'), ('initrd_sha256', 'lanrith-initrd-base.tar.gz')):
        require(native.get(field) == file_record(directory/name)['sha256'],
                'Native qualification describes a different filesystem.')
    require(native.get('source_sha256') == file_record(project/'tests/vm.py')['sha256'],
            'Native qualification used a different test implementation.')
    stamp = datetime.datetime.fromisoformat(native['assessed_at'])
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'Native qualification is stale or future-dated.')
    profiles = native.get('profiles')
    require(isinstance(profiles, list) and len(profiles) == len(CHECKS) and
            {item.get('profile') for item in profiles} == set(CHECKS) and
            all(item.get('result') == 'pass' and isinstance(item.get('checks'), list) and
                set(item['checks']) == CHECKS[item['profile']] for item in profiles),
            'Native qualification has incomplete profile or failure-path coverage.')
    storage = value(directory/'storage-qualification.json')
    require(storage.get('result') == 'pass' and storage.get('test') == 'factory-slot-expansion' and
            storage.get('initial_partitions') == 4 and storage.get('expanded_partitions') == 8,
            'Matching-builder signed storage expansion did not pass.')
    security = value(directory/'security.json')
    require(security.get('production_qualified') is False and security.get('custom', {}).get('result') == 'pass' and
            security.get('inventory_sha256') == file_record(directory/'inventory.json')['sha256'],
            'Base security evidence is incomplete or was already promoted.')
    # A PR/local test can qualify behavior but cannot make a production claim.
    hosted_main = environment.get('GITHUB_ACTIONS') == 'true' and \
        environment.get('GITHUB_REPOSITORY') == 'Lanrith/lanrith' and \
        environment.get('GITHUB_REF') == 'refs/heads/main' and \
        environment.get('GITHUB_WORKFLOW_REF') == 'Lanrith/lanrith/.github/workflows/release.yml@refs/heads/main' and \
        environment.get('LANRITH_REUSABLE_WORKFLOW_REPOSITORY') == 'Lanrith/lanrith' and \
        environment.get('LANRITH_REUSABLE_WORKFLOW_SHA') == environment.get('GITHUB_SHA') and \
        environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    if not hosted_main:
        return False
    commit, run_id, attempt = (environment.get(name, '') for name in
                              ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
    require(re.fullmatch(r'[0-9a-f]{40}', commit) and re.fullmatch(r'[1-9][0-9]*', run_id) and
            re.fullmatch(r'[1-9][0-9]*', attempt), 'Hosted build identity is incomplete.')
    record = {'schema': 1, 'result': 'pass', 'specification': 'SLSA v1.2', 'build_level': 3,
        'scope': ['x86-64-qemu-uefi-core-tpm2', 'x86-64-qemu-uefi-core-manual-encryption',
                  'x86-64-qemu-uefi-core-rootless-administration'],
        'source_commit': commit, 'workflow': 'Lanrith/lanrith/.github/workflows/build-base.yml',
        'run_id': run_id, 'run_attempt': attempt, 'runner_environment': 'github-hosted',
        'assessed_at': now.isoformat(), 'assessment': assessment,
        'native_sha256': file_record(directory/'native-qualification.json')['sha256'],
        'storage_sha256': file_record(directory/'storage-qualification.json')['sha256'],
        'filesystem_sha256': file_record(directory/'lanrith-base.tar.gz')['sha256'],
        'initrd_sha256': file_record(directory/'lanrith-initrd-base.tar.gz')['sha256'],
        'requires_consumer_verified_file_and_oci_provenance': True}
    publish(directory/'qualification.json', canonical(record))
    security.update(production_qualified=True, slsa_spec='1.2', slsa_build_level=3,
        qualification={'result': 'pass', 'scope': record['scope'],
                       'record_sha256': file_record(directory/'qualification.json')['sha256']})
    publish(directory/'security.json', canonical(security))
    manifest = document(read(directory/'release.json', 65536))
    artifact = next(item for item in manifest['artifacts'] if item['role'] == 'security')
    actual = file_record(directory/artifact['name'])
    artifact.update(size=actual['size'], sha256=actual['sha256'])
    publish(directory/'release.json', canonical(document(canonical(manifest))))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    qualified = qualify(args.directory, Path(__file__).resolve().parents[1], os.environ)
    print('Hosted main native/SLSA qualification passed.' if qualified else
          'Native qualification passed; this is not an eligible hosted main release.')


if __name__ == '__main__':
    main()
