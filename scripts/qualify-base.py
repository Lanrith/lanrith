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
from lanrith import ids_qualification, dns_qualification, firewall_qualification

REQUIREMENTS = {'appropriate-platform', 'consistent-process', 'distributed-provenance',
                'provenance-exists', 'provenance-authentic', 'provenance-unforgeable',
                'hosted', 'isolated-signing', 'isolated-concurrent-builds',
                'isolated-subsequent-builds', 'isolated-caches', 'isolated-remote-influence',
                'external-parameters', 'security-practices'}
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
LOG_CHECKS = {'generated-graph-readiness', 'exited-exporter-not-ready', 'real-journal-ingestion',
    'own-journal-exclusion', 'redaction-before-queue', 'authenticated-verified-https',
    'collector-outage', 'bounded-nonblocking-overflow', 'persistent-queue-crash-restart',
    'collector-return-delivery', 'private-state-directory-boundary', 'exporter-loss-observations',
    'local-metadata-body-withheld', 'local-reader-and-credential-boundary',
    'local-bounded-rotation', 'local-filesystem-failure-independent-delivery', 'local-producer-restart-identity'}
DIRECTORY_CHECKS = {'ldaps-ipv4-ipv6', 'starttls-ipv4-ipv6', 'hostname-and-authority-validation',
    'expired-certificate-rejection', 'no-plaintext-fallback-or-bind', 'bounded-slow-peer',
    'reader-and-observer-exact-egress', 'other-identities-destination-port-source-interface-denied',
    'independent-observer-identity', 'private-fresh-observation', 'disabled-components-remove-paths'}
DIRECTORY_IMPLEMENTATION = {'lanrith/directory_config.py', 'lanrith/directory_runtime.py', 'lanrith/firewall.py',
    'lanrith/metrics.py', 'lanrith/router_metrics_runtime.py', 'lanrith/integrations.py',
    'lanrith/config.py', 'lanrith/build.py', 'lanrith/runtime_plan.py',
    'tests/test_directory.py', 'tests/test_policy_agent.py', 'tests/test_intent.py'}
CREDENTIAL_CHECKS = {'generated-unit-verification', 'operator-uid-socket-stage-and-commit',
    'unauthorized-uid-and-root-denied', 'malformed-input-preserves-consumers',
    'failed-requests-collected',
    'consumer-waits-for-complete-staged-set', 'native-loadcredential-bytes',
    'capability-empty-no-new-privileges', 'inet-and-outside-write-denial',
    'active-completion-observer-not-stopped', 'extension-native-loadcredential-unprivileged-readers',
    'generated-log-credential-staging', 'pid1-named-user-acl-and-owning-group-denial',
    'extension-operator-uid-boundary', 'extension-exact-writable-namespace',
    'optional-extension-current-boot-acceptance-gate', 'optional-extension-no-core-service-control',
    'required-extension-committed-readiness', 'extension-invalid-and-fallback-values-preserve-consumers'}
CREDENTIAL_IMPLEMENTATION = {'lanrith/credential_operation.py', 'lanrith/credential_config.py',
    'lanrith/credential_store.py', 'lanrith/credential_values.py', 'lanrith/build.py',
    'lanrith/logs.py', 'lanrith/logs_runtime.py', 'lanrith/systemd_credential.py', 'tests/test_systemd_credential.py', 'lanrith/policy_runtime.py', 'lanrith/extension_observations.py',
    'lanrith/runtime.py', 'lanrith/image_operation.py', 'lanrith/config.py', 'tests/test_intent.py',
    'scripts/qualify-credentials.py', 'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_credentials.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_service.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/credential_runtime.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/systemd_service.py', 'lanrith/extension_credential_values.py',
    'lanrith/extension_credential_config.py', 'lanrith/extension_credential_operation.py',
    'lanrith/extensions.py', 'tests/extension_credentials_native.py'}


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
    logs = value(directory/'logs-qualification.json')
    custom = value(directory/'custom-security.json')
    require(logs.get('schema') == 1 and logs.get('result') == 'pass' and
            logs.get('test') == 'offline-journal-https-outage' and set(logs.get('checks', [])) == LOG_CHECKS and
            logs.get('source_sha256') == file_record(project/'tests/logs_native.py')['sha256'] and
            logs.get('alloy_sha256') == custom.get('components', {}).get('alloy', {}).get('binary_sha256') and
            logs.get('queue_capacity_bytes') == 67108864 and 0 < logs.get('overflow_records', 0) and
            0 < logs.get('queue_physical_bytes', 0) <= 160*1024*1024 and
            logs.get('delivered_batches', 0) > 0 and
            all(type(logs.get(field)) is int for field in ('local_output_bytes', 'local_output_files', 'local_failed_records')) and
            0 < logs.get('local_output_bytes', 0) <= 3*1024*1024 and
            2 <= logs.get('local_output_files', 0) <= 3 and logs.get('local_failed_records', 0) > 0,
            'Native journal delivery qualification is incomplete or describes another exporter.')
    stamp = datetime.datetime.fromisoformat(logs['assessed_at'])
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'Native journal delivery qualification is stale or future-dated.')
    implementation = logs.get('implementation_sha256', {})
    require(set(implementation) == {'lanrith/logs.py', 'lanrith/logs_runtime.py', 'lanrith/service_plane.py', 'lanrith/extension_observations.py'} and
            all(file_record(project/name)['sha256'] == expected for name, expected in implementation.items()),
            'Log delivery implementation changed after native qualification.')
    directory_tls = value(directory/'directory-qualification.json')
    require(directory_tls.get('schema') == 1 and directory_tls.get('result') == 'pass' and
            directory_tls.get('test') == 'offline-directory-tls-egress' and
            set(directory_tls.get('checks', [])) == DIRECTORY_CHECKS and
            directory_tls.get('external_network') is False and
            directory_tls.get('source_sha256') == file_record(project/'tests/directory_native.py')['sha256'],
            'Native directory qualification is incomplete or describes different tests.')
    stamp = datetime.datetime.fromisoformat(directory_tls['assessed_at'])
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'Native directory qualification is stale or future-dated.')
    implementation = directory_tls.get('implementation_sha256', {})
    require(set(implementation) == DIRECTORY_IMPLEMENTATION and
            all(file_record(project/name)['sha256'] == expected for name, expected in implementation.items()),
            'Directory implementation changed after native qualification.')
    credentials = value(directory/'credential-qualification.json')
    require(type(credentials.get('schema')) is int and credentials['schema'] == 1 and
            credentials.get('result') == 'pass' and credentials.get('test') == 'offline-systemd-credential-provisioning' and
            isinstance(credentials.get('checks'), list) and all(isinstance(check, str) for check in credentials['checks']) and
            set(credentials['checks']) == CREDENTIAL_CHECKS and credentials.get('external_network') is False and
            credentials.get('container_cleanup') == 'removed' and credentials.get('private_image_qualified') is False and
            isinstance(credentials.get('container_runtime'), str) and credentials['container_runtime'] in ('docker', 'podman') and
            isinstance(credentials.get('builder_image_sha256'), str) and
            re.fullmatch(r'[0-9a-f]{64}', credentials['builder_image_sha256']) and
            credentials.get('source_sha256') == file_record(project/'tests/credentials_native.py')['sha256'],
            'Native credential qualification is incomplete or describes different tests.')
    try:
        stamp = datetime.datetime.fromisoformat(credentials['assessed_at'])
    except (KeyError, TypeError, ValueError):
        require(False, 'Native credential qualification timestamp is invalid.')
    require(stamp.tzinfo is not None and datetime.timedelta(0) <= now-stamp <= datetime.timedelta(hours=6),
            'Native credential qualification is stale or future-dated.')
    implementation = credentials.get('implementation_sha256', {})
    require(isinstance(implementation, dict) and set(implementation) == CREDENTIAL_IMPLEMENTATION and
            all(file_record(project/name)['sha256'] == expected for name, expected in implementation.items()),
            'Credential implementation changed after native qualification.')
    ids_qualification.validate(value(directory/'ids-qualification.json'),
        file_record(directory/'lanrith-base.tar.gz')['sha256'], project=project, now=now)
    dns_qualification.validate(value(directory/'dns-qualification.json'),
        file_record(directory/'lanrith-base.tar.gz')['sha256'], project=project, now=now)
    firewall_qualification.validate(value(directory/'firewall-qualification.json'),
        file_record(directory/'lanrith-base.tar.gz')['sha256'], project=project, now=now)
    assessment = value(project/'security/slsa-assessment.json')
    require(assessment.get('schema') == 1 and assessment.get('specification') == 'SLSA v1.2' and
            assessment.get('target') == 'Build L3' and assessment.get('result') == 'design-assessed' and
            set(assessment.get('requirements', {})) == REQUIREMENTS and
            all(item.get('result') == 'satisfied-by-design' and item.get('evidence')
                for item in assessment['requirements'].values()),
            'The build platform lacks a complete requirement assessment.')
    workflows = assessment.get('reviewed_workflows', {})
    require(set(workflows) == {'.github/workflows/build-base.yml', '.github/workflows/release.yml',
                              '.github/workflows/check.yml', '.github/workflows/restore-cache.yml',
                              '.github/workflows/publish-release.yml', '.github/workflows/archive-evidence.yml',
                              '.github/workflows/security-review.yml', '.github/workflows/security-proposal.yml'},
            'The reviewed workflow set is incomplete.')
    require(all(file_record(project/name)['sha256'] == expected for name, expected in workflows.items()),
            'A build workflow changed after its platform requirement assessment.')
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
        'logs_sha256': file_record(directory/'logs-qualification.json')['sha256'],
        'directory_sha256': file_record(directory/'directory-qualification.json')['sha256'],
        'credentials_sha256': file_record(directory/'credential-qualification.json')['sha256'],
        'ids_sha256': file_record(directory/'ids-qualification.json')['sha256'],
        'dns_sha256': file_record(directory/'dns-qualification.json')['sha256'],
        'firewall_sha256': file_record(directory/'firewall-qualification.json')['sha256'],
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
