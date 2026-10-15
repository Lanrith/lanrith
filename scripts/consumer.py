#!/usr/bin/env python3
"""Trusted reusable-workflow implementation for a private owner repository."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import admission, archive as handoff, config, evidence, extensions, release, trust


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, **kwargs)


def fetch(selection, directory):
    directory.mkdir(mode=0o700)
    names = sorted(set(selection['files']) | {'release.json', 'builder.intoto.jsonl'})
    argv = ['gh', 'release', 'download', selection['version'], '--repo', trust.REPOSITORY, '--dir', str(directory)]
    for name in names:
        argv += ['--pattern', name]
        if not name.endswith('.intoto.jsonl'):
            argv += ['--pattern', name+'.intoto.jsonl']
    run(*argv)
    # A retained image needs a fresh assessment even when its package inputs did not change.
    response = json.loads(run('gh', 'api', 'repos/'+trust.REPOSITORY+'/releases?per_page=100',
                              capture_output=True, text=True).stdout)
    suffix = '-'+selection['files']['inventory.json'][:12]
    assessments = [item for item in response if not item['draft'] and
                   re.fullmatch(r'assessment-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}', item['tag_name']) and
                   item['tag_name'].endswith(suffix)]
    if assessments:
        latest = max(assessments, key=lambda item: item['tag_name'])
        run('gh', 'release', 'download', latest['tag_name'], '--repo', trust.REPOSITORY, '--dir', str(directory),
            '--pattern', 'security-assessment.json', '--pattern', 'security-assessment.json.intoto.jsonl')
    reference = trust.verify(directory, selection)
    trust.verify_builder(selection, directory/'builder.intoto.jsonl')
    admission.assess(directory, selection)
    return reference


def protections(repository):
    require = release.require
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'Invalid owner repository.')
    def api(suffix):
        return json.loads(run('gh', 'api', 'repos/'+repository+suffix, capture_output=True, text=True).stdout)
    description = api('')
    require(description['private'], 'The standard signing workflow requires a private configuration repository.')
    require(description['default_branch'] == 'main', 'The template requires protected main as its release branch.')
    rules = api('/rules/branches/main?per_page=100')
    require(isinstance(rules, list) and any(rule['type'] == 'pull_request' and
            rule.get('parameters', {}).get('required_approving_review_count', 0) >= 1 and
            rule.get('parameters', {}).get('dismiss_stale_reviews_on_push') is True for rule in rules) and
            any(rule['type'] == 'required_status_checks' and
                rule.get('parameters', {}).get('required_status_checks') for rule in rules),
            'Main requires an active ruleset with review, stale-review dismissal and required checks.')
    for name in ('lanrith-signing', 'lanrith-evidence'):
        environment = api('/environments/'+name)
        policy = environment.get('deployment_branch_policy') or {}
        require(policy.get('protected_branches') is True and not policy.get('custom_branch_policies'),
                'Signing environments must allow only protected branches.')
    return {'repository': repository, 'private': True, 'protected_signing': True}


def integration_pins(owner, value):
    if not value['extensions']:
        return {}
    selected = json.loads(release.read(owner/'extensions.lock', 65536), object_pairs_hook=release.unique)
    release.require(set(selected) == set(value['extensions']), 'Integration lock differs from configuration.')
    result = {}
    for name, digest in selected.items():
        directory = owner/'extensions'/name
        admitted = extensions.admit(directory, digest)
        release.require(admitted['id'] == name, 'Integration identity differs from its lock.')
        result[name] = (directory, digest)
    return result


def preflight(owner, bundle):
    selection = trust.lock(owner/'platform.lock')
    fetch(selection, bundle)
    value = config.load(owner/'config.yaml')
    for name in ('boot.crt', 'evidence.crt'):
        release.public_key(owner/'trust'/name)
    pins = integration_pins(owner, value)
    return {'schema': 1, 'configuration_sha256': hashlib.sha256(release.canonical(value)).hexdigest(),
            'integration_digests': {name: pin[1] for name, pin in pins.items()},
            'platform_lock_sha256': release.file_record(owner/'platform.lock')['sha256'],
            'boot_certificate_sha256': release.file_record(owner/'trust/boot.crt')['sha256'],
            'evidence_certificate_sha256': release.file_record(owner/'trust/evidence.crt')['sha256'],
            'source_commit': os.environ['GITHUB_SHA'], 'repository': os.environ['GITHUB_REPOSITORY'],
            'workflow_commit': os.environ['LANRITH_WORKFLOW_COMMIT']}


def assemble(owner, bundle, request, output):
    expected = json.loads(release.read(request, 65536), object_pairs_hook=release.unique)
    receipt = json.loads(release.read(bundle/'signing-admission.json', 65536), object_pairs_hook=release.unique)
    actual = receipt['request']
    assessment = bundle/'security-assessment.json'
    release.require(receipt['assessment_sha256'] == (release.file_record(assessment)['sha256'] if assessment.exists() else None),
                    'Security assessment changed after isolated admission.')
    age = datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(receipt['admitted_at'])
    release.require(actual == expected and datetime.timedelta(0) <= age <= datetime.timedelta(minutes=30),
                    'Signing request differs from its fresh isolated admission.')
    release.require(release.file_record(owner/'platform.lock')['sha256'] == actual['platform_lock_sha256'] and
                    hashlib.sha256(release.canonical(config.load(owner/'config.yaml'))).hexdigest() ==
                    actual['configuration_sha256'], 'Signing inputs changed after admission.')
    selection = trust.lock(owner/'platform.lock')
    reference = selection['builder']+'@sha256:'+selection['builder_digest']
    for name, expected_digest in selection['files'].items():
        release.require(release.file_record(bundle/name)['sha256'] == expected_digest,
                        'Admitted platform bytes changed before signing.')
    release.require(Path('/dev/shm').is_mount(), 'Signing inputs require private tmpfs.')
    with tempfile.TemporaryDirectory(prefix='lanrith-signing.', dir='/dev/shm') as temporary, \
            tempfile.TemporaryDirectory(prefix='lanrith-assembly.', dir=os.environ['RUNNER_TEMP']) as assembly_directory:
        private = Path(temporary)
        assembly_root = Path(assembly_directory)
        assembly_root.chmod(0o700)
        private.chmod(0o700)
        for name, variable in (('boot.key','LANRITH_BOOT_KEY'), ('boot.crt','LANRITH_BOOT_CERTIFICATE')):
            data = os.environ.pop(variable, '')
            release.require(bool(data), 'Protected signing material is incomplete.')
            path = private/name
            path.write_text(data)
            path.chmod(0o600)
        release.require((private/'boot.crt').read_bytes().strip() ==
                        release.read(owner/'trust/boot.crt', 65536).strip(),
                        'Boot certificate differs from reviewed owner trust.')
        floor = config.load(owner/'config.yaml').get('release', {}).get('sequence_floor', 0)
        if config.load(owner/'config.yaml')['administration']['serial']['enabled']:
            data = os.environ.pop('LANRITH_SERIAL_PASSPHRASE_HASH', '')
            release.require(bool(data), 'Serial administration requires its protected provisioning hash.')
            (private/'serial.hash').write_text(data.strip()+'\n')
            (private/'serial.hash').chmod(0o600)
        sequence = floor + int(os.environ['GITHUB_RUN_NUMBER'])
        release.require(sequence <= 999999999, 'Deployment sequence exceeds its supported bound.')
        release.require(sequence > 0, 'Invalid deployment sequence.')
        tools = assembly_root/'tools'
        tools.mkdir()
        # Authenticated compiler archives have only ordinary source files and directories.
        handoff.extract(bundle/'tools.tar.gz', tools, entries=10000, maximum_size=64*1024*1024,
                        maximum_file=4*1024*1024, nested=True)
        workspace = assembly_root/'work'
        payload = assembly_root/'update'
        command = ['docker', 'run', '--rm', '--network', 'none', '--privileged',
                   '-v', str(private)+':'+str(private)+':ro', '-v', str(assembly_root)+':'+str(assembly_root),
                   '-v', str(owner)+':/owner:ro',
                   '-v', str(bundle)+':/platform:ro', '-w', str(tools), reference,
                   'python3', 'scripts/assemble-offline.py', '--owner', '/owner', '--platform', '/platform',
                   '--private', str(private), '--workspace', str(workspace), '--output', str(payload),
                   '--sequence', str(sequence)]
        # This receipt is made only by the trusted host after maintained verifier checks.
        # No download, package transaction or caller build hook runs with the keys present.
        (private/'admitted.json').write_bytes(release.canonical({'platform_lock_sha256':
            release.file_record(owner/'platform.lock')['sha256'], 'workflow_commit': actual['workflow_commit'],
            'configuration_sha256': actual['configuration_sha256'], 'files': selection['files'],
            'integration_digests': actual['integration_digests'], 'assessment_sha256': receipt['assessment_sha256']}))
        (private/'admitted.json').chmod(0o600)
        run(*command)
        run('sudo', 'chown', '--recursive', str(os.getuid())+':'+str(os.getgid()), str(assembly_root))
        release.verify(payload, private/'boot.crt', purpose='update', image_id=
                       config.load(owner/'config.yaml').get('release', {}).get('image_id', 'lanrith'))
        output.mkdir(mode=0o700)
        with tarfile.open(output/'update.tar.gz', 'w:gz', format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(payload.iterdir()):
                archive.add(path, arcname=path.name)
        factory=assembly_root/'factory'
        with tarfile.open(output/'factory.tar.gz','w:gz',format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(factory.iterdir()):
                archive.add(path,arcname=path.name)
        manifest = json.loads((payload/'release.json').read_text())
        (output/'deployment.json').write_bytes(release.canonical({**actual,
            'deployment_sequence': sequence, 'release': manifest,
            'factory':json.loads((factory/'release.json').read_text())}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check-setup', 'preflight', 'qualify-signing', 'assemble'))
    parser.add_argument('--owner', required=True, type=Path)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--request', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.command == 'check-setup':
        print(json.dumps(protections(os.environ['GITHUB_REPOSITORY'])))
    elif args.command in ('preflight', 'qualify-signing'):
        value = preflight(args.owner.resolve(), args.bundle.resolve())
        if args.command == 'preflight':
            args.request.write_bytes(release.canonical(value))
        else:
            release.require(json.loads(release.read(args.request, 65536)) == value,
                            'Signing request changed after qualification.')
            protections(os.environ['GITHUB_REPOSITORY'])
            selection = trust.lock(args.owner/'platform.lock')
            run('docker', 'pull', selection['builder']+'@sha256:'+selection['builder_digest'])
            (args.bundle/'signing-admission.json').write_bytes(release.canonical({
                'request': value, 'admitted_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'assessment_sha256': release.file_record(args.bundle/'security-assessment.json')['sha256']
                    if (args.bundle/'security-assessment.json').exists() else None}))
            (args.bundle/'signing-admission.json').chmod(0o600)
        print('Configuration and platform admission passed.')
    else:
        assemble(args.owner.resolve(), args.bundle.resolve(), args.request.resolve(), args.output.resolve())


if __name__ == '__main__':
    try:
        main()
    except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, release.ReleaseError) else 'Consumer build failed.', file=sys.stderr)
        sys.exit(1)
