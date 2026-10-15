#!/usr/bin/env python3
"""Build the site-neutral filesystem with the reviewed package universe."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import gzip

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.release import canonical, file_record, require, unsigned_manifest

PROJECT = Path(__file__).resolve().parents[1]


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, **kwargs)


def locks(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in values and
                value and not any(c.isspace() for c in value), 'Invalid public build lock.')
        values[key] = value
    return values


def image(component, work, inputs):
    context = work / ('context-' + component)
    shutil.copytree(PROJECT / 'builders' / component, context)
    if component == 'vpp':
        shutil.copytree(PROJECT / 'builders/patches', context / 'patches')
    values = {key: value for key, value in inputs.items() if key in
              (component.upper() + '_BUILDER_OCI', 'DEBIAN_SNAPSHOT', 'DEBIAN_SECURITY_SNAPSHOT')}
    if component != 'mkosi':
        values.update(locks(PROJECT / 'builders' / (component + '-source.lock')))
    identifier = hashlib.sha256(canonical({'arguments': values, 'files': {
        p.relative_to(context).as_posix(): file_record(p)['sha256']
        for p in sorted(context.rglob('*')) if p.is_file()}})).hexdigest()
    tag = 'lanrith-' + component + ':' + identifier
    argv = ['docker', 'build', '--pull', '--platform', 'linux/amd64', '--file', str(context / 'Containerfile'),
            '--tag', tag]
    for key, value in sorted(values.items()):
        argv += ['--build-arg', key + '=' + value]
    run(*argv, str(context))
    return tag


def extract_packages(tag, destination):
    result = run('docker', 'create', tag, capture_output=True, text=True)
    container = result.stdout.strip()
    require(re.fullmatch(r'[0-9a-f]{64}', container), 'Invalid package container identity.')
    try:
        run('docker', 'cp', container + ':/packages/.', str(destination))
    finally:
        run('docker', 'rm', container, stdout=subprocess.DEVNULL)


def components(selection, destination):
    require(set(selection) == {'discovery-bridge', 'router-policy-agent'},
            'Both freshly qualified Lanrith component releases must be pinned before building.')
    for component, pin in selection.items():
        require(set(pin) == {'repository', 'tag', 'source_commit', 'workflow_commit', 'files'} and
                pin['repository'] == 'Lanrith/' + component and
                re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', pin['tag']) and
                all(re.fullmatch(r'[0-9a-f]{40}', pin[key]) for key in ('source_commit', 'workflow_commit')),
                'Invalid component release selection.')
        directory = destination / component
        directory.mkdir()
        for name, expected in pin['files'].items():
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,191}', name) and
                    re.fullmatch(r'[0-9a-f]{64}', expected), 'Invalid component asset pin.')
            run('gh', 'release', 'download', pin['tag'], '--repo', pin['repository'], '--pattern', name,
                '--pattern', name + '.intoto.jsonl', '--dir', str(directory))
            require(file_record(directory / name)['sha256'] == expected, 'Component asset differs from its lock.')
            run('gh', 'attestation', 'verify', str(directory / name), '--bundle', str(directory / (name+'.intoto.jsonl')),
                '--repo', pin['repository'], '--signer-workflow', pin['repository']+'/.github/workflows/build-release.yml',
                '--source-digest', pin['source_commit'], '--signer-digest', pin['workflow_commit'],
                '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--deny-self-hosted-runners')
        require(any(path.suffix == '.deb' for path in directory.iterdir()), 'Component selection contains no packages.')
        for path in directory.glob('*.deb'):
            shutil.copyfile(path, destination / path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.work = args.work.resolve()
    args.output = args.output.resolve()
    require(not args.work.exists() and not args.output.exists(), 'Build directories must be new.')
    selection = json.loads((PROJECT / 'build-inputs.json').read_text())
    recipes = {p.relative_to(PROJECT).as_posix(): file_record(p)['sha256']
               for p in sorted((PROJECT/'builders').rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
    require(selection['custom_package_inputs'] == recipes, 'Builder recipes differ from the reviewed input lock.')
    # Resolve these before allocating an expensive builder. Empty pins are deliberately ineligible.
    require(set(selection['component_releases']) == {'discovery-bridge', 'router-policy-agent'},
            'Fresh Lanrith component release pins are required; old release evidence cannot be reused.')
    args.work.mkdir(mode=0o700)
    args.output.mkdir(mode=0o755)
    packages = args.work / 'packages'
    packages.mkdir()
    components(selection['component_releases'], packages)
    inputs = locks(PROJECT / 'builders/build-inputs.lock')
    for key in ('DEBIAN_RELEASE_SHA256', 'DEBIAN_SECURITY_RELEASE_SHA256'):
        snapshot = inputs['DEBIAN_SNAPSHOT']
        archive, suite = ('debian-security', 'trixie-security') if 'SECURITY' in key else ('debian', 'trixie')
        path = args.work / (key + '.Release')
        run('curl', '--proto', '=https', '--tlsv1.2', '--fail', '--location', '--retry', '3', '--output', str(path),
            f'https://snapshot.debian.org/archive/{archive}/{snapshot}/dists/{suite}/Release')
        require(file_record(path)['sha256'] == inputs[key], 'Debian snapshot Release differs from the reviewed lock.')
    # Non-Debian packages and native PAM are produced and scanned by the same run.
    run(sys.executable, str(PROJECT / 'scripts/custom-packages.py'), '--output', str(packages),
        '--evidence', str(args.work / 'custom-security.json'))
    for component in ('vpp', 'unbound', 'tayga'):
        extract_packages(image(component, args.work, inputs), packages)
    builder = image('mkosi', args.work, inputs)
    build = args.work / 'image'
    build.mkdir()
    shutil.copytree(PROJECT / 'mkosi/base', build, dirs_exist_ok=True)
    shutil.copytree(packages, build / 'mkosi.packages')
    pam = build / 'mkosi.extra/usr/lib/x86_64-linux-gnu/security/pam_rssh.so'
    pam.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(packages/'pam_rssh.so', pam)
    notices = build/'mkosi.extra/usr/share/doc/pam-rssh/THIRD-PARTY-NOTICES'
    notices.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(packages/'pam-rssh.notices.txt', notices)
    version = (PROJECT / 'VERSION').read_text().strip()
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version), 'Invalid platform release version.')
    package_list = json.loads((PROJECT / 'mkosi/packages.json').read_text())['packages']
    (build / 'mkosi.conf').write_text(
        '[Distribution]\nDistribution=debian\nRelease=trixie\nArchitecture=x86-64\n'
        f'Snapshot={inputs["DEBIAN_SNAPSHOT"]}\n\n[Output]\nFormat=tar\n'
        f'ImageId=lanrith\nImageVersion={version}\nOutput=lanrith-base\nOutputDirectory=/work/output\n'
        'ManifestFormat=json\nCompressOutput=gz\n\n[Content]\nBootable=no\nPackages=' + ','.join(package_list) + '\n')
    run('docker', 'run', '--rm', '--privileged', '-v', str(args.work) + ':/work', '-w', '/work/image', builder,
        'mkosi', '--force', 'build')
    initrd = args.work/'initrd-image'
    initrd.mkdir()
    (initrd/'mkosi.conf').write_text(
        '[Include]\nInclude=mkosi-initrd\n'
        '[Distribution]\nDistribution=debian\nRelease=trixie\nArchitecture=x86-64\n'
        f'Snapshot={inputs["DEBIAN_SNAPSHOT"]}\n'
        '[Output]\nFormat=tar\nOutput=lanrith-initrd-base\nOutputDirectory=/work/output\nCompressOutput=gz\nManifestFormat=json\n'
        '[Content]\nPackages=linux-image-amd64,python3,openssl,coreutils,util-linux,fdisk,dmsetup,e2fsprogs,cryptsetup-bin,systemd-cryptsetup,systemd-repart,tpm2-tools\n')
    run('docker', 'run', '--rm', '--privileged', '-v', str(args.work)+':/work', '-w', '/work/initrd-image',
        builder, 'mkosi', '--force', 'build')
    generated = args.work / 'output'
    root_inventory = json.loads((generated/'lanrith-base.manifest').read_text())
    initrd_inventory = json.loads((generated/'lanrith-initrd-base.manifest').read_text())
    # The root security assessment covers every initrd package, at the identical version.
    root_packages = {(p['name'], p['version']) for p in root_inventory['packages']}
    require(all((p['name'], p['version']) in root_packages for p in initrd_inventory['packages']),
            'Initrd packages are not completely covered by the root package assessment.')
    for source, target in (('lanrith-base.tar.gz', 'lanrith-base.tar.gz'),
                           ('lanrith-initrd-base.tar.gz', 'lanrith-initrd-base.tar.gz'),
                           ('lanrith-base.manifest', 'inventory.json')):
        shutil.copyfile(generated / source, args.output / target)
    shutil.copyfile(PROJECT / 'build-inputs.json', args.output / 'inputs.json')
    shutil.copyfile(args.work / 'custom-security.json', args.output / 'custom-security.json')
    with urllib.request.urlopen('https://security-tracker.debian.org/tracker/data/json', timeout=90) as response:
        tracker = response.read(256 * 1024 * 1024 + 1)
    require(0 < len(tracker) <= 256 * 1024 * 1024, 'Debian tracker exceeds the admission limit.')
    (args.output/'tracker.json.gz').write_bytes(gzip.compress(tracker, mtime=0))
    run('docker', 'run', '--rm', '--network', 'none', '-v', str(PROJECT)+':/source:ro',
        '-v', str(args.output)+':/output', builder, 'python3', '/source/scripts/base-evidence.py',
        '--directory', '/output', '--version', version)
    # Export this exact builder. The publishing job binds the registry digest into provenance.
    run('docker', 'tag', builder, 'ghcr.io/lanrith/lanrith-builder:' + os.environ['GITHUB_SHA'])
    run('docker', 'save', '--output', str(args.output / 'builder.tar'), builder)
    import tarfile
    with tarfile.open(args.output/'tools.tar.gz', 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name in ('lanrith', 'scripts', 'security', 'mkosi', 'pyproject.toml', 'requirements.txt', 'LICENSE'):
            archive.add(PROJECT/name, arcname=name, filter=lambda entry: None if '__pycache__' in entry.name else entry)
    manifest = unsigned_manifest(args.output, purpose='base', version=version, sequence=0,
                                configuration_sha256=hashlib.sha256((PROJECT/'build-inputs.json').read_bytes()).hexdigest(),
                                files={'filesystem': 'lanrith-base.tar.gz', 'inventory': 'inventory.json',
                                       'initrd-filesystem': 'lanrith-initrd-base.tar.gz',
                                       'sbom': 'sbom.spdx.json', 'security': 'security.json', 'inputs': 'inputs.json',
                                       'tools': 'tools.tar.gz'})
    (args.output / 'release.json').write_bytes(canonical(manifest))


if __name__ == '__main__':
    main()
