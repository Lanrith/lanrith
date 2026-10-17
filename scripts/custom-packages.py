#!/usr/bin/env python3
"""Build and rescan non-Debian packages; no retained reports grant admission."""

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
import tempfile
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.release import canonical, file_record, require
from lanrith.sbom import go_modules

ROOT = Path(__file__).resolve().parents[1]


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, **kwargs)


def inert_package(binary, license_file, name, version, output, notices=None):
    with tempfile.TemporaryDirectory(prefix='lanrith-package.') as temporary:
        root = Path(temporary)
        (root/'DEBIAN').mkdir()
        (root/'usr/bin').mkdir(parents=True)
        (root/('usr/share/doc/'+name)).mkdir(parents=True)
        shutil.copyfile(binary, root/('usr/bin/'+name))
        (root/('usr/bin/'+name)).chmod(0o755)
        shutil.copyfile(license_file, root/('usr/share/doc/'+name+'/copyright'))
        if notices:
            shutil.copyfile(notices, root/('usr/share/doc/'+name+'/THIRD-PARTY-NOTICES'))
        (root/'DEBIAN/control').write_text(
            f'Package: {name}\nVersion: {version}\nArchitecture: amd64\n'
            'Maintainer: Lanrith <maintainers@lanrith.org>\nSection: net\nPriority: optional\n'
            'Description: Lanrith qualified router component\n')
        run('dpkg-deb', '--build', '--root-owner-group', str(root), str(output/(name+'_'+version+'_amd64.deb')))


def main():
    import importlib.util
    spec = importlib.util.spec_from_file_location('base', ROOT/'scripts/build-base.py')
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    inputs = base.locks(ROOT/'builders/build-inputs.lock')
    reports = {}
    for component, repository, patched in (
            ('vpp', 'FDio/vpp', {'GHSA-rc9p-89wj-mx7h'}),
            ('tayga-internal', 'apalrd/tayga', set())):
        feed = run('gh', 'api', 'repos/'+repository+'/security-advisories', '--paginate',
                   capture_output=True, text=True).stdout
        advisories = json.loads(feed)
        require(isinstance(advisories, list) and
                all(item.get('ghsa_id') in patched for item in advisories),
                'An upstream native component has an unreviewed advisory.')
        reports[component] = {'advisory_feed_sha256': hashlib.sha256(feed.encode()).hexdigest(),
                              'reviewed_patches': sorted(patched)}
    require(file_record(ROOT/'builders/patches/GHSA-rc9p-89wj-mx7h.patch')['sha256'] ==
            base.locks(ROOT/'builders/vpp-source.lock')['VPP_SECURITY_PATCH_SHA256'],
            'Reviewed VPP security patch differs from its lock.')
    scanner = shutil.which('govulncheck')
    require(scanner is not None and 'govulncheck@v1.9.0' in
            run(scanner, '-version', capture_output=True, text=True).stdout,
            'Custom binaries require the reviewed govulncheck version.')
    with tempfile.TemporaryDirectory(prefix='lanrith-custom.', dir=args.output.parent) as temporary:
        work = Path(temporary)
        pin = json.loads((ROOT/'builders/node-exporter/source.json').read_text())
        source = work/'node-exporter'
        run('git', 'clone', '--depth', '1', '--branch', pin['tag'], pin['repository'], str(source))
        require(run('git', '-C', str(source), 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip()
                == pin['commit'], 'Node exporter source tag changed.')
        run('git', '-C', str(source), 'apply', '--check', str(ROOT/'builders/node-exporter/dependencies.patch'))
        run('git', '-C', str(source), 'apply', str(ROOT/'builders/node-exporter/dependencies.patch'))
        shutil.copyfile(ROOT/'scripts/collect-notices.py', work/'collect-notices.py')
        run('docker', 'run', '--rm', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', str(os.getuid())+':'+str(os.getgid()),
            '--env', 'GOCACHE=/work/go-cache', '--env', 'GOMODCACHE=/work/go-mod', '--env', 'GOENV=off',
            '--env', 'LANRITH_GO_VERSION='+pin['go_version'],
            '-v', str(work)+':/work', '-v', str(scanner)+':/scanner:ro', '-w', '/work/node-exporter',
            pin['builder'], 'sh', '-ec',
            'test "$(go env GOVERSION)" = "$LANRITH_GO_VERSION"; go mod download all; go mod verify; '
            './ttar -C collector/fixtures -x -f collector/fixtures/sys.ttar; '
            './ttar -C collector/fixtures -x -f collector/fixtures/udev.ttar; '
            'go test ./...; /scanner ./... > /work/exporter-source.txt; '
            'CGO_ENABLED=0 go build -trimpath -o /work/node_exporter .; '
            '/scanner -mode=binary /work/node_exporter > /work/exporter-binary.txt; '
            'python3 /work/collect-notices.py go --output /work/exporter-notices.txt')
        inert_package(work/'node_exporter', source/'LICENSE', 'prometheus-node-exporter',
                      '1.12.1-1+lanrith1', args.output, work/'exporter-notices.txt')
        reports['node-exporter'] = {'source_commit': pin['commit'], 'patch_sha256':
                                    file_record(ROOT/'builders/node-exporter/dependencies.patch')['sha256'],
                                    'binary_sha256': {'prometheus-node-exporter':
                                        file_record(work/'node_exporter')['sha256']},
                                    'go_modules': {'prometheus-node-exporter': go_modules(json.loads(
                                        run('go', 'version', '-m', '-json', str(work/'node_exporter'),
                                            capture_output=True, text=True).stdout))},
                                    'scans': {name: file_record(work/name)['sha256']
                                              for name in ('exporter-source.txt', 'exporter-binary.txt')}}
        run(sys.executable, str(ROOT/'scripts/build-alloy.py'), '--work', str(work/'alloy-build'),
            '--output', str(args.output), '--evidence', str(work/'alloy-assessment.json'))
        reports['alloy'] = json.loads((work/'alloy-assessment.json').read_text())
        # The assessed package contains its notices. Release the large source,
        # vendor and compiler caches before assembling the remaining filesystem.
        run('go', 'clean', '-modcache', cwd=work, env={**os.environ, 'GOENV': 'off', 'GOTOOLCHAIN': 'local',
            'GOMODCACHE': str(work/'alloy-build/modules')})
        shutil.rmtree(work/'alloy-build')
        pam = work/'pam'
        commit = 'fb6e93908fa5c95fbad7682de081bcc70f341216'
        run('git', 'clone', '--recursive', 'https://github.com/z4yx/pam_rssh.git', str(pam))
        run('git', '-C', str(pam), 'checkout', '--detach', commit)
        run('git', '-C', str(pam), 'submodule', 'update', '--init', '--recursive')
        require(run('git', '-C', str(pam), 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() == commit,
                'PAM source revision differs.')
        # Query every locked Cargo dependency, including build dependencies.
        import tomllib
        locked = tomllib.loads((pam/'Cargo.lock').read_text())
        from lanrith import advisories
        queries = advisories.cargo_queries(locked)
        feed_digest = advisories.assess(queries)
        shutil.copyfile(ROOT/'scripts/collect-notices.py', pam/'collect-notices.py')
        argv = ['docker', 'build', '--file', str(ROOT/'builders/pam/Containerfile'), '--tag', 'lanrith-pam:build']
        argv += [argument for key in ('PAM_RSSH_BUILDER_OCI', 'PAM_RSSH_RUST_VERSION', 'DEBIAN_BOOKWORM_SNAPSHOT',
                                     'DEBIAN_BOOKWORM_SECURITY_SNAPSHOT')
                 for argument in ('--build-arg', key+'='+inputs[key])]
        run(*argv, str(pam))
        container = run('docker', 'create', 'lanrith-pam:build', '/none', capture_output=True, text=True).stdout.strip()
        try:
            run('docker', 'cp', container+':/libpam_rssh.so', str(args.output/'pam_rssh.so'))
            run('docker', 'cp', container+':/notices.txt', str(args.output/'pam-rssh.notices.txt'))
        finally:
            run('docker', 'rm', container, stdout=subprocess.DEVNULL)
        reports['pam-rssh'] = {'source_commit': commit, 'cargo_lock_sha256': file_record(pam/'Cargo.lock')['sha256'],
                               'advisory_feed_sha256': feed_digest,
                               'queried_packages': len(queries), 'queries': queries}
        # Recheck the exact component binaries independently of their original release age.
        for package in args.output.glob('*.deb'):
            name = run('dpkg-deb', '--field', str(package), 'Package', capture_output=True, text=True).stdout.strip()
            if not (name.startswith('router-policy-') or name == 'discovery-bridge'):
                continue
            tree = work/name
            run('dpkg-deb', '--extract', str(package), str(tree))
            binaries = [p for p in (tree/'usr/bin').iterdir() if p.is_file()]
            require(binaries, 'Component package contains no executable.')
            scanned = {}
            for binary in binaries:
                with (work/(binary.name+'.scan')).open('w') as stream:
                    run(scanner, '-mode=binary', str(binary), stdout=stream)
                scanned[binary.name] = file_record(work/(binary.name+'.scan'))['sha256']
            reports[name] = {'package_sha256': file_record(package)['sha256'], 'scans': scanned}
            reports[name]['binary_sha256'] = {binary.name: file_record(binary)['sha256'] for binary in binaries}
            reports[name]['go_modules'] = {binary.name: go_modules(json.loads(
                run('go', 'version', '-m', '-json', str(binary), capture_output=True, text=True).stdout))
                for binary in binaries}
    args.evidence.write_bytes(canonical({'schema': 1, 'result': 'pass',
        'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'components': reports}))


if __name__ == '__main__':
    main()
