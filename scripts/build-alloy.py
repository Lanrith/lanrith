#!/usr/bin/env python3
"""Build a pinned, complete Alloy package and return fresh source/binary evidence."""

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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith.release import canonical, file_record, require
from lanrith import advisories, build_cache, embedded


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--engine', choices=('docker', 'podman'), default='docker')
    parser.add_argument('--resume', action='store_true',
                        help='Reassess and package a completed, owned worker result; CI builds always start fresh')
    parser.add_argument('--cache-from', type=Path,
                        help='Reuse an owned local Go cache; hosted release builds do not supply this option')
    args = parser.parse_args()
    definition = ROOT/'builders/alloy'
    pin = json.loads((definition/'source.json').read_text())
    selection = json.loads((ROOT/'build-inputs.json').read_text())
    require(args.work.is_absolute() and args.work.parent.resolve() == args.work.parent and
            (not args.work.exists() or args.resume and args.work.is_dir() and not args.work.is_symlink() and
             args.work.stat().st_uid == os.getuid() and args.work.stat().st_mode & 0o777 == 0o700),
            'Alloy requires a new canonical workspace or an explicitly resumed owned worker result.')
    if not args.resume:
        args.work.mkdir(mode=0o700)
    source = args.work/'alloy'
    beyla = args.work/'beyla'
    for repository, version, commit, destination in (
            ('grafana/alloy', pin['version'], pin['commit'], source),
            ('grafana/beyla', pin['beyla']['version'], pin['beyla']['commit'], beyla)):
        if not args.resume:
            run('git', 'clone', '--depth', '1', '--branch', 'v'+version,
                'https://github.com/'+repository+'.git', str(destination))
        require(run('git', 'rev-parse', 'HEAD', cwd=destination, capture_output=True, text=True).stdout.strip() ==
                commit, 'Upstream release source differs from its reviewed identity.')
    if not args.resume:
        run('git', 'submodule', 'update', '--init', '--recursive', cwd=beyla)
    require(run('git', 'rev-parse', 'HEAD', cwd=beyla/'.obi-src', capture_output=True, text=True).stdout.strip() ==
            pin['beyla']['obi_commit'], 'Beyla OBI source differs from its reviewed identity.')
    java = pin['beyla']['java_agent']
    require(file_record(beyla/java['path'])['sha256'] == java['sha256'] and
            file_record(beyla/java['source_manifest'])['sha256'] == java['source_manifest_sha256'],
            'Embedded Java agent or its runtime dependency declaration changed.')
    declared = set(re.findall(r'implementation\("([^"]+)"\)',
                              (beyla/java['source_manifest']).read_text()))
    require(declared == {item['name']+':'+item['version'] for item in java['dependencies']},
            'Java agent runtime dependency coverage is incomplete.')
    java_queries = [{'package': {'ecosystem': 'Maven', 'name': item['name']}, 'version': item['version']}
                    for item in java['dependencies']]
    java_diagnostic = args.work/'evidence/java-osv.json'
    java_assessment = advisories.assess(java_queries, diagnostic=java_diagnostic)
    feeds = {}
    source_fixes = {}
    for repository in ('grafana/alloy', 'grafana/beyla', 'grafana/opentelemetry-ebpf-instrumentation',
                       'open-telemetry/opentelemetry-ebpf-instrumentation'):
        raw = run('gh', 'api', 'repos/'+repository+'/security-advisories', '--paginate',
                  capture_output=True, text=True).stdout
        value = json.loads(raw)
        require(isinstance(value, list), 'Upstream source advisory coverage is malformed.')
        if repository == 'open-telemetry/opentelemetry-ebpf-instrumentation':
            # The fork has no advisory feed. Bind upstream fixed releases to exact
            # reviewed commits and require their presence in the pinned fork's history.
            for advisory in value:
                affected = advisory.get('vulnerabilities')
                require(isinstance(affected, list) and affected, 'Upstream advisory has unknown fix coverage.')
                fixes = []
                for item in affected:
                    tag = item.get('patched_versions')
                    commit = pin['beyla']['fixed_releases'].get(tag)
                    require(commit and re.fullmatch(r'[0-9a-f]{40}', commit),
                            'Embedded source has an unreviewed fixed-release requirement.')
                    run('git', 'merge-base', '--is-ancestor', commit, pin['beyla']['obi_commit'], cwd=beyla/'.obi-src')
                    fixes.append({'fixed_tag': tag, 'fixed_commit': commit})
                source_fixes[advisory['ghsa_id']] = fixes
        else:
            require(not value, 'Alloy or an embedded source has an unreviewed upstream advisory.')
        feeds[repository] = hashlib.sha256(raw.encode()).hexdigest()
    image_inputs = {'GO_IMAGE': pin['go_image'], 'NODE_IMAGE': pin['node_image'],
                    'DEBIAN_IMAGE': selection['builder_base'],
                    'DEBIAN_SNAPSHOT': selection['debian_snapshot'],
                    'DEBIAN_SECURITY_SNAPSHOT': selection['security_snapshot']}
    identity = hashlib.sha256(canonical({'arguments': image_inputs,
        'containerfile': file_record(definition/'Containerfile')['sha256']})).hexdigest()
    tag = 'localhost/lanrith-alloy-builder:'+identity
    command = [args.engine, 'build', '--pull', '--platform', 'linux/amd64', '--file',
               str(definition/'Containerfile'), '--tag', tag]
    if args.engine == 'docker':
        command += build_cache.image_arguments('alloy')
    for name, value in sorted(image_inputs.items()):
        command += ['--build-arg', name+'='+value]
    if args.engine != 'docker' or not build_cache.reuse_image('alloy', tag):
        run(*command, str(definition))
    if args.engine == 'docker':
        build_cache.record_image('alloy', tag)
    compiler_identity = identity
    if build_cache.state()[0] is not None:
        try:
            probe = run(args.engine, 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--user', str(os.getuid())+':'+str(os.getgid()),
                '-v', str(ROOT)+':/implementation:ro', tag, 'python3',
                '/implementation/scripts/compiler-identity.py', capture_output=True, text=True,
                timeout=180).stdout.strip()
            require(re.fullmatch(r'[0-9a-f]{64}', probe), 'Invalid compiler environment fingerprint.')
            compiler_identity = build_cache.compiler_key(image_inputs, probe)
        except (OSError, subprocess.SubprocessError, ValueError):
            print('Compiler fingerprint unavailable; requiring the complete pinned builder identity.')
    scanner = shutil.which('govulncheck')
    require(scanner and 'govulncheck@v1.9.0' in
            run(scanner, '-version', capture_output=True, text=True).stdout, 'Unexpected Alloy scanner.')
    command = [args.engine, 'run', '--rm', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--user', str(os.getuid())+':'+str(os.getgid())]
    if args.engine == 'podman':
        command += ['--userns=keep-id']
    for name, value in {'HOME': '/work/home', 'GOCACHE': '/work/cache', 'GOMODCACHE': '/work/modules',
                        'GOPATH': '/work/gopath', 'GOTMPDIR': '/work/tmp', 'GOTOOLCHAIN': 'local',
                        'GOENV': 'off', 'GOMAXPROCS': '2', 'GOMEMLIMIT': '4GiB'}.items():
        command += ['--env', name+'='+value]
    for name in ('home', 'cache', 'modules', 'gopath', 'tmp'):
        if not args.resume:
            (args.work/name).mkdir(mode=0o700)
    ci_cache_reused = not args.resume and build_cache.restore_compiler(args.work/'cache', compiler_identity)
    if args.cache_from:
        require(not os.environ.get('GITHUB_ACTIONS') and args.cache_from.resolve() == args.cache_from and
                args.cache_from.stat().st_uid == os.getuid() and not args.cache_from.stat().st_mode & 0o077,
                'Cache reuse is limited to an explicitly selected private local workspace.')
        for name in ('cache', 'modules'):
            path = args.cache_from/name
            require(path.is_dir() and not path.is_symlink() and path.stat().st_uid == os.getuid(),
                    'Local compiler cache has unsafe ownership.')
            command += ['-v', str(path)+':/work/'+name]
    command += ['-v', str(args.work)+':/work', '-v', str(ROOT)+':/implementation:ro',
                '-v', scanner+':/scanner:ro', '-w', '/work', tag,
                'python3', '/implementation/scripts/alloy-worker.py', '--work', '/work',
                '--definition', '/implementation/builders/alloy']
    if not args.resume:
        try:
            run(*command)
        except subprocess.CalledProcessError:
            # custom-packages owns a temporary source tree. Copy only diagnostic
            # data out before its context manager removes the failed worker tree.
            diagnostics = args.output/'security-diagnostics'
            diagnostics.mkdir(exist_ok=True)
            for path in (args.work/'evidence').glob('*'):
                if path.is_file() and not path.is_symlink() and path.suffix in ('.json', '.txt', '.stderr') and path.stat().st_size <= 8*1024*1024:
                    shutil.copyfile(path, diagnostics/path.name)
            raise
    evidence = json.loads((args.work/'evidence/result.json').read_text())
    require(evidence['result'] == 'pass' and evidence['source_commit'] == pin['commit'] and
            evidence['binary_sha256'] == file_record(args.work/'alloy-security')['sha256'] and
            evidence['worker_sha256'] == file_record(ROOT/'scripts/alloy-worker.py')['sha256'] and
            evidence['notice_collector_sha256'] == file_record(ROOT/'scripts/collect-notices.py')['sha256'],
            'Alloy worker output differs from its fresh evidence.')
    require(evidence['source_definition_sha256'] == file_record(definition/'source.json')['sha256'] and
            evidence['patches'] == {p.relative_to(definition).as_posix(): file_record(p)['sha256']
                                   for p in definition.rglob('*.patch')}, 'Alloy worker input selection changed.')
    if args.resume:
        for binary in ('alloy-security', 'beyla-security'):
            run(*command[:-6], '/scanner', '-mode=binary', '/work/'+binary)
    npm_queries = advisories.npm_queries(evidence['npm_modules'])
    npm_diagnostic = args.work/'evidence/npm-osv.json'
    npm_assessment = advisories.assess(npm_queries, diagnostic=npm_diagnostic)
    beyla_subject = args.output/'alloy-beyla.scan'
    require(file_record(args.work/'beyla-security')['sha256'] == evidence['beyla']['binary_sha256'],
            'Embedded Beyla differs from its independently scanned bytes.')
    shutil.copyfile(args.work/'beyla-security', beyla_subject)
    beyla_subject.chmod(0o644)
    embedded_record = embedded.verify(args.work/'alloy-security', beyla_subject,
                                      evidence['beyla']['binary_sha256'])
    # Retain upstream units, users, dependencies and copyright; replace only the
    # binary, package version and additional notices in the verified upstream Deb.
    upstream = args.work/'upstream.deb'
    if not args.resume or not upstream.exists():
        run('gh', 'release', 'download', 'v'+pin['version'], '--repo', 'grafana/alloy',
            '--pattern', 'alloy-'+pin['version']+'-1.amd64.deb', '--output', str(upstream))
    require(file_record(upstream)['sha256'] == pin['upstream_deb_sha256'], 'Upstream Alloy packaging changed.')
    # A resumed local package step uses a new extraction tree as well.
    import uuid
    tree = args.work/('package-'+uuid.uuid4().hex)
    def package_tools(*arguments):
        container = [args.engine, 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--user', str(os.getuid())+':'+str(os.getgid())]
        if args.engine == 'podman':
            container += ['--userns=keep-id']
        run(*container, '-v', str(args.work)+':/work', '-v', str(args.output)+':/packages', tag, *arguments)
    package_tools('dpkg-deb', '--raw-extract', '/work/upstream.deb', '/work/'+tree.name)
    shutil.copyfile(args.work/'alloy-security', tree/'usr/bin/alloy')
    (tree/'usr/bin/alloy').chmod(0o755)
    control = tree/'DEBIAN/control'
    text = control.read_text()
    require(re.search(r'^Package: alloy$', text, re.MULTILINE) and
            re.search(r'^Architecture: amd64$', text, re.MULTILINE), 'Unexpected upstream package identity.')
    text = re.sub(r'^Version: .*$', 'Version: '+pin['package_version'], text, flags=re.MULTILINE)
    notices = tree/'usr/share/doc/alloy/THIRD-PARTY-NOTICES.lanrith'
    notices.parent.mkdir(parents=True, exist_ok=True)
    notices.write_text('Lanrith source changes and build inputs:\n'+json.dumps(pin, sort_keys=True, indent=2)+
        '\n'+(args.work/'evidence/alloy-notices.txt').read_text()+
        '\nEmbedded Beyla:\n'+(args.work/'evidence/beyla-notices.txt').read_text()+
        '\nUI dependencies:\n'+(args.work/'evidence/npm-notices.txt').read_text())
    installed_size = sum((path.stat().st_size+1023)//1024 for path in tree.rglob('*')
                         if path.is_file() and not path.is_symlink() and 'DEBIAN' not in path.relative_to(tree).parts)
    text, count = re.subn(r'^Installed-Size: .*$', 'Installed-Size: '+str(installed_size), text, flags=re.MULTILINE)
    require(count == 1, 'Upstream package has no unique installed-size field.')
    control.write_text(text)
    md5 = tree/'DEBIAN/md5sums'
    if md5.exists():
        records = []
        for path in sorted(tree.rglob('*')):
            if path.is_file() and not path.is_symlink() and 'DEBIAN' not in path.relative_to(tree).parts:
                with path.open('rb') as stream:
                    records.append(hashlib.file_digest(stream, lambda: hashlib.md5(usedforsecurity=False)).hexdigest()+
                                   '  '+path.relative_to(tree).as_posix()+'\n')
        md5.write_text(''.join(records))
    output = args.output/('alloy_'+pin['package_version']+'_amd64.deb')
    package_tools('dpkg-deb', '--build', '--root-owner-group', '/work/'+tree.name, '/packages/'+output.name)
    args.evidence.write_bytes(canonical({**evidence, 'package_sha256': file_record(output)['sha256'],
        'embedded_beyla': embedded_record,
        'cache_reused': args.cache_from is not None or ci_cache_reused,
        'compiler_identity': compiler_identity,
        'upstream_deb_sha256': pin['upstream_deb_sha256'], 'fresh_source_advisories': feeds,
        'source_fix_ancestry': source_fixes,
        'npm_osv_feed_sha256': npm_assessment,
        'npm_osv_diagnostic': json.loads(npm_diagnostic.read_text()),
        'java_agent': {'sha256': java['sha256'], 'queries': java_queries,
                       'advisory_feed_sha256': java_assessment,
                       'diagnostic': json.loads(java_diagnostic.read_text())},
        'builder_definition_sha256': file_record(definition/'Containerfile')['sha256'],
        'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    if not args.resume:
        build_cache.retain_compiler(args.work/'cache', compiler_identity)
    print('Pinned Alloy package built and freshly assessed.')


if __name__ == '__main__':
    main()
