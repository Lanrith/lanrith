#!/usr/bin/env python3
"""Build reviewed Alloy/Beyla sources without owner configuration or signing authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.release import canonical, file_record, require


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, **kwargs)


def patch(root, filename, strip=1):
    run('git', 'apply', '--check', '-p'+str(strip), str(filename), cwd=root)
    run('git', 'apply', '-p'+str(strip), str(filename), cwd=root)


def module_copy(work, module, version, destination, expected=None):
    resolve = work/'resolve'
    resolve.mkdir(exist_ok=True)
    (resolve/'go.mod').write_text('module github.com/lanrith/build-resolution\n\ngo 1.27.3\n')
    value = json.loads(run('go', 'mod', 'download', '-json', module+'@'+version,
                          cwd=resolve, capture_output=True, text=True).stdout)
    require(value['Path'] == module and value['Version'] == version and
            (expected is None or value['Sum'] == expected), 'Upstream module differs from its reviewed checksum.')
    shutil.copytree(value['Dir'], destination)
    destination.chmod(0o755)
    for path in destination.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(0o644)
    return value['Sum']


def notices(source, destination, definition):
    """Preserve all vendored notices and identify every imported module/version."""
    legal = runpy.run_path(str(Path(__file__).with_name('collect-notices.py')))['licenses']
    vendor = source/'vendor'
    supplemental = json.loads((definition/'source.json').read_text()).get('supplemental_notices', {})
    modules, current = [], None
    for line in (vendor/'modules.txt').read_text().splitlines():
        if line.startswith('# '):
            parts = line.split()
            current = {'module': parts[1], 'version': parts[2]} if len(parts) >= 3 and parts[2] != '=>' else None
            if current is not None:
                current['vendor_path'] = parts[1]
                if len(parts) >= 6 and parts[3] == '=>':
                    current.update(module=parts[4], version=parts[5])
        elif line and not line.startswith('#') and current is not None:
            if not modules or modules[-1] != current:
                modules.append(current)
    with destination.open('x') as output:
        for module in modules:
            directory = vendor/module['vendor_path']
            files = legal(directory)
            parent = directory.parent
            while not files and parent.is_relative_to(vendor):
                files = [(name, data) for name, data in legal(parent) if '/' not in name]
                parent = parent.parent
            if not files:
                downloaded = json.loads(run('go', 'mod', 'download', '-json',
                    module['module']+'@'+module['version'], cwd=source, capture_output=True, text=True).stdout)
                files = legal(Path(downloaded['Dir']))
            if not files and (notice := supplemental.get(module['module']+'@'+module['version'])):
                compiled = {p.relative_to(directory).as_posix(): file_record(p)['sha256']
                            for p in directory.rglob('*.go') if not p.name.endswith('_test.go')}
                require(compiled == notice['compiled_files'] and
                        file_record(definition/notice['path'])['sha256'] == notice['sha256'],
                        'Supplemental upstream notice does not cover these exact compiled sources.')
                files = [('Upstream LICENSE at '+notice['upstream_commit'],
                          (definition/notice['path']).read_text())]
            require(files, 'Vendored module lacks an attributable license: '+module['module'])
            output.write('\n===== '+module['module']+'@'+module['version']+' =====\n')
            output.write('Vendor import path: '+module['vendor_path']+'\n')
            for name, data in files:
                output.write('\n--- '+name+' ---\n'+data+'\n')
        goroot = Path(run('go', 'env', 'GOROOT', capture_output=True, text=True).stdout.strip())
        output.write('\n===== Go standard library =====\n'+(goroot/'LICENSE').read_text())
    return modules


def scan(binary, output):
    with output.open('x') as stream:
        run('/scanner', '-mode=binary', str(binary), stdout=stream)
    return file_record(output)['sha256']


def javascript_inventory(ui, destination):
    """Keep the exact locked graph and upstream notices for installed packages."""
    legal = runpy.run_path(str(Path(__file__).with_name('collect-notices.py')))['licenses']
    locked = json.loads((ui/'package-lock.json').read_text())
    require(locked.get('lockfileVersion') == 3, 'Unsupported UI dependency lock.')
    modules = []
    with destination.open('x') as output:
        for path, value in sorted(locked['packages'].items()):
            if not path:
                continue
            require(path.startswith('node_modules/') and '..' not in Path(path).parts and
                    value.get('version'), 'Invalid UI dependency identity.')
            name = value.get('name', path.rsplit('node_modules/', 1)[1])
            modules.append({'name': name, 'version': value['version'],
                            'integrity': value.get('integrity'), 'license': value.get('license'),
                            'development': bool(value.get('dev'))})
            directory = ui/path
            if not directory.is_dir():
                require(value.get('optional'), 'A required UI dependency is absent.')
                continue
            files = legal(directory)
            missing_license_file = not files
            # Some upstream packages put their license or copyright only in a
            # README/source header. Preserve those exact files and metadata too.
            for candidate in sorted(directory.iterdir()):
                if candidate.is_file() and not candidate.is_symlink() and candidate.stat().st_size < 4*1024*1024 and (
                        candidate.name == 'package.json' or candidate.name.lower().startswith('readme') or
                        (missing_license_file and candidate.suffix in ('.js', '.ts'))):
                    files.append((candidate.name, candidate.read_text(errors='replace')))
            require(files and value.get('license'), 'UI dependency attribution is incomplete: '+name)
            output.write('\n===== '+name+'@'+value['version']+' =====\n')
            for filename, text in files:
                output.write('\n--- '+filename+' ---\n'+text+'\n')
    return modules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--definition', type=Path, required=True)
    args = parser.parse_args()
    work, definition = args.work, args.definition
    selected = json.loads((definition/'source.json').read_text())
    require(run('go', 'env', 'GOVERSION', capture_output=True, text=True).stdout.strip() ==
            'go'+selected['go_version'], 'Unexpected Alloy Go compiler.')
    require(run('node', '--version', capture_output=True, text=True).stdout.strip() ==
            'v'+selected['node_version'], 'Unexpected Alloy Node compiler.')
    source, beyla = work/'alloy', work/'beyla'
    for directory, commit in ((source, selected['commit']), (beyla, selected['beyla']['commit']),
                              (beyla/'.obi-src', selected['beyla']['obi_commit'])):
        require(run('git', 'rev-parse', 'HEAD', cwd=directory, capture_output=True, text=True).stdout.strip() ==
                commit, 'Unexpected upstream source identity.')
    component_file = 'internal/component/all/all.go'
    original_components = run('git', 'show', selected['commit']+':'+component_file,
                              cwd=source, capture_output=True).stdout
    patch(source, definition/'dependencies.patch')
    patch(source, definition/'ui-dependencies.patch')
    replacements = source/'lanrith-patches'
    replacements.mkdir()
    for module in selected['modules']:
        destination = replacements/module['directory']
        module_copy(work, module['module'], module['version'], destination, module['sum'])
        patch(destination, definition/module['patch'])
    run('go', 'mod', 'edit', '-require=golang.org/x/net@v0.60.0', cwd=beyla)
    run('go', 'mod', 'download', 'all', cwd=beyla)
    run('go', 'mod', 'verify', cwd=beyla)
    run('go', 'mod', 'vendor', cwd=beyla)
    evidence = work/'evidence'
    evidence.mkdir()
    run('go', 'test', '-count=1', '-mod=vendor', './pkg/config', './pkg/helpers/config', './pkg/beyla',
        cwd=beyla, env={**os.environ, 'CGO_ENABLED': '0'})
    beyla_binary = work/'beyla-security'
    flags = ('-X github.com/grafana/beyla/v3/pkg/buildinfo.Version=v'+selected['beyla']['version']+
             '+lanrith.1 -X github.com/grafana/beyla/v3/pkg/buildinfo.Revision='+selected['beyla']['commit'])
    run('go', 'build', '-mod=vendor', '-p=2', '-trimpath', '-ldflags', flags,
        '-o', str(beyla_binary), './cmd/beyla', cwd=beyla, env={**os.environ, 'CGO_ENABLED': '0'})
    beyla_scan = scan(beyla_binary, evidence/'beyla-scan.txt')
    beyla_modules = notices(beyla, evidence/'beyla-notices.txt', definition)
    target = source/'internal/component/beyla/ebpf/binaries/amd64/beyla'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(beyla_binary, target)
    ui = source/'internal/web/ui'
    run('npm', 'ci', '--no-audit', '--no-fund', cwd=ui)
    assessment = subprocess.run(['npm', 'audit', '--json'], cwd=ui, capture_output=True, text=True)
    (evidence/'npm-audit.json').write_text(assessment.stdout)
    if assessment.stderr:
        (evidence/'npm-audit.stderr').write_text(assessment.stderr)
    require(assessment.returncode in (0, 1), 'UI advisory service failed.')
    report = json.loads(assessment.stdout)
    if report.get('vulnerabilities'):
        print(json.dumps(report['vulnerabilities'], sort_keys=True), flush=True)
    require('error' not in report and 'vulnerabilities' in report and
            all(item['severity'] in ('info', 'low') and not item.get('fixAvailable')
                for item in report['vulnerabilities'].values()), 'Alloy UI has unresolved security findings.')
    npm_modules = javascript_inventory(ui, evidence/'npm-notices.txt')
    run('npm', 'run', 'build', cwd=ui)
    collector = source/'collector'
    run('go', 'mod', 'download', 'all', cwd=collector)
    run('go', 'mod', 'verify', cwd=collector)
    run('go', 'mod', 'vendor', cwd=collector)
    # Local replacements prepare reviewed patches; the final vendor graph retains
    # upstream module identities so vulnerability scanners still cover those modules.
    identities = {module['module'] for module in selected['modules']}
    for identity in identities:
        run('go', 'mod', 'edit', '-dropreplace='+identity, cwd=collector)
    lines = []
    for line in (collector/'vendor/modules.txt').read_text().splitlines():
        if line.startswith('# ') and line.split()[1] in identities and ' => ' in line:
            prefix = line.split(' => ', 1)[0]
            if len(prefix.split()) == 2:
                continue
            line = prefix
        lines.append(line)
    (collector/'vendor/modules.txt').write_text('\n'.join(lines)+'\n')
    patch(collector/'vendor', definition/'loki-compatibility.patch')
    # Root-module tests use the same stable compatibility patch as the vendor build.
    loki = replacements/'loki'
    module_copy(work, 'github.com/grafana/loki/v3', 'v3.7.8', loki)
    patch(loki, definition/'loki-compatibility.patch', strip=5)
    run('go', 'mod', 'edit', '-replace=github.com/grafana/loki/v3=./lanrith-patches/loki', cwd=source)
    run('go', 'test', '-count=1', '-mod=mod', '-race', './internal/component/loki/write',
        './internal/component/prometheus/exporter/snowflake', './internal/web/ui', cwd=source)
    run('go', 'test', '-count=1', '-mod=mod', 'github.com/burningalchemist/sql_exporter/config', cwd=source)
    require(hashlib.sha256(original_components).hexdigest() == file_record(source/component_file)['sha256'],
            'Alloy component registration changed; removing features is not an accepted security fix.')
    binary = work/'alloy-security'
    flags = ('-X github.com/grafana/alloy/internal/build.Version='+selected['version']+
             '+lanrith.1 -X github.com/grafana/alloy/internal/build.Revision='+selected['commit']+
             ' -X github.com/grafana/alloy/internal/build.BuildUser=lanrith@builder')
    # Full symbols preserve precise scanner coverage; stripping causes module-only
    # fallback and can both over-report unused APIs and miss symbol-scoped findings.
    run('go', 'build', '-mod=vendor', '-p=2', '-trimpath', '-tags',
        'gore2regex netgo embedalloyui promtail_journal_enabled', '-ldflags', flags,
        '-o', str(binary), '.', cwd=collector)
    alloy_scan = scan(binary, evidence/'alloy-scan.txt')
    modules = notices(collector, evidence/'alloy-notices.txt', definition)
    with (evidence/'beyla-notices.txt').open('a') as output:
        for path in ('LICENSE', '.obi-src/LICENSE', '.obi-src/NOTICE',
                     '.obi-src/NOTICES/java/agent/THIRD_PARTY_LICENSES.txt'):
            output.write('\n===== Embedded source '+path+' =====\n'+(beyla/path).read_text())
    (evidence/'result.json').write_bytes(canonical({'schema': 1, 'result': 'pass',
        'worker_sha256': file_record(Path(__file__))['sha256'],
        'notice_collector_sha256': file_record(Path(__file__).with_name('collect-notices.py'))['sha256'],
        'source_commit': selected['commit'], 'source_definition_sha256': file_record(definition/'source.json')['sha256'],
        'patches': {p.relative_to(definition).as_posix(): file_record(p)['sha256']
                    for p in definition.rglob('*.patch')},
        'toolchains': {'go': selected['go_version'], 'node': selected['node_version']},
        'components_sha256': file_record(source/component_file)['sha256'],
        'binary_sha256': file_record(binary)['sha256'], 'scan_sha256': alloy_scan, 'modules': modules,
        'beyla': {**selected['beyla'], 'binary_sha256': file_record(beyla_binary)['sha256'],
                  'scan_sha256': beyla_scan, 'modules': beyla_modules},
        'npm_assessment_sha256': file_record(evidence/'npm-audit.json')['sha256'],
        'npm_modules': npm_modules,
        'native_tests': 'config, Loki write, Snowflake exporter, SQL configuration, UI module'}))
    print('Complete Alloy/Beyla build, behavior checks, notices and fresh security checks passed.')


if __name__ == '__main__':
    main()
