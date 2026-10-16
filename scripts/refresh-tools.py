#!/usr/bin/env python3
"""Propose supported toolchain patches and report source changes requiring review."""

import json
import datetime
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith.release import require


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(4*1024*1024+1)
    require(0 < len(data) <= 4*1024*1024, 'Upstream version metadata exceeds its bound.')
    return data


def run(*arguments):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout


def version(value):
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value), 'Upstream tool version is not a stable release.')
    return tuple(map(int, value.split('.')))


def image(name, tag):
    selected = json.loads(run('docker', 'manifest', 'inspect', 'docker.io/library/'+name+':'+tag))
    matches = [item for item in selected['manifests'] if item.get('platform', {}).get('os') == 'linux' and
               item['platform'].get('architecture') == 'amd64' and not item['platform'].get('variant')]
    require(len(matches) == 1 and re.fullmatch(r'sha256:[0-9a-f]{64}', matches[0]['digest']),
            'Proposed tool image has ambiguous native platform identity.')
    return 'docker.io/library/'+name+'@'+matches[0]['digest']


def main():
    alloy_path = ROOT/'builders/alloy/source.json'
    alloy = json.loads(alloy_path.read_text())
    exporter_path = ROOT/'builders/node-exporter/source.json'
    exporter = json.loads(exporter_path.read_text())
    releases = json.loads(fetch('https://go.dev/dl/?mode=json'))
    supported = [item['version'].removeprefix('go') for item in releases if item.get('stable')]
    for data, key, image_key, prefix in ((alloy, 'go_version', 'go_image', ''),
                                        (exporter, 'go_version', 'builder', 'go')):
        current = data[key].removeprefix('go')
        choices = [value for value in supported if version(value)[:2] == version(current)[:2]]
        require(choices, 'Selected Go branch has no supported upstream release.')
        latest = max(choices, key=version)
        data[key], data[image_key] = prefix+latest, image('golang', latest+'-bookworm')
    nodes = json.loads(fetch('https://nodejs.org/dist/index.json'))
    schedule = json.loads(fetch('https://raw.githubusercontent.com/nodejs/Release/main/schedule.json'))
    branch = 'v'+str(version(alloy['node_version'])[0])
    require(datetime.date.today() < datetime.date.fromisoformat(schedule[branch]['end']),
            'Selected Node branch is end of life; review a supported branch migration.')
    choices = [item['version'].removeprefix('v') for item in nodes if item.get('lts') and
               version(item['version'].removeprefix('v'))[0] == version(alloy['node_version'])[0]]
    require(choices, 'Selected Node branch has no supported LTS release.')
    alloy['node_version'] = max(choices, key=version)
    alloy['node_image'] = image('node', alloy['node_version']+'-bookworm')
    rust = tomllib.loads(fetch('https://static.rust-lang.org/dist/channel-rust-stable.toml').decode())
    rust_version = rust['pkg']['rust']['version'].split()[0]
    version(rust_version)
    lock_path = ROOT/'builders/build-inputs.lock'
    text = lock_path.read_text()
    for key, value in {'PAM_RSSH_RUST_VERSION': rust_version,
                       'PAM_RSSH_BUILDER_OCI': image('rust', rust_version+'-slim-bookworm')}.items():
        text, count = re.subn(r'^'+key+'=.+$', key+'='+value, text, flags=re.MULTILINE)
        require(count == 1, 'Toolchain lock does not have one selected value.')
    proposals = {}
    # Source upgrades can invalidate patches or change behavior. Record a reviewed
    # candidate rather than silently copying a new tag into an old patch recipe.
    for name, repository in {'alloy': 'grafana/alloy', 'beyla': 'grafana/beyla',
                             'node-exporter': 'prometheus/node_exporter', 'unbound': 'NLnetLabs/unbound',
                             'vpp': 'FDio/vpp', 'tayga': 'apalrd/tayga', 'pam-rssh': 'z4yx/pam_rssh',
                             'mkosi': 'systemd/mkosi', 'vulnerability-scanner': 'golang/vuln'}.items():
        values = json.loads(run('gh', 'api', 'repos/'+repository+'/releases?per_page=100'))
        choices = [item for item in values if not item['draft'] and not item['prerelease'] and
                   re.fullmatch(r'(?:v|release-)?[0-9]+\.[0-9]+(?:\.[0-9]+)?', item['tag_name'])]
        if choices:
            chosen = max(choices, key=lambda item: item['published_at'])
            proposals[name] = {'repository': repository, 'tag': chosen['tag_name'],
                               'release': chosen['html_url'], 'review': 'source, patches, native behavior and security'}
        else:
            proposals[name] = {'repository': repository, 'review': 'no stable release feed; inspect pinned source advisories'}
    scanners = fetch('https://proxy.golang.org/golang.org/x/vuln/@v/list').decode().splitlines()
    stable = [item for item in scanners if re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item)]
    require(stable, 'Vulnerability scanner has no stable module release.')
    proposals['vulnerability-scanner'] = {'module': 'golang.org/x/vuln',
        'version': max(stable, key=lambda item: version(item[1:])),
        'review': 'scanner source, coverage changes and native scan fixtures'}
    for path, value in ((alloy_path, alloy), (exporter_path, exporter),
                        (ROOT/'docs/upstream-proposals.json', {'schema': 1, 'candidates': proposals})):
        path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')
    lock_path.write_text(text)
    print('Proposed supported toolchain updates and upstream source review candidates; nothing was approved.')


if __name__ == '__main__':
    main()
