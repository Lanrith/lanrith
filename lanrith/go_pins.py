"""Apply reviewed checksum pins to existing embedded compression dependencies."""
import json
import os
import re

from .release import require

MODULES = frozenset(('github.com/andybalholm/brotli', 'github.com/klauspost/compress'))


def validate(value):
    require(isinstance(value, dict) and set(value) == MODULES, 'Embedded Go module coverage changed.')
    for item in value.values():
        require(isinstance(item, dict) and set(item) == {'version', 'sum', 'go_mod_sum'} and
                isinstance(item['version'], str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['version']) and
                all(isinstance(item[k], str) and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', item[k])
                    for k in ('sum', 'go_mod_sum')), 'Embedded Go version or checksum is not a reviewed stable pin.')
    return value


def apply(root, value, run):
    pins = validate(value)
    environment = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off',
                   'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
                   'GOPRIVATE': '', 'GONOSUMDB': '', 'GONOPROXY': ''}
    def command(*arguments):
        return run('go', *arguments, cwd=root, env=environment, capture_output=True, text=True).stdout
    manifest = json.loads(command('mod', 'edit', '-json'))
    existing = {r['Path']: r['Version'] for r in manifest['Require']}
    require(MODULES <= set(existing) and not any(r['Old']['Path'] in MODULES for r in manifest.get('Replace') or []),
            'Compression pins must update existing unreplaced dependencies, not add or redirect modules.')
    for name, item in pins.items():
        current = existing[name]
        require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', current) and
                tuple(map(int, current[1:].split('.'))) <= tuple(map(int, item['version'][1:].split('.'))),
                'Embedded Go pin would downgrade an existing dependency.')
    command('mod', 'edit', *('-require='+name+'@'+pins[name]['version'] for name in sorted(pins)))
    for name, item in sorted(pins.items()):
        resolved = json.loads(command('mod', 'download', '-json', name+'@'+item['version']))
        require(not resolved.get('Error') and resolved.get('Path') == name and resolved.get('Version') == item['version'] and
                resolved.get('Sum') == item['sum'] and resolved.get('GoModSum') == item['go_mod_sum'],
                'Embedded Go module differs from its reviewed checksum-database identity.')
        selected = json.loads(command('list', '-mod=mod', '-m', '-json', name))
        require(selected.get('Path') == name and selected.get('Version') == item['version'] and not selected.get('Replace'),
                'Embedded Go graph did not select the reviewed fixed dependency.')
