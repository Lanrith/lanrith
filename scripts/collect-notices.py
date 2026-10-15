#!/usr/bin/env python3
"""Collect upstream license and notice files without publishing local cache paths."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tomllib


def licenses(root):
    result = []
    for base, directories, files in os.walk(root):
        directories[:] = [d for d in directories if d not in ('.git', 'target', 'node_modules', '__pycache__')]
        for name in sorted(files):
            if name.lower().split('.')[0] in ('license', 'licence', 'copying', 'notice', 'authors', 'copyright'):
                path = Path(base)/name
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= 4*1024*1024:
                    result.append((path.relative_to(root).as_posix(), path.read_text(errors='replace')))
    return sorted(result)


def go_modules(source):
    raw = subprocess.run(['go','list','-m','-json','all'],cwd=source,check=True,capture_output=True,text=True).stdout
    decoder = json.JSONDecoder()
    while raw.strip():
        module, offset = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[offset:]
        actual = module.get('Replace', module)
        if not actual.get('Dir'):
            raise ValueError('A selected Go module is not available for notice collection.')
        identity = module['Path']+'@'+actual.get('Version','main')
        if not module.get('Main') and 'Replace' in module and not actual.get('Version'):
            raise ValueError('Local module replacement cannot be a public package input.')
        notices = licenses(Path(actual['Dir']))
        if not notices:
            raise ValueError('A selected Go dependency has no upstream license or notice file: '+identity)
        yield identity, notices
    goroot = subprocess.run(['go','env','GOROOT'],check=True,capture_output=True,text=True).stdout.strip()
    yield 'Go standard library', [('LICENSE',(Path(goroot)/'LICENSE').read_text())]


def rust_modules(source):
    yield 'pam-rssh source', licenses(source)
    cache = Path(os.environ.get('CARGO_HOME','/usr/local/cargo'))/'registry/src'
    for manifest in sorted(cache.glob('*/*/Cargo.toml')):
        value = tomllib.loads(manifest.read_text())['package']
        notices = licenses(manifest.parent)
        notices.append(('Cargo.toml (upstream license and author metadata)', manifest.read_text()))
        yield value['name']+'@'+value['version'], notices


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('language',choices=('go','rust'))
    parser.add_argument('--source',type=Path,default=Path.cwd())
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    entries = list(go_modules(args.source) if args.language=='go' else rust_modules(args.source))
    with args.output.open('x') as stream:
        for identity, files in entries:
            stream.write('\n===== '+identity+' =====\n')
            for name, text in files:
                stream.write('\n--- '+name+' ---\n'+text+'\n')
    args.output.chmod(0o644)
    print('Collected upstream notices for '+str(len(entries))+' module identities.')


if __name__=='__main__':
    main()
