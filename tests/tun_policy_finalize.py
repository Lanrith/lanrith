#!/usr/bin/env python3
"""Execute the actual policy finalizer, then independently reproduce its pin.

Run in an offline disposable container with the profile CLI and compiled fixture.
The miniature chroot contains native tools and build inputs, never owner YAML.
"""

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=20, **kwargs).stdout


def main(fixture, finalizer, profile):
    assert os.geteuid() == 0 and Path('/run/.containerenv').exists()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link'))} == {'lo'}
    parsed = ast.parse(finalizer.read_text())
    # Execute the unchanged production function without invoking unrelated
    # whole-image account and boot-unit checks against this miniature fixture.
    selected = [node for node in parsed.body if isinstance(node, (ast.Import, ast.ImportFrom)) or
                isinstance(node, ast.FunctionDef) and node.name == 'finalize_policy']
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(finalizer), 'exec'), namespace)
    def traced_run(*args, **kwargs):
        result = subprocess.run(*args, **kwargs)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
        return result
    # These are synthetic build inputs; expose subprocess diagnostics in the
    # test without changing the production finalizer's redacted error handling.
    namespace['subprocess'] = SimpleNamespace(run=traced_run, DEVNULL=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)/'root'
        root.mkdir()
        def copy(source, destination):
            path = root/destination.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, path)
            path.chmod(0o755)
        binaries = ['/usr/bin/python3', '/usr/sbin/nft', '/usr/sbin/ip']
        version = f'{sys.version_info.major}.{sys.version_info.minor}'
        library = Path('/usr/lib/python'+version)
        shutil.copytree(library, root/library.relative_to('/'))
        dependencies = set()
        for source in [*binaries, *map(str, (library/'lib-dynload').glob('*.so'))]:
            for dependency in re.findall(r'(?:=>\s*)?(/[^\s()]+)', run('ldd', source)):
                dependencies.add(dependency)
        for source in {*binaries, *dependencies}:
            copy(source, source)
        copy(profile, '/usr/bin/router-policy-profile')
        for directory in ('run', 'dev', 'usr/share/lanrith', 'usr/lib/lanrith-build'):
            (root/directory).mkdir(parents=True, exist_ok=True)
        # Rootless containers cannot create device nodes; bind the existing
        # device only for the actual chroot invocation below.
        (root/'dev/null').touch()
        copy(fixture/'accounts.passwd', '/etc/passwd')
        for name in ('protocols', 'services'):
            copy('/etc/'+name, '/etc/'+name)
        copy(fixture/'policy.nft', '/etc/nftables.conf')
        inputs = root/'usr/lib/lanrith-build'
        shutil.copyfile(fixture/'baseline.json', inputs/'policy-baseline.json')
        (inputs/'policy-baseline.json').chmod(0o600)
        (inputs/'policy-backend').write_text('tun\n')
        guards = (fixture/'identity-egress.nft').read_text()
        interfaces = sorted(set(re.findall(r'device "([^"]+)"', guards)))
        (inputs/'policy-interfaces.json').write_text(json.dumps(interfaces))
        (inputs/'policy-egress.nft').write_text(guards)
        run('mount', '--bind', '/dev/null', str(root/'dev/null'))
        try:
            namespace['finalize_policy'](root)
        except Exception:
            diagnostic = subprocess.run(['chroot', str(root), '/usr/sbin/nft', '-c', '-f', '/etc/nftables.conf'],
                capture_output=True, text=True, timeout=10)
            print(diagnostic.stderr, file=sys.stderr)
            raise
        finally:
            run('umount', str(root/'dev/null'))
        metadata = json.loads((root/'usr/share/lanrith/policy-profile-metadata.json').read_text())
        installed = root/'etc/router-policy-agent/profile/profile.json'
        assert installed.stat().st_mode & 0o777 == 0o400
        assert hashlib.sha256(installed.read_bytes()).hexdigest() == metadata['profile_sha256']
        assert not inputs.exists() and not (root/'run/lanrith-policy-build').exists()
        for interface in interfaces:
            run('ip', 'link', 'add', 'dev', interface, 'type', 'dummy')
        run('nft', '-f', str(fixture/'policy.nft'))
        run('nft', '-f', str(fixture/'identity-egress.nft'))
        listing = Path(temporary)/'runtime.json'
        listing.write_text(run('nft', '-j', '-n', 'list', 'ruleset'))
        output = Path(temporary)/'runtime-pin'
        output.mkdir(mode=0o700)
        run(str(profile), '-backend', 'tun', '-baseline', str(fixture/'baseline.json'),
            '-ruleset', str(listing), '-guards', str(fixture/'identity-egress.nft'),
            '-output-directory', str(output))
        assert metadata == json.loads((output/'router-profile-metadata.json').read_text()), 'build and runtime program pins differ'
        observed = root/'usr/share/lanrith/policy-program.json'
        program = json.loads(observed.read_text())
        assert observed.stat().st_mode & 0o777 == 0o444
        assert set(program) == {'schema_version', 'backend', 'program_sha256', 'objects'}
        assert program['schema_version'] == 1 and program['backend'] == 'tun'
        assert program['program_sha256'] == metadata['floor_sha256']
        assert program['objects'] == [row for row in json.loads(listing.read_text())['nftables'] if 'metainfo' not in row]
        assert 'baseline' not in program
        print(json.dumps({'status': 'pass', 'actual_finalizer': True, 'numeric_runtime_pin_matches': True,
            'baseline_and_scratch_removed': True, 'runtime_profile_mode': '0400', 'runtime_yaml': False,
            'native_observation_program': True}, sort_keys=True))


if __name__ == '__main__':
    main(*map(Path, sys.argv[1:]))
