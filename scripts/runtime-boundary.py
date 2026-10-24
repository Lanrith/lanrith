#!/usr/bin/env python3
"""Reject compiler inputs and compiler dependencies from the assembled image."""

import argparse
import ast
from pathlib import Path
import sys


COMPILER = {'config', 'intent', 'build', 'cli', 'runtime_plan', 'hardware_config', 'bindings',
            'integrations', 'access', 'firewall', 'service_plane', 'authoritative', 'routing',
            'translation', 'nat46', 'nat64', 'ids', 'metrics', 'policy_agent', 'discovery',
            'logs', 'radius', 'fancontrol_config'}


def check(root):
    library = root/'usr/lib/lanrith/lanrith'
    modules = {path.stem for path in library.glob('*.py')}
    if not {'runtime', 'boot_health', 'hardware', 'factory', 'release', 'update'} <= modules or modules & COMPILER:
        raise ValueError('The image has an incomplete runtime or contains configuration compiler code.')
    build_inputs = root/'usr/lib/lanrith-build'
    if build_inputs.exists() or build_inputs.is_symlink():
        raise ValueError('The image contains an unconsumed build-only policy input.')
    for directory in (library, root/'etc/lanrith', root/'usr/share/lanrith'):
        if any(path.suffix in ('.yaml', '.yml') or path.name in ('resolved.json', 'configuration.json')
               for path in directory.rglob('*')):
            raise ValueError('The image contains source configuration input.')
    # Check dormant imports too. No site-package or compiler module may become
    # necessary only after a health probe or translator restart.
    for path in library.glob('*.py'):
        for node in ast.walk(ast.parse(path.read_bytes())):
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    if node.level != 1:
                        raise ValueError('The runtime imports outside its package.')
                    names = ['lanrith.'+node.module] if node.module else ['lanrith.'+item.name for item in node.names]
                else:
                    names = [node.module]
            else:
                continue
            for name in names:
                parts = name.split('.')
                if parts[0] == 'lanrith':
                    valid = len(parts) == 1 or parts[1] in modules
                else:
                    valid = parts[0] in sys.stdlib_module_names
                if not valid:
                    raise ValueError('The image runtime depends on a compiler or external Python package.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    check(args.root)
    print('Compiled runtime boundary verified.')


if __name__ == '__main__':
    main()
