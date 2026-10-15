"""Build and verify a router image from declared network intent."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import admission, build, config, release, trust


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('configuration', type=Path)
    render = commands.add_parser('render')
    render.add_argument('configuration', type=Path)
    render.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('directory', type=Path)
    verify.add_argument('--certificate', type=Path, required=True)
    verify.add_argument('--image-id', default='lanrith')
    verify.add_argument('--minimum-sequence', type=int, default=0)
    sign = commands.add_parser('sign')
    sign.add_argument('directory', type=Path)
    sign.add_argument('--key', type=Path, required=True)
    platform = commands.add_parser('verify-platform')
    platform.add_argument('directory', type=Path)
    platform.add_argument('--lock', type=Path, required=True)
    image = commands.add_parser('build')
    image.add_argument('configuration', type=Path)
    image.add_argument('--base', type=Path, required=True)
    image.add_argument('--initrd-base', type=Path, required=True)
    image.add_argument('--workspace', type=Path, required=True)
    image.add_argument('--output', type=Path, required=True)
    image.add_argument('--platform-lock', type=Path)
    image.add_argument('--platform-bundle', type=Path)
    image.add_argument('--version', required=True)
    image.add_argument('--sequence', type=int, required=True)
    image.add_argument('--certificate', type=Path)
    image.add_argument('--key', type=Path)
    image.add_argument('--serial-passphrase-hash', type=Path)
    image.add_argument('--qualification', action='store_true')
    image.add_argument('--integration-lock', type=Path,
                       help='Reviewed private mapping of extension IDs to canonical directories and manifest digests')
    args = parser.parse_args(arguments)
    try:
        if args.command == 'validate':
            value = config.load(args.configuration)
            config.render(value)
            print(json.dumps({'valid': True, 'networks': len(value['networks']),
                              'extensions': len(value.get('extensions', []))}))
        elif args.command == 'render':
            digest = config.write(config.load(args.configuration), args.output)
            print(json.dumps({'configuration_sha256': digest}))
        elif args.command == 'verify':
            value = release.verify(args.directory.resolve(), args.certificate, purpose='update',
                                   image_id=args.image_id, minimum_sequence=args.minimum_sequence)
            print(json.dumps({'verified': True, 'deployment_sequence': value['deployment_sequence']}))
        elif args.command == 'sign':
            release.sign(args.directory.resolve(), args.key)
            print('Release manifest signed.')
        elif args.command == 'verify-platform':
            selection = trust.lock(args.lock)
            reference = trust.verify(args.directory.resolve(), selection)
            trust.verify_builder(selection, args.directory / 'builder.intoto.jsonl')
            print(json.dumps({'verified': True, 'builder': reference}))
        else:
            release.require(args.qualification or args.platform_lock and args.platform_bundle,
                            'Production assembly requires a reviewed platform lock and authenticated bundle.')
            release.require(not args.qualification or args.key is None,
                            'Qualification mode cannot use production signing material.')
            if not args.qualification:
                selection = trust.lock(args.platform_lock)
                trust.verify(args.platform_bundle.resolve(), selection)
                trust.verify_builder(selection, args.platform_bundle / 'builder.intoto.jsonl')
                admission.assess(args.platform_bundle, selection)
                release.require(args.base.name in selection['files'] and
                                release.file_record(args.base)['sha256'] == selection['files'][args.base.name],
                                'Selected base differs from admitted platform inputs.')
                release.require(args.initrd_base.name in selection['files'] and
                                release.file_record(args.initrd_base)['sha256'] == selection['files'][args.initrd_base.name],
                                'Selected initrd differs from admitted platform inputs.')
            integrations = {}
            if args.integration_lock:
                pins = json.loads(release.read(args.integration_lock, 65536), object_pairs_hook=release.unique)
                for name, pin in pins.items():
                    release.require(isinstance(pin, dict) and set(pin) == {'directory', 'sha256'},
                                    'Invalid integration selection.')
                    integrations[name] = (Path(pin['directory']).absolute(), pin['sha256'])
            identity = build.assembly(config.load(args.configuration), args.base.resolve(), args.workspace.resolve(),
                                      version=args.version, sequence=args.sequence,
                                      certificate=args.certificate, private_key=args.key, integrations=integrations,
                                      serial_hash=args.serial_passphrase_hash, initrd_base=args.initrd_base.resolve())
            build.run(args.workspace.resolve())
            build.update_payload(args.workspace.resolve(), identity, args.output.resolve())
            if args.key is not None:
                release.sign(args.output.resolve(), args.key)
                release.verify(args.output.resolve(), args.certificate, purpose='update', image_id=identity['image_id'])
            print(json.dumps({**identity, 'signed': args.key is not None, 'qualified': False}))
    except (release.ReleaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, release.ReleaseError) else 'Build or verification operation failed.',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
