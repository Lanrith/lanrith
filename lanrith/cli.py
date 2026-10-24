"""Build and verify a router image from declared network intent."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from contextlib import ExitStack

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
    verify.add_argument('--purpose', choices=('update','factory'), default='update')
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
    image.add_argument('--factory-output', type=Path)
    image.add_argument('--platform-lock', type=Path)
    image.add_argument('--platform-bundle', type=Path)
    image.add_argument('--version', required=True)
    image.add_argument('--sequence', type=int, required=True)
    image.add_argument('--certificate', type=Path)
    image.add_argument('--key', type=Path)
    image.add_argument('--serial-passphrase-hash', type=Path)
    image.add_argument('--qualification', action='store_true')
    for command in (validate, render, image):
        command.add_argument('--hardware-facts', type=Path,
                             help='Private JSON snapshot of verified target hardware')
        command.add_argument('--hardware-facts-sha256', help='Reviewed SHA-256 of the hardware snapshot')
        command.add_argument('--translation-allocations', type=Path,
                             help='Private strict JSON map of retained IPv6 to IPv4 source identities')
        command.add_argument('--translation-allocations-sha256',
                             help='Reviewed SHA-256 of the retained source identity map')
    image.add_argument('--integration-lock', type=Path,
                       help='Reviewed private mapping of extension IDs to canonical directories and manifest digests')
    args = parser.parse_args(arguments)
    try:
        target_facts = None
        retained_allocations = None
        if args.command in ('validate', 'render', 'build'):
            release.require((args.hardware_facts is None) == (args.hardware_facts_sha256 is None),
                            'Hardware facts require an explicit reviewed digest.')
            if args.hardware_facts is not None:
                raw = release.read(args.hardware_facts, 1024*1024)
                release.require(hashlib.sha256(raw).hexdigest() == args.hardware_facts_sha256,
                                'Hardware facts differ from the reviewed snapshot.')
                target_facts = json.loads(raw, object_pairs_hook=release.unique)
            release.require((args.translation_allocations is None) == (args.translation_allocations_sha256 is None),
                            'Translation allocations require an explicit reviewed digest.')
            if args.translation_allocations is not None:
                raw = release.read(args.translation_allocations, 1024*1024)
                release.require(hashlib.sha256(raw).hexdigest() == args.translation_allocations_sha256,
                                'Translation allocations differ from the reviewed snapshot.')
                retained_allocations = json.loads(raw, object_pairs_hook=release.unique)
                release.require(isinstance(retained_allocations, dict), 'Translation allocations must be an object.')
        if args.command == 'validate':
            value = config.load(args.configuration)
            config.render(value, target_facts=target_facts, retained_allocations=retained_allocations)
            print(json.dumps({'valid': True, 'networks': len(value['networks']),
                              'extensions': len(value.get('extensions', []))}))
        elif args.command == 'render':
            digest = config.write(config.load(args.configuration), args.output, target_facts=target_facts,
                                  retained_allocations=retained_allocations)
            print(json.dumps({'configuration_sha256': digest}))
        elif args.command == 'verify':
            value = release.verify(args.directory.resolve(), args.certificate, purpose=args.purpose,
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
                release.require(args.version==selection['version'][1:], 'Image version differs from its admitted platform.')
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
            with ExitStack() as resources:
                if args.qualification:
                    release.require(args.certificate is None, 'Qualification uses an ephemeral test authority only.')
                    private=Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-qualification.',dir='/dev/shm')))
                    args.key, args.certificate=private/'test.key', private/'test.crt'
                    subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','1',
                        '-subj','/CN=Lanrith Disposable Qualification Authority','-keyout',str(args.key),
                        '-out',str(args.certificate)],check=True,capture_output=True)
                    args.key.chmod(0o600)
                release.require(args.key is not None and args.certificate is not None, 'Signed image assembly requires owner authority.')
                identity = build.assembly(config.load(args.configuration), args.base.resolve(), args.workspace.resolve(),
                                          version=args.version, sequence=args.sequence,
                                          certificate=args.certificate, private_key=args.key, integrations=integrations,
                                          serial_hash=args.serial_passphrase_hash, initrd_base=args.initrd_base.resolve(),
                                          target_facts=target_facts, retained_allocations=retained_allocations)
                build.run(args.workspace.resolve())
                build.update_payload(args.workspace.resolve(), identity, args.output.resolve())
                if args.key is not None:
                    release.sign(args.output.resolve(), args.key)
                    release.verify(args.output.resolve(), args.certificate, purpose='update', image_id=identity['image_id'])
                if args.factory_output:
                    output=args.factory_output.resolve()
                    release.require(output != args.output.resolve() and args.output.resolve() not in output.parents and
                                    output not in args.output.resolve().parents, 'Factory and update outputs must be separate.')
                    build.factory_payload(args.workspace.resolve(),identity,args.output.resolve(),output)
                    release.sign(output,args.key)
                    release.verify(output,args.certificate,purpose='factory',image_id=identity['image_id'])
                print(json.dumps({**identity, 'signed': True, 'qualification_only': args.qualification, 'qualified': False}))
    except (release.ReleaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, release.ReleaseError) else 'Build or verification operation failed.',
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
