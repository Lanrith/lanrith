#!/usr/bin/env python3
"""Assemble admitted files inside the isolated signing container."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import admission, build, build_inputs as boot, config, release, trust
import importlib.util
spec = importlib.util.spec_from_file_location("consumer", Path(__file__).with_name("consumer.py"))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--owner', type=Path, required=True)
parser.add_argument('--platform', type=Path, required=True)
parser.add_argument('--private', type=Path, required=True)
parser.add_argument('--sequence', type=int, required=True)
parser.add_argument('--workspace', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--fallback-release', type=Path)
args = parser.parse_args()
receipt = json.loads(release.read(args.private/'admitted.json', 65536), object_pairs_hook=release.unique)
selection = trust.lock(args.owner/'platform.lock')
release.require(release.file_record(args.owner/'platform.lock')['sha256'] == receipt['platform_lock_sha256'] and
                receipt['files'] == selection['files'], 'Offline admission receipt differs from the selected inputs.')
for name, expected in receipt['files'].items():
    release.require(release.file_record(args.platform/name)['sha256'] == expected, 'Offline platform input changed.')
assessment = args.platform/'security-assessment.json'
release.require(receipt['assessment_sha256'] == (release.file_record(assessment)['sha256'] if assessment.exists() else None),
                'Offline assessment differs from the isolated admission receipt.')
admission.assess(args.platform, selection)
value = config.load(args.owner/'config.yaml')
release.require(hashlib.sha256(release.canonical(value)).hexdigest() == receipt['configuration_sha256'],
                'Owner configuration changed after preflight.')
integrations = consumer.integration_pins(args.owner, value)
release.require({name: pin[1] for name, pin in integrations.items()} == receipt['integration_digests'],
                'Owner integrations changed after isolated admission.')
boot_inputs = receipt.get('boot_inputs', {})
extra = {}
if boot_inputs:
    release.require(boot_inputs.get('image_id') == value.get('release', {}).get('image_id', 'lanrith'),
                    'Boot build inputs select another image.')
    if 'pcr_certificate_sha256' in boot_inputs:
        release.require(release.file_record(args.private/'pcr.crt')['sha256'] == boot_inputs['pcr_certificate_sha256'] and
                        hashlib.sha256(release.public_key(args.private/'pcr.crt')).hexdigest() == boot_inputs['pcr_public_key_sha256'],
                        'PCR signing authority differs from admission.')
        extra.update(pcr_key=args.private/'pcr.key', pcr_certificate=args.private/'pcr.crt')
    if 'recovery_credential_sha256' in boot_inputs:
        release.require(release.file_record(args.private/'recovery.hash')['sha256'] == boot_inputs['recovery_credential_sha256'],
                        'Recovery credential differs from admission.')
        extra['recovery_hash'] = args.private/'recovery.hash'
    if 'fallback_binding' in boot_inputs:
        release.require(args.fallback_release is not None and
                        release.file_record(args.fallback_release/'release.json')['sha256'] == boot_inputs['fallback_manifest_sha256'],
                        'Fallback manifest differs from admission.')
        extra.update(fallback_release=args.fallback_release,
                     fallback_disk_by_id=boot_inputs['fallback_binding']['disk_by_id'],
                     fallback_esp_uuid=boot_inputs['fallback_binding']['esp_uuid'])
release.require((args.fallback_release is not None) == ('fallback_binding' in boot_inputs),
                'Unexpected or missing fallback release input.')

serial_hash = args.private/'serial.hash' if value['administration']['serial']['enabled'] else None
serial_digest = release.file_record(serial_hash)['sha256'] if serial_hash else None
effective_digest = config.effective_digest(value, receipt['integration_digests'], serial_digest,
                                         boot_inputs=boot.digest_fields(boot_inputs))
release.require(serial_digest == receipt['serial_provisioning_sha256'] and
                effective_digest == receipt['effective_configuration_sha256'],
                'Effective configuration changed after isolated admission.')
identity = build.assembly(value, args.platform/'lanrith-base.tar.gz', args.workspace,
                          version=selection['version'][1:], sequence=args.sequence,
                          certificate=args.private/'boot.crt', private_key=args.private/'boot.key',
                          initrd_base=args.platform/'lanrith-initrd-base.tar.gz', integrations=integrations,
                          serial_hash=serial_hash, **extra)
release.require(identity['configuration_sha256'] == effective_digest,
                'Assembly identity differs from the admitted effective configuration.')
build.run(args.workspace)
build.update_payload(args.workspace, identity, args.output)
release.sign(args.output, args.private/'boot.key')
release.verify(args.output, args.private/'boot.crt', purpose='update', image_id=identity['image_id'],
               expected_configuration=effective_digest)
factory=args.output.parent/'factory'
build.factory_payload(args.workspace,identity,args.output,factory,consume=True)
release.sign(factory,args.private/'boot.key')
release.verify(factory,args.private/'boot.crt',purpose='factory',image_id=identity['image_id'],
               expected_configuration=effective_digest)
