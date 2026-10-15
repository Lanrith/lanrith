#!/usr/bin/env python3
"""Assemble admitted files inside the isolated signing container."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import admission, build, config, release, trust
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
identity = build.assembly(value, args.platform/'lanrith-base.tar.gz', args.workspace,
                          version=selection['version'][1:], sequence=args.sequence,
                          certificate=args.private/'boot.crt', private_key=args.private/'boot.key',
                          initrd_base=args.platform/'lanrith-initrd-base.tar.gz', integrations=integrations,
                          serial_hash=args.private/'serial.hash' if value['administration']['serial']['enabled'] else None)
build.run(args.workspace)
build.update_payload(args.workspace, identity, args.output)
release.sign(args.output, args.private/'boot.key')
release.verify(args.output, args.private/'boot.crt', purpose='update', image_id=identity['image_id'])
