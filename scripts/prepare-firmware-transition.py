#!/usr/bin/env python3
"""Summarize a pre-maintenance LUKS2 JSON dump for a signed recovery build."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import early_unlock, firmware_recovery, recovery_enrollment, release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-partuuid', required=True)
    parser.add_argument('--approved-pcr7', required=True, help='Expected SHA-256 PCR 7 from independent qualification')
    args = parser.parse_args()
    data = sys.stdin.buffer.read(1024**2 + 1)
    release.require(0 < len(data) <= 1024**2, 'Invalid LUKS2 metadata length.')
    luks = json.loads(data, object_pairs_hook=release.unique)
    ids = early_unlock.tpm_tokens(luks)
    release.require(len(ids) == 1 and recovery_enrollment.recovery_slots(luks),
                    'Firmware maintenance requires one TPM enrollment and a recorded recovery key.')
    token = luks['tokens'][ids[0]]
    release.require(len(token['keyslots']) == 1, 'TPM token must refer to exactly one keyslot.')
    binding = {'state_partuuid': args.state_partuuid, 'pcr7_sha256': args.approved_pcr7, 'old_token': ids[0],
               'old_slot': token['keyslots'][0], 'inventory': recovery_enrollment.inventory(luks)}
    firmware_recovery.validate(binding)
    encoded = release.canonical(binding)
    release.require(len(encoded) <= 4096, 'Firmware transition exceeds the builder input limit.')
    sys.stdout.buffer.write(encoded)


if __name__ == '__main__':
    main()
