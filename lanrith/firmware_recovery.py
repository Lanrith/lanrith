"""Replace a specific TPM enrollment during an owner-approved firmware transition."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import NamedTuple

from . import early_unlock, factory, recovery_authority, recovery_enrollment as enrollment
from . import recovery_inputs, recovery_slot, release, update


PUBLIC = Path('/sysroot/usr/lib/systemd/tpm2-pcr-public-key.pem')
SIGNATURE = '/run/systemd/tpm2-pcr-signature.json'


def validate(binding):
    release.require(isinstance(binding, dict) and set(binding) ==
                    {'state_partuuid', 'pcr7_sha256', 'old_token', 'old_slot', 'inventory'} and
                    isinstance(binding['state_partuuid'], str) and re.fullmatch(update.UUID, binding['state_partuuid']) and
                    isinstance(binding['pcr7_sha256'], str) and re.fullmatch('[0-9a-f]{64}', binding['pcr7_sha256']) and
                    binding['pcr7_sha256'] != early_unlock.ZERO and binding['old_token'] in enrollment.IDS and
                    binding['old_slot'] in enrollment.IDS, 'Invalid firmware transition binding.')
    inventory = binding['inventory']
    release.require(isinstance(inventory, dict) and set(inventory) == {'keyslots', 'tokens'} and
                    all(isinstance(items, dict) and 2 <= len(items) < len(enrollment.IDS) and
                        all(i in enrollment.IDS and isinstance(d, str) and re.fullmatch('[0-9a-f]{64}', d)
                            for i, d in items.items()) for items in inventory.values()) and
                    len(inventory['keyslots']) == len(inventory['tokens']) and
                    binding['old_slot'] in inventory['keyslots'] and binding['old_token'] in inventory['tokens'],
                    'Invalid pre-maintenance enrollment inventory.')


class EnrollmentState(NamedTuple):
    old_tagged: bool
    old_live: bool
    new_token: str
    new_slot: str
    new_tagged: bool
    new_live: bool


def layout(luks, binding, policy):
    """Recognize only the original methods and the two reserved enrollment IDs."""
    before, current = binding['inventory'], enrollment.inventory(luks)
    old_slot, old_token = binding['old_slot'], binding['old_token']
    slot, token = (next(i for i in enrollment.IDS if i not in before[k]) for k in ('keyslots', 'tokens'))
    for kind, old, new in (('keyslots', old_slot, slot), ('tokens', old_token, token)):
        known = {i: v for i, v in current[kind].items() if i != new}
        expected = {i: v for i, v in before[kind].items() if i != old or i in known}
        release.require(known == expected, 'State differs from the signed firmware transition inventory.')
    old_tagged, old_live = old_token in luks['tokens'], old_slot in luks['keyslots']
    tagged, live = token in luks['tokens'], slot in luks['keyslots']
    release.require((not old_tagged or old_live and luks['tokens'][old_token].get('keyslots') == [old_slot]) and
                    (not tagged or live and luks['tokens'][token].get('keyslots') == [slot]) and
                    (old_tagged or tagged), 'Unexpected partial firmware enrollment.')
    # Native enrollment creates a keyslot before its token. Retirement removes
    # the old token first. Only these two signed/reserved slots may be untagged.
    untagged = {i for i, present, bound in ((old_slot, old_live, old_tagged), (slot, live, tagged))
                if present and not bound}
    projected = {**luks, 'keyslots': {i: s for i, s in luks['keyslots'].items() if i not in untagged}}
    factory.enrollment_tokens(projected, tpm_required=True, policy=policy)
    expected_tpm = {i for i, present in ((old_token, old_tagged), (token, tagged)) if present}
    release.require(set(early_unlock.tpm_tokens(projected)) == expected_tpm and enrollment.recovery_slots(luks),
                    'Firmware maintenance requires the bound TPM and independent recovery methods.')
    return EnrollmentState(old_tagged, old_live, token, slot, tagged, live)


def require_firmware(binding):
    observed = early_unlock.kernel_text(Path('/sys/class/tpm/tpm0/pcr-sha256/7'), 256).lower()
    release.require(observed == binding['pcr7_sha256'], 'Firmware differs from its approved destination PCR 7.')


def _replace_enrollment(device, uuid, binding, policy, secret, *, check):
    """Resume between header writes; authenticate recovery before each mutation."""
    validate(binding)
    early_unlock.validate(policy)
    release.require(hashlib.sha256(release.read(PUBLIC, 16384)).hexdigest() == policy['public_key_sha256'],
                    'Recovery image has a different signed PCR authority.')
    release.require(isinstance(secret, bytearray) and enrollment.KEY.fullmatch(secret),
                    'The recorded offline recovery key is required.')

    def inspect():
        check()
        early_unlock.in_initrd()
        require_firmware(binding)
        release.require(enrollment.volume_id(device) == uuid, 'Firmware maintenance state UUID differs.')
        luks = enrollment.header(device)
        state = layout(luks, binding, policy)
        release.require(any(enrollment.matches(device, slot, secret) for slot in enrollment.recovery_slots(luks).values()),
                        'Recorded key does not unlock the bound independent recovery slot.')
        return state

    state = inspect()
    if state.old_tagged:
        release.require(not early_unlock.token_test(device, binding['old_token']),
                        'The predecessor TPM enrollment still opens this state.')
    if not state.new_tagged:
        if state.new_live:
            # This first spare keyslot is explicitly reserved by the signed pre-image.
            release.require(enrollment.run_private(['luksKillSlot', '--key-file=-', device, state.new_slot], secret),
                            'Could not clear the interrupted reserved TPM keyslot.')
            inspect()
        args = ['systemd-cryptenroll', '--unlock-key-file=/proc/self/fd/0', '--tpm2-device=/dev/tpmrm0',
                '--tpm2-pcrs=7:sha256='+binding['pcr7_sha256']+'+15:sha256='+early_unlock.ZERO,
                '--tpm2-pcrlock=', '--tpm2-public-key='+str(PUBLIC), '--tpm2-public-key-pcrs=11',
                '--tpm2-signature='+SIGNATURE, device]
        result = subprocess.run(args, input=secret, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=enrollment.ENV, timeout=120)
        release.require(result.returncode == 0, 'Could not enroll the approved firmware policy.')
    state = inspect()
    approved = enrollment.inventory(enrollment.header(device))
    release.require(state.new_tagged and early_unlock.token_test(device, state.new_token), 'Replacement TPM enrollment cannot unseal.')
    # Prove the new token closes before touching the predecessor. A retry from
    # this point uses a new recovery boot, with a fresh PCR 15.
    update.command(['/usr/lib/systemd/systemd-pcrextend', '--bank=sha256', '--pcr=15', early_unlock.BARRIER])
    release.require(early_unlock.pcr15() == early_unlock.CLOSED and not early_unlock.token_test(device, state.new_token),
                    'Replacement TPM enrollment did not close at the PCR 15 barrier.')

    def check_closed():
        check()
        require_firmware(binding)
        release.require(early_unlock.pcr15() == early_unlock.CLOSED and enrollment.volume_id(device) == uuid,
                        'Firmware maintenance target changed during retirement.')
        luks = enrollment.header(device)
        state = layout(luks, binding, policy)
        current = enrollment.inventory(luks)
        release.require(current['tokens'].get(state.new_token) == approved['tokens'][state.new_token] and
                        current['keyslots'].get(state.new_slot) == approved['keyslots'][state.new_slot],
                        'Replacement TPM enrollment changed after its native probe.')
        release.require(state.new_tagged and any(enrollment.matches(device, s, secret)
                        for s in enrollment.recovery_slots(luks).values()), 'Offline recovery method changed.')
        return state

    if state.old_tagged:
        check_closed()
        update.command(['cryptsetup', 'token', 'remove', '--token-id', binding['old_token'], device])
    if state.old_live:
        check_closed()
        release.require(enrollment.run_private(['luksKillSlot', '--key-file=-', device, binding['old_slot']], secret),
                        'Could not retire the bound previous TPM keyslot.')
    final = check_closed()
    release.require(not final.old_tagged and not final.old_live, 'Previous TPM enrollment remains.')


def approved_destination(value):
    release.require(recovery_authority.permits('reenroll-tpm', value), 'Firmware maintenance is not authorized.')
    early_unlock.in_initrd()
    require_firmware(value['firmware_transition'])


def reenroll(value, secret):
    approved_destination(value)
    binding = value['firmware_transition']
    disk = recovery_inputs.canonical_disk(value['disk_by_id'])
    recovery_disk, _ = factory.verified_root('/sysroot')
    release.require(disk != recovery_disk, 'Firmware maintenance requires an independent recovery disk.')
    before = recovery_inputs.disk_snapshot(disk)
    rows = before[1]
    release.require(all(not row['mounted'] for row in rows), 'Firmware maintenance target is busy.')
    device = recovery_inputs.partition(rows, disk, binding['state_partuuid'], factory.VAR_GUID, label='var')
    installed = json.loads(release.read(Path('/sysroot/usr/share/lanrith/installed.json'), 65536),
                           object_pairs_hook=release.unique)

    def check():
        factory.secure_boot()
        release.require(disk == recovery_inputs.canonical_disk(value['disk_by_id']), 'Recovery disk binding changed.')
        recovery_inputs.stable_snapshot(disk, before, None)
    # Authenticate the destination and offline key before even opening a write window.
    check()
    early_unlock.in_initrd()
    require_firmware(binding)
    luks = enrollment.header(device)
    layout(luks, binding, installed['tpm_policy'])
    release.require(enrollment.volume_id(device) == value['state_uuid'] and isinstance(secret, bytearray) and
                    enrollment.KEY.fullmatch(secret) and
                    any(enrollment.matches(device, s, secret) for s in enrollment.recovery_slots(luks).values()),
                    'Firmware maintenance requires the bound state and recorded offline key.')
    other_devices = [row['device'] for row in rows if row['device'] != device]

    def check_window():
        check()
        release.require(all(update.command(['blockdev', '--getro', other]).strip() == '1' for other in other_devices),
                        'A non-state partition lost its read-only protection.')
    with recovery_slot.writable(disk, rows, {device}):
        _replace_enrollment(device, value['state_uuid'], binding, installed['tpm_policy'], secret, check=check_window)
