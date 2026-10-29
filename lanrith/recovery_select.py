"""Select an authenticated compatible fallback for one boot after confirmation."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess

from . import early_failure, factory, recovery_inputs, release, update


OPERATOR_SELECTION_QUALIFIED = False
ONESHOT = Path('/sys/firmware/efi/efivars/LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')
OBSERVATION_DEADLINE_SECONDS = 900


def bounded_observation(observe):
    """Bound interruptible verification; do not time the operator prompt.

    An uninterruptible kernel I/O stall still needs a qualified watchdog.
    """
    release.require(callable(observe) and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
                    'Recovery verification cannot replace an existing timer.')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise TimeoutError('Recovery verification deadline exceeded.')
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, OBSERVATION_DEADLINE_SECONDS)
        return observe()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def select_bound(*, confirm):
    """Select the bound installed fallback once without changing the default.

    The caller must authenticate an operator on a physical console. Confirmation
    must return the exact decimal deployment number. The signed running initrd
    must bind the target and fallback; no arbitrary boot path is accepted.
    """
    release.require(callable(confirm) and os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Fallback selection requires an authenticated recovery initrd.')
    def initial_observation():
        installed = json.loads(release.read(Path('/usr/share/lanrith/initrd-failure.json'), 65536),
                               object_pairs_hook=release.unique)
        early_failure.failure_identity(installed)
        release.require('steady_state' in installed or OPERATOR_SELECTION_QUALIFIED and
                        early_failure.FALLBACK_AUTHENTICATION_QUALIFIED and
                        early_failure.ROLLBACK_COMPATIBILITY_QUALIFIED,
                        'Operator fallback selection is not qualified.')
        release.require('fallback_binding' in installed, 'No bound fallback is available.')
        factory.secure_boot()
        binding = installed['fallback_binding']
        disk = recovery_inputs.canonical_disk(binding['disk_by_id'])
        early_failure.observe_boot_esp(disk, binding['esp_uuid'])
        before, rows = recovery_inputs.disk_snapshot(disk)
        esp = recovery_inputs.partition(rows, disk, binding['esp_uuid'], recovery_inputs.ESP_GUID)
        release.require(not ONESHOT.exists(), 'A pending one-shot boot selection already exists.')
        return installed, binding, disk, before, rows, esp

    installed, binding, disk, before, rows, esp = bounded_observation(initial_observation)

    def check_state():
        observation = bounded_observation(lambda: early_failure.observe_rollback_compatibility(installed))
        release.require(isinstance(observation, dict) and
                        observation.get('scope') == 'rollback-compatibility-observation' and
                        observation.get('authorized_to_boot') is False,
                        'Fallback state compatibility observation differs.')

    # The fallback verifier mounts the ESP itself and requires it to be
    # unmounted. Check before the operator prompt and again after the prompt,
    # because state or disk bindings may change while the operator decides.
    check_state()
    with recovery_inputs.mounted(esp, 'vfat') as point:
        observed = bounded_observation(lambda: early_failure.observe_bound_fallback(installed, point))
        sequence = binding['release']['sequence']
        release.require(observed.get('sequence') == sequence and observed.get('authorized_to_boot') is False,
                        'Bound fallback observation differs.')
        release.require(confirm(sequence, binding['release']['uki_sha256']) == str(sequence),
                        'Fallback selection was not confirmed.')
        bounded_observation(lambda: early_failure.observe_bound_fallback(installed, point))
        bounded_observation(lambda: recovery_inputs.stable_snapshot(disk, (before, rows), esp))
    check_state()
    with recovery_inputs.mounted(esp, 'vfat') as point:
        bounded_observation(lambda: early_failure.observe_bound_fallback(installed, point))
        bounded_observation(lambda: recovery_inputs.stable_snapshot(disk, (before, rows), esp))
        bounded_observation(factory.secure_boot)
        release.require(not ONESHOT.exists(), 'A pending one-shot boot selection appeared.')
        listing = json.loads(bounded_observation(
            lambda: update.command(['bootctl', '--esp-path='+str(point), '--json=short', 'list'])))
        release.require(isinstance(listing, list), 'Fallback boot inventory is invalid.')
        base = binding['release']['uki_name']
        folder = point/'EFI/Linux'
        matches = [p for p in folder.iterdir() if re.fullmatch(
            re.escape(base[:-4])+r'(?:\+[0-9]+(?:-[0-9]+)?)?\.efi', p.name)]
        release.require(len(matches) == 1 and not matches[0].is_symlink(), 'Fallback boot entry is ambiguous.')
        entries = [item for item in listing if isinstance(item, dict) and item.get('type') == 'type2' and
                   item.get('source') == 'esp' and item.get('path') == str(matches[0])]
        release.require(len(entries) == 1 and entries[0].get('id') in (base, matches[0].name),
                        'Boot loader does not identify the bound fallback.')
        identifier = entries[0]['id']
        bounded_observation(lambda: early_failure.observe_bound_fallback(installed, point))
        release.require(not ONESHOT.exists(), 'A pending one-shot boot selection appeared.')
        # No ESP or default-entry writes: bootctl sets a single EFI one-shot.
        def current_choice():
            if not ONESHOT.exists():
                return None
            data = release.read(ONESHOT, 4096)
            try:
                return data[4:].decode('utf-16-le').rstrip('\0') if len(data) >= 6 and (len(data)-4) % 2 == 0 else ''
            except UnicodeError:
                return ''
        try:
            update.command(['bootctl', '--esp-path='+str(point), 'set-oneshot', identifier])
            release.require(current_choice() == identifier, 'One-shot fallback selection could not be verified.')
            bounded_observation(lambda: recovery_inputs.stable_snapshot(disk, (before, rows), esp))
        except Exception:
            # Clear only the value we just selected. If its identity is unknown,
            # do not erase another actor's selection; report the unresolved state.
            try:
                selected = current_choice()
                if selected == identifier:
                    update.command(['bootctl', '--esp-path='+str(point), 'set-oneshot', ''])
                    release.require(not ONESHOT.exists(), 'Fallback selection cleanup failed.')
                elif selected is not None:
                    raise release.ReleaseError('Fallback selection state is uncertain.')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                raise release.ReleaseError('Fallback selection state is uncertain.') from None
            raise
    return {'schema': 1, 'scope': 'experimental-one-shot-fallback', 'sequence': sequence,
            'automatic_reboot': False, 'default_changed': False}
