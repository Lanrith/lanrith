"""Select an authenticated compatible fallback for one boot after confirmation."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess

from . import early_failure, factory, recovery_inputs, release, update


OPERATOR_SELECTION_QUALIFIED = False
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


def eligible_identity(*, oneshot=None):
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Fallback selection requires the signed initrd.')
    installed = factory.read_failure_identity()
    early_failure.require_fallback_policy(installed)
    if 'steady_state' not in installed and not OPERATOR_SELECTION_QUALIFIED:
        raise early_failure.FallbackUnavailable('The signed recovery policy is unqualified for serial selection.')
    early_failure.accepted_predecessor(installed, oneshot=oneshot)
    return installed


def unavailable_reason():
    """Report only static policy/selector reasons before offering the command."""
    try:
        eligible_identity()
    except early_failure.FallbackUnavailable as error:
        return str(error)
    except (release.ReleaseError, OSError, ValueError, KeyError):
        return 'The signed policy or boot choices could not be verified.'
    return None


def reboot_selected(selection):
    identifier = selection['entry']
    release.require(isinstance(identifier, str) and identifier, 'Missing confirmed boot entry.')
    installed = eligible_identity(oneshot=identifier)
    factory.secure_boot()
    bound = installed['fallback_binding']['release']
    release.require(selection['sequence'] == bound['sequence'] and
                    re.sub(r'\+[0-9]+(?:-[0-9]+)?(?=\.efi$)', '', identifier) == bound['uki_name'],
                    'The confirmed boot entry differs from the signed fallback.')
    early_failure.accepted_predecessor(installed, oneshot=identifier)
    update.command(['systemctl', '--force', 'reboot'])


def select_bound(*, confirm):
    """Select the bound installed fallback once without changing the default.

    The caller must authenticate an operator on a physical console. Confirmation
    must return the exact decimal deployment number. The signed running initrd
    must bind the target and fallback; no arbitrary boot path is accepted.
    """
    release.require(callable(confirm), 'Fallback selection requires operator confirmation.')
    def initial_observation():
        installed = eligible_identity()
        factory.secure_boot()
        binding = installed['fallback_binding']
        disk = recovery_inputs.canonical_disk(binding['disk_by_id'])
        early_failure.observe_boot_esp(disk, binding['esp_uuid'])
        before, rows = recovery_inputs.disk_snapshot(disk)
        esp = recovery_inputs.partition(rows, disk, binding['esp_uuid'], recovery_inputs.ESP_GUID)
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
        early_failure.accepted_predecessor(installed)
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
        early_failure.accepted_predecessor(installed)
        # No ESP or default-entry writes: bootctl sets a single EFI one-shot.
        def current_choice():
            try:
                return early_failure.loader_entry('LoaderEntryOneShot')
            except FileNotFoundError:
                return None
        try:
            update.command(['bootctl', '--esp-path='+str(point), 'set-oneshot', identifier])
            early_failure.accepted_predecessor(installed, oneshot=identifier)
            bounded_observation(lambda: recovery_inputs.stable_snapshot(disk, (before, rows), esp))
        except Exception:
            # Clear only the value we just selected. If its identity is unknown,
            # do not erase another actor's selection; report the unresolved state.
            try:
                selected = current_choice()
                if selected == identifier:
                    update.command(['bootctl', '--esp-path='+str(point), 'set-oneshot', ''])
                    release.require(current_choice() is None, 'Fallback selection cleanup failed.')
                elif selected is not None:
                    raise release.ReleaseError('Fallback selection state is uncertain.')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                raise release.ReleaseError('Fallback selection state is uncertain.') from None
            raise
    return {'schema': 1, 'scope': 'experimental-one-shot-fallback', 'sequence': sequence,
            'entry': identifier, 'automatic_reboot': False, 'default_changed': False}
