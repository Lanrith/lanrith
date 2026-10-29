"""Local security observations; these are neither attestation nor qualification."""

from pathlib import Path
import re

from .update import command


def efi_flag(name, *, root=Path('/sys/firmware/efi/efivars')):
    try:
        data = (root/(name+'-8be4df61-93ca-11d2-aa0d-00e098032b8c')).read_bytes()
        return bool(data[4]) if len(data) == 5 and data[4] in (0, 1) else None
    except OSError:
        return None


def mount_options(path):
    try:
        return set(command(['findmnt', '--noheadings', '--output', 'OPTIONS', path]).strip().split(','))
    except (OSError, ValueError):
        return None


def mapped(path, prefix):
    try:
        source = command(['findmnt', '--noheadings', '--output', 'SOURCE', path]).strip()
        name = Path(source).resolve().name
        if not source.startswith('/dev/') or not re.fullmatch(r'dm-[0-9]+', name):
            return False
        return (Path('/sys/class/block')/name/'dm/uuid').read_text().strip().startswith(prefix)
    except (OSError, ValueError):
        return None


def observe(installed, *, luks=None):
    boot = installed['boot']
    prepare = installed.get('tpm_transition', {}).get('phase') in ('prepare', 'enroll')
    root_options = mount_options('/')
    state_options = mount_options('/var')
    declared = {'secure_boot': boot.get('secure_boot', True), 'verified_root': True,
                'encrypted_state': True, 'tpm': boot.get('tpm', 'required'),
                'root_access': installed.get('root_access', 'enabled'),
                'signed_pcr_policy': 'tpm_policy' in installed and not prepare,
                'early_boot_only_unlock': installed.get('tpm_policy', {}).get('early_boot_only', False) and not prepare,
                'tpm_migration': installed.get('tpm_transition', {}).get('phase', 'none')}
    observed = {'secure_boot': efi_flag('SecureBoot'), 'setup_mode': efi_flag('SetupMode'),
                'tpm_present': Path('/sys/class/tpm/tpm0').exists(),
                'root_read_only': None if root_options is None else 'ro' in root_options,
                'verity_mapping': mapped('/', 'CRYPT-VERITY-'),
                'encrypted_state': mapped('/var', 'CRYPT-LUKS'),
                'state_restricted': None if state_options is None else
                    {'nodev', 'nosuid', 'noexec'} <= state_options}
    observed['signed_pcr_policy'] = None
    observed['early_boot_only_unlock'] = None
    if luks is not None and 'tpm_policy' in installed:
        from .factory import enrollment_tokens
        try:
            enrollment_tokens(luks, tpm_required=True, policy=installed['tpm_policy'])
            observed['signed_pcr_policy'] = True
        except (ValueError, KeyError):
            observed['signed_pcr_policy'] = False
    if declared['early_boot_only_unlock']:
        from .early_unlock import observation
        try:
            observation(installed)
            observed['early_boot_only_unlock'] = True
        except (OSError, ValueError, KeyError):
            observed['early_boot_only_unlock'] = False
    checks = [observed['root_read_only'], observed['verity_mapping'],
              observed['encrypted_state'], observed['state_restricted']]
    if prepare:
        # The bridge deliberately retains its bound legacy token until the
        # enforcement image is installed. It is never a completed profile.
        checks.append(False)
    if declared['secure_boot']:
        checks += [observed['secure_boot'], None if observed['setup_mode'] is None else not observed['setup_mode']]
    if declared['tpm'] == 'required':
        checks.append(observed['tpm_present'])
    if declared['signed_pcr_policy']:
        checks.append(observed['signed_pcr_policy'])
    if declared['early_boot_only_unlock']:
        checks.append(observed['early_boot_only_unlock'])
    result = 'degraded' if False in checks else 'unknown' if None in checks else 'matches-declared'
    return {'schema': 1, 'scope': 'local-observation', 'attestation': False,
            'hardware_qualification': 'not-asserted', 'status': result,
            'declared': declared, 'observed': observed}
