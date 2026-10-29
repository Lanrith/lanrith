"""Admit only image operations with a compatible target, state and trust contract.

Opaque native formats are conservatively tied to their admitted base. Changing
that base needs a separately qualified compatibility/bridge implementation; a
version string or a successful signature alone is not a migration guarantee.
"""

import re
import json
import os
from pathlib import Path
import stat
import tempfile

from .release import canonical, read, require, unique


HEX = re.compile(r'[0-9a-f]{64}\Z')
FORMAT = re.compile(r'[a-z0-9][a-z0-9._:-]{0,159}\Z')
AUTHORITIES = {'manifest', 'secure_boot', 'verity', 'pcr_policy'}


def validate(value):
    fields = {'schema', 'machine_id', 'state', 'trust'}
    require(isinstance(value, dict) and fields <= set(value) <= fields | {'recovery'},
            'Image contract fields differ.')
    require(type(value['schema']) is int and value['schema'] == 1 and isinstance(value['machine_id'], str) and
            re.fullmatch(r'[0-9a-f]{32}', value['machine_id']), 'Invalid image contract target.')
    state = value['state']
    require(isinstance(state, dict) and 1 <= len(state) <= 64, 'Invalid state consumer inventory.')
    for name, item in state.items():
        require(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name) and
                isinstance(item, dict) and set(item) == {'writes', 'reads'} and
                isinstance(item['writes'], str) and FORMAT.fullmatch(item['writes']) and
                isinstance(item['reads'], list) and 1 <= len(item['reads']) <= 8 and
                all(isinstance(fmt, str) and FORMAT.fullmatch(fmt) for fmt in item['reads']) and
                len(set(item['reads'])) == len(item['reads']) and item['writes'] in item['reads'],
                'Invalid state reader/writer contract.')
    trust = value['trust']
    require(isinstance(trust, dict) and set(trust) == {'generation', 'authorities', 'transition'} and
            type(trust['generation']) is int and 1 <= trust['generation'] <= 999999999 and
            trust['transition'] == 'steady' and isinstance(trust['authorities'], dict) and
            set(trust['authorities']) == AUTHORITIES and
            all(item is None or isinstance(item, str) and HEX.fullmatch(item)
                for item in trust['authorities'].values()), 'Unsupported image trust contract.')
    recovery = value.get('recovery')
    if recovery is not None:
        from .early_failure import validate_fallback_binding
        require(isinstance(recovery, dict) and set(recovery) == {'image_id', 'sequence', 'binding'} and
                isinstance(recovery['image_id'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', recovery['image_id']) and
                type(recovery['sequence']) is int and 1 <= recovery['sequence'] <= 999999999,
                'Invalid image recovery contract.')
        validate_fallback_binding(recovery['binding'], image=recovery['image_id'], current_sequence=recovery['sequence'])
    return value


def core(value):
    """Exclude per-image recovery bindings when comparing persistent state."""
    validate(value)
    return {key: value[key] for key in ('schema', 'machine_id', 'state', 'trust')}


def compatible(current, candidate):
    validate(current)
    validate(candidate)
    require(current['machine_id'] == candidate['machine_id'], 'Image belongs to another machine identity.')
    require(current['trust'] == candidate['trust'],
            'Trust changes require a qualified transition image; steady updates cannot rotate authority.')
    for name in current['state'].keys() & candidate['state'].keys():
        before, after = current['state'][name], candidate['state'][name]
        require(before['writes'] in after['reads'], 'Candidate cannot read retained state.')
        require(after['writes'] in before['reads'], 'Accepted fallback cannot read candidate state.')


def retained(installed):
    path = Path(installed['state_directory'])/'state-contract.json'
    if not path.exists():
        require(not path.is_symlink(), 'Retained state inventory is unsafe.')
        return None
    info = path.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            'Retained state inventory is not protected.')
    return validate(json.loads(read(path, 32768), object_pairs_hook=unique))


def admission(installed, candidate):
    current = installed['image_contract']
    compatible(current, candidate)
    previous = retained(installed)
    if previous is not None:
        require(previous['machine_id'] == current['machine_id'], 'Retained state target differs.')
        for name in previous['state'].keys() & candidate['state'].keys():
            require(previous['state'][name]['writes'] in candidate['state'][name]['reads'],
                    'Candidate cannot read state retained by a disabled component.')


def remember(installed):
    current = validate(installed['image_contract'])
    previous = retained(installed)
    value = {**current, 'state': {**(previous['state'] if previous else {}), **current['state']}}
    validate(value)
    directory = Path(installed['state_directory'])
    require(directory.resolve() == directory and directory.stat().st_uid == 0 and
            stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Retained state directory is unsafe.')
    descriptor, temporary = tempfile.mkstemp(prefix='.state-contract-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory/'state-contract.json')
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)
