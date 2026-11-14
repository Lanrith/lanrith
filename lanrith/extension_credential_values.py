"""Namespaced extension credential bindings and bounded JSON objects.

Application-specific schemas belong to the admitted consumer. This module
defines custody and resource bounds, without application names or secret values.
"""

import base64
import json
import math
import re

from .credential_values import CredentialValueError
from .release import canonical, require, unique


VALUE_LIMIT = 64*1024
ENCODED_LIMIT = 4*((VALUE_LIMIT+2)//3)
SLOT_LIMIT = 16
UNIT_LIMIT = 64
NODE_LIMIT = 4096
DEPTH_LIMIT = 16


def namespace(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value),
            'Extension credential namespace differs.')
    return value


def reference(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', value),
            'Extension credential reference differs.')
    return value


def control_path(extension):
    return '/var/lib/lanrith/extension-credential-provisioning/'+namespace(extension)


def secret_path(extension, name):
    return '/var/lib/lanrith/extension-credentials/'+namespace(extension)+'/'+reference(name)


def consumers(value):
    require(isinstance(value, list) and 1 <= len(value) <= UNIT_LIMIT and
            all(isinstance(unit, str) and re.fullmatch(
                r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}\.service', unit) and
                '@.' not in unit and not unit.startswith(('lanrith-', 'systemd-')) for unit in value) and
            len(value) == len(set(value)), 'Extension credential consumers differ.')
    return sorted(value)


def descriptor(extension, item):
    namespace(extension)
    require(isinstance(item, dict) and set(item) == {'reference', 'path', 'format', 'parameters'} and
            item.get('format') == 'json' and isinstance(item.get('parameters'), dict) and
            set(item['parameters']) == {'consumers'}, 'Extension credential descriptor differs.')
    require(item['path'] == secret_path(extension, item['reference']) and
            item['parameters']['consumers'] == consumers(item['parameters']['consumers']),
            'Extension credential custody differs.')
    return item


def validate_catalog(extension, value):
    namespace(extension)
    require(isinstance(value, dict) and set(value) == {'schema', 'credentials', 'units'} and
            type(value['schema']) is int and value['schema'] == 1 and
            isinstance(value['credentials'], list) and len(value['credentials']) <= SLOT_LIMIT and
            isinstance(value['units'], list), 'Extension credential catalog differs.')
    names, units = [], set()
    for item in value['credentials']:
        descriptor(extension, item)
        names.append(item['reference'])
        units.update(item['parameters']['consumers'])
    require(names == sorted(set(names)) and len(units) <= UNIT_LIMIT and value['units'] == sorted(units),
            'Extension credential inventory is ambiguous.')
    return value


def declarations(extension, value, files):
    """Compile declarations only for literal service files owned by this overlay."""
    namespace(extension)
    require(isinstance(value, list) and len(value) <= SLOT_LIMIT,
            'Extension credential declaration count differs.')
    items, units = [], set()
    for row in value:
        require(isinstance(row, dict) and set(row) == {'name', 'format', 'consumers'} and
                row['format'] == 'json', 'Extension credential declaration differs.')
        name, selected = reference(row['name']), consumers(row['consumers'])
        require(all('usr/lib/systemd/system/'+unit in files for unit in selected),
                'Extension credential consumer is not an owned service file.')
        items.append({'reference': name, 'path': secret_path(extension, name), 'format': 'json',
                      'parameters': {'consumers': selected}})
        units.update(selected)
    return validate_catalog(extension, {'schema': 1, 'credentials': sorted(items, key=lambda row: row['reference']),
                                        'units': sorted(units)})


def validate(item, raw):
    """Return semantic JSON for idempotence; preserve original bytes on disk."""
    try:
        if item['format'] != 'json' or not isinstance(raw, bytes) or not 1 <= len(raw) <= VALUE_LIMIT:
            raise ValueError
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise ValueError
        pending, count = [(value, 0)], 0
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > NODE_LIMIT or depth > DEPTH_LIMIT:
                raise ValueError
            if isinstance(node, dict):
                pending.extend((part, depth+1) for pair in node.items() for part in pair)
            elif isinstance(node, list):
                pending.extend((part, depth+1) for part in node)
            elif isinstance(node, str):
                node.encode('utf-8')  # reject unpaired surrogate escapes
            elif type(node) is float and not math.isfinite(node):
                raise ValueError
        return canonical(value)
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError, OverflowError):
        raise CredentialValueError('Extension credential does not match its JSON bounds.') from None


def decoded(text):
    require(isinstance(text, str) and 1 <= len(text) <= ENCODED_LIMIT and text.isascii(),
            'Encoded extension credential differs.')
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise ValueError('Encoded extension credential differs.') from None
    require(1 <= len(raw) <= VALUE_LIMIT and base64.b64encode(raw).decode('ascii') == text,
            'Encoded extension credential is not canonical or exceeds its bound.')
    return raw
