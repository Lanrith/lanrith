"""Bounded native credential grammars; no paths, transport or persistence."""

import base64
import binascii
import json
from pathlib import PurePosixPath
import re

from .release import require, unique


FORMAT_UNITS = {
    'tsig-base64': {'named.service'},
    'bgp-token': {'frr.service', 'lanrith-routing-credentials.service'},
    'radius-secret': {'freeradius.service'},
    'directory-password': {'lanrith-policy-bootstrap.service', 'lanrith-policy-bindings.service',
                           'lanrith-policy-helper.service', 'lanrith-policy-reader.service'},
    'log-password': {'alloy.service'}, 'snmp-user': {'snmpd.service'},
}
FORMATS = set(FORMAT_UNITS)
UNITS = set().union(*FORMAT_UNITS.values())


def validate_catalog(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'credentials', 'units'} and
            type(value['schema']) is int and value['schema'] == 1 and
            isinstance(value['credentials'], list) and len(value['credentials']) <= 256 and
            isinstance(value['units'], list), 'Credential catalog differs.')
    names, paths, units = [], [], set()
    for item in value['credentials']:
        require(isinstance(item, dict) and set(item) == {'reference', 'path', 'format', 'parameters'} and
                isinstance(item['reference'], str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', item['reference']) and
                isinstance(item['format'], str) and item['format'] in FORMATS and
                isinstance(item['parameters'], dict) and isinstance(item['path'], str) and
                len(item['path']) <= 256 and re.fullmatch(r'/[A-Za-z0-9_./-]+', item['path']),
                'Credential descriptor differs.')
        path = PurePosixPath(item['path'])
        require(str(path) == item['path'] and '..' not in path.parts and
                str(path).startswith(('/var/lib/', '/var/cache/')) and
                str(path.parent) not in ('/var/lib', '/var/cache', '/var/lib/lanrith') and
                not path.is_relative_to('/var/lib/lanrith/credential-provisioning') and
                not path.name.startswith(('.provisioning-', '.activation')) and path.name != '.lock',
                'Credential needs a dedicated directory outside provisioning control state.')
        if item['format'] in ('tsig-base64', 'bgp-token'):
            require(len(item['reference']) <= 48, 'Credential reference exceeds its native consumer limit.')
        if item['format'] == 'snmp-user':
            parameters = item['parameters']
            require(path.name == 'snmpd.conf' and set(parameters) == {'username', 'header'} and
                    isinstance(parameters['username'], str) and
                    re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,31}', parameters['username']) and
                    isinstance(parameters['header'], str) and re.fullmatch(r'#[ -~]{1,125}\n', parameters['header']),
                    'SNMP provisioning identity differs.')
        else:
            require(item['parameters'] == {}, 'Unexpected credential parameters.')
        names.append(item['reference'])
        paths.append(path)
        units.update(FORMAT_UNITS[item['format']])
    require(names == sorted(set(names)) and len(paths) == len(set(paths)) and
            sum(item['format'] == 'snmp-user' for item in value['credentials']) <= 1 and
            not any(a != b and a in b.parents for a in paths for b in paths) and
            value['units'] == sorted(units), 'Credential inventory is ambiguous or has unexpected service control.')
    return value


class CredentialValueError(ValueError):
    """A credential differs from its compiled native consumer grammar."""


def validate(item, raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 4097:
        raise CredentialValueError('Credential size or type differs.')
    body = raw.removesuffix(b'\n')
    kind = item['format']
    try:
        if kind == 'tsig-base64':
            decoded = base64.b64decode(body, validate=True)
            if len(raw) > 256 or not 16 <= len(decoded) <= 128 or base64.b64encode(decoded) != body:
                raise ValueError
        elif kind == 'bgp-token':
            if len(raw) > 81 or not re.fullmatch(rb'[a-zA-Z0-9_+=./:-]{1,80}', body):
                raise ValueError
        elif kind == 'radius-secret':
            if len(raw) > 4096:
                raise ValueError
            if body.startswith(b'{'):
                value = json.loads(body, object_pairs_hook=unique)
                if not isinstance(value, dict) or set(value) != {'shared_secret'} or not isinstance(value['shared_secret'], str):
                    raise ValueError
                body = value['shared_secret'].encode('ascii')
            if not re.fullmatch(rb'[A-Za-z0-9+/_=-]{32,256}', body):
                raise ValueError
        elif kind == 'directory-password':
            if not 1 <= len(body) <= 4096 or b'\x00' in body:
                raise ValueError
            body.decode('utf-8')
        elif kind == 'log-password':
            if not 1 <= len(body) <= 4096 or any(c in body for c in (b'\x00', b'\r', b'\n')):
                raise ValueError
        elif kind == 'snmp-user':
            # This pure native grammar is installed beside the package. Its
            # fields and header are selected by the image, never by the caller.
            from snmp_credentials import parse
            value = parse(raw, header=item['parameters']['header'])
            if value['username'] != item['parameters']['username']:
                raise ValueError
            body = raw
        else:
            raise ValueError
    except (ValueError, UnicodeError, TypeError, KeyError, binascii.Error, RecursionError):
        raise CredentialValueError('Credential does not match its native grammar.') from None
    return body
