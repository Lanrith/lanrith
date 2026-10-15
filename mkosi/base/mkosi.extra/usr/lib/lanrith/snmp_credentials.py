#!/usr/bin/env python3
"""SNMP credential grammar shared by Ansible and image activation."""

import ipaddress
import re


class SNMPError(ValueError):
    def __init__(self, message, code=65):
        super().__init__(message)
        self.code = code


AUTH = {'SHA', 'SHA-256', 'SHA-384', 'SHA-512'}
PRIV = {'AES', 'AES-128', 'AES-192', 'AES-256'}
HEADER = '# Managed by the homelab Ansible router runtime role.\n'


def validate(value):
    if (not isinstance(value, dict)
            or set(value) != {'username', 'auth_protocol', 'priv_protocol', 'auth_password', 'priv_password'}
            or not isinstance(value['username'], str)
            or re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,31}', value['username']) is None
            or not isinstance(value['auth_protocol'], str) or value['auth_protocol'] not in AUTH
            or not isinstance(value['priv_protocol'], str) or value['priv_protocol'] not in PRIV):
        raise SNMPError('SNMP credential fields or algorithms are invalid.')
    for name in ('auth_password', 'priv_password'):
        password = value[name]
        # Net-SNMP's token parser consumes backslash escapes even inside
        # quotes. Bound the token and reject characters it could reinterpret.
        if (not isinstance(password, str) or re.fullmatch(r'[!-~]{16,255}', password) is None
                or any(character in password for character in '\"\'\\')):
            raise SNMPError('SNMP passphrases require 16–255 printable ASCII characters without quotes or backslashes.')
    return value


def configuration(value):
    value = validate(value)
    return (HEADER + f'createUser {value["username"]} {value["auth_protocol"]} '
            f'"{value["auth_password"]}" {value["priv_protocol"]} "{value["priv_password"]}"\n').encode('ascii')


def parse(raw):
    try:
        text = raw.decode('ascii')
    except (AttributeError, UnicodeError) as error:
        raise SNMPError('SNMP credential file is not supported ASCII configuration.') from error
    pattern = (re.escape(HEADER) + r'createUser ([A-Za-z][A-Za-z0-9_.-]{2,31}) ([A-Z0-9-]+) '
               r'"([^"\n]+)" ([A-Z0-9-]+) "([^"\n]+)"\n')
    match = re.fullmatch(pattern, text)
    if match is None:
        raise SNMPError('SNMP credential file does not have the managed format.')
    return validate(dict(zip(('username', 'auth_protocol', 'auth_password', 'priv_protocol', 'priv_password'), match.groups())))


def listener_address(value):
    try:
        if not isinstance(value, str) or '%' in value:
            raise ValueError
        address = ipaddress.IPv6Address(value)
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError
        return str(address)
    except ValueError as error:
        raise SNMPError('SNMP listener must be a concrete unscoped IPv6 address.') from error


def listeners(ipv6, ipv4, address):
    """Require exactly the intended local UDP/161 endpoint and no IPv4 one."""
    wanted = f'[{listener_address(address)}]:161'
    endpoints = []
    for family, raw in ((6, ipv6), (4, ipv4)):
        try:
            text = raw.decode('ascii')
        except (AttributeError, UnicodeError) as error:
            raise SNMPError('SNMP socket inventory is malformed.', 69) from error
        for line in text.splitlines():
            fields = line.split()
            if (len(fields) != 5 or fields[0] != 'UNCONN'
                    or not all(item.isascii() and item.isdigit() for item in fields[1:3])):
                raise SNMPError('SNMP socket inventory is malformed.', 69)
            endpoint = fields[3]
            if not endpoint.endswith(':161'):
                raise SNMPError('SNMP socket filter returned an unexpected endpoint.', 69)
            if family == 4:
                raise SNMPError('SNMP has a forbidden IPv4 listener.', 69)
            match = re.fullmatch(r'\[([^\]]+)\]:161', endpoint)
            if match is None:
                raise SNMPError('SNMP IPv6 listener is wildcard or malformed.', 69)
            endpoints.append(f'[{listener_address(match[1])}]:161')
    if endpoints != [wanted]:
        raise SNMPError('SNMP is not bound exclusively to the required IPv6 endpoint.', 69)


def audit(path):
    """Read a legacy or current credential file; never repair it during audit."""
    import os
    from pathlib import Path
    import stat
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise SNMPError('SNMP credential path contains a symlink.')
    parent = path.parent.stat()
    if parent.st_uid != 0 or not (stat.S_IMODE(parent.st_mode) == 0o750
                                 or (parent.st_gid == 0 and stat.S_IMODE(parent.st_mode) == 0o700)):
        raise SNMPError('SNMP credential directory has unsafe ownership or mode.')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4097):
            raise SNMPError('SNMP credential file has unsafe metadata.')
        parse(stream.read(4098))


if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description='Read-only SNMP credential validation.')
    parser.add_argument('--file', required=True)
    args = parser.parse_args()
    try:
        audit(args.file)
    except (OSError, ValueError, KeyError):
        print('SNMP credential audit failed; encoding, grammar, or metadata is invalid.', file=sys.stderr)
        raise SystemExit(65)
