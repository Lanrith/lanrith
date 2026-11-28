"""Read the LDAP options shared by the configuration compiler and policy service."""

import re
import unicodedata


ATTRIBUTE = re.compile(r'(?:[A-Za-z][A-Za-z0-9_-]*|[0-9]+(?:\.[0-9]+)+)\Z')
BASES = {'users_base_dn', 'groups_base_dn'}
CLASSES = {'user_object_class', 'group_object_class'}
FLAGS = {'active_value', 'inactive_value'}
ATTRIBUTES = {'user_id', 'group_id', 'user_rdn', 'group_rdn', 'device_mac',
              'group_name', 'device_active', 'group_member', 'group_policy'}
CHOICES = {'user_scope': ('one', 'subtree'), 'group_scope': ('one', 'subtree'),
           'user_id_encoding': ('text', 'hex'), 'group_id_encoding': ('text', 'hex')}


def reader_options(directory):
    options = {key: directory[key] for key in ('search_mode', 'mapping') if key in directory}
    if 'search_mode' in options and options['search_mode'] not in ('auto', 'unpaged', 'paged'):
        raise ValueError('LDAP search_mode must be auto, unpaged or paged.')
    if 'mapping' not in options:
        return options

    mapping = options['mapping']
    if not isinstance(mapping, dict):
        raise ValueError('LDAP mapping must be an object.')
    required = BASES | CLASSES | ATTRIBUTES | ({'disabled_bit'} if 'disabled_bit' in mapping else FLAGS)
    if set(mapping) - {'member_of', *CHOICES} != required:
        raise ValueError('LDAP mapping needs both search bases, object classes, identity, membership and activation fields.')
    for key, value in mapping.items():
        if key == 'disabled_bit':
            if type(value) is not int or not 1 <= value <= 1 << 31 or value & (value - 1):
                raise ValueError('LDAP disabled_bit must be a single bit in an unsigned 32-bit account flag.')
            continue
        if key in CHOICES:
            if value not in CHOICES[key]:
                raise ValueError('Invalid LDAP mapping choice for '+key+'.')
            continue
        limit = 1024 if key in BASES else (128 if key in FLAGS else 127)
        if (not isinstance(value, str) or not value or len(value.encode('utf-8', errors='surrogatepass')) > limit
                or any(unicodedata.category(char) in ('Cc', 'Cs') for char in value)):
            raise ValueError('Invalid LDAP mapping value for '+key+'.')
        if key in BASES:
            # The reader parses RFC 4514 DNs and compares their ancestry before searching.
            if '=' not in value:
                raise ValueError('LDAP search bases must be distinguished names.')
        elif key not in FLAGS:
            legacy_class = key in CLASSES and value.lower() in ('goauthentik.io/ldap/user', 'goauthentik.io/ldap/group')
            if not (ATTRIBUTE.fullmatch(value) or legacy_class) or key not in CLASSES and value.lower() == 'objectclass':
                raise ValueError('Invalid LDAP object class or attribute for '+key+'.')
    if 'disabled_bit' not in mapping and mapping['active_value'] == mapping['inactive_value']:
        raise ValueError('LDAP active and inactive account values must differ.')
    for kind, names in (('user', ('user_rdn', 'device_mac')), ('group', ('group_rdn', 'group_name'))):
        if mapping.get(kind+'_id_encoding') == 'hex' and any(
                mapping[kind+'_id'].lower() == mapping[name].lower() for name in names):
            raise ValueError('A binary LDAP ID cannot also identify a device MAC, name or RDN.')
    for ordinary, protected in ((('user_id', 'user_rdn', 'device_mac'), ('device_active', 'member_of')),
                                (('group_id', 'group_rdn', 'group_name'), ('group_member', 'group_policy', 'member_of'))):
        used = {mapping[key].lower() for key in ordinary}
        for key in protected:
            if key in mapping:
                attr = mapping[key].lower()
                if attr in used:
                    raise ValueError('LDAP membership, policy and activation fields require distinct attributes.')
                used.add(attr)
    if (mapping['users_base_dn'].casefold() == mapping['groups_base_dn'].casefold() and
            mapping['user_object_class'].lower() == mapping['group_object_class'].lower()):
        raise ValueError('LDAP users and groups in a shared search base require different object classes.')
    return options
