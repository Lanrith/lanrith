"""Explicit runtime references and account assertions, never a state overlay."""

from pathlib import PurePosixPath
import re
import ssl

from . import intent
from .release import ReleaseError, require


ACCOUNT = re.compile(r'[A-Za-z_][A-Za-z0-9_-]{0,31}\Z')
PATH = re.compile(r'/[A-Za-z0-9_./-]+\Z')
CERTIFICATE = re.compile(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n')


def credential_references(value):
    """Only the typed integration fields may declare a runtime secret."""
    groups = value.get('routing', {}).get('bgp', {}).get('peer_groups', {})
    writers = value['services']['dns'].get('authoritative', {}).get('writers', {})
    identity = value.get('identity', {})
    radius = identity.get('radius', {})
    entries = [*groups.values(), *writers.values(), *identity.get('directories', {}).values(),
               *radius.get('clients', {}).values(), radius.get('proxy', {}),
               value.get('observability', {}).get('logs', {}),
               value.get('observability', {}).get('snmp', {})]
    return {entry['credential'] for entry in entries if 'credential' in entry}


def path(value):
    require(isinstance(value, str) and len(value) <= 256 and PATH.fullmatch(value) and
            str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts,
            'Runtime path must be canonical and contain no substitutions.')
    return value


def credential_path(value, reference):
    snmp = value.get('observability', {}).get('snmp', {})
    default = '/var/lib/lanrith/snmp/snmpd.conf' if snmp.get('credential') == reference else '/var/lib/lanrith/credentials/'+reference
    return value.get('runtime', {}).get('credentials', {}).get(
        reference, default)


def credential_header(value, reference):
    return value.get('runtime', {}).get('credential_headers', {}).get(
        reference, '# Managed by the Lanrith owner runtime.\n')


def validate(value):
    settings = value.get('runtime', {})
    intent.fields(settings, {'credentials', 'credential_headers', 'service_identities', 'trust'})
    references = credential_references(value)
    credentials = intent.named(settings.get('credentials', {}), 256)
    require(credentials.keys() <= references, 'Runtime binding references an undeclared credential.')
    for source in credentials.values():
        path(source)
        require(source.startswith(('/var/lib/', '/var/cache/')) and not source.endswith('/'),
                'Runtime credential must reference protected persistent state.')
    require(len({credential_path(value, name) for name in references}) == len(references),
            'Distinct credentials cannot share a runtime file.')
    headers = intent.named(settings.get('credential_headers', {}), 1)
    snmp_reference = value.get('observability', {}).get('snmp', {}).get('credential')
    require(headers.keys() <= ({snmp_reference} if snmp_reference else set()),
            'Credential headers require a declared SNMP credential reference.')
    for header in headers.values():
        require(isinstance(header, str) and re.fullmatch(r'#[ -~]{1,125}\n', header),
                'Credential header must be one bounded ASCII comment line.')
    identities = settings.get('service_identities', {})
    require(isinstance(identities, dict) and len(identities) <= 256, 'Too many service identity assertions.')
    for name, assertion in identities.items():
        require(isinstance(name, str) and ACCOUNT.fullmatch(name), 'Invalid asserted account name.')
        intent.fields(assertion, {'uid', 'gid', 'home', 'shell'}, {'uid', 'gid'})
        for key in ('uid', 'gid'):
            require(type(assertion[key]) is int and 0 <= assertion[key] <= 2**31-2,
                    'Invalid asserted account number.')
        require(assertion['uid'] != 0 or name == 'root', 'Only root may assert UID zero.')
        for key in ('home', 'shell'):
            if key in assertion:
                path(assertion[key])
    trust = settings.get('trust', {})
    expected = {entry['ca_file'] for entry in value.get('identity', {}).get('directories', {}).values()}
    require(isinstance(trust, dict) and len(trust) <= 16 and trust.keys() <= expected,
            'Trust binding must reference a declared directory CA.')
    total = 0
    for name, content in trust.items():
        require(re.fullmatch(r'trust/[A-Za-z0-9_.-]+\.pem', name) and
                isinstance(content, str) and 0 < len(content) <= 65536 and content.isascii(),
                'Invalid public certificate binding.')
        blocks = CERTIFICATE.findall(content)
        require(1 <= len(blocks) <= 16 and ''.join(blocks) == content,
                'Trust accepts only PEM certificates, without keys or other data.')
        total += len(content)
        require(total <= 262144, 'Public trust material exceeds its size bound.')
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=content)
        except (ssl.SSLError, ValueError):
            raise ReleaseError('Public trust material is not a valid X.509 certificate chain.') from None


def render(value):
    return {'usr/share/lanrith/'+name: content
            for name, content in value.get('runtime', {}).get('trust', {}).items()}


def verify_accounts(value, accounts, overlay):
    """Assert the effective admitted registry without remapping IDs or state."""
    assertions = value.get('runtime', {}).get('service_identities', {})
    if not assertions:
        return
    require(set(accounts) == {'passwd', 'group'}, 'Admitted account registry is missing.')
    registries = {}
    for kind, columns in (('passwd', 7), ('group', 4)):
        target = overlay/'etc'/kind
        require(not target.is_symlink(), 'Account assertion cannot follow an overlay symlink.')
        content = target.read_bytes() if target.is_file() else accounts[kind]
        require(0 < len(content) <= 1024*1024 and b'\x00' not in content,
                'Admitted account registry exceeds its boundary.')
        try:
            rows = [line.split(':') for line in content.decode('ascii').splitlines()]
        except UnicodeError:
            raise ReleaseError('Admitted account registry is not ASCII.') from None
        require(rows and all(len(row) == columns and ACCOUNT.fullmatch(row[0]) and
                            row[2].isascii() and row[2].isdecimal() and len(row[2]) <= 10 and
                            (kind != 'passwd' or row[3].isascii() and row[3].isdecimal() and
                             len(row[3]) <= 10) for row in rows),
                'Malformed admitted account registry.')
        require(len({row[0] for row in rows}) == len(rows), 'Ambiguous admitted account registry.')
        registries[kind] = rows
    for name, assertion in assertions.items():
        matches = [row for row in registries['passwd'] if row[0] == name]
        require(len(matches) == 1, 'An asserted service account is missing from the admitted image.')
        row = matches[0]
        actual = {'uid': int(row[2]), 'gid': int(row[3]), 'home': row[5], 'shell': row[6]}
        require(all(actual[key] == expected for key, expected in assertion.items()) and
                sum(int(other[2]) == actual['uid'] for other in registries['passwd']) == 1 and
                sum(int(group[2]) == actual['gid'] for group in registries['group']) == 1,
                'Admitted service identity differs from retained ownership; explicit migration is required.')
