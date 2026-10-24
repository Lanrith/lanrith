"""Stage only credential-bearing FreeRADIUS fragments from compiled JSON."""

import argparse
import grp
import ipaddress as ip
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .policy_runtime import decode, exact, read


MANIFEST = Path('/usr/share/lanrith/radius.json')
RUNTIME = Path('/run/lanrith-radius')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
SECRET = re.compile(r'[A-Za-z0-9+/_=-]{32,256}\Z', re.ASCII)


class RadiusRuntimeError(ValueError):
    """The compiled RADIUS boundary or a protected credential differs."""


def load(path=MANIFEST):
    value = exact(decode(read(path, 256*1024), 256*1024), {
        'schema_version', 'listeners', 'authentication_port', 'accounting_port',
        'admission_vlan', 'clients', 'proxy', 'fallback_clients'}, 'RADIUS runtime')
    if (value['schema_version'] != 1 or value['authentication_port'] != 1812 or
            value['accounting_port'] != 1813 or type(value['admission_vlan']) is not int or
            not 1 <= value['admission_vlan'] <= 4094 or not isinstance(value['listeners'], list) or
            not 1 <= len(value['listeners']) <= 3 or not isinstance(value['clients'], list) or
            not 1 <= len(value['clients']) <= 64 or not isinstance(value['fallback_clients'], list)):
        raise RadiusRuntimeError('RADIUS runtime structure differs.')
    try:
        listeners = [ip.ip_address(item) for item in value['listeners']]
    except (TypeError, ValueError) as error:
        raise RadiusRuntimeError('RADIUS listener differs.') from error
    if value['listeners'] != list(dict.fromkeys(map(str, listeners))):
        raise RadiusRuntimeError('RADIUS listener inventory differs.')
    names = set()
    references = set()
    for client in value['clients']:
        required = {'name', 'address', 'kind', 'credential_name'}
        optional = {'port'}
        if (not isinstance(client, dict) or not required <= set(client) or
                not set(client) <= required | optional):
            raise RadiusRuntimeError('RADIUS client structure differs.')
        try:
            scope = ip.ip_network(client['address'])
        except (TypeError, ValueError) as error:
            raise RadiusRuntimeError('RADIUS client address differs.') from error
        if (not NAME.fullmatch(client['name']) or client['name'] in names or
                str(scope) != client['address'] or client['kind'] not in ('wired_mab', 'wireless_mac') or
                not NAME.fullmatch(client['credential_name']) or
                ('port' in client and (type(client['port']) is not int or not 1 <= client['port'] <= 65535))):
            raise RadiusRuntimeError('RADIUS client value differs.')
        names.add(client['name'])
        references.add(client['credential_name'])
    proxy = exact(value['proxy'], {'address', 'port', 'source', 'credential_name'}, 'RADIUS proxy')
    try:
        target, source = ip.ip_address(proxy['address']), ip.ip_address(proxy['source'])
    except (TypeError, ValueError) as error:
        raise RadiusRuntimeError('RADIUS proxy address differs.') from error
    if (proxy['port'] != 1812 or target.version != source.version or str(source) not in value['listeners'] or
            not NAME.fullmatch(proxy['credential_name'])):
        raise RadiusRuntimeError('RADIUS proxy value differs.')
    references.add(proxy['credential_name'])
    if (value['fallback_clients'] != sorted(set(value['fallback_clients'])) or
            any(name not in names for name in value['fallback_clients'])):
        raise RadiusRuntimeError('RADIUS fallback inventory differs.')
    by_name = {client['name']: client for client in value['clients']}
    if any(by_name[name]['kind'] != 'wired_mab' or 'port' not in by_name[name] or
           ip.ip_network(by_name[name]['address']).num_addresses != 1 for name in value['fallback_clients']):
        raise RadiusRuntimeError('RADIUS fallback scope differs.')
    return value, references


def credential(name):
    root = os.environ.get('CREDENTIALS_DIRECTORY')
    if not root or not NAME.fullmatch(name):
        raise RadiusRuntimeError('RADIUS credential transport differs.')
    raw = read(Path(root)/name, 4096, private=True)
    if raw.endswith(b'\n'):
        raw = raw[:-1]
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise RadiusRuntimeError('RADIUS credential encoding differs.') from error
    if text.startswith('{'):
        value = exact(decode(raw, 4096), {'shared_secret'}, 'RADIUS credential')
        text = value['shared_secret']
    if not isinstance(text, str) or not SECRET.fullmatch(text):
        raise RadiusRuntimeError('RADIUS credential value differs.')
    return text


def write(path, data, gid):
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(data.encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def clients_configuration(policy, secrets):
    lines = []
    for client in policy['clients']:
        lines += ['client '+client['name']+' {', '    ipaddr = '+client['address'],
                  '    proto = udp', '    secret = "'+secrets[client['credential_name']]+'"',
                  '    require_message_authenticator = yes',
                  '    shortname = '+client['name'], '}']
    return '\n'.join(lines)+'\n'


def proxy_configuration(policy, secrets):
    proxy = policy['proxy']
    address_field = 'ipv6addr' if ':' in proxy['address'] else 'ipaddr'
    lines = [
        'proxy server {', '    default_fallback = no', '}',
        'home_server lanrith_upstream {', '    type = auth',
        '    '+address_field+' = '+proxy['address'], '    port = 1812', '    proto = udp',
        '    secret = "'+secrets[proxy['credential_name']]+'"',
        '    src_ipaddr = '+proxy['source'], '    require_message_authenticator = yes', '}',
        'home_server lanrith_fallback {', '    virtual_server = lanrith_mab_fallback', '}',
        'home_server_pool lanrith_pool {', '    type = fail-over',
        '    home_server = lanrith_upstream',
    ]
    if policy['fallback_clients']:
        lines.append('    home_server = lanrith_fallback')
    lines += ['}', 'realm lanrith {', '    auth_pool = lanrith_pool', '    nostrip', '}',
              'realm NULL {', '    auth_pool = lanrith_pool', '}',
              'realm DEFAULT {', '    auth_pool = lanrith_pool', '}']
    return '\n'.join(lines)+'\n'


def stage(path=MANIFEST):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RadiusRuntimeError('RADIUS staging requires root.')
    policy, references = load(path)
    group = grp.getgrnam('freerad').gr_gid
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RadiusRuntimeError('RADIUS runtime directory differs.')
    os.chown(RUNTIME, 0, group)
    os.chmod(RUNTIME, 0o750)
    secrets = {name: credential(name) for name in references}
    write(RUNTIME/'clients.conf', clients_configuration(policy, secrets), group)
    write(RUNTIME/'proxy.conf', proxy_configuration(policy, secrets), group)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage',))
    args = parser.parse_args(arguments)
    try:
        if args.operation == 'stage':
            stage()
    except (OSError, KeyError, TypeError, ValueError) as error:
        print('radius-runtime: '+type(error).__name__+'; service remains closed', file=os.sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
