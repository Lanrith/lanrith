"""Create only the signed translator's TUN and routes; never grant permission."""

import hashlib
import ipaddress as ip
import json
from pathlib import Path
import pwd
import subprocess
import sys

from .release import read, require


def run(*arguments, json_output=False):
    result = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=15)
    return json.loads(result.stdout) if json_output else result.stdout


def validate(manifest):
    require(isinstance(manifest, dict) and manifest.get('interface') in ('nat46', 'nat64', 'nat64-internal'),
            'Invalid translator manifest.')
    name = manifest['interface']
    component = 'nat46' if name == 'nat46' else 'nat64'
    expected_config = '/etc/tayga'+('' if name == 'nat64' else '-'+name)+'.conf'
    expected_state = '/var/lib/tayga'+('' if name == 'nat64' else '-'+name)
    if name == 'nat64-internal':
        expected_state += '/'+str(ip.ip_network(manifest['pool'])).replace('/', '-')
    require(manifest.get('component') == component and manifest.get('config') == expected_config and
            manifest.get('state_directory') == expected_state, 'Invalid translator paths.')
    require(hashlib.sha256(read(Path(manifest['config']), 1024*1024)).hexdigest() ==
            manifest.get('config_sha256'), 'Translator configuration differs from its signed manifest.')
    require(manifest['routes'] == [manifest['pool'], manifest['prefix']] and
            manifest['addresses'] == [manifest['ipv4']+'/32', manifest['ipv6']+'/128'] and
            ip.ip_network(manifest['pool']).version == 4 and ip.ip_network(manifest['prefix']).version == 6,
            'Translator routes differ from their manifest.')


def existing(manifest, uid):
    name = manifest.get('interface', 'nat46')
    links = run('ip', '-d', '-j', 'link', 'show', json_output=True)
    match = [link for link in links if link['ifname'] == name]
    if not match:
        return False
    link = match[0]
    info = link.get('linkinfo', {})
    require(info.get('info_kind') == 'tun' and info.get('info_data', {}).get('type') == 'tun' and
            info['info_data'].get('user') in (uid, 'lanrith-'+name) and
            link.get('ifalias') == 'lanrith-'+name+':'+manifest['config_sha256'],
            'Refusing an unowned or mismatched translation interface.')
    return True


def status(manifest):
    validate(manifest)
    name = manifest['interface']
    require(existing(manifest, pwd.getpwnam('lanrith-'+name).pw_uid), 'Required translator interface is absent.')
    rows = run('ip', '-j', 'address', 'show', 'dev', name, json_output=True)
    require(len(rows) == 1 and 'UP' in rows[0]['flags'], 'Required translator interface is down.')
    addresses = {entry['local']+'/'+str(entry['prefixlen']) for entry in rows[0].get('addr_info', [])
                 if entry['scope'] == 'global'}
    require(addresses == set(manifest['addresses']), 'Translator control addresses differ from their manifest.')
    require(not any(entry.get('tentative') or entry.get('dadfailed') for entry in rows[0].get('addr_info', [])),
            'Translator control address is not ready.')
    for prefix in manifest['routes']:
        rows = run('ip', '-'+str(ip.ip_network(prefix).version), '-j', 'route', 'show',
                   'exact', prefix, json_output=True)
        require(len(rows) == 1 and rows[0].get('dev') == name and
                'gateway' not in rows[0] and 'nexthops' not in rows[0],
                'Required translator route is absent or redirected.')
    require(Path('/proc/sys/net/ipv4/conf', name, 'accept_local').read_text().strip() == '1',
            'Translator control-error source handling is unavailable.')


def configure(manifest, operation):
    validate(manifest)
    name = manifest['interface']
    uid = pwd.getpwnam('lanrith-'+name).pw_uid
    present = existing(manifest, uid)
    # Validate every route before creating or changing any interface.
    for prefix in manifest['routes']:
        rows = run('ip', '-'+str(ip.ip_network(prefix).version), '-j', 'route', 'show',
                   'exact', prefix, json_output=True)
        require(all(row.get('dev') == name and 'gateway' not in row and 'nexthops' not in row
                    for row in rows), 'A translation route is owned by another attachment.')
    if operation == 'stop':
        if present:
            run('ip', 'link', 'delete', 'dev', name)
        return
    require(operation == 'start', 'Unknown translator operation.')
    created = False
    try:
        if not present:
            run('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun', 'user', str(uid))
            created = True
            run('ip', 'link', 'set', 'dev', name, 'alias', 'lanrith-'+name+':'+manifest['config_sha256'])
        # TAYGA originates correlated errors at its own control address, which is
        # also assigned to this TUN. Permit that kernel source check on this device
        # only; the generated source and tuple guards still constrain every packet.
        run('sysctl', '-qw', 'net.ipv4.conf.'+name+'.accept_local=1')
        # Do not flush state or unrelated routes on restart.
        for address in manifest['addresses']:
            version = ip.ip_interface(address).version
            run('ip', '-'+str(version), 'address', 'replace', address, 'dev', name,
                *(['nodad'] if version == 6 else []))
        run('ip', 'link', 'set', 'dev', name, 'up')
        for prefix in manifest['routes']:
            run('ip', '-'+str(ip.ip_network(prefix).version), 'route', 'replace', prefix, 'dev', name)
    except BaseException:
        if created:
            run('ip', 'link', 'delete', 'dev', name)
        raise


def main():
    require(len(sys.argv) in (2, 3) and sys.argv[1] in ('start', 'stop'), 'Expected start or stop.')
    name = sys.argv[2] if len(sys.argv) == 3 else 'nat46'
    require(name in ('nat46', 'nat64', 'nat64-internal'), 'Unknown translator.')
    configure(json.loads(read(Path('/usr/share/lanrith', name+'.json'), 1024*1024)), sys.argv[1])


if __name__ == '__main__':
    main()
