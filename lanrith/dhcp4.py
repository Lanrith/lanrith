"""Build native DHCP geometry and its host-local enforcement declaration."""

import ipaddress as ip

from . import bindings, intent
from .release import require


def scopes(value):
    """Use one subnet projection for Kea and build-time host enforcement."""
    if not value['services'].get('dhcp4', {}).get('enabled', False):
        return []
    result = []
    for network in value['networks'].values():
        if 'dhcp4' not in network:
            continue
        address = next(ip.ip_interface(a) for a in network['addresses'] if ':' not in a)
        result.append({'id': network['dhcp4']['id'], 'subnet': str(address.network),
                       'interface': network['name'],
                       'pools': [{'pool': pool} for pool in network['dhcp4']['pools']],
                       'reservations': [{('hw-address' if k == 'mac' else 'ip-address' if k == 'address' else k): v
                                         for k, v in entry.items()}
                                        for entry in network['dhcp4'].get('reservations', [])],
                       'option-data': [{'name': 'routers', 'data': str(address.ip)}] +
                                      ([{'name': 'domain-name-servers', 'data': intent.service_addresses(value, 'dns')[0]}]
                                       if network.get('dns') else []) +
                                      ([{'name': 'ntp-servers', 'data': intent.service_addresses(value, 'ntp')[0]}]
                                       if network.get('ntp') else []) +
                                      ([{'name': 'domain-name', 'data': value['services']['dns']['domain']}]
                                       if network.get('dns') and value['services']['dns'].get('domain') else [])})
    return result


def host_scopes(value, accounts):
    """Derive the dedicated UID from admitted account bytes, never owner knobs.

    This is a construction-only input to the paired compiler. It is not a
    runtime manifest or an account-registry reader on the deployed router.
    """
    selected = scopes(value)
    if not selected:
        return []
    require(isinstance(accounts, dict) and set(accounts) == {'passwd', 'group'},
            'Host DHCP requires the admitted image account registry.')
    rows = bindings.account_registry(accounts['passwd'], 'passwd')
    bindings.account_registry(accounts['group'], 'group')
    servers = [row for row in rows if row[0] == '_kea']
    require(len(servers) == 1, 'Host DHCP requires its dedicated image service account.')
    uid = int(servers[0][2])
    require(1 <= uid <= 2**31-2 and sum(int(row[2]) == uid for row in rows) == 1,
            'Host DHCP service UID must be nonroot and exclusive.')
    require(len(selected) <= 64, 'Host DHCP scope capacity exceeded.')
    result = []
    for scope in selected:
        gateway = next(option['data'] for option in scope['option-data'] if option['name'] == 'routers')
        result.append({'uid': uid, 'interface': scope['interface'],
                       'server_address': gateway, 'subnet': scope['subnet']})
    return sorted(result, key=lambda entry: entry['interface'])
