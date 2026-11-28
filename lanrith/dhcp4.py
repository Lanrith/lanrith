"""Build native DHCP geometry and its host-local enforcement declaration."""

import ipaddress as ip
import json

from . import bindings, intent, radius
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
                       'pools': [{'pool': pool, 'pool-id': int(ip.IPv4Address(pool.split('-')[0].strip())) -
                                  int(address.network.network_address)} for pool in network['dhcp4']['pools']],
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


def render(value):
    selected = scopes(value)
    directory = radius.directory_admission(value)
    metrics = bool(selected and value.get('observability', {}).get('metrics', {}).get('enabled'))
    dhcp = {
        'interfaces-config': {'interfaces': [s['interface'] for s in selected],
                              'service-sockets-require-all': True, 'service-sockets-max-retries': 3,
                              'service-sockets-retry-wait-time': 500},
        'multi-threading': {'enable-multi-threading': True, 'thread-pool-size': 2, 'packet-queue-size': 64},
        'lease-database': {'type': 'memfile', 'persist': True, 'name': '/var/lib/kea/kea-leases4.csv'},
        'valid-lifetime': 3600, 'subnet4': selected}
    unit = 'etc/systemd/system/kea-dhcp4-server.service.d/'
    listeners = {}
    for scope in selected:
        gateway = next(opt['data'] for opt in scope['option-data'] if opt['name'] == 'routers')
        listeners[scope['interface']] = [gateway, ip.IPv4Network(scope['subnet']).prefixlen]
    files = {'usr/share/lanrith/kea-listeners.json': json.dumps(listeners, sort_keys=True)+'\n',
             unit+'40-lanrith-listeners.conf': (
        '[Unit]\nStartLimitIntervalSec=120\nStartLimitBurst=4\n'
        '[Service]\nRestart=on-failure\nRestartSec=3s\nTimeoutStartSec=20s\n'
        'ExecStartPre=/usr/lib/lanrith/wait-for-kea-interfaces\n'
        'ExecStartPost=/usr/lib/lanrith/verify-kea-sockets --wait $MAINPID\n')}
    service = ('[Service]\nUser=_kea\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'
               'RestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
               'PrivateDevices=yes\nRestrictNamespaces=yes\nUMask=0077\nMemoryMax=96M\nTasksMax=4\n'
               'InaccessiblePaths=-/var/lib/kea -/var/log/kea\nReadOnlyPaths=/run/kea\n')
    executable = '/usr/bin/python3 -I /usr/lib/lanrith/lanrith/kea_observer.py'
    if directory or metrics:
        dhcp['hooks-libraries'] = [{'library': '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so'}]
        dhcp['control-socket'] = {'socket-type': 'unix', 'socket-name': '/run/kea/kea4-ctrl-socket'}
        files[unit+'60-lanrith-control.conf'] = (
            '[Service]\nExecStartPost=/usr/bin/python3 /usr/lib/lanrith/lanrith/kea_runtime.py $MAINPID\n')
    if directory:
        admission = value['networks'][value['identity']['radius']['admission']['network']]
        scope = next(s for s in selected if s['id'] == admission['dhcp4']['id'])
        files['usr/lib/sysusers.d/80-lanrith-kea.conf'] = 'g lanrith-kea-lease-readers -\n'
        files['usr/lib/systemd/system/lanrith-kea-leases.service'] = (
            '[Unit]\nDescription=Scoped DHCP lease lookups for directory admission\n'
            'After=kea-dhcp4-server.service\nPartOf=kea-dhcp4-server.service\n'
            + service + 'Type=notify\nGroup=lanrith-kea-lease-readers\nRuntimeDirectory=lanrith-kea-leases\n'
            'RuntimeDirectoryMode=0750\nRestart=on-failure\nRestartSec=2s\n'
            f'ExecStart={executable} leases {scope["id"]} {scope["subnet"]}\n')
        files[unit+'65-lanrith-lease-reader.conf'] = '[Unit]\nWants=lanrith-kea-leases.service\n'
        files['etc/systemd/system/lanrith-policy-bindings.service.d/65-lanrith-kea.conf'] = (
            '[Unit]\nWants=lanrith-kea-leases.service\nAfter=lanrith-kea-leases.service\n'
            '[Service]\nSupplementaryGroups=lanrith-kea-lease-readers\nInaccessiblePaths=-/run/kea\n')
    if metrics:
        files['usr/lib/systemd/system/lanrith-kea-statistics.socket'] = (
            '[Unit]\nDescription=Local DHCP capacity statistics\n'
            '[Socket]\nListenStream=/run/lanrith-kea-statistics.sock\nSocketMode=0600\nAccept=yes\n'
            'MaxConnections=4\nRemoveOnStop=yes\n')
        files['usr/lib/systemd/system/lanrith-kea-statistics@.service'] = (
            '[Unit]\nDescription=Read DHCP capacity statistics\n' + service +
            'StandardInput=socket\nStandardOutput=socket\nStandardError=journal\n'
            f'ExecStart={executable} statistics\nRuntimeMaxSec=4s\n')
        files[unit+'65-lanrith-statistics.conf'] = '[Unit]\nWants=lanrith-kea-statistics.socket\n'
    files['etc/kea/kea-dhcp4.conf'] = json.dumps({'Dhcp4': dhcp}, indent=2)+'\n'
    return files
