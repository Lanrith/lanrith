"""Project active credential consumers into an image-owned provisioning catalog."""

from pathlib import PurePosixPath

from . import bindings
from .release import canonical, require
from .credential_values import FORMAT_UNITS, FORMATS, UNITS, validate_catalog


def catalog(value):
    credentials, units = {}, set()

    def add(reference, kind, parameters=None):
        item = {'reference': reference, 'path': bindings.credential_path(value, reference),
                'format': kind, 'parameters': parameters or {}}
        require(reference not in credentials or credentials[reference] == item,
                'One credential reference cannot have different provisioning grammars.')
        credentials[reference] = item
        units.update(FORMAT_UNITS[kind])

    dns = value['services']['dns'].get('authoritative', {})
    if dns.get('enabled', False):
        for writer in dns.get('writers', {}).values():
            add(writer['credential'], 'tsig-base64')
    bgp = value.get('routing', {}).get('bgp', {})
    if bgp.get('enabled', False):
        for group in bgp['peer_groups'].values():
            if 'credential' in group:
                add(group['credential'], 'bgp-token')
    identity = value.get('identity', {})
    policy = identity.get('policy', {})
    if policy.get('enabled', False):
        directory = identity['directories'][policy['directory']]
        add(directory['credential'], 'directory-password')
    radius = identity.get('radius', {})
    if radius.get('enabled', False):
        for consumer in [*radius['clients'].values(), radius['proxy']]:
            add(consumer['credential'], 'radius-secret')
    logs = value.get('observability', {}).get('logs', {})
    if logs.get('enabled', False):
        add(logs['credential'], 'log-password')
    snmp = value.get('observability', {}).get('snmp', {})
    if snmp.get('enabled', False):
        add(snmp['credential'], 'snmp-user', {
            'username': snmp['username'], 'header': bindings.credential_header(value, snmp['credential'])})
    return validate_catalog({'schema': 1, 'credentials': [credentials[name] for name in sorted(credentials)],
                             'units': sorted(units)})


def encoded(value):
    """No values, source YAML, inactive consumers or controller inputs are emitted."""
    return canonical(catalog(value))


def render(value):
    result = catalog(value)
    if not result['credentials']:
        return {}
    control = '/var/lib/lanrith/credential-provisioning'
    directories = sorted({str(PurePosixPath(i['path']).parent) for i in result['credentials']})
    hardening = ('UMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nPrivateNetwork=yes\n'
        'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
        'RestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\nRestrictRealtime=yes\n'
        'RestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n'
        'SystemCallArchitectures=native\nTasksMax=16\nMemoryMax=128M\nMemorySwapMax=0\n'
        'LimitNOFILE=128\nLimitCORE=0\n')
    files = {'usr/share/lanrith/credentials.json': canonical(result).decode(),
        'usr/lib/systemd/system/lanrith-credential-setup.service': (
            '[Unit]\nDescription=Prepare protected credential state\nDefaultDependencies=no\n'
            'Requires=local-fs.target\nAfter=local-fs.target\n'
            'Before=lanrith-credentials.socket lanrith-credential-ready.service shutdown.target\n'
            'Conflicts=shutdown.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart=/usr/bin/lanrith-credentials setup\nTimeoutStartSec=60s\n'
            'ReadWritePaths=/var/lib /var/cache\n'+hardening),
        'usr/lib/systemd/system/lanrith-credential-ready.service': (
            '[Unit]\nDescription=Wait for a complete credential set\nDefaultDependencies=no\n'
            'Requires=lanrith-credential-setup.service\nAfter=lanrith-credential-setup.service\n'
            'Before=shutdown.target\nConflicts=shutdown.target\n'
            '\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart=/usr/bin/lanrith-credentials gate\nTimeoutStartSec=610s\n'
            'ReadWritePaths='+control+'\n'+hardening),
        'usr/lib/systemd/system/lanrith-credentials.socket': (
            '[Unit]\nDescription=Operator credential provisioning socket\n'
            'Requires=lanrith-credential-setup.service\nAfter=lanrith-credential-setup.service\n'
            '\n[Socket]\nListenStream=/run/lanrith-credentials.sock\n'
            f'SocketUser={value["administration"]["username"]}\nSocketMode=0600\n'
            'Accept=yes\nMaxConnections=4\nBacklog=4\nRemoveOnStop=yes\n'
            '\n[Install]\nWantedBy=sockets.target\n'),
        'usr/lib/systemd/system/lanrith-credentials@.service': (
            '[Unit]\nDescription=Bounded operator credential provisioning\n'
            'Requires=lanrith-credential-setup.service\nAfter=lanrith-credential-setup.service\n'
            '\n[Service]\nType=exec\nExecStart=/usr/bin/lanrith-credentials serve\n'
            'StandardInput=socket\nStandardOutput=journal\nStandardError=journal\n'
            'RuntimeMaxSec=300s\nTimeoutStopSec=15s\nKillMode=control-group\n'
            'ReadWritePaths='+control+' '+' '.join(directories)+'\n'+hardening)}
    for unit in result['units']:
        files['etc/systemd/system/'+unit+'.d/50-lanrith-credentials.conf'] = (
            '[Unit]\nRequires=lanrith-credential-ready.service\nAfter=lanrith-credential-ready.service\n')
    return files
