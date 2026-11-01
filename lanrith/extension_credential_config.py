"""Generate fixed namespace services and LoadCredential bindings at build time."""

import hashlib
import re

from . import extension_credential_values as values
from .release import canonical, require


def render(extension, selected, operator, *, core_required):
    values.validate_catalog(extension, selected)
    require(type(core_required) is bool, 'Extension credential readiness role differs.')
    require(isinstance(operator, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', operator),
            'Extension credential operator identity differs.')
    if not selected['credentials']:
        return {}
    stem = 'lanrith-extension-credential-'+extension
    control = values.control_path(extension)
    secrets = '/var/lib/lanrith/extension-credentials/'+extension
    command = '/usr/bin/lanrith-extension-credentials '+extension+' '
    # The common directories and exact namespace directories are created by
    # tmpfiles. Neither request executor needs a broad writable /var subtree.
    writable = 'ReadWritePaths='+control+' '+secrets+'\n'
    hardening = ('UMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nPrivateNetwork=yes\n'
        'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
        'RestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\nRestrictRealtime=yes\n'
        'RestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n'
        'SystemCallArchitectures=native\nTasksMax=16\nMemoryMax=128M\nMemorySwapMax=0\n'
        'LimitNOFILE=128\nLimitCORE=0\n')
    after = '' if core_required else ('Requires=boot-complete.target lanrith-observation.service\n'
                                      'After=boot-complete.target lanrith-observation.service\n')
    result = {'usr/share/lanrith/extension-credentials/'+extension+'.json': canonical(selected).decode(),
        'usr/lib/tmpfiles.d/80-'+stem+'.conf': ''.join('d '+path+' 0700 root root -\n' for path in (
            '/var/lib/lanrith/extension-credential-provisioning', '/var/lib/lanrith/extension-credentials',
            control, secrets)),
        'usr/lib/systemd/system/'+stem+'-setup.service': (
            '[Unit]\nDescription=Prepare admitted extension credential state\nDefaultDependencies=no\n'
            'Requires=local-fs.target systemd-tmpfiles-setup.service\n'
            'After=local-fs.target systemd-tmpfiles-setup.service\n'+after+
            'Before=shutdown.target\nConflicts=shutdown.target\n'
            '\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart='+command+'setup\nTimeoutStartSec=610s\n'+writable+hardening),
        'usr/lib/systemd/system/'+stem+'-ready.service': (
            '[Unit]\nDescription=Wait for admitted extension credentials\nDefaultDependencies=no\n'
            'Requires='+stem+'-setup.service\nAfter='+stem+'-setup.service\n'
            'Before=shutdown.target\nConflicts=shutdown.target\n'
            '\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart='+command+'gate\nTimeoutStartSec=610s\n'+writable+hardening),
        'usr/lib/systemd/system/'+stem+'.socket': (
            '[Unit]\nDescription=Operator extension credential provisioning socket\n'
            'Requires=systemd-tmpfiles-setup.service\nAfter=systemd-tmpfiles-setup.service\n'
            '\n[Socket]\nListenStream=/run/lanrith-extension-credentials.'+extension+'.sock\n'
            'SocketUser='+operator+'\nSocketMode=0600\nAccept=yes\nMaxConnections=4\nBacklog=4\n'
            'RemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n'),
        'usr/lib/systemd/system/'+stem+'@.service': (
            '[Unit]\nDescription=Bounded operator extension credential provisioning\n'
            'CollectMode=inactive-or-failed\n'
            '\n[Service]\nType=exec\nExecStart='+command+'serve\n'
            'StandardInput=socket\nStandardOutput=journal\nStandardError=journal\n'
            'RuntimeMaxSec=300s\nTimeoutStopSec=15s\nKillMode=control-group\n'+writable+hardening)}
    for unit in selected['units']:
        credentials = ''.join('LoadCredential='+item['reference']+':'+item['path']+'\n'
            for item in selected['credentials'] if unit in item['parameters']['consumers'])
        result['etc/systemd/system/'+unit+'.d/50-lanrith-extension-credentials.conf'] = (
            '[Unit]\nRequires='+stem+'-ready.service\nAfter='+stem+'-ready.service\n'
            '\n[Service]\n'+credentials)
    return result


def install(declarations, destination, operator):
    index = {}
    for extension, selected, required in declarations:
        if not selected['credentials']:
            continue
        require(extension not in index and len(index) < 64, 'Extension credential namespace inventory differs.')
        for name, text in render(extension, selected, operator, core_required=required).items():
            target = destination/name
            require(not target.exists() and not target.is_symlink(),
                    'Extension file conflicts with generated credential authority.')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            target.chmod(0o644)
        index[extension] = {'sha256': hashlib.sha256(canonical(selected)).hexdigest(), 'core_required': required}
    return index
