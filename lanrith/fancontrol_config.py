"""Compile optional, hardware-independent thermal control into a small contract."""

import copy

from .fancontrol_runtime import validate
from .release import canonical, require


def active(value):
    return value['hardware'].get('fancontrol', {}).get('enabled', False)


def normalize(hardware):
    if 'fancontrol' not in hardware:
        return
    selected = hardware['fancontrol']
    require(isinstance(selected, dict) and type(selected.get('enabled')) is bool,
            'Fan control requires an explicit enabled boolean.')
    if not selected['enabled']:
        require(set(selected) == {'enabled'}, 'Disabled fan control cannot retain active settings.')
        return
    require('schema' not in selected, 'Fan control schema is selected by the compiler.')
    contract = validate({'schema': 1, **{k: v for k, v in selected.items() if k != 'enabled'}})
    for sensor in contract['sensors'].values():
        if 'interface' in sensor:
            interface = hardware['interfaces'].get(sensor['interface'])
            require(interface is not None and interface.get('owner', 'linux') == 'linux',
                    'NIC temperature requires a declared Linux-owned physical interface.')
    hardware['fancontrol'] = {'enabled': True, **{k: v for k, v in contract.items() if k != 'schema'}}


def manifest(value):
    selected = copy.deepcopy(value['hardware']['fancontrol'])
    del selected['enabled']
    for sensor in selected['sensors'].values():
        if 'interface' in sensor:
            sensor['interface'] = value['hardware']['interfaces'][sensor['interface']]['name']
    return validate({'schema': 1, **selected})


def render(value):
    if not active(value):
        return {}
    return {
        'usr/share/lanrith/fancontrol.json': canonical(manifest(value)).decode(),
        'usr/lib/sysusers.d/80-lanrith-fancontrol.conf':
            'u lanrith-fancontrol - "Fan control" /\n',
        'usr/lib/systemd/system/lanrith-fancontrol.service':
            '[Unit]\nDescription=Fan control from configured CPU and NIC temperatures\n'
            'After=systemd-udev-trigger.service systemd-sysusers.service systemd-modules-load.service\n'
            'Before=boot-complete.target\nConflicts=fancontrol.service\n'
            'StartLimitIntervalSec=60\nStartLimitBurst=5\n'
            '\n[Service]\nType=notify\nNotifyAccess=main\n'
            'ExecStartPre=/usr/bin/udevadm settle --timeout=15\n'
            'ExecStart=/usr/lib/lanrith/fancontrol-runtime run\n'
            'ExecStopPost=/usr/lib/lanrith/fancontrol-runtime failsafe\n'
            'Restart=on-failure\nRestartSec=5s\nWatchdogSec=30s\n'
            'TimeoutStartSec=60s\nTimeoutStopSec=10s\n'
            # The small bootstrap opens only selected PWM descriptors, then
            # irreversibly becomes the dedicated UID with no capabilities.
            'CapabilityBoundingSet=CAP_SETUID CAP_SETGID\nNoNewPrivileges=yes\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
            'ProtectKernelTunables=yes\nReadWritePaths=/sys/devices\n'
            'ProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            'ProtectClock=yes\nProtectProc=invisible\nProcSubset=pid\n'
            'RestrictAddressFamilies=AF_UNIX\nIPAddressDeny=any\n'
            'RestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\n'
            'LockPersonality=yes\nMemoryDenyWriteExecute=yes\n'
            'SystemCallArchitectures=native\nSystemCallFilter=@system-service\n'
            'SystemCallFilter=~@mount @reboot @swap @raw-io @module @debug\n'
            'UMask=0077\nMemoryMax=64M\nMemorySwapMax=0\nTasksMax=8\nLimitNOFILE=512\n',
    }
