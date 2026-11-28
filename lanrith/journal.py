"""Compile the boot journal's local storage and socket policy."""

import re

from . import intent
from .release import require


FLUSH = 'systemd-journal-flush.service'
MIB = 1024 * 1024


def settings(value):
    return value.get('observability', {}).get('journal', {})


def validate(policy, state_mib):
    intent.fields(policy, {'system_keep_free_mib', 'system_max_use_mib', 'syslog_receiver_unit'})
    if 'system_keep_free_mib' in policy:
        reserve = policy['system_keep_free_mib']
        require(type(reserve) is int and 0 < reserve < state_mib,
                'Journal reserve must be positive and smaller than the state partition.')
    if 'system_max_use_mib' in policy:
        maximum = policy['system_max_use_mib']
        # The fixed 64 MiB maximum file size raises any smaller cap to 128 MiB.
        require(type(maximum) is int and 128 <= maximum <= state_mib,
                'Journal maximum must be at least 128 MiB and fit the state partition.')
    if 'syslog_receiver_unit' in policy:
        unit = policy['syslog_receiver_unit']
        require(isinstance(unit, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\.service', unit)
                and unit != FLUSH and unit != 'systemd-journald.service',
                'Declare a concrete local syslog receiver service.')


def render(value):
    policy = settings(value)
    maximum = policy.get('system_max_use_mib', 1024)
    reserve = policy.get('system_keep_free_mib')
    receiver = policy.get('syslog_receiver_unit')
    # A drop-in with this filename in /etc supersedes Debian's syslog.conf in /usr.
    conf = '[Journal]\nForwardToSyslog=' + ('yes' if receiver else 'no') + f'\nSystemMaxUse={maximum}M\n'
    if reserve is not None:
        conf += f'SystemKeepFree={reserve}M\n'
    verify = f'/usr/lib/lanrith/verify-journal-flush {maximum*MIB}'
    if reserve is not None:
        verify += f' {reserve*MIB}'
    units = 'etc/systemd/system/'
    files = {'etc/systemd/journald.conf.d/syslog.conf': conf,
             units+FLUSH+'.d/60-lanrith-persistence.conf': (
                 '[Unit]\nRequires=var.mount\nAfter=var.mount\n\n[Service]\n'
                 'RuntimeDirectory=lanrith-journal-flush\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n'
                 'ExecStartPre=/usr/bin/logger --socket-errors=on --socket=/dev/log '
                 '--tag=lanrith-journal-flush -- lanrith-journal-flush-${INVOCATION_ID}\n'
                 'ExecStartPre=/usr/bin/journalctl --sync\n'
                 'ExecStartPre=/usr/lib/lanrith/verify-journal-flush remember\n'
                 'ExecStartPost=/usr/bin/journalctl --sync\n'
                 f'ExecStartPost={verify}\n')}
    if receiver:
        files[units+'syslog.socket.d/60-lanrith-receiver.conf'] = f'[Socket]\nService={receiver}\n'
        files[units+'systemd-journald.service.d/60-lanrith-syslog.conf'] = '[Unit]\nWants=syslog.socket\n'
        files[units+receiver+'.d/60-lanrith-syslog.conf'] = (
            '[Unit]\nRequires=syslog.socket\nAfter=syslog.socket\n\n[Service]\nSockets=syslog.socket\n')
    return files
