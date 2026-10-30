"""Reviewed native state-format declarations for the admitted platform.

These names are Lanrith contracts, not upstream version numbers. A package or
runtime change that changes persistent data must update writes/reads here and
pass an upgrade and rollback drill before release admission.
"""

FORMATS = {'schema': 1, 'consumers': {
    name: {'writes': version, 'reads': [version]}
    for name, version in {
        'platform': 'lanrith-platform-state-v1',
        'credentials': 'lanrith-runtime-credentials-v1',
        'dhcp4': 'lanrith-kea-memfile-v1',
        'dns': 'lanrith-bind-state-v1',
        'journal': 'lanrith-journal-state-v1',
        'ssh_identity': 'openssh-host-keys-v1',
        'luks': 'luks2-systemd-tokens-v1',
        'time': 'lanrith-chrony-state-v1',
        'telemetry': 'lanrith-alloy-state-v1',
    }.items()
}}
