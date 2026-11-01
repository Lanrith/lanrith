"""Opt-in WAN packet observation using only the admitted image's alert rules."""

import ipaddress as ip

import yaml


def active(value):
    return value.get('observability', {}).get('ids', {}).get('enabled', False)


def render(value):
    if not active(value):
        return {}
    wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
    networks = {value['addressing']['ula_prefix']}
    networks.update(str(ip.ip_interface(address).network) for network in value['networks'].values()
                    for address in network['addresses'])
    networks.update(value['addressing']['services'].values())
    networks.update(str(ip.ip_interface(address).ip) for address in value['uplink'].get('addresses', []))
    if value['uplink'].get('downstream_prefix'):
        networks.add(value['uplink']['downstream_prefix'])
    settings = {
        'suricata-version': '7.0',
        'vars': {'address-groups': {'HOME_NET': '['+','.join(sorted(networks))+']',
                                   'EXTERNAL_NET': '!$HOME_NET'}},
        'default-rule-path': '/usr/share/lanrith',
        'rule-files': ['suricata.rules'],
        'default-log-dir': '/var/log/suricata',
        'max-pending-packets': 1024,
        'runmode': 'workers',
        'af-packet': [{'interface': wan, 'threads': 1, 'cluster-id': 99, 'cluster-type': 'cluster_flow',
                       'use-mmap': True, 'tpacket-v3': True, 'disable-promisc': True}],
        'flow': {'memcap': '32mb', 'hash-size': 65536, 'prealloc': 10000},
        'stream': {'memcap': '32mb', 'reassembly': {'memcap': '64mb'}},
        'stats': {'enabled': True, 'interval': 30},
        'outputs': [
            {'eve-log': {'enabled': True, 'filetype': 'regular', 'filename': 'eve.json',
                         'types': [{'alert': {'payload': False, 'packet': False,
                                              'http-body': False, 'http-body-printable': False}},
                                   {'stats': {'totals': True, 'threads': False}}]}},
        ],
        'logging': {'default-log-level': 'notice', 'outputs': [{'console': {'enabled': True}}]},
        'unix-command': {'enabled': False},
    }
    return {
        'etc/suricata/lanrith.yaml': '%YAML 1.1\n---\n'+yaml.safe_dump(settings, sort_keys=False),
        'usr/lib/sysusers.d/80-lanrith-ids.conf': 'u lanrith-ids - "WAN intrusion detection" /\n',
        'usr/lib/systemd/system/lanrith-ids.service': (
            '[Unit]\nDescription=Observe WAN traffic with admitted alert rules\n'
            'Requires=nftables.service systemd-networkd.service\n'
            'After=nftables.service systemd-networkd.service\nBindsTo=nftables.service\n'
            '[Service]\nUser=lanrith-ids\nGroup=lanrith-ids\n'
            f'ExecStart=/usr/bin/suricata --af-packet={wan} -c /etc/suricata/lanrith.yaml '
            '-l /var/log/suricata --init-errors-fatal\n'
            'LogsDirectory=suricata\nLogsDirectoryMode=0750\n'
            'CapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'ProtectKernelTunables=yes\nProtectControlGroups=yes\nProtectKernelModules=yes\n'
            'RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET AF_INET6\n'
            'MemoryMax=512M\nTasksMax=32\nLimitNOFILE=65536\n'
            'Restart=on-failure\nRestartSec=2s\n'
            '[Install]\nWantedBy=multi-user.target\n'),
        'etc/logrotate.d/suricata': (
            '/var/log/suricata/eve.json {\n  size 16M\n  rotate 4\n  compress\n  missingok\n'
            '  notifempty\n  copytruncate\n  su lanrith-ids lanrith-ids\n}\n'),
    }
