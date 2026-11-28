"""Opt-in WAN packet observation using only the admitted image's alert rules."""

import ipaddress as ip

import yaml

from . import intent, routing


def active(value):
    return value.get('observability', {}).get('ids', {}).get('enabled', False)


def render(value):
    if not active(value):
        return {}
    wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
    observability = value['observability']
    forward_alerts = observability['ids'].get('forward_alerts', False)
    monitor = observability.get('metrics', {}).get('enabled', False)
    networks = set(map(str, intent.service_networks(value)))
    for key, network in value['networks'].items():
        networks.update(str(ip.ip_interface(address).network) for address in
                        network['addresses'] + network.get('additional_subnets', []) +
                        network.get('routed_prefixes', []) + routing.routed_sources(value, key))
    networks.update(str(ip.ip_interface(address).ip) for address in value['uplink'].get('addresses', []))
    # A provider next hop can share a prefix with the router's on-link allocation.
    for gateway in map(ip.ip_address, value['uplink'].get('gateways', [])):
        for entry in list(networks):
            network = ip.ip_network(entry)
            if gateway.version == network.version and gateway in network:
                networks.remove(entry)
                networks.update(map(str, network.address_exclude(ip.ip_network(gateway))))
    settings = {
        'suricata-version': '8.0',
        'vars': {'address-groups': {'HOME_NET': '['+','.join(sorted(networks))+']',
                                   'EXTERNAL_NET': '!$HOME_NET'}},
        'default-rule-path': '/usr/share/lanrith',
        'rule-files': ['suricata.rules'],
        'default-log-dir': '/var/log/suricata',
        'max-pending-packets': 1024,
        'runmode': 'workers',
        # Observation must not attempt to change the router's NIC settings.
        'capture': {'disable-offloading': False},
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
    observer = ''
    files = {}
    if forward_alerts or monitor:
        types = []
        if forward_alerts:
            types.append({'alert': {'payload': False, 'packet': False, 'metadata': False}})
        if monitor:
            types.append({'stats': {'totals': True, 'threads': False, 'null-values': True}})
        settings['outputs'].append({'eve-log': {'enabled': True, 'filetype': 'unix_dgram',
            'filename': '/run/lanrith-ids-observer.sock', 'types': types}})
        observer = 'Wants=lanrith-ids-observer.socket\nAfter=lanrith-ids-observer.socket\n'
        flags = (' --alerts' if forward_alerts else '') + (' --stats' if monitor else '')
        files.update({
            'usr/lib/systemd/system/lanrith-ids-observer.socket': (
                '[Unit]\nDescription=Receive selected WAN sensor events locally\n'
                '[Socket]\nListenDatagram=/run/lanrith-ids-observer.sock\n'
                'SocketMode=0620\nSocketGroup=lanrith-ids\nPassCredentials=yes\nRemoveOnStop=yes\n'),
            'usr/lib/sysusers.d/80-lanrith-ids-observer.conf': 'u lanrith-ids-observer - "WAN sensor observer" /\n',
            'usr/lib/systemd/system/lanrith-ids-observer.service': (
                '[Unit]\nDescription=Project approved WAN sensor observations\n'
                '[Service]\nUser=lanrith-ids-observer\nGroup=lanrith-ids-observer\n'
                'ExecStart=/usr/bin/python3 -I /usr/lib/lanrith/lanrith/ids_observer.py '+wan+flags+'\n'
                'RuntimeDirectory=lanrith-ids-observer\nRuntimeDirectoryMode=0755\nUMask=0022\n'
                'NoNewPrivileges=yes\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=yes\n'
                'PrivateNetwork=yes\nPrivateDevices=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX\n'
                'MemoryMax=48M\nTasksMax=4\nRestart=on-failure\nRestartSec=1s\n'),
        })
    return {
        **files,
        'etc/suricata/lanrith.yaml': '%YAML 1.1\n---\n'+yaml.safe_dump(settings, sort_keys=False),
        'usr/lib/sysusers.d/80-lanrith-ids.conf': 'u lanrith-ids - "WAN intrusion detection" /\n',
        'usr/lib/systemd/system/lanrith-ids.service': (
            '[Unit]\nDescription=Observe WAN traffic with admitted alert rules\n'
            'Requires=nftables.service systemd-networkd.service\n'
            'After=nftables.service systemd-networkd.service\nBindsTo=nftables.service\n'
             + observer + '[Service]\nUser=lanrith-ids\nGroup=lanrith-ids\nUMask=0027\n'
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
        'etc/logrotate.d/suricata': '# The managed sensor has a separate size-check timer.\n',
        'etc/lanrith/ids.logrotate': (
            '/var/log/suricata/eve.json {\n  size 16M\n  rotate 4\n  compress\n  delaycompress\n'
            '  missingok\n  notifempty\n  su lanrith-ids lanrith-ids\n  create 0640 lanrith-ids lanrith-ids\n'
            '  postrotate\n'
            '    /usr/bin/systemctl kill --kill-whom=main --signal=HUP lanrith-ids.service || exit 1\n'
            '    for i in $(seq 1 65); do [ ! -s /var/log/suricata/eve.json ] || exit 0; sleep 1; done\n'
            '    echo "Suricata did not write to the reopened EVE file" >&2; exit 1\n  endscript\n}\n'),
        'usr/lib/systemd/system/lanrith-ids-rotate.service': (
            '[Unit]\nDescription=Rotate WAN sensor events and verify reopening\n'
            'After=lanrith-ids.service\nRequisite=lanrith-ids.service\n'
            '[Service]\nType=oneshot\nStateDirectory=lanrith-ids-rotate\nStateDirectoryMode=0700\n'
            'ExecStart=/usr/sbin/logrotate --state /var/lib/lanrith-ids-rotate/status /etc/lanrith/ids.logrotate\n'
            'TimeoutStartSec=100s\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n'
            'ReadWritePaths=/var/log/suricata\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX\n'),
        'usr/lib/systemd/system/lanrith-ids-rotate.timer': (
            '[Unit]\nDescription=Check WAN sensor log size every minute\n'
            '[Timer]\nOnBootSec=1min\nOnUnitInactiveSec=1min\nAccuracySec=1s\n'
            '[Install]\nWantedBy=timers.target\n'),
    }
