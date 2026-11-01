"""Generate an optional client-edge DNS observation channel from admitted intent."""

from .release import canonical, require


CONFIG = 'usr/share/lanrith/dns-observations.json'
RESOLVER = 'etc/unbound/unbound.conf.d/lanrith.conf'
SOCKET = 'lanrith-dns-observations.socket'
SERVICE = 'lanrith-dns-observations.service'
RUNTIME = '/run/lanrith-dns-observations'
TAP = '/run/lanrith-dns-tap.sock'
ACCOUNT = 'lanrith-dns-observer'


def render(observer):
    return {
        CONFIG: canonical({'schema': 1, 'record_schema': 1, 'observer': observer}).decode(),
        'etc/unbound/unbound.conf.d/62-lanrith-observations.conf': (
            'dnstap:\n  dnstap-enable: yes\n  dnstap-bidirectional: yes\n'
            '  dnstap-socket-path: "'+TAP+'"\n'
            '  dnstap-send-identity: no\n  dnstap-send-version: no\n'
            '  dnstap-log-client-query-messages: yes\n'
            '  dnstap-log-client-response-messages: yes\n'
            '  dnstap-log-resolver-query-messages: no\n'
            '  dnstap-log-resolver-response-messages: no\n'
            '  dnstap-log-forwarder-query-messages: no\n'
            '  dnstap-log-forwarder-response-messages: no\n'),
        'etc/systemd/system/unbound.service.d/62-lanrith-observations.conf': (
            '[Unit]\nWants='+SOCKET+'\nAfter='+SOCKET+'\n'),
        'etc/systemd/system/'+SOCKET: (
            '[Unit]\nDescription=Optional local DNS observation ingress\n'
            '[Socket]\nListenStream='+TAP+'\nFileDescriptorName=dns-tap\nSocketUser=unbound\nSocketGroup=unbound\n'
            'SocketMode=0600\nBacklog=1\nReceiveBuffer=16K\nSendBuffer=16K\n'
            'RemoveOnStop=yes\nTimeoutSec=5s\nService='+SERVICE+'\n'),
        'etc/systemd/system/'+SERVICE: (
            '[Unit]\nDescription=Bounded local DNS metadata observations\n'
            'Requires='+SOCKET+'\nAfter='+SOCKET+'\n'
            'StartLimitIntervalSec=0\n'
            '[Service]\nType=simple\nUser='+ACCOUNT+'\n'
            'Group='+str(observer['gid'])+'\n'
            'ExecStart=/usr/lib/lanrith/dns-observations-runtime\n'
            'Restart=always\nRestartSec=5s\nSuccessExitStatus=1\nTimeoutStopSec=3s\n'
            'RuntimeDirectory=lanrith-dns-observations\nRuntimeDirectoryMode=0750\n'
            'RuntimeDirectoryPreserve=restart\nUMask=0027\n'
            'BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/lanrith-dns-boot-id\n'
            'NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
            'PrivateNetwork=yes\nPrivateTmp=yes\nPrivateDevices=yes\nRemoveIPC=yes\n'
            'ProtectSystem=strict\nProtectHome=yes\nProtectProc=invisible\nProcSubset=pid\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\n'
            'ProtectControlGroups=yes\nProtectClock=yes\nProtectHostname=yes\n'
            'RestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\nRestrictRealtime=yes\n'
            'RestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n'
            'SystemCallArchitectures=native\n'
            'SystemCallFilter=~@cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap\n'
            'MemoryMax=64M\nMemorySwapMax=0\nTasksMax=16\nLimitNOFILE=32\n'
            'LogRateLimitIntervalSec=30s\nLogRateLimitBurst=10\n'),
        'usr/lib/lanrith/dns-observations-runtime': (
            '#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
            'from lanrith.dns_observations_runtime import main\nsys.exit(main())\n'),
    }


def install(configuration, observer, destination):
    require(configuration['services']['dns']['enabled'], 'DNS observations require the resolver.')
    require((destination/RESOLVER).is_file() and not (destination/RESOLVER).is_symlink(),
            'Core resolver wiring is missing.')
    for name, text in render(observer).items():
        path = destination/name
        require(not path.exists() and not path.is_symlink(), 'DNS observation path is already occupied.')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o755 if name.endswith('/dns-observations-runtime') else 0o644)


def account_declarations(accounts, declarations, destination):
    """Allocate the locked collector account while building the immutable /etc.

    Never defer a new account or UID decision to a deployed read-only image.
    Both registries and all extension identities reserve their numbers first.
    """
    if not (destination/CONFIG).exists():
        return []
    require(set(accounts) == {'passwd', 'group'}, 'DNS collector needs admitted base accounts.')
    rows = {kind: [line.split(':') for line in text.decode().splitlines() if line]
            for kind, text in accounts.items()}
    require(all(row[0] != ACCOUNT for entries in rows.values() for row in entries),
            'Base already has an unreviewed DNS collector identity.')
    used = {int(row[2]) for entries in rows.values() for row in entries}
    for declaration in declarations:
        for kind in ('users', 'groups'):
            for entry in declaration[kind]:
                require(entry['name'] != ACCOUNT, 'Integration collides with the DNS collector.')
                used.add(entry['gid'])
                if kind == 'users':
                    used.add(entry['uid'])
    selected = next((uid for uid in range(100, 1000) if uid not in used), None)
    require(selected is not None, 'No unused system identity for the DNS collector.')
    return [{'users': [{'name': ACCOUNT, 'uid': selected, 'gid': selected}],
             'groups': [{'name': ACCOUNT, 'gid': selected}]}]
