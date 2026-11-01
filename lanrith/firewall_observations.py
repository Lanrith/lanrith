"""Build-only, explicitly admitted host default-deny observation wiring."""

import hashlib
from . import firewall_metadata
from .release import canonical, require


CONFIG = 'usr/share/lanrith/firewall-observations.json'
ACCOUNT = 'lanrith-firewall-observer'
SERVICE = 'lanrith-firewall-observations.service'
RUNTIME = '/run/lanrith-firewall-observations'
RULESET = 'etc/nftables.conf'


def render(observer, native_firewall):
    observed, contract = firewall_metadata.instrument(native_firewall)
    contract.update(record_schema=1, observer=observer, firewall_sha256=hashlib.sha256(observed.encode()).hexdigest())
    return {RULESET: observed, CONFIG: canonical(contract).decode(),
        'etc/modules-load.d/65-lanrith-firewall-observations.conf': 'nfnetlink_log\n',
        'etc/systemd/system/nftables.service.d/62-lanrith-observations.conf': '[Unit]\nWants='+SERVICE+'\n',
        'etc/systemd/system/'+SERVICE: (
            '[Unit]\nDescription=Bounded host default-deny observations\nAfter=nftables.service\n'
            'StartLimitIntervalSec=0\n'
            '[Service]\nType=simple\nUser='+ACCOUNT+'\nGroup='+str(observer['gid'])+'\n'
            'ExecStart=/usr/lib/lanrith/firewall-observations-runtime\n'
            'Restart=always\nRestartSec=5s\nSuccessExitStatus=1\nTimeoutStopSec=3s\n'
            'RuntimeDirectory=lanrith-firewall-observations\nRuntimeDirectoryMode=0750\n'
            'RuntimeDirectoryPreserve=restart\nUMask=0027\n'
            'BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/lanrith-firewall-boot-id\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_ADMIN\nNoNewPrivileges=yes\n'
            'PrivateTmp=yes\nPrivateDevices=yes\nRemoveIPC=yes\n'
            'ProtectSystem=strict\nProtectHome=yes\nProtectProc=invisible\nProcSubset=pid\n'
            'InaccessiblePaths=-/run/credentials -/run/router-policy-ipc -/run/lanrith-policy '
            '-/var/lib/lanrith -/usr/lib/lanrith-build -/var/log -/run/log\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\n'
            'ProtectControlGroups=yes\nProtectClock=yes\nProtectHostname=yes\n'
            'RestrictAddressFamilies=AF_NETLINK AF_UNIX\nRestrictNamespaces=yes\nRestrictRealtime=yes\n'
            'RestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n'
            'SystemCallArchitectures=native\n'
            'SystemCallFilter=~@cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap\n'
            'MemoryMax=64M\nMemorySwapMax=0\nCPUQuota=5%\nCPUWeight=10\nTasksMax=8\nLimitNOFILE=24\n'
            'LogRateLimitIntervalSec=30s\nLogRateLimitBurst=10\n'),
        'usr/lib/lanrith/firewall-observations-runtime': (
            '#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, "/usr/lib/lanrith")\n'
            'from lanrith.firewall_observations_runtime import main\nsys.exit(main())\n')}


def install(observer, destination):
    path = destination/RULESET
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8*1024*1024,
            'Core firewall observation input is missing or unsafe.')
    files = render(observer, path.read_text())
    require(all(name == RULESET or not (destination/name).exists() and not (destination/name).is_symlink()
                for name in files), 'Core firewall observation path is already occupied.')
    for name, text in files.items():
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        target.chmod(0o755 if name.endswith('/firewall-observations-runtime') else 0o644)


def account_declarations(accounts, declarations, destination):
    from .observation_accounts import allocate
    return allocate(accounts, declarations, destination, name=ACCOUNT, manifest=CONFIG)
