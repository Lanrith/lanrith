"""Activate the immutable host policy while retaining runtime-owned nft objects."""

import json
from pathlib import Path
import subprocess


NFT = '/usr/sbin/nft'
FLOOR = '/etc/lanrith/firewall-recovery.nft'
FORWARDING = '/usr/lib/lanrith/firewall-forwarding.conf'
HARDENING = '/etc/sysctl.d/90-lanrith-routing.conf'
STAMP = Path('/run/lanrith-firewall/installed')


def activate(stamp=STAMP):
    # nftables.service serializes starts. /run survives service restarts and is
    # cleared on reboot, the supported transition between signed configurations.
    if not stamp.exists():
        batch = f'include "/etc/nftables.conf"\ninclude "{FLOOR}"\n'
        subprocess.run([NFT, '-f', '-'], input=batch.encode(), check=True)
    result = subprocess.run([NFT, '-j', '-t', 'list', 'table', 'inet', 'lanrith'],
                            stdout=subprocess.PIPE, check=True)
    objects = json.loads(result.stdout)['nftables']
    if not any(table.get('family') == 'inet' and table.get('name') == 'lanrith'
               and 'dormant' not in table.get('flags', [])
               for item in objects if (table := item.get('table'))):
        raise RuntimeError('Host firewall table is inactive.')
    hooks = {chain['hook'] for item in objects
             if (chain := item.get('chain', {})).get('table') == 'lanrith'
             and chain.get('family') == 'inet' and chain.get('type') == 'filter'
             and chain.get('policy') == 'drop' and chain.get('hook') in ('input', 'forward', 'output')}
    if not {'input', 'forward', 'output'} <= hooks:
        raise RuntimeError('Host firewall is missing a required default-drop hook.')
    stamp.touch(mode=0o600)
    # Setting ip_forward changes kernel defaults. Reapply per-interface
    # hardening before releasing the recovery floor.
    subprocess.run(['/usr/lib/systemd/systemd-sysctl', '--strict', FORWARDING, HARDENING], check=True)
    subprocess.run([NFT, 'delete', 'table', 'inet', 'lanrith_recovery'], check=True)


if __name__ == '__main__':
    activate()
