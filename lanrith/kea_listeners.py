"""Check declared IPv4 gateways and the raw listeners of the running Kea unit."""

import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

MANIFEST = Path('/usr/share/lanrith/kea-listeners.json')


def expected():
    scopes = json.loads(MANIFEST.read_bytes())
    result = {}
    for name, (address, length) in scopes.items():
        if (not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', name) or
                type(length) is not int or not 0 <= length <= 32):
            raise ValueError('Invalid DHCP listener scope.')
        result[name] = (str(ipaddress.IPv4Address(address)), length)
    return result


def interfaces(scopes):
    rows = json.loads(subprocess.check_output(['/usr/bin/ip', '-j', '-4', 'address', 'show', 'up'], timeout=1))
    ready = {row['ifname']: row['ifindex'] for row in rows
             if row.get('ifname') in scopes and {'UP', 'LOWER_UP'} <= set(row['flags']) and
             scopes[row['ifname']] in {(a['local'], a['prefixlen']) for a in row['addr_info']}}
    return set(ready.values()) if ready.keys() == scopes.keys() else None


def listeners(pid, indices):
    # Match the socket table inode to a descriptor in this exact daemon.
    # Packet socket UIDs alone could include other processes using its account.
    process = Path('/proc', str(pid))
    uid = pwd.getpwnam('_kea').pw_uid
    if process.stat().st_uid != uid or (process/'comm').read_text().strip() != 'kea-dhcp4':
        return False
    owned = set()
    for fd in (process/'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:  # An accepted control connection may just have closed.
            continue
        match = re.fullmatch(r'socket:\[(\d+)\]', target)
        if match:
            owned.add(match[1])
    rows = [line.split() for line in Path('/proc/self/net/packet').read_text().splitlines()[1:]]
    selected = [row for row in rows if row[8] in owned and int(row[7]) == uid]
    return {int(row[4]) for row in selected if int(row[2]) == 3 and int(row[5]) == 1} == indices


def main(argv):
    if argv == ['interfaces']:
        delay, pid = 10, None
    elif argv in (['sockets'], ['sockets', '--wait']):
        pid = int(subprocess.check_output(['systemctl', 'show', '-P', 'MainPID', 'kea-dhcp4-server.service'], timeout=2))
        delay = 3 if len(argv) == 2 else 0
    elif len(argv) == 3 and argv[:2] == ['sockets', '--wait'] and re.fullmatch('[1-9][0-9]{0,9}', argv[2]):
        delay, pid = 3, int(argv[2])
    else:
        return 64
    scopes = expected()
    deadline = time.monotonic()+delay
    while True:
        indices = interfaces(scopes)
        if indices is not None and (pid is None or (pid > 1 and listeners(pid, indices))):
            return 0
        if time.monotonic() >= deadline:
            return 1
        time.sleep(0.15)


if __name__ == '__main__':
    try:
        result = main(sys.argv[1:])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result = 1
    if result:
        print('Required Kea IPv4 interfaces or packet sockets are unavailable.', file=sys.stderr)
    sys.exit(result)
