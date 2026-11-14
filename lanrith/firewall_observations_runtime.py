"""Optional fixed-group receiver; only bounded tuples reach the metadata spool."""

import errno
import hashlib
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import time

from . import firewall_metadata as wire
from .observation_spool import Spool
from .policy_runtime import decode, exact, read


MANIFEST = Path('/usr/share/lanrith/firewall-observations.json')
RULESET = Path('/etc/nftables.conf')
DIRECTORY = Path('/run/lanrith-firewall-observations')
BOOT = Path('/run/lanrith-firewall-boot-id')
ACCOUNT = 'lanrith-firewall-observer'
HASH = re.compile(r'[a-f0-9]{64}\Z')
COUNTERS = ('emitted', 'rejected', 'write_failed', 'overwritten', 'netlink_overruns', 'kernel_sequence_gaps', 'startup_gaps')
COVERAGE = 'Rate-limited host input/forward default-deny only; no earlier guard, explicit-rule, policy-agent, translator, output or service-namespace coverage.'


def load(path=MANIFEST, *, ruleset=RULESET, owner=0):
    value = exact(decode(read(path, 8192, owner=owner), 8192),
        {'schema', 'record_schema', 'observer', 'group', 'prefixes', 'native_firewall_sha256', 'firewall_sha256', 'coverage'},
        'Firewall observations')
    observer = exact(value['observer'], {'user', 'uid', 'gid'}, 'Firewall reader')
    if (type(value['schema']) is not int or value['schema'] != 1 or type(value['record_schema']) is not int or value['record_schema'] != 1 or
            type(value['group']) is not int or value['group'] != wire.GROUP or value['coverage'] != COVERAGE or
            not isinstance(observer['user'], str) or re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', observer['user']) is None or
            any(type(observer[key]) is not int or not 100 <= observer[key] <= 59999 for key in ('uid', 'gid')) or
            any(not isinstance(value[key], str) or HASH.fullmatch(value[key]) is None
                for key in ('native_firewall_sha256', 'firewall_sha256'))):
        raise ValueError('Firewall observation contract differs.')
    account = pwd.getpwnam(observer['user'])
    if (account.pw_uid, account.pw_gid) != (observer['uid'], observer['gid']):
        raise ValueError('Firewall reader identity drift.')
    prefixes = {}
    for hook, code in (('input', 'I'), ('forward', 'F')):
        digest = value['native_firewall_sha256']
        revision = hashlib.sha256((digest+':'+hook+':default-drop').encode()).hexdigest()
        prefixes['LN_D1_'+digest[:24]+'_'+code] = {'hook': hook, 'id': 'native-default-drop:'+revision[:24], 'revision': revision}
    if value['prefixes'] != prefixes or hashlib.sha256(read(ruleset, 8*1024*1024, owner=owner)).hexdigest() != value['firewall_sha256']:
        raise ValueError('Firewall observation ruleset binding differs.')
    return value


def interface(index):
    if index is None:
        return None
    try:
        name = socket.if_indextoname(index)
    except OSError:
        return None
    return name if re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name) else None


def serve(source, spool, contract, *, stopped):
    previous, health_at = None, -3
    spool.bump('startup_gaps')
    while not stopped():
        now = time.monotonic()
        if now-health_at >= 3:
            try:
                spool.health()
            except OSError:
                spool.bump('write_failed')
            health_at = now
        if not select.select([source], [], [], .2)[0]:
            continue
        try:
            data, ancillary, flags, sender = source.recvmsg(wire.MAX_DATAGRAM)
        except OSError as error:
            if error.errno != errno.ENOBUFS:
                raise
            spool.bump('netlink_overruns')
            continue
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            spool.bump('rejected')
            continue
        try:
            rows = wire.decode(data, sender, contract['prefixes'])
        except (ValueError, TypeError, KeyError):
            spool.bump('rejected')
            continue
        for row in rows:
            sequence = row['kernel_sequence']
            if previous is not None:
                difference = (sequence-previous) & 0xffffffff
                if difference == 0 or difference >= 1 << 31:
                    spool.bump('rejected')
                    continue
                spool.bump('kernel_sequence_gaps', difference-1)
            else:
                spool.bump('kernel_sequence_gaps', sequence)
            previous = sequence
            if not -5*10**9 <= time.time_ns()-row['observed_ns'] <= 6900*10**9:
                spool.bump('rejected')
                continue
            try:
                spool.append({**row, 'namespace': 'host', 'firewall_sha256': contract['firewall_sha256'],
                    'interface_in': interface(row['in_ifindex']), 'interface_out': interface(row['out_ifindex'])})
            except OSError:
                spool.bump('write_failed')


def main():
    try:
        value = load()
        observer = value['observer']
        account = pwd.getpwnam(ACCOUNT)
        if (os.geteuid() == 0 or os.geteuid() != account.pw_uid or os.geteuid() == observer['uid'] or
                os.getegid() != observer['gid'] or set(os.getgroups())-{observer['gid']}):
            raise ValueError('Firewall observation process identity differs.')
        done = False

        def stop(signum, frame):
            nonlocal done
            done = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        with wire.kernel_listener() as source:
            wire.discard_configuration_capability()
            spool = Spool(DIRECTORY, boot=BOOT, counters=COUNTERS)
            serve(source, spool, value, stopped=lambda: done)
        return 0
    except (ValueError, OSError, KeyError, LookupError) as error:
        print('Optional firewall observation collector unavailable: '+type(error).__name__, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
