"""Project native sensor events before they enter the journal and metric spool."""

import argparse
import datetime
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import struct
import tempfile
import time


OUTPUT = Path('/run/lanrith-ids-observer/stats.json')
FIELDS = {
    'capture_packets': ('capture', 'kernel_packets'),
    'kernel_drops': ('capture', 'kernel_drops'),
    'capture_errors': ('capture', 'errors'),
    'tcp_reassembly_gaps': ('tcp', 'reassembly_gap'),
    'tcp_session_memcap_drops': ('tcp', 'ssn_memcap_drop'),
    'tcp_segment_memcap_drops': ('tcp', 'segment_memcap_drop'),
    'flow_emergencies': ('flow', 'emerg_mode_entered'),
}
MAX_AGE = 75


def integer(value):
    return type(value) is int and 0 <= value < 2**63


def timestamp(event):
    stamp = datetime.datetime.fromisoformat(event['timestamp'])
    if stamp.tzinfo is None:
        raise ValueError('Missing timestamp offset')
    return stamp.astimezone(datetime.timezone.utc)


def alert(event, interface):
    sid = event['alert']['signature_id']
    if event.get('in_iface') == interface and type(sid) is int and sid in (1000001, 1000002):
        return {'sid': sid, 'interface': interface, 'event_time': timestamp(event).isoformat()}


def counters(record):
    return (isinstance(record, dict) and set(record) == FIELDS.keys() and
            all(integer(value) for value in record.values()))


def sample(event, previous, *, sender, now_mono, now_utc):
    stats = event['stats']
    totals = {name: stats[group][key] for name, (group, key) in FIELDS.items()}
    wall = int(timestamp(event).timestamp())
    if not counters(totals) or not integer(stats['uptime']) or not -5 <= now_utc - wall <= MAX_AGE:
        raise ValueError('Invalid or stale sensor stats')
    delta = None
    if previous is not None:
        pid, uptime, last = previous
        if (pid == sender and uptime <= stats['uptime'] and
                0 < now_mono - last['monotonic_ns'] <= MAX_AGE * 10**9 and
                all(last['totals'][name] <= total for name, total in totals.items())):
            delta = {name: total-last['totals'][name] for name, total in totals.items()}
    return {'monotonic_ns': now_mono, 'timestamp': wall, 'totals': totals, 'delta': delta}


def publish(record, path=OUTPUT):
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
        try:
            json.dump(record, stream, separators=(',', ':'))
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.replace(stream.name, path)
        finally:
            Path(stream.name).unlink(missing_ok=True)


def read_observation(path=OUTPUT):
    from .release import read
    user = pwd.getpwnam('lanrith-ids-observer')
    parent = path.parent.lstat()
    if parent.st_uid != user.pw_uid or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o755:
        raise ValueError('Invalid sensor observation directory')
    state = json.loads(read(path, 4096))
    if (set(state) != {'monotonic_ns', 'timestamp', 'totals', 'delta'} or not integer(state['monotonic_ns']) or
            not integer(state['timestamp']) or not -5 <= time.time()-state['timestamp'] <= MAX_AGE or
            not 0 <= time.monotonic_ns()-state['monotonic_ns'] <= MAX_AGE * 10**9 or
            not counters(state['totals']) or state['delta'] is not None and not counters(state['delta'])):
        raise ValueError('Invalid or stale sensor observation')
    return state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    parser.add_argument('--alerts', action='store_true')
    parser.add_argument('--stats', action='store_true')
    args = parser.parse_args()
    if int(os.environ['LISTEN_PID']) != os.getpid() or os.environ['LISTEN_FDS'] != '1':
        raise ValueError('Expected a single managed observation socket')
    uid = pwd.getpwnam('lanrith-ids').pw_uid
    previous = None
    with socket.socket(fileno=3) as receiver:
        while True:
            raw, credentials, flags, _ = receiver.recvmsg(128 * 1024, socket.CMSG_SPACE(12))
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                continue
            peers = [struct.unpack('3i', data) for level, key, data in credentials
                     if level == socket.SOL_SOCKET and key == socket.SCM_CREDENTIALS and len(data) == 12]
            if len(peers) != 1 or peers[0][1] != uid:
                continue
            try:
                event = json.loads(raw)
                if event['event_type'] == 'alert' and args.alerts:
                    projected = alert(event, args.interface)
                    if projected:
                        print(json.dumps(projected, separators=(',', ':')), flush=True)
                elif event['event_type'] == 'stats' and args.stats:
                    latest = sample(event, previous, sender=peers[0][0], now_mono=time.monotonic_ns(), now_utc=time.time())
                    publish(latest)
                    previous = peers[0][0], event['stats']['uptime'], latest
            except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
                continue


if __name__ == '__main__':
    main()
