#!/usr/bin/env python3
"""Measure the signed profile's NTP service from a client on one admitted attachment."""

import argparse
import hashlib
import ipaddress as ip
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, intent, service_plane
from lanrith.release import canonical


def measure(target, scopes):
    family = socket.AF_INET if target.version == 4 else socket.AF_INET6
    result = {'family': target.version, 'target': str(target), 'accepted': False}
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as route:
            route.connect((str(target), 123))
            source = ip.ip_address(route.getsockname()[0])
        result['source'] = str(source)
        if not any(source in scope for scope in scopes):
            return {**result, 'reason': 'source-outside-admission'}
        client = subprocess.run(['/usr/sbin/chronyd', '-Q', '-'+str(target.version), '-t', '8',
                                 'server '+str(target)+' iburst maxsamples 1', 'bindacqaddress '+str(source)],
                                env={**os.environ, 'LC_ALL': 'C'}, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
        if client.returncode == 0 and b'System clock wrong by' in client.stderr:
            result['accepted'] = True
        else:
            result['reason'] = 'no-accepted-measurement'
    except (OSError, subprocess.TimeoutExpired) as error:
        result['reason'] = type(error).__name__
    return result


def qualify(value, network):
    if network not in value['networks']:
        raise ValueError('Unknown NTP test attachment.')
    scopes = []
    if value['services']['ntp']['enabled']:
        scopes = [ip.ip_network(prefix) for client in service_plane.clients(value, 'ntp')
                  if client['network'] == network for prefix in client['addresses']]
    # These are the IPv4/IPv6 bindaddress and service DNS records. Additional
    # provider addresses participate in upstream acquisition.
    targets = [ip.ip_address(raw) for raw in intent.service_addresses(value, 'ntp')[:2]]
    results = [measure(target, scopes) for target in targets if any(scope.version == target.version for scope in scopes)]
    status = 'not-selected'
    if results:
        status = 'pass' if all(row['accepted'] for row in results) else 'fail'
    return {'schema': 1, 'network': network, 'normalized_profile_sha256': hashlib.sha256(canonical(value)).hexdigest(),
            'tested_at': int(time.time()), 'result': status, 'measurements': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--network', required=True)
    args = parser.parse_args()
    receipt = qualify(config.load(args.profile), args.network)
    print(json.dumps(receipt, sort_keys=True))
    sys.exit(1 if receipt['result'] == 'fail' else 0)
