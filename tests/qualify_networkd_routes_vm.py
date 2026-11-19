"""Exercise foreign IPv4/IPv6 route ownership against the real network daemon."""

import shlex


SCRIPT = r'''
import json
import subprocess
import sys

interface, gateway4, gateway6 = sys.argv[1:]
fixtures = [(4, gateway4, 25001, '198.18.254.0/24', '198.18.255.0/24'),
            (6, gateway6, 25002, '2001:db8:fffe::/64', '2001:db8:ffff::/64')]

def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)

try:
    for family, gateway, identifier, indirect, direct in fixtures:
        run('ip', '-'+str(family), 'nexthop', 'add', 'id', str(identifier),
            'via', gateway, 'dev', interface, 'protocol', 'bgp')
        run('ip', '-'+str(family), 'route', 'add', indirect, 'nhid', str(identifier), 'proto', 'bgp')
        run('ip', '-'+str(family), 'route', 'add', direct, 'via', gateway, 'dev', interface, 'proto', 'bgp')
    for _ in range(2):
        run('systemctl', 'restart', 'systemd-networkd.service')
        for family, gateway, identifier, indirect, direct in fixtures:
            nexthops = json.loads(run('ip', '-'+str(family), '-j', 'nexthop', 'show', 'id', str(identifier)))
            assert len(nexthops) == 1 and nexthops[0]['gateway'] == gateway, nexthops
            for prefix in (indirect, direct):
                routes = json.loads(run('ip', '-'+str(family), '-j', 'route', 'show', 'exact', prefix))
                assert len(routes) == 1 and routes[0]['dst'] == prefix, routes
                assert routes[0].get('gateway') == gateway and routes[0]['dev'] == interface, routes
                assert not routes[0].get('flags'), routes
                if prefix == indirect:
                    assert routes[0].get('nhid') == identifier, routes
    print('IPv4 and IPv6 routes and nexthops survived two networkd restarts.')
finally:
    for family, _, identifier, indirect, direct in fixtures:
        for prefix in (indirect, direct):
            subprocess.run(['ip', '-'+str(family), 'route', 'del', prefix],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'nexthop', 'del', 'id', str(identifier)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
'''


def qualify(guest, interface, gateway4, gateway6):
    command = shlex.join(['/usr/bin/python3', '-c', SCRIPT, interface, gateway4, gateway6])
    guest.ssh('sudo '+command, timeout=180)
    guest.ready()
