"""Manage only the generated core-service namespace; never adopt existing links."""

import json
from pathlib import Path
import subprocess
import sys


def run(arguments):
    if arguments[:2] == ['ip', '-netns']:
        arguments = ['nsenter', '--net=/run/netns/'+arguments[2], '--', 'ip', *arguments[3:]]
    subprocess.run(arguments, stdin=subprocess.DEVNULL, check=True, timeout=10)


def start(plane):
    ns, host, peer = plane['namespace'], plane['host_link'], plane['service_link']
    if Path('/run/netns', ns).exists() or Path('/sys/class/net', host).exists():
        raise ValueError('Generated service attachment already exists; refusing to adopt it.')
    run(['ip', 'netns', 'add', ns])
    link_created = False
    proxies = []
    try:
        run(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer, 'netns', ns])
        link_created = True
        # Deterministic link-local addresses avoid an asynchronous DAD window
        # before dependent DNS/NTP units can receive IPv6 traffic.
        run(['ip', 'link', 'set', 'dev', host, 'addrgenmode', 'none'])
        run(['ip', '-netns', ns, 'link', 'set', 'dev', peer, 'addrgenmode', 'none'])
        run(['ip', '-6', 'address', 'add', 'fe80::1/64', 'dev', host, 'nodad'])
        run(['ip', '-netns', ns, '-6', 'address', 'add', 'fe80::2/64', 'dev', peer, 'nodad'])
        run(['ip', '-netns', ns, 'link', 'set', 'lo', 'up'])
        for endpoint in plane['host_addresses']:
            run(['ip', 'address', 'add', endpoint, 'dev', host, *(['nodad'] if ':' in endpoint else [])])
        for endpoint in plane['peer_addresses'] + [a+('/128' if ':' in a else '/32')
                for addresses in plane['endpoints'].values() for a in addresses]:
            run(['ip', '-netns', ns, 'address', 'add', endpoint, 'dev', peer,
                 *(['nodad'] if ':' in endpoint else [])])
        run(['nsenter', '--net=/run/netns/'+ns, '--', 'nft', '-f', '/etc/lanrith/services.nft'])
        run(['ip', 'link', 'set', host, 'up'])
        run(['ip', '-netns', ns, 'link', 'set', peer, 'up'])
        for gateway, source in zip(plane['defaults'], plane['default_sources'], strict=True):
            run(['ip', '-netns', ns, '-6' if ':' in gateway else '-4', 'route', 'add', 'default', 'via', gateway, 'src', source])
        for route in plane.get('dependency_routes', []):
            run(['ip', '-netns', ns, '-6' if ':' in route['via'] else '-4', 'route', 'add',
                 route['to'], 'via', route['via'], 'src', route['source']])
        if plane['proxy']:
            run(['sysctl', '--quiet', '--write', 'net/ipv6/conf/'+plane['wan']+'/proxy_ndp=1'])
            for endpoint in plane['proxy']:
                run(['ip', '-6', 'neigh', 'add', 'proxy', endpoint, 'dev', plane['wan']])
                proxies.append(endpoint)
    except BaseException:
        for endpoint in proxies:
            run(['ip', '-6', 'neigh', 'delete', 'proxy', endpoint, 'dev', plane['wan']])
        if link_created:
            run(['ip', 'link', 'delete', host])
        run(['ip', 'netns', 'delete', ns])
        raise


def stop(plane):
    # ExecStop is invoked only after this oneshot successfully created its links.
    for endpoint in plane['proxy']:
        run(['ip', '-6', 'neigh', 'delete', 'proxy', endpoint, 'dev', plane['wan']])
    run(['ip', 'link', 'delete', plane['host_link']])
    run(['ip', 'netns', 'delete', plane['namespace']])


if __name__ == '__main__':
    plane = json.loads(Path('/usr/share/lanrith/service-plane.json').read_text())
    if sys.argv[1:] == ['start']:
        start(plane)
    elif sys.argv[1:] == ['stop']:
        stop(plane)
    else:
        raise SystemExit('Expected start or stop.')
