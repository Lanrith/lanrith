"""Check the signed local readiness requirements of the running image."""

import ipaddress as ip
import json
from pathlib import Path
import re
import signal
import subprocess
import time

from .release import read, require, ReleaseError
from .update import command


PROBES = {'nat46', 'nat64', 'nat64-internal', 'ownership'}
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
LABEL = re.compile(r'[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\Z')
RESOLV = Path('/etc/resolv.conf')


class LocalRequirementFailed(ReleaseError):
    """A local diagnostic composed only of a fixed check and validated signed identifiers."""


def ready(condition, message):
    if not condition:
        raise LocalRequirementFailed(message)


def fqdn(name):
    return (isinstance(name, str) and name.endswith('.') and len(name) <= 254 and
            all(LABEL.fullmatch(label) for label in name[:-1].split('.')))


def validate(plan):
    require(isinstance(plan, dict) and {'schema', 'units', 'interfaces', 'probes'} <= set(plan) <=
            {'schema', 'units', 'interfaces', 'probes', 'native_translation', 'dns'} and
            ('native_translation' not in plan or plan['native_translation'] is True) and
            type(plan['schema']) is int and plan['schema'] in (1, 2) and
            (plan['schema'] == 2 or 'dns' not in plan) and
            isinstance(plan['units'], list) and 3 <= len(plan['units']) <= 256 and
            isinstance(plan['interfaces'], list) and 1 <= len(plan['interfaces']) <= 256 and
            isinstance(plan['probes'], list) and len(plan['probes']) <= len(PROBES),
            'Invalid compiled boot requirements.')
    require(all(isinstance(unit, str) and re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(?:service|timer)', unit)
                for unit in plan['units']) and len(set(plan['units'])) == len(plan['units']) and
            all(isinstance(probe, str) and probe in PROBES for probe in plan['probes']) and
            len(set(plan['probes'])) == len(plan['probes']), 'Invalid compiled boot requirements.')
    if plan['schema'] == 2:
        require({'nftables.service', 'ssh.service', 'systemd-networkd.service'} <= set(plan['units']) and
                ('dns' in plan) == ('unbound.service' in plan['units']), 'Incomplete compiled boot requirements.')
    for item in plan['interfaces']:
        require(isinstance(item, dict) and {'name', 'addresses'} <= set(item) <=
                {'name', 'addresses', 'namespace', 'optional', 'carrier_optional', 'routes', 'routable_families'} and
                isinstance(item['name'], str) and len(item['name']) <= 15 and IDENTIFIER.fullmatch(item['name'])
                and isinstance(item['addresses'], list) and len(item['addresses']) <= 256 and
                ('namespace' not in item or isinstance(item['namespace'], str) and IDENTIFIER.fullmatch(item['namespace']))
                and all(item.get(key, True) is True for key in ('optional', 'carrier_optional')),
                'Invalid compiled interface requirement.')
        if plan['schema'] == 1:
            require(set(item) <= {'name', 'namespace', 'addresses'}, 'Invalid legacy interface requirement.')
        for address in item['addresses']:
            if plan['schema'] == 1:
                ip.ip_address(address)
            else:
                require(isinstance(address, str) and '/' in address, 'Invalid compiled interface prefix.')
                ip.ip_interface(address)
        families = item.get('routable_families', [])
        require(isinstance(families, list) and all(type(family) is int and family in (4, 6) for family in families),
                'Invalid required uplink families.')
        routes = item.get('routes', [])
        require(isinstance(routes, list), 'Invalid compiled route inventory.')
        for route in routes:
            require(isinstance(route, dict) and set(route) in ({'to'}, {'to', 'via'}), 'Invalid compiled route requirement.')
            subnet = ip.ip_network(route['to'])
            if 'via' in route:
                require(ip.ip_address(route['via']).version == subnet.version, 'Invalid compiled route gateway.')
    if 'dns' in plan:
        dns = plan['dns']
        require(isinstance(dns, dict) and set(dns) in ({'listeners', 'ntp_client', 'queries'},
                             {'listeners', 'ntp_client', 'queries', 'authority', 'source'}) and
                type(dns['ntp_client']) is bool and isinstance(dns['queries'], list) and 1 <= len(dns['queries']) <= 256,
                'Invalid compiled DNS requirements.')
        require(isinstance(dns['listeners'], list) and 1 <= len(dns['listeners']) <= 256,
                'Invalid recursive DNS listeners.')
        for address in dns['listeners']:
            ip.ip_address(address)
        for field in {'authority', 'source'} & dns.keys():
            ip.ip_address(dns[field])
        for query in dns['queries']:
            require(isinstance(query, list) and len(query) == 3, 'Invalid compiled DNS query.')
            name, kind, expected = query
            require(fqdn(name) and kind in ('SOA', 'A', 'AAAA', 'CNAME') and
                    (expected == 'present' and kind == 'SOA' or expected == 'NXDOMAIN' or
                     isinstance(expected, list) and all(isinstance(a, str) for a in expected)),
                    'Invalid compiled DNS record requirement.')


def check_interface(item, run, *, legacy=False):
    name = item['name']
    ipcmd = ['ip'] + (['-netns', item['namespace']] if 'namespace' in item else [])
    # Show all links for an optional device so a deliberately disconnected or absent WAN is admissible.
    args = ['-j', 'address', 'show'] + ([] if item.get('optional') else ['dev', name])
    rows = [row for row in json.loads(run(ipcmd+args, f'interface {name}')) if row['ifname'] == name]
    if legacy:
        ready(len(rows) == 1 and {ip.ip_address(a) for a in item['addresses']} <=
                {ip.ip_address(a['local']) for a in rows[0]['addr_info']},
                f'Required legacy gateway on {name} is unavailable.')
        return
    flags = set(rows[0]['flags']) if len(rows) == 1 else set()
    if item.get('optional') and 'LOWER_UP' not in flags:
        return
    ready('UP' in flags and (item.get('carrier_optional') or 'LOWER_UP' in flags and 'DORMANT' not in flags),
            f'Required interface {name} is unavailable.')
    usable = [a for a in rows[0]['addr_info']
              if not any(a.get(flag) for flag in ('tentative', 'dadfailed', 'deprecated', 'optimistic'))
              and a.get('preferred_life_time', 1) != 0 and a.get('valid_life_time', 1) != 0]
    addresses = {ip.ip_interface(f"{a['local']}/{a['prefixlen']}") for a in usable}
    families = {ip.ip_address(a['local']).version for a in usable if a.get('scope') == 'global'}
    for family in item.get('routable_families', []):
        ready(family in families, f'Required routable IPv{family} address on {name} is unavailable.')
    for cidr in item['addresses']:
        ready(ip.ip_interface(cidr) in addresses, f'Required gateway {cidr} on {name} is unavailable.')
    for route in item.get('routes', []):
        prefix = ip.ip_network(route['to'])
        label = f'route {prefix} on {name}'
        rows = json.loads(run(ipcmd+[f'-{prefix.version}', '-j', 'route', 'show', 'table', 'main',
                                    'exact', str(prefix)], label))

        def matches(row):
            dst = row.get('dst')
            if dst == 'default':
                dst = '::/0' if prefix.version == 6 else '0.0.0.0/0'
            return (dst and ip.ip_network(dst) == prefix and row.get('dev') == name
                    and row.get('type', 'unicast') == 'unicast' and 'linkdown' not in row.get('flags', [])
                    and ('via' not in route or row.get('gateway') == route['via'])
                    and (prefix.prefixlen == 0 or 'gateway' not in row))
        ready(any(matches(row) for row in rows), f'Required {label} is unavailable.')


def dns_answers(command_prefix, options, queries, label, run, *, authority=False):
    # dig accepts multiple questions as arguments. Retain question, RCODE, owner
    # and (on the primary) AA; +short would also accept a stale CNAME chain.
    for offset in range(0, len(queries), 32):
        batch = queries[offset:offset+32]
        args = [*command_prefix, '/usr/bin/dig', '-r', '+time=2', '+tries=1', '+nosearch',
                '+noedns', '+nocmd', '+noall', '+comments', '+question', '+answer', *options]
        for name, kind, _ in batch:
            args.extend([name, kind])
        output = run(args, f'{label} query for {batch[0][0]}')
        messages = re.split(r'^;; ->>HEADER<<- ', output, flags=re.M)[1:]
        ready(len(messages) == len(batch), f'Incomplete {label} response for {batch[0][0]}.')
        for (name, kind, expected), message in zip(batch, messages):
            reason = f'Required {label} answer for {name} {kind} is unavailable.'
            lines = message.splitlines()
            rcode = re.search(r'\bstatus: ([A-Z]+),', lines[0])
            flags = re.search(r'^;; flags: ([^;]*);', message, re.M)
            question = [line[1:].lower().split() for line in lines if line.startswith(';') and not line.startswith(';;')]
            ready(rcode and flags and ('aa' in flags[1].split() or not authority) and
                    question == [[name.lower(), 'in', kind.lower()]], reason)
            rows = [line.split() for line in lines[1:] if line and not line.startswith(';')]
            answers = {' '.join(row[4:]).lower() for row in rows
                       if len(row) >= 5 and row[0].lower() == name.lower() and row[2:4] == ['IN', kind]}
            if expected == 'NXDOMAIN':
                ready(rcode[1] == 'NXDOMAIN' and not rows, reason)
            elif expected == []:
                ready(rcode[1] in ('NOERROR', 'NXDOMAIN') and not rows, reason)
            else:
                ready(rcode[1] == 'NOERROR' and (bool(answers) if expected == 'present' else
                        answers == {a.lower() for a in expected}), reason)


def check_dns(dns, run):
    # Validate the host's effective destination before sending any private name.
    lines = read(RESOLV, 4096).decode().splitlines()
    servers = [line.split()[1:] for line in lines if line.split()[:1] == ['nameserver']]
    ready(servers == [[dns['listeners'][0]]], 'Host DNS resolver differs from its signed local endpoint.')
    pid = run(['systemctl', 'show', '-P', 'MainPID', 'unbound.service'], 'Unbound identity').strip()
    ready(re.fullmatch('[1-9][0-9]{0,9}', pid) and int(pid) > 1, 'Unbound identity is unavailable.')
    for protocol in ('tcp', 'udp'):
        sockets = run(['nsenter', '--net=/run/netns/lanrith-services', '--', 'ss', '-Hnlp', '--'+protocol,
                       'sport = :53'], f'Unbound {protocol} listeners')
        owned = {line.split()[3] for line in sockets.splitlines() if f',pid={pid},' in line}
        for addr in dns['listeners']:
            endpoint = f'[{addr}]:53' if ':' in addr else addr+':53'
            ready(endpoint in owned, f'Required Unbound {protocol} listener {addr} is unavailable.')
    queries = dns['queries']
    namespace = ['nsenter', '--net=/run/netns/lanrith-services', '--', 'setpriv', '--clear-groups']
    if 'authority' in dns:
        dns_answers(namespace+['--reuid=unbound', '--regid=unbound'], ['-b', dns['source'], '@'+dns['authority'],
                    '+norecurse'], queries, 'authoritative DNS', run, authority=True)
    # An absent native AAAA may legitimately be synthesized by DNS64. Removals
    # are verified at the authoritative source, independently of resolver cache.
    visible = [q for q in queries if q[2] != []]
    dns_answers([], [], visible, 'host DNS', run)
    if dns['ntp_client']:
        pid = run(['systemctl', 'show', '-P', 'MainPID', 'chrony.service'], 'NTP resolver identity').strip()
        ready(re.fullmatch('[1-9][0-9]{0,9}', pid) and int(pid) > 1, 'NTP resolver identity is unavailable.')
        private_resolver = Path('/proc', pid, 'root/etc/resolv.conf')
        ready(read(private_resolver, 4096).split() == [b'nameserver', b'127.0.0.1'],
                'NTP client resolver differs from its signed loopback endpoint.')
        client = ['nsenter', '--net=/proc/'+pid+'/ns/net', '--', 'setpriv', '--clear-groups',
                  '--reuid=_chrony', '--regid=_chrony']
        dns_answers(client, ['@127.0.0.1'], visible[:1], 'NTP resolver', run)


def check(plan, *, settle_seconds=0):
    validate(plan)
    deadline = time.monotonic()+40

    def run(args, requirement):
        remaining = deadline-time.monotonic()
        ready(remaining > 0, 'Local readiness deadline expired at '+requirement+'.')
        try:
            return command(args, timeout=min(remaining, 6))
        except ReleaseError as error:
            raise LocalRequirementFailed(f'Required {requirement} failed.') from error

    settle = min(deadline, time.monotonic()+settle_seconds)
    while True:
        try:
            check_local(plan, run)
            break
        except ReleaseError:
            if time.monotonic() >= settle:
                raise
            time.sleep(max(0, min(0.25, settle-time.monotonic())))

    if plan['probes']:
        # Existing translator and hardware probes inspect several kernel objects
        # with their own per-command timeouts. Bound their aggregate time too.
        remaining = deadline-time.monotonic()
        ready(remaining > 0, 'Local boot readiness deadline expired.')

        def expired(signum, frame):
            raise LocalRequirementFailed('Feature readiness deadline expired.')

        previous = signal.signal(signal.SIGALRM, expired)
        try:
            signal.setitimer(signal.ITIMER_REAL, remaining)
            check_features(plan)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    ready(time.monotonic() <= deadline, 'Local boot readiness deadline expired.')


def check_local(plan, run):
    # Query each unit separately so a nonzero is-active result is attributed.
    for unit in plan['units']:
        ready(run(['systemctl', 'is-active', unit], unit).strip() == 'active',
                f'Required unit {unit} is inactive.')
    for interface in plan['interfaces']:
        check_interface(interface, run, legacy=plan['schema'] == 1)
    if plan['schema'] == 2 and 'ssh.service' in plan['units']:
        run(['/usr/lib/lanrith/verify-ssh-listeners'], 'SSH management listeners')
    if plan['schema'] == 2 and 'kea-dhcp4-server.service' in plan['units']:
        run(['/usr/lib/lanrith/verify-kea-sockets'], 'Kea scope listeners')
    if 'dns' in plan:
        check_dns(plan['dns'], run)


def check_features(plan):
    for probe in plan['probes']:
        manifest = json.loads(read(Path('/usr/share/lanrith', probe+'.json'), 1024*1024))
        if probe == 'ownership':
            from .hardware import ownership_status as status
        else:
            ready(probe == 'nat46' or plan.get('native_translation') is True,
                    'Legacy translation health plans require their original image runtime.')
            from .translation_runtime import status
        try:
            status(manifest)
        except (ReleaseError, OSError, subprocess.SubprocessError) as error:
            raise LocalRequirementFailed(f'Required {probe} feature readiness failed.') from error
