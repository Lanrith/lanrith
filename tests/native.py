#!/usr/bin/env python3
"""Parse and load synthetic network configurations in a disposable namespace."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import ipaddress
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config
from vm import network_hardening

if '--isolated' not in sys.argv:
    if os.geteuid() != 0:
        raise SystemExit('Native configuration checks require an isolated root namespace.')
    subprocess.run(['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()), '--isolated'], check=True)
    raise SystemExit(0)

for example in ('minimal.yaml', 'segmented.yaml'):
    value = config.load(Path(__file__).resolve().parents[1]/'examples'/example)
    with tempfile.TemporaryDirectory(prefix='lanrith-native.') as temporary:
        output = Path(temporary)/'root'
        config.write(value, output)
        sysctls = output/'etc/sysctl.d/90-lanrith-routing.conf'
        names = {network['name'] for network in value['networks'].values()}
        names.add(value['hardware']['interfaces'][value['uplink']['interface']]['name'])
        early = 'early.link'
        try:
            # Reproduce a device that appears before systemd-sysctl and has
            # unsafe per-link values. All writes stay in this fresh netns.
            subprocess.run(['ip', 'link', 'add', early, 'type', 'dummy'], check=True)
            subprocess.run(['sysctl', '--quiet', '--write', 'net/ipv4/conf/'+early+'/send_redirects=1',
                            'net/ipv6/conf/'+early+'/accept_source_route=0'], check=True)
            try:
                network_hardening()
            except AssertionError:
                pass
            else:
                raise AssertionError('Unsafe interface positive control was not detected.')
            subprocess.run(['/usr/lib/systemd/systemd-sysctl', str(sysctls)], check=True)
            network_hardening()
            for name in names:
                subprocess.run(['ip', 'link', 'add', name, 'type', 'dummy'], check=True)
                subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
            # Later links must inherit the safe defaults too. Reading actual
            # procfs values avoids trusting the generated file as its own oracle.
            network_hardening()
            subprocess.run(['nft', '--check', '--file', str(output/'etc/nftables.conf')], check=True)
            subprocess.run(['nft', '--file', str(output/'etc/nftables.conf')], check=True)
            subprocess.run(['unbound-checkconf', str(output/'etc/unbound/unbound.conf.d/lanrith.conf')], check=True)
            # No gateway addresses have been assigned yet, as can happen
            # before IPv6 DAD completes during boot. Explicit DNS listeners
            # must start without opening wildcard addresses.
            # Respect Ubuntu's existing Unbound AppArmor configuration boundary.
            descriptor, name = tempfile.mkstemp(prefix='lanrith-native.', suffix='.conf', dir='/etc/unbound')
            os.close(descriptor)
            candidate_dns = Path(name)
            candidate_dns.write_text((output/'etc/unbound/unbound.conf.d/lanrith.conf').read_text()+
                '  port: 1053\n  username: ""\n  directory: "/etc/unbound"\n  use-syslog: no\n')
            daemon = subprocess.Popen(['unbound', '-d', '-p', '-c', str(candidate_dns)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                expected = {'127.0.0.1', '::1'} | set(config.intent.service_addresses(value, 'dns'))
                deadline = time.monotonic()+10
                while True:
                    sockets = subprocess.run(['ss', '--no-header', '--listening', '--udp', '--tcp', '--numeric',
                                               'sport = :1053'], check=True, capture_output=True, text=True)
                    observed = {(row[0], row[4].removesuffix(':1053').strip('[]'))
                                for line in sockets.stdout.splitlines() if (row := line.split())}
                    if observed == {(protocol, address) for protocol in ('tcp', 'udp') for address in expected}:
                        break
                    if daemon.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError('DNS did not bind only its declared addresses before network readiness.')
                    time.sleep(0.05)
            finally:
                daemon.terminate()
                daemon.communicate(timeout=10)
                candidate_dns.unlink()
            # Ubuntu's Kea AppArmor profile permits /etc/kea, not arbitrary /tmp files.
            # Use the production configuration boundary without changing that policy.
            descriptor, name = tempfile.mkstemp(prefix='lanrith-native.', suffix='.json', dir='/etc/kea')
            os.close(descriptor)
            candidate = Path(name)
            try:
                shutil.copyfile(output/'etc/kea/kea-dhcp4.conf', candidate)
                candidate.chmod(0o644)
                subprocess.run(['kea-dhcp4', '-t', str(candidate)], check=True)
            finally:
                candidate.unlink()
        finally:
            for name in names | {early}:
                subprocess.run(['ip', 'link', 'delete', name], check=False, capture_output=True)
# Parse less common generic selectors too; every value is synthetic.
value = config.load(Path(__file__).resolve().parents[1]/'examples/segmented.yaml')
rules = []
for protocol in ('tcp', 'udp', 'sctp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah'):
    rule = {'action': 'allow', 'from': 'home', 'to': 'guest', 'protocol': protocol}
    if protocol in ('tcp', 'udp', 'sctp'):
        rule['ports'] = [80, 443]
    if protocol == 'tcp':
        rule.update(tcp_flags=['ack', 'syn'], states=['established'], direction='reply')
    if protocol in ('icmp', 'icmpv6'):
        rule.update(icmp_types=['echo-reply', 3], icmp_codes=[0, 1])
    rules.append(rule)
rules.append({'action': 'deny', 'from': {'network': 'home', 'addresses': ['192.0.2.1', '2001:db8::1'],
              'mac': '02:00:00:00:00:07'}, 'to': {'interface': 'tunnel0',
              'addresses': ['198.51.100.0/24', '2001:db8:1::/64']}})
value['access'] = {'rules': rules}
with tempfile.TemporaryDirectory(prefix='lanrith-access-native.') as temporary:
    path = Path(temporary)/'nftables.conf'
    path.write_text(config.render(value)['etc/nftables.conf'])
    subprocess.run(['nft', '--check', '--file', str(path)], check=True)
print('Both topologies passed native firewall, DNS, DHCP and effective network hardening; advanced generic selectors also parse.')

# Validate generated ordering and executable paths without binding a device.
from test_hardware_ownership import declaration
value, facts = declaration()
with tempfile.TemporaryDirectory(prefix='lanrith-ownership-native.') as temporary:
    output = Path(temporary)/'root'
    config.write(value, output, target_facts=facts)
    unit = output/'usr/lib/systemd/system/lanrith-hardware-ownership.service'
    subprocess.run(['systemd-analyze', 'verify', '--man=no', str(unit)], check=True)
print('Dormant hardware ownership unit passed native systemd verification without touching hardware.')
