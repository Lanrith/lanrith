#!/usr/bin/env python3
"""Qualify SNMP host data, scoped polling and credential recovery offline."""

import argparse
import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, '/usr/lib/lanrith')
from lanrith import config, service_runtime, snmp
from phase_b_native import run, ns
from test_intent import minimal
import snmp_credentials
import snmp_service
from credential_runtime import Activation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gua', action='store_true')
    parser.add_argument('--with-core-services', action='store_true')
    parser.add_argument('--legacy-custody', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0 and {a['ifname'] for a in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}, \
        'Refusing an existing network topology.'
    # The kernel's empty initramfs root starts at 01777. Match the protected
    # image root and standard service umask before creating fixture state.
    Path('/').chmod(0o755)
    os.umask(0o022)
    value = minimal()
    value['uplink'] = {'interface': 'wan', 'ipv4': {'address': '198.51.100.1/24', 'gateway': '198.51.100.2'},
                       'ipv6': {'address': '2001:db8:100::1/64', 'gateway': '2001:db8:100::2'}}
    value['services'] = {'dns': {'enabled': args.with_core_services},
                         'ntp': {'enabled': args.with_core_services}, 'dhcp4': {'enabled': False}}
    if args.gua:
        value['uplink']['ipv6'].update(downstream_prefix='2001:db8:100::/48', delivery='on_link')
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    value['hardware']['interfaces']['guest'] = {'match': {'mac': '02:00:00:00:02:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.0.0/24',
                                 'ipv6': {'subnet_id': 32, 'ra': False, 'gua': False}}
    value['routing'] = {'static_routes': [{'to': 'fd42:1234:5678:ffff::/64', 'network': 'home', 'on_link': True}]}
    value['observability'] = {'snmp': {'enabled': True, 'username': 'synthetic-monitor', 'credential': 'monitor_user',
        'clients': [{'network': 'home', 'addresses': 'fd42:1234:5678:10::2/128'},
                    {'addresses': 'fd42:1234:5678:ffff::56/128'}]}}
    if args.legacy_custody:
        value['runtime'] = {'credentials': {'monitor_user': '/var/lib/example-router/snmp/snmpd.conf'},
                           'credential_headers': {'monitor_user': '# Managed by a previous example router runtime.\n'}}
    value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any', 'authorization': 'owner'}]}
    value = config.normalize(value)
    files = config.render(value)
    disabled = json.loads(json.dumps(value))
    disabled['observability']['snmp']['enabled'] = False
    disabled_files = config.render(disabled)
    policy = snmp_service.policy_value(snmp.manifest(value))
    credential = {'username': policy['username'], 'auth_protocol': 'SHA-256', 'priv_protocol': 'AES',
                  'auth_password': 'Synthetic-Authentication-Only-1', 'priv_password': 'Synthetic-Encryption-Only-1'}
    plane = json.loads(files['usr/share/lanrith/service-plane.json'])
    for name, content in files.items():
        path = Path('/')/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    run('systemd-analyze', 'verify', '--man=no', '--recursive-errors=no',
        '/usr/lib/systemd/system/snmpd.service', '/usr/lib/systemd/system/lanrith-services.service')
    run('ip', 'link', 'set', 'lo', 'up')
    run('sysctl', '--quiet', '--write', 'net.ipv6.conf.all.forwarding=1', 'net.ipv4.ip_forward=1')
    for name, addresses in (
            ('lan', ['192.168.10.1/24', 'fd42:1234:5678:10::1/64']),
            ('guest', ['172.20.0.1/24', 'fd42:1234:5678:20::1/64']),
            ('wan', ['198.51.100.1/24', '2001:db8:100::1/64'])):
        run('ip', 'netns', 'add', name+'-test')
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name+'-test')
        run('ip', 'link', 'set', name, 'up')
        ns(name+'-test', 'ip', 'link', 'set', 'lo', 'up')
        ns(name+'-test', 'ip', 'link', 'set', 'eth0', 'up')
        for address in addresses:
            local = ip.ip_interface(address)
            flags = ['nodad'] if local.version == 6 else []
            run('ip', 'address', 'add', address, 'dev', name, *flags)
            prefix = 48 if args.gua and name == 'wan' and local.version == 6 else local.network.prefixlen
            ns(name+'-test', 'ip', 'address', 'add', str(local.ip+1)+'/'+str(prefix), 'dev', 'eth0', *flags)
            ns(name+'-test', 'ip', '-'+str(local.version), 'route', 'add', 'default', 'via', str(local.ip))
    run('ip', 'link', 'add', 'hostproof0', 'type', 'veth', 'peer', 'name', 'hostproof1')
    run('ip', 'link', 'set', 'hostproof0', 'up')
    index = json.loads(run('ip', '-j', 'link', 'show', 'hostproof0').stdout)[0]['ifindex']
    for address in ('fd42:1234:5678:10::3/128', 'fd42:1234:5678:ffff::56/128', 'fd42:1234:5678:ffff::57/128'):
        ns('lan-test', 'ip', '-6', 'address', 'add', address, 'dev', 'eth0', 'nodad')
    ns('guest-test', 'ip', '-6', 'address', 'add', 'fd42:1234:5678:10::2/128', 'dev', 'eth0', 'nodad')
    run('ip', '-6', 'route', 'add', 'fd42:1234:5678:ffff::/64', 'dev', 'lan')
    run('nft', '-f', '/etc/nftables.conf')
    service_runtime.start(plane)
    work = Path('/run/lanrith-snmp')
    work.mkdir(mode=0o700, exist_ok=True)
    if args.legacy_custody:
        old_root = Path(policy['state_directory'])
        old_root.mkdir(mode=0o750, parents=True)
        account = pwd.getpwnam('Debian-snmp')
        os.chown(old_root, 0, account.pw_gid)
        old_file = old_root/'snmpd.conf'
        original = snmp_credentials.configuration(credential, policy['credential_header'])
        old_file.write_bytes(original)
        old_file.chmod(0o600)
        os.chown(old_file, 0, account.pw_gid)
    state = snmp_service.private_state(Path(policy['state_directory']), header=policy['credential_header'])
    if args.legacy_custody:
        assert old_file.read_bytes() == original
        assert old_file.stat().st_uid == old_file.stat().st_gid == 0
        assert state.root.stat().st_uid == state.root.stat().st_gid == 0
    log = work/'daemon.log'

    class FixtureService(snmp_service.Service):
        """Substitute PID-1 control only; acceptance uses real sockets and USM."""
        process = None
        fail_acceptance_once = False

        def status(self):
            live = self.process is not None and self.process.poll() is None
            return {'ActiveState': 'active' if live else 'inactive', 'SubState': 'running' if live else 'dead',
                    'MainPID': str(self.process.pid) if live else '0', 'ControlGroup': ''}

        def stop(self):
            if self.process is not None:
                self.process.terminate()
                self.process.wait(timeout=10)
                self.process = None

        def start(self):
            assert self.process is None
            prepared = subprocess.run(['/usr/lib/lanrith/snmp-runtime', 'prepare'],
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            assert prepared.returncode in (0, 1), 'Installed SNMP runtime preparation failed.'
            if prepared.returncode == 1:
                return
            with log.open('ab') as output:
                self.process = subprocess.Popen(['/usr/sbin/snmpd', '-f', '-LOw', '-u', 'Debian-snmp', '-g', 'Debian-snmp',
                    '-c', policy['state_directory']+'/snmpd.conf'],
                    stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                    env={**os.environ, 'MIBS': '', 'SNMP_PERSISTENT_DIR': '/var/lib/snmp'})
            deadline = time.monotonic()+8
            while time.monotonic() < deadline:
                assert self.process.poll() is None, 'SNMP daemon exited before readiness.'
                if policy['server'] in run('ss', '-H', '-lun6', 'sport = :161').stdout:
                    return
                time.sleep(.05)
            raise AssertionError('SNMP listener did not become ready.')

        def verify(self, values):
            verified = super().verify(values)
            if self.fail_acceptance_once and values['snmpd.conf'] == encoded(credential):
                self.fail_acceptance_once = False
                return False
            return verified

    service = FixtureService(policy)
    activation = Activation(state, service, service.preflight)

    def encoded(current):
        return snmp_credentials.configuration(current, policy['credential_header'])

    def poll(namespace, current, *, source='', allowed=True, level='authPriv', oid='.1.3.6.1.2.1.1.3.0', change=False):
        with tempfile.TemporaryDirectory(dir=work) as directory:
            path = Path(directory)/'snmp.conf'
            path.write_text('defSecurityLevel '+level+'\n'+
                'defSecurityName '+current['username']+'\n'+
                'defAuthType '+current['auth_protocol']+'\ndefPrivType '+current['priv_protocol']+'\n'+
                'defAuthPassphrase "'+current['auth_password']+'"\n'+
                'defPrivPassphrase "'+current['priv_password']+'"\n'+
                ('clientaddr '+source+'\n' if source else ''))
            path.chmod(0o600)
            argv = ['snmpset' if change else 'snmpget', '-v3', '-r0', '-t1', '-Oqv',
                    'udp6:['+policy['server']+']:161', oid]
            if change:
                argv += ['s', 'unapproved-change']
            if namespace:
                argv = ['nsenter', '--net=/run/netns/'+namespace, '--', *argv]
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                env={**os.environ, 'SNMPCONFPATH': directory, 'SNMP_PERSISTENT_DIR': directory, 'MIBS': ''})
            detail = result.stderr.decode(errors='replace')[-1000:]
            for key in ('auth_password', 'priv_password'):
                detail = detail.replace(current[key], '[redacted]')
            assert (result.returncode == 0) == allowed, \
                f'Unexpected SNMP admission: namespace={namespace} source={source} level={level} allowed={allowed}: {detail}'
            return result.stdout

    def engine():
        text = Path('/var/lib/snmp/snmpd.conf').read_text()
        identity = re.search(r'^oldEngineID (\S+)$', text, re.M)
        boots = re.search(r'^engineBoots ([0-9]+)$', text, re.M)
        assert identity and boots, 'Persistent USM engine data is missing.'
        return identity[1], int(boots[1])

    checks = []
    if args.legacy_custody:
        checks.append('retained private credential bytes survive validated metadata adoption')
    try:
        result = activation.apply({'snmpd.conf': encoded(credential)})
        assert result['changed'] and service.verify({'snmpd.conf': encoded(credential)})
        checks.append('real SNMPv3 authentication and encryption with generated configuration')
        status = Path('/proc', str(service.process.pid), 'status').read_text()
        account = pwd.getpwnam('Debian-snmp')
        assert re.search(r'^Uid:\s+'+(str(account.pw_uid)+r'\s+')*3+str(account.pw_uid)+r'$', status, re.M)
        for field in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'):
            assert re.search(r'^'+field+r':\s+0+$', status, re.M), 'Steady SNMP daemon retained capabilities.'
        snmp_credentials.listeners(*service.socket_inventory(), policy['server'])
        checks.append('nonroot host agent has no effective capabilities and one IPv6 listener')
        poll('lan-test', credential, source='fd42:1234:5678:10::2')
        poll('lan-test', credential, source='fd42:1234:5678:ffff::56')
        assert b'hostproof0' in poll('lan-test', credential, source='fd42:1234:5678:10::2',
            oid='.1.3.6.1.2.1.31.1.1.1.1.'+str(index)), 'SNMP reported namespace rather than host interfaces.'
        checks.append('declared collectors read real host interface data')
        pinned = '[fd42:1234:5678:10::2]:49161'
        poll('lan-test', credential, source=pinned)
        poll('lan-test', credential, source=pinned)
        restricted = json.loads(json.dumps(value))
        restricted['observability']['snmp']['clients'] = [{'addresses': 'fd42:1234:5678:ffff::56/128'}]
        Path('/run/withdrawn-snmp.nft').write_text(config.render(restricted)['etc/nftables.conf'])
        run('nft', '-f', '/run/withdrawn-snmp.nft')
        Path('/run/observed-snmp.nft').write_text('table inet snmp_observation {\n counter old_tuple {}\n'
            'chain seen {\n type filter hook input priority -1;policy accept;\n'
            'ip6 saddr fd42:1234:5678:10::2 udp sport 49161 udp dport 161 '
            'ct state established counter name old_tuple\n}\n}\n')
        run('nft', '-f', '/run/observed-snmp.nft')
        poll('lan-test', credential, source=pinned, allowed=False)
        seen = json.loads(run('nft', '-j', 'list', 'counter', 'inet', 'snmp_observation', 'old_tuple').stdout)
        assert next(item['counter']['packets'] for item in seen['nftables'] if 'counter' in item) > 0, \
            'Revocation did not exercise the confirmed original UDP tuple.'
        run('nft', '-f', '/etc/nftables.conf')
        poll('lan-test', credential, source=pinned)
        checks.append('collector withdrawal rejects the confirmed UDP tuple before generic stateful admission')
        for namespace, source in (('lan-test', 'fd42:1234:5678:10::3'), ('lan-test', 'fd42:1234:5678:ffff::57'),
                                  ('guest-test', ''), ('guest-test', 'fd42:1234:5678:10::2'), ('wan-test', '')):
            poll(namespace, credential, source=source, allowed=False)
        if args.gua:
            neighbours = json.loads(ns('wan-test', 'ip', '-j', '-6', 'neighbour', 'show', policy['server']).stdout)
            assert len(neighbours) == 1 and 'lladdr' in neighbours[0], 'Upstream service-address ND proxy did not resolve.'
            checks.append('on-link provider GUA resolves upstream without granting WAN service access')
        checks.append('undeclared collector extra attachment wrong interface and WAN denied')
        for level in ('noAuthNoPriv', 'authNoPriv'):
            poll('lan-test', credential, source='fd42:1234:5678:10::2', level=level, allowed=False)
        poll('lan-test', credential, source='fd42:1234:5678:10::2', change=True,
             oid='.1.3.6.1.2.1.1.6.0', allowed=False)
        checks.append('unauthenticated unencrypted and write requests denied')
        service.stop()
        original_id, original_boots = engine()
        service.start()
        poll('lan-test', credential, source='fd42:1234:5678:10::2')
        rotated = {**credential, 'auth_password': 'Synthetic-Authentication-Only-2',
                   'priv_password': 'Synthetic-Encryption-Only-2'}
        activation.apply({'snmpd.conf': encoded(rotated)})
        poll('lan-test', rotated, source='fd42:1234:5678:10::2')
        poll('lan-test', credential, source='fd42:1234:5678:10::2', allowed=False)
        checks.append('credential rotation replaces old localized users without resetting the engine')
        service.fail_acceptance_once = True
        try:
            activation.apply({'snmpd.conf': encoded(credential)})
        except snmp_credentials.SNMPError as error:
            assert error.code == 69, 'Credential rollback did not finish authenticated verification.'
        else:
            raise AssertionError('Injected post-start acceptance failure did not roll back.')
        assert state.values(['snmpd.conf'])['snmpd.conf'] == encoded(rotated)
        assert (state.root/'snmpd.conf').read_bytes() == encoded(rotated)
        poll('lan-test', rotated, source='fd42:1234:5678:10::2')
        poll('lan-test', credential, source='fd42:1234:5678:10::2', allowed=False)
        service.stop()
        current_id, current_boots = engine()
        assert current_id == original_id and current_boots > original_boots
        checks.append('failed activation restores verified credentials and engine boot count increases')
        run('nft', '-f', '/etc/nftables.conf')
        # Daemon startup consumes only its generated files and narrow runtime
        # policy after source configuration and compiler files are removed.
        for path in Path('/work/examples').glob('*.yaml'):
            path.unlink()
        Path('/work/lanrith/config.py').unlink()
        Path('/work/lanrith/__pycache__/config.cpython-313.pyc').unlink(missing_ok=True)
        service.start()
        poll('lan-test', rotated, source='fd42:1234:5678:10::2')
        checks.append('restart needs no owner YAML or compiler')
        service.stop()
        service_runtime.stop(plane)
        assert not any('snmp' in name for name in disabled_files)
        Path('/etc/nftables.conf').write_text(disabled_files['etc/nftables.conf'])
        run('nft', '-f', '/etc/nftables.conf')
        assert '161' not in run('ss', '-H', '-lun').stdout
        assert not Path('/sys/class/net/lr-services').exists()
        checks.append('disabled component removes listener service attachment and collector rules')
        print(json.dumps({'result': 'pass', 'checks': checks, 'pid1_service_control_substituted': True,
                          'provider_gua': args.gua, 'dns_ntp_configured': args.with_core_services,
                          'retained_credential_format': args.legacy_custody,
                          'image_boot_qualified': False, 'private_image_qualified': False}), flush=True)
    except BaseException:
        text = log.read_text() if log.exists() else ''
        for password in ('Synthetic-Authentication-Only-1', 'Synthetic-Encryption-Only-1',
                         'Synthetic-Authentication-Only-2', 'Synthetic-Encryption-Only-2'):
            text = text.replace(password, '[redacted]')
        print('SNMP failure diagnostic', text[-4000:], flush=True)
        raise
    finally:
        service.stop()


if __name__ == '__main__':
    main()
