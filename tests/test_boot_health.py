"""Signed local boot requirements and failure boundaries."""

import copy
import json
import ipaddress
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from lanrith import boot_health, config, runtime_plan
from lanrith.release import ReleaseError
from test_authoritative import declaration
from test_logs import declaration as logs_declaration
from test_snmp import fixture as snmp_profile


ROOT = Path(__file__).resolve().parents[1]


def monitored_profile():
    value = logs_declaration()
    value['services'].update(declaration()['services'])
    value['observability'].update({
        'metrics': {'enabled': True, 'clients': [{'network': 'home'}]},
        'snmp': snmp_profile()['observability']['snmp'],
        'ids': {'enabled': True},
    })
    value['hardware']['interfaces']['oob'] = {'match': {'mac': '02:00:00:00:99:01'}}
    value['networks']['management'] = {'interface': 'oob', 'ipv4': '192.0.2.0/28',
                                       'role': 'management', 'forwarding': False, 'dns': False, 'ntp': False}
    value['networks']['lab'] = {'interface': 'lan', 'vlan': 40, 'ipv4': '198.51.100.0/28',
                                'namespace': 'lab-test', 'forwarding': False, 'dns': False, 'ntp': False}
    return value


class BootHealthTests(unittest.TestCase):
    def test_minimal_and_monitored_profiles_match_the_actual_renderer(self):
        for profile_name, value in (('minimal', config.load(ROOT/'examples/minimal.yaml')), ('monitored', monitored_profile())):
            with self.subTest(profile=profile_name):
                files = config.render(value)
                plan = json.loads(files['usr/share/lanrith/health.json'])
                boot_health.validate(plan)
                self.assertIn('kea-dhcp4-server.service', plan['units'])
                scopes = json.loads(files['usr/share/lanrith/kea-listeners.json'])
                interfaces = {i['name']: i for i in plan['interfaces']}
                for name, (address, length) in scopes.items():
                    self.assertIn(f'{address}/{length}', interfaces[name]['addresses'])
                checks = plan['dns']
                self.assertEqual(files['etc/resolv.conf'], 'nameserver '+checks['listeners'][0]+'\n')
                for address in checks['listeners']:
                    self.assertIn('interface: '+address+'\n', files['etc/unbound/unbound.conf.d/lanrith.conf'])
                self.assertFalse(any(unit.endswith('.timer') for unit in plan['units']))
                if profile_name == 'minimal':
                    self.assertEqual(checks['queries'], [['localhost.', 'A', ['127.0.0.1']]])
                    self.assertNotIn('wan', interfaces)
                    continue
                self.assertEqual(set(runtime_plan.advisory_timers(config.normalize(value))),
                                 {'lanrith-telemetry-heartbeat.timer', 'lanrith-router-metrics.timer',
                                  'lanrith-ntp-health.timer', 'lanrith-directory-health.timer', 'lanrith-ids-rotate.timer'})
                self.assertIn({'to': '0.0.0.0/0', 'via': '10.243.0.1'}, interfaces['wan']['routes'])
                self.assertEqual(interfaces['lan.40']['namespace'], 'lab-test')
                self.assertTrue(interfaces['oob']['carrier_optional'])
                zone = files['usr/share/lanrith/zones/db.home.arpa']
                for name in ('dns', 'ns1', 'ntp', 'snmp', 'metrics'):
                    addresses = next(answers for owner, kind, answers in checks['queries']
                                     if owner == name+'.home.arpa.' and kind == 'AAAA')
                    self.assertIn(name+' IN AAAA '+addresses[0]+'\n', zone)
                self.assertFalse(any(owner.startswith('directory.') for owner, _, _ in checks['queries']))

    def test_chrony_only_requires_private_dns_for_named_upstreams(self):
        value = declaration()
        for servers, required in ((['192.0.2.5', {'type': 'server', 'address': '2001:db8::4'}], False),
                                  (['192.0.2.5', {'type': 'pool', 'address': 'peer.home.arpa'}], True)):
            with self.subTest(servers=servers):
                value['services']['ntp'] = {'enabled': True, 'upstreams': servers}
                files = config.render(value)
                plan = json.loads(files['usr/share/lanrith/health.json'])
                self.assertEqual(plan['dns']['ntp_client'], required)
                self.assertIn('chrony.service', plan['units'])

    def test_persistent_managed_additions_and_removals_have_signed_expectations(self):
        value = declaration()
        zone = value['services']['dns']['authoritative']['zones']['example.test']
        zone['managed_rrsets'] = {'seeded': {'A': {'previous': []}},
                                  'old': {'AAAA': {'previous': ['fd00::20'], 'remove': True}}}
        plan = json.loads(config.render(value)['usr/share/lanrith/health.json'])
        self.assertIn(['seeded.example.test.', 'A', ['192.0.2.20']], plan['dns']['queries'])
        self.assertIn(['old.example.test.', 'AAAA', []], plan['dns']['queries'])

    def test_local_authority_remains_reachable_on_single_stack_and_disconnected_profiles(self):
        for ipv4, ipv6, family in (('dhcp', 'disabled', 4), ('disabled', 'ra', 6), ('disabled', 'disabled', 6)):
            value = declaration()
            value['uplink'] = {'interface': 'wan', 'ipv4': ipv4, 'ipv6': ipv6}
            files = config.render(value)
            dns = json.loads(files['usr/share/lanrith/health.json'])['dns']
            text = files['etc/unbound/unbound.conf.d/lanrith.conf']
            self.assertEqual(ipaddress.ip_address(dns['authority']).version, family)
            self.assertIn('stub-addr: '+dns['authority']+'\n', text)
            blocks = [ipaddress.ip_network(line.split()[-1]) for line in text.splitlines() if 'do-not-query-address:' in line]
            self.assertFalse(any(ipaddress.ip_address(dns['authority']) in subnet for subnet in blocks))
            if ipv4 == ipv6 == 'disabled':
                for external in ('192.0.2.45', '2001:db8:10::4'):
                    self.assertTrue(any(ipaddress.ip_address(external) in subnet for subnet in blocks))

    def test_usable_cidrs_and_link_flags(self):
        lan = {'name': 'lan', 'addresses': ['fd00::1/64']}
        address = {'local': 'fd00::1', 'prefixlen': 64, 'preferred_life_time': 63}
        def inspect(flags, **changes):
            row = {'ifname': 'lan', 'flags': flags, 'addr_info': [{**address, **changes}]}
            boot_health.check_interface(lan, lambda *args: json.dumps([row]))

        inspect(['UP', 'LOWER_UP'])
        for flags in ([], ['UP'], ['LOWER_UP'], ['UP', 'LOWER_UP', 'DORMANT']):
            with self.subTest(flags=flags), self.assertRaises(ReleaseError):
                inspect(flags)
        for mutation in ({'local': 'fd00::2'}, {'prefixlen': 128}, {'tentative': True},
                         {'dadfailed': True}, {'deprecated': True}, {'preferred_life_time': 0}):
            with self.subTest(mutation=mutation), self.assertRaises(ReleaseError):
                inspect(['UP', 'LOWER_UP'], **mutation)
        lan['carrier_optional'] = True
        inspect(['UP'])
        wan = {'name': 'wan', 'addresses': [], 'optional': True}
        boot_health.check_interface(wan, lambda *args: '[]')

    def test_optional_static_wan_without_a_gateway(self):
        value = config.load(ROOT/'examples/minimal.yaml')
        value['uplink'] = {'interface': 'wan', 'ipv4': 'static', 'addresses': ['192.0.2.2/24'], 'ipv6': 'disabled'}
        plan = json.loads(config.render(value)['usr/share/lanrith/health.json'])
        wan = next(item for item in plan['interfaces'] if item['name'] == 'wan')
        self.assertEqual(wan['addresses'], ['192.0.2.2/24'])
        self.assertEqual(wan['routes'], [])
        boot_health.check_interface(wan, lambda *args: '[]')
        row = {'ifname': 'wan', 'flags': ['UP', 'LOWER_UP'], 'addr_info': []}
        with self.assertRaisesRegex(ReleaseError, '192.0.2.2/24'):
            boot_health.check_interface(wan, lambda *args: json.dumps([row]))

    def test_required_dynamic_wan_needs_a_live_address_in_each_family(self):
        value = config.load(ROOT/'examples/minimal.yaml')
        value['uplink']['required_for_online'] = True
        plan = json.loads(config.render(value)['usr/share/lanrith/health.json'])
        wan = next(item for item in plan['interfaces'] if item['name'] == 'wan')
        self.assertEqual(wan['routable_families'], [4, 6])
        self.assertEqual(wan['routes'], [{'to': '0.0.0.0/0'}, {'to': '::/0'}])
        row = {'ifname': 'wan', 'flags': ['UP', 'LOWER_UP'], 'addr_info': [
            {'local': '192.0.2.1', 'prefixlen': 24, 'scope': 'global'},
            {'local': 'fe80::1', 'prefixlen': 64, 'scope': 'link'}]}
        with self.assertRaisesRegex(ReleaseError, 'routable IPv6'):
            boot_health.check_interface(wan, lambda *args: json.dumps([row]))

    def test_host_resolver_mismatch_sends_no_query(self):
        with patch.object(boot_health, 'read', return_value=b'nameserver 192.0.2.9\n'):
            run = Mock()
            with self.assertRaisesRegex(ReleaseError, 'Host DNS resolver'):
                boot_health.check_dns({'listeners': ['192.0.2.10']}, run)
            run.assert_not_called()

    def test_old_signed_contract_retains_address_only_behavior(self):
        plan = {'schema': 1, 'probes': [], 'units': ['ssh.service', 'systemd-networkd.service', 'nftables.service'],
                'interfaces': [{'name': 'lan', 'addresses': ['fd00::1']}]}
        def command(args, timeout):
            if args[0] == 'systemctl':
                return 'active'
            self.assertEqual(args[:3], ['ip', '-j', 'address'])
            return '[{"ifname":"lan","addr_info":[{"local":"fd00::1"}]}]'
        with patch.object(boot_health, 'command', command):
            boot_health.check(plan)
            broken = copy.deepcopy(plan)
            broken['interfaces'][0]['addresses'][0] = 'fd00::2'
            with self.assertRaisesRegex(ReleaseError, 'gateway'):
                boot_health.check(broken)

    def test_settle_and_shared_deadline(self):
        plan = {'schema': 2, 'probes': [], 'units': ['ssh.service', 'systemd-networkd.service', 'nftables.service'],
                'interfaces': [{'name': 'lan', 'addresses': ['192.0.2.1/24']}]}
        with patch.object(boot_health, 'check_local', side_effect=[ReleaseError('not ready'), None]) as check:
            boot_health.check(plan, settle_seconds=1)
            self.assertEqual(check.call_count, 2)
        with patch.object(boot_health.time, 'monotonic', side_effect=[1, 1, 42, 42]), \
                patch.object(boot_health, 'command') as run:
            with self.assertRaisesRegex(ReleaseError, 'deadline'):
                boot_health.check(plan, settle_seconds=1)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
