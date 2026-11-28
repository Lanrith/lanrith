"""Networkd and firewall contracts for static LANs and optional carriers."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from lanrith import boot_health, config, intent
from lanrith.release import ReleaseError


ROOT = Path(__file__).resolve().parents[1]
WAITER = 'etc/systemd/system/systemd-networkd-wait-online.service.d/60-lanrith.conf'
WAN = 'etc/systemd/network/20-uplink.network'
HOME = 'etc/systemd/network/40-home.network'


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.value = config.load(ROOT/'examples/minimal.yaml')

    def test_waiter_scopes_and_management(self):
        self.value['hardware']['interfaces']['mgt'] = {'match': {'mac': '02:00:00:00:01:03'}}
        self.value['networks']['mgt'] = {'interface': 'mgt', 'role': 'management', 'ipv4': '192.0.2.0/24'}
        files = config.render(self.value)
        self.assertIn('--interface=lan --interface=mgt --timeout=', files[WAITER])
        self.assertNotIn('--interface=wan', files[WAITER])
        self.assertIn('RequiredFamilyForOnline=both', files[HOME])
        self.assertIn('RequiredForOnline=no', files[WAN])
        self.assertIn('ConfigureWithoutCarrier=yes', files['etc/systemd/network/40-mgt.network'])
        self.assertNotIn('ConfigureWithoutCarrier=yes', files[HOME])
        health = json.loads(files['usr/share/lanrith/health.json'])
        self.assertIn({'name': 'mgt', 'addresses': ['192.0.2.1/24'], 'carrier_optional': True}, health['interfaces'])
        def without_gateways(argv, timeout):
            return 'active' if argv[0] == 'systemctl' else '[]'
        with patch.object(boot_health, 'command', without_gateways), self.assertRaises(ReleaseError):
            boot_health.check(health)
        self.value['uplink']['required_for_online'] = True
        files = config.render(self.value)
        self.assertIn('--interface=wan', files[WAITER])
        self.assertIn('RequiredFamilyForOnline=both', files[WAN])
        self.assertIn('systemd-networkd-wait-online.service', json.loads(files['usr/share/lanrith/health.json'])['units'])

    def test_ra_wan_does_not_solicit_dhcpv6(self):
        files = config.render(self.value)
        self.assertIn('[IPv6AcceptRA]\nDHCPv6Client=no\nUseDNS=no', files[WAN])
        self.assertIn('DHCP=ipv4', files[WAN])
        self.assertNotIn('udp dport 547', files['etc/nftables.conf'])
        self.value['uplink']['ipv6'] = 'disabled'
        self.assertNotIn('[IPv6AcceptRA]', config.render(self.value)[WAN])

    def test_local_delivery_and_upstream_private_routes(self):
        self.value['services']['ntp'] = {'enabled': True, 'upstreams': ['192.0.2.123']}
        self.value['networks']['home']['ntp'] = True
        self.value['networks']['home']['ipv6_upstream_routes'] = ['fd12:3456:7890::/64']
        files = config.render(self.value)
        self.assertIn('RouterLifetimeSec=0', files[HOME])
        self.assertIn('[IPv6Prefix]\nPrefix=fd42:1000:1000:10::/64', files[HOME])
        self.assertIn('Route=fd12:3456:7890::/64', files[HOME])
        for feature in ('dns', 'ntp'):
            self.assertIn('Route='+intent.service_addresses(self.value, feature)[1]+'/128', files[HOME])
        rule = 'iifname "lan" oifname "wan" meta nfproto ipv6 ip6 daddr != { fd12:3456:7890::/64 } drop'
        for backend in ('legacy', 'tun'):
            fw = config.render(self.value, access_backend=backend)['etc/nftables.conf']
            self.assertLess(fw.index(rule), fw.index('ct state invalid,untracked drop'))
        self.value['networks']['home']['ipv6_upstream_routes'] = ['::/0']
        with self.assertRaises(ReleaseError):
            config.render(self.value)

    def test_routed_allocations_and_on_link_provider(self):
        self.value['uplink'].update(downstream_prefix='2001:db8:20::/48', delivery='routed')
        lan = self.value['networks']['home']
        lan['addresses'].append('2001:db8:20:2::1/64')
        files = config.render(self.value)
        self.assertNotIn('RouterLifetimeSec=0', files[HOME])
        guard = 'oifname "wan" meta nfproto ipv6 ip6 saddr != { 2001:db8:20:2::/64 } drop'
        self.assertIn(guard, files['etc/nftables.conf'])
        self.value['uplink']['delivery'] = 'on_link'
        self.assertIn('RouterLifetimeSec=0', config.render(self.value)[HOME])
        lan['ipv6_delivery'] = 'routed'
        self.assertNotIn('RouterLifetimeSec=0', config.render(self.value)[HOME])
        lan['addresses'][-1] = '2001:db8:99:2::1/64'
        with self.assertRaisesRegex(ReleaseError, 'downstream allocation'):
            config.render(self.value)

    def test_only_selected_lan_advertises_selected_translator(self):
        value = config.load(ROOT/'examples/segmented.yaml')
        value['translation'] = {'nat64': {'enabled': True}}
        value['access'] = {'rules': [{'action': 'allow', 'from': 'home', 'to': {'translation': 'nat64'},
                                      'protocol': 'tcp', 'ports': [443]}]}
        plain = config.render(value)
        self.assertNotIn('[IPv6PREF64Prefix]', plain[HOME])
        for translator in ('nat64', 'nat64-internal'):
            select = copy.deepcopy(value)
            select['networks']['home']['pref64'] = translator
            selected = config.render(select)
            prefix = intent.translations(value)[translator]['prefix']
            self.assertEqual(selected[f'usr/lib/lanrith/networkd/pref64-{translator}.conf'],
                             '[IPv6PREF64Prefix]\nPrefix='+prefix+'\nLifetimeSec=1800\n')
            unit = selected[f'usr/lib/systemd/system/lanrith-pref64-{translator}.service']
            self.assertIn('40-home.network.d/60-lanrith-pref64.conf', unit)
            self.assertNotIn('40-guest.network.d', unit)
            self.assertIn(f'BindsTo=lanrith-{translator}.service', unit)
            self.assertEqual(plain['etc/nftables.conf'], selected['etc/nftables.conf'])
            for key in set(value['networks']) - {'home'}:
                self.assertNotIn('[IPv6PREF64Prefix]', selected[f'etc/systemd/network/40-{key}.network'])
        for change in ('off', 'unavailable', 'denied', 'foreign', 'v4', 'disabled-ra'):
            selected = copy.deepcopy(value)
            selected['networks']['home']['pref64'] = 'nat64' if change != 'unavailable' else 'nat46'
            rule = selected['access']['rules'][0]
            if change == 'denied':
                rule['action'] = 'deny'
            if change == 'off':
                selected['translation']['nat64']['enabled'] = False
            if change == 'foreign':
                rule['from'] = {'network': 'home', 'addresses': '2001:db8:100::/64'}
            if change == 'v4':
                rule['family'] = 'ipv4'
            if change == 'disabled-ra':
                selected['networks']['home']['ra'] = False
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                config.normalize(selected)
