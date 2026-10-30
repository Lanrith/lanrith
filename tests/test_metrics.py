"""Host metrics keep collector scope and service isolation independently of DNS."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from lanrith import authoritative, build, config, metrics, metrics_runtime
from lanrith.release import ReleaseError
from test_intent import minimal


def fixture():
    value = minimal()
    value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}}
    value['observability'] = {'metrics': {'enabled': True, 'clients': [{'network': 'home'}]}}
    return value


class MetricsTests(unittest.TestCase):
    def test_metrics_has_no_dns_ntp_or_identity_runtime_dependency(self):
        files = config.render(fixture())
        self.assertNotIn('etc/chrony/chrony.conf', files)
        self.assertNotIn('etc/unbound/unbound.conf.d/lanrith.conf', files)
        self.assertIn('usr/lib/systemd/system/lanrith-services.service', files)
        plane = json.loads(files['usr/share/lanrith/service-plane.json'])
        self.assertEqual(plane['endpoints'], {'metrics': ['10.255.254.50', 'fd42:1234:5678:fe02::50']})
        exporter = files['usr/lib/systemd/system/prometheus-node-exporter.service']
        self.assertIn('NetworkNamespacePath=\n', exporter)
        self.assertIn('PrivateNetwork=no', exporter)
        self.assertIn('--web.listen-address=10.255.254.1:9101', exporter)
        self.assertIn('--collector.systemd.unit-include=^.+[.](service|socket)$$', exporter)
        self.assertIn('--collector.textfile.directory=/var/lib/node_exporter/textfile_collector', exporter)
        proxy = files['usr/lib/systemd/system/lanrith-metrics.service']
        self.assertIn('NetworkNamespacePath=/run/netns/lanrith-services', proxy)
        self.assertIn('CapabilityBoundingSet=\n', proxy)
        collector = files['usr/lib/systemd/system/lanrith-router-metrics.service']
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\n', collector)
        self.assertIn('RestrictAddressFamilies=AF_UNIX AF_NETLINK\n', collector)
        self.assertIn('Unit=lanrith-router-metrics.service\n',
                      files['usr/lib/systemd/system/lanrith-router-metrics.timer'])
        self.assertIn('0755 root root', files['usr/lib/tmpfiles.d/80-lanrith-metrics.conf'])
        self.assertEqual(json.loads(files['usr/share/lanrith/router-metrics.json'])['interfaces'], ['lan', 'wan'])
        self.assertFalse((Path(__file__).parents[1]/'mkosi/base/mkosi.extra/usr/lib/systemd/system/lanrith-metrics.timer').exists())

    def test_selected_metrics_units_and_runtime_are_required_for_boot_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            build.assembly(fixture(), base, root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            health = (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text()
            for name in ('lanrith-metrics.service', 'prometheus-node-exporter.service', 'lanrith-services.service'):
                self.assertIn(name, health)
                self.assertTrue((overlay/'etc/systemd/system'/name).is_symlink())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/metrics_runtime.py').is_file())
            self.assertEqual(json.loads((overlay/'usr/share/lanrith/router-metrics.json').read_bytes())['units'],
                             json.loads((overlay/'usr/share/lanrith/health.json').read_bytes())['units'])
            self.assertTrue((overlay/'usr/lib/lanrith/router-metrics').is_file())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/router_metrics_runtime.py').is_file())

    def test_client_and_backend_rules_keep_interface_endpoint_port_and_uid(self):
        files = config.render(fixture())
        self.assertIn('oifname "lr-services" iifname "lan" ip saddr { 192.168.10.0/24 } '
                      'ip daddr { 10.255.254.50 } tcp dport 9100 accept', files['etc/nftables.conf'])
        self.assertIn('iifname "lr-services" ip saddr 10.255.254.50 ip daddr 10.255.254.1 tcp dport 9101 accept',
                      files['etc/nftables.conf'])
        self.assertIn('meta skuid "lanrith-metrics" ip saddr 10.255.254.50 ip daddr 10.255.254.1 '
                      'tcp dport 9101 accept', files['etc/lanrith/services.nft'])
        self.assertNotIn('tcp dport 9101 accept', '\n'.join(metrics.client_rules(config.normalize(fixture()))))

    def test_disabling_metrics_removes_its_addresses_rules_and_units(self):
        value = fixture()
        value['observability']['metrics']['enabled'] = False
        files = config.render(value)
        self.assertFalse(any('metrics' in path or 'node-exporter' in path for path in files))
        self.assertNotIn('10.255.254.50', files['etc/nftables.conf'])
        self.assertNotIn('usr/share/lanrith/service-plane.json', files)

    def test_custom_ranges_and_gua_keep_stable_component_addresses(self):
        value = fixture()
        value['addressing']['services'] = {'ipv4': '172.30.40.0/24', 'ipv6': 'fd42:1234:5678:700::/64'}
        value['uplink']['ipv6'] = {'address': '2001:db8:20::2/48', 'gateway': '2001:db8:20::1',
                                  'downstream_prefix': '2001:db8:20::/48', 'delivery': 'on_link'}
        settings = json.loads(config.render(value)['usr/share/lanrith/metrics.json'])
        self.assertEqual(settings['listeners'], ['172.30.40.50', 'fd42:1234:5678:700::50', '2001:db8:20:700::50'])
        self.assertEqual(settings['backend'], '172.30.40.1')
        self.assertEqual(metrics_runtime.validate(settings), settings)

    def test_authoritative_dns_generates_metrics_records_only_when_enabled(self):
        value = fixture()
        value['services']['dns'] = {'authoritative': {'enabled': True, 'primary_zone': 'home.arpa',
                                                     'zones': {'home.arpa': {}}}}
        records = authoritative.zone_records(config.normalize(value))['home.arpa']
        self.assertEqual(records['metrics'], {'A': '10.255.254.50', 'AAAA': 'fd42:1234:5678:fe02::50'})
        value['observability']['metrics']['enabled'] = False
        self.assertNotIn('metrics', authoritative.zone_records(config.normalize(value))['home.arpa'])

    def test_undeclared_wrong_and_ambiguous_attachments_cannot_admit_collectors(self):
        for selector in ({'network': 'missing'}, {'network': 'home', 'addresses': '192.0.2.1/32'},
                         {'addresses': '0.0.0.0/0'}, {'addresses': 'fe80::1/128'},
                         {'network': 'home', 'mac': '02:00:00:00:00:01'},
                         {'interface': 'lan', 'addresses': '192.168.10.2/32'}):
            with self.subTest(selector=selector), self.assertRaises(ReleaseError):
                value = fixture()
                value['observability']['metrics']['clients'] = [selector]
                config.normalize(value)
        value = fixture()
        value['networks']['home']['role'] = 'management'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_static_attachment_supplies_only_explicit_service_source_admission(self):
        value = fixture()
        value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
        value['routing'] = {'static_routes': [{'to': 'fd42:1234:5678:ffff::/64', 'network': 'home', 'on_link': True}]}
        value['observability']['metrics']['clients'] = [{'addresses': 'fd42:1234:5678:ffff::56/128'}]
        normalized = config.normalize(value)
        admission = metrics.client_rules(normalized, ingress=True)
        self.assertEqual(len(admission), 2)
        self.assertIn('iifname "lan" ip6 saddr { fd42:1234:5678:ffff::56/128 }', admission[0])
        self.assertIn('tcp dport 9100 return', admission[0])
        self.assertNotIn('ffff::/64', admission[0])
        self.assertIn('ip6 hoplimit 255', admission[1])
        self.assertIn('nd-neighbor-solicit, nd-neighbor-advert', admission[1])
        self.assertNotIn('nd-router-advert', admission[1])
        value['observability']['metrics']['clients'] = [{'network': 'home'}]
        self.assertFalse(metrics.client_rules(config.normalize(value), ingress=True))

    def test_proxy_manifest_rejects_overrides_scoped_and_ambiguous_addresses(self):
        settings = metrics.manifest(config.normalize(fixture()))
        for changes in ({'port': 22}, {'listeners': []}, {'listeners': [settings['source']]*2},
                        {'backend': '127.0.0.1'}, {'source': settings['backend']},
                        {'backend': '255.255.255.255'},
                        {'listeners': [settings['source'], '2001:db8::1%eth0']},
                        {'listeners': ['::ffff:192.0.2.1']}, {'schema': 2}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                metrics_runtime.validate({**copy.deepcopy(settings), **changes})

    def test_proxy_accepts_only_bounded_bodyless_metrics_gets(self):
        self.assertTrue(metrics_runtime.valid_request(b'GET /metrics HTTP/1.1\r\nHost: metrics\r\nUser-Agent: scraper\r\n\r\n'))
        for request in (b'GET /debug/pprof/ HTTP/1.0\r\n\r\n', b'POST /metrics HTTP/1.0\r\n\r\n',
                        b'GET /metrics?target=other HTTP/1.0\r\n\r\n',
                        b'GET /metrics HTTP/1.0\r\nContent-Length: 0\r\n\r\n',
                        b'GET /metrics HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n',
                        b'GET /metrics HTTP/1.0\r\n Content-Length: 0\r\n\r\n',
                        b'GET /metrics HTTP/1.0\r\nBad Header: invalid\r\n\r\n',
                        b'GET /metrics HTTP/1.0\r\nX-Test: bad\x00value\r\n\r\n',
                        b'GET /metrics HTTP/1.0\r\nX-Large: '+b'a'*16384+b'\r\n\r\n'):
            with self.subTest(request=request[:64]):
                self.assertFalse(metrics_runtime.valid_request(request))


if __name__ == '__main__':
    unittest.main()
