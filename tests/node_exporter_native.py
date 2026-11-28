#!/usr/bin/env python3
"""Scrape the rendered netstat selection against disposable kernel counter files."""

import argparse
from pathlib import Path
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config
from lanrith.exporter_qualification import local_scrape
from test_metrics import fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    value = fixture()
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    unit = config.render(value)['usr/lib/systemd/system/prometheus-node-exporter.service']
    fields, = [arg.replace('$$', '$') for arg in unit.split() if arg.startswith('--collector.netstat.fields=')]
    ipv4 = {'IpExt_InOctets': 11, 'Ip_Forwarding': 1, 'Icmp_InMsgs': 17, 'Udp_InDatagrams': 19}
    ipv6 = {
        'Ip6_InOctets': 31, 'Ip6_OutOctets': 33, 'Ip6_InHdrErrors': 0, 'Ip6_InTooBigErrors': 2,
        'Ip6_InNoRoutes': 3, 'Ip6_InAddrErrors': 4, 'Ip6_InUnknownProtos': 5, 'Ip6_InTruncatedPkts': 6,
        'Ip6_OutNoRoutes': 7, 'Icmp6_InMsgs': 37, 'Icmp6_OutMsgs': 9, 'Icmp6_InErrors': 10,
        'Icmp6_OutErrors': 11, 'Icmp6_InCsumErrors': 12, 'Udp6_InDatagrams': 41, 'Udp6_OutDatagrams': 14,
        'Udp6_NoPorts': 15, 'Udp6_InErrors': 16, 'Udp6_RcvbufErrors': 17, 'Udp6_SndbufErrors': 18,
        'Udp6_InCsumErrors': 19, 'UdpLite6_InDatagrams': 20, 'UdpLite6_OutDatagrams': 43,
        'UdpLite6_NoPorts': 22, 'UdpLite6_InErrors': 23, 'UdpLite6_RcvbufErrors': 24,
        'UdpLite6_SndbufErrors': 25, 'UdpLite6_InCsumErrors': 26,
    }
    with tempfile.TemporaryDirectory(prefix='exporter-proc.') as root:
        net = Path(root)/'net'
        net.mkdir()
        (net/'netstat').write_text('IpExt: InOctets\nIpExt: 11\n')
        (net/'snmp').write_text('Ip: Forwarding\nIp: 1\nIcmp: InMsgs\nIcmp: 17\nUdp: InDatagrams\nUdp: 19\n')
        snmp6 = net/'snmp6'
        with local_scrape(args.binary.resolve(), '--path.procfs='+root, '--collector.netstat', fields) as scrape:
            for expected in (ipv6, {k: v for k, v in ipv6.items() if k != 'Ip6_InHdrErrors'}, {}):
                if expected:
                    snmp6.write_text(''.join(f'{name.replace("_", "")} {v}\n' for name, v in expected.items())+
                                     'Ip6InMcastOctets 47\nIcmp6InType135 53\nUdp6IgnoredMulti 59\n')
                else:
                    snmp6.unlink()
                data = scrape().splitlines()
                assert 'node_scrape_collector_success{collector="netstat"} 1' in data
                samples = [row for row in data if row.startswith('node_netstat_')]
                assert sorted(samples) == sorted(f'node_netstat_{k} {v}' for k, v in (ipv4 | expected).items()), samples
                print(f'{len(samples)} netstat samples ({len(ipv4)} IPv4 and {len(expected)} IPv6)')


if __name__ == '__main__':
    main()
