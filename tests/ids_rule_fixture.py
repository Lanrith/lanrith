"""Benign Ethernet PCAP with known directions, TCP flags, echo and ND."""

import collections
import ipaddress
import json
import struct
import subprocess
import time

from lanrith import config, ids
from test_intent import minimal


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(word[0] for word in struct.iter_unpack('!H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def frame(source, destination, proto, flag, sequence):
    src, dst = (ipaddress.ip_address(a).packed for a in (source, destination))
    if proto == 6:
        body = struct.pack('!HHIIBBHHH', 40000+sequence, 22, 1, 0, 0x50, flag, 8192, 0, 0)
        offset = 16
    elif proto == 17:
        body = struct.pack('!HHHH', 40000+sequence, 9000, 8, 0)
        offset = 6
    else:
        if flag == 135:
            body = struct.pack('!BBHI16s', flag, 0, 0, 0, dst)
        else:
            body = struct.pack('!BBHHH', flag, 0, 0, 1234, sequence)
        offset = 2
    if len(src) == 4:
        pseudo = src+dst+struct.pack('!BBH', 0, proto, len(body))
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(body), sequence, 0, 64, proto, 0, src, dst)
        header = header[:10]+struct.pack('!H', checksum(header))+header[12:]
        family = 0x0800
    else:
        pseudo = src+dst+struct.pack('!I3xB', len(body), proto)
        header = struct.pack('!IHBB16s16s', 6 << 28, len(body), proto, 255, src, dst)
        family = 0x86dd
    body = body[:offset]+struct.pack('!H', checksum(pseudo+body))+body[offset+2:]
    return bytes.fromhex('020000000001020000000002') + struct.pack('!H', family) + header + body


def replay(work):
    value = minimal()
    value['uplink']['ipv4'] = {'address': '192.0.2.1/24', 'gateway': '192.0.2.2'}
    value['uplink']['ipv6'] = {'address': '2001:db8:10::2/48', 'gateway': '2001:db8:10::1',
                               'downstream_prefix': '2001:db8:10::/48', 'delivery': 'on_link'}
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': True}
    value['observability'] = {'ids': {'enabled': True}}
    yaml = ids.render(config.normalize(value))['etc/suricata/lanrith.yaml']
    (work/'rules.yaml').write_text(yaml)
    gateway, client6 = '2001:db8:10::1', '2001:db8:10:10::2'
    outside, client4 = '198.51.100.2', '192.168.10.2'
    cases = [(outside, client4, 6, 0x10), (client4, outside, 6, 2), (client6, gateway, 58, 128),
             (gateway, client6, 58, 135), ('192.168.10.3', client4, 6, 2), (outside, client4, 17, 0)]
    for _ in range(8):
        cases.extend([(outside, client4, 6, 2), (gateway, client6, 6, 0xc2), (gateway, client6, 58, 128)])
    start = int(time.time())
    with (work/'traffic.pcap').open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for seq, case in enumerate(cases):
            packet = frame(*case, seq)
            output.write(struct.pack('<IIII', start, seq*1000, len(packet), len(packet))+packet)
    subprocess.run(['suricata', '--runmode=single', '-c', str(work/'rules.yaml'), '-l', str(work),
                    '-r', str(work/'traffic.pcap'), '--init-errors-fatal'], check=True)
    rows = [row for row in map(json.loads, (work/'eve.json').read_text().splitlines()) if row['event_type'] == 'alert']
    assert collections.Counter(row['alert']['signature_id'] for row in rows) == {1000001: 6, 1000002: 6}, rows
    assert {row['ip_v'] for row in rows if row['alert']['signature_id'] == 1000001} == {4, 6}
    assert all(row['pcap_cnt'] > 6 for row in rows)
    return len(cases)
