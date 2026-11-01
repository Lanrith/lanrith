"""Kernel identity, bounded tuples and logging/drop separation."""

import ipaddress
import json
import struct
import unittest
from unittest.mock import Mock, patch

from lanrith import config, firewall_metadata as wire
from test_intent import minimal


RULE = {'hook': 'forward', 'id': 'native-default-drop:'+'a'*24, 'revision': 'a'*64}
PREFIXES = {'LN_D1_SYNTHETIC_F': RULE}


def attribute(kind, value):
    length = 4+len(value)
    return struct.pack('=HH', length, kind)+value+b'\0'*(wire.align(length)-length)


def ip_packet(family=4, protocol=17, *, fragment=False, extensions=False):
    if protocol == 17:
        transport = struct.pack('!HHHH', 12345, 54321, 8+7, 0)+b'PRIVATE'
    elif protocol == 6:
        transport = struct.pack('!HHIIBBHHH', 12345, 54321, 0, 0, 0x50, 2, 65535, 0, 0)+b'PRIVATE'
    else:
        transport = bytes([8 if family == 4 else 128, 0])+b'\0'*6+b'PRIVATE'
    if family == 4:
        return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(transport), 1, 0x2000 if fragment else 0x4000,
            64, protocol, 0, ipaddress.ip_address('192.0.2.2').packed, ipaddress.ip_address('198.51.100.2').packed)+transport
    first = 44 if fragment else 0 if extensions else protocol
    ext = bytes([protocol, 0])+b'\0'*6 if fragment or extensions else b''
    return struct.pack('!IHBB16s16s', 6 << 28, len(ext)+len(transport), first, 64,
        ipaddress.ip_address('2001:db8::2').packed, ipaddress.ip_address('2001:db8:1::2').packed)+ext+transport


def frame(family=4, protocol=17, *, prefix='LN_D1_SYNTHETIC_F', hook=2, attrs=None, payload=None):
    body = struct.pack('!BBH', 2 if family == 4 else 10, 0, wire.GROUP)
    values = attrs if attrs is not None else [(1, struct.pack('!HBB', 0x0800 if family == 4 else 0x86dd, hook, 0)),
        (3, struct.pack('!QQ', 1793500000, 123456)), (4, struct.pack('!I', 3)), (5, struct.pack('!I', 4)),
        (9, payload if payload is not None else ip_packet(family, protocol)),
        (10, prefix.encode()+b'\0'), (12, struct.pack('!I', 0))]
    body += b''.join(attribute(kind, value) for kind, value in values)
    length = 16+len(body)
    return struct.pack('=IHHII', length, wire.MESSAGE, 0, 0, 0)+body+b'\0'*(wire.align(length)-length)


class FirewallMetadataTests(unittest.TestCase):
    def test_startup_accepts_the_kernel_ack_after_an_early_packet(self):
        source = Mock()
        source.getsockname.return_value = (20000, 0)
        ack = struct.pack('=IHHIIi', 20, 2, 0, 1, 20000, 0)
        source.recvmsg.side_effect = [(frame(), [], 0, (0, 0)), (ack, [], 0, (0, 0))]
        with patch.object(wire.socket, 'socket', return_value=source):
            self.assertIs(wire.kernel_listener(), source)
        self.assertEqual(source.recvmsg.call_count, 2)
        source.close.assert_not_called()

    def test_failed_or_untrusted_ack_closes_only_the_new_socket(self):
        ack = struct.pack('=IHHIIi', 20, 2, 0, 1, 20000, 0)
        denied = struct.pack('=IHHIIi', 20, 2, 0, 1, 20000, -1)
        for response in ((ack, [], 0, (1234, 0)), (ack, [], wire.socket.MSG_TRUNC, (0, 0)),
                         (denied, [], 0, (0, 0)), (b'bad', [], 0, (0, 0))):
            source = Mock()
            source.getsockname.return_value = (20000, 0)
            source.recvmsg.return_value = response
            with self.subTest(response=response), patch.object(wire.socket, 'socket', return_value=source), self.assertRaises((ValueError, OSError)):
                wire.kernel_listener()
            source.close.assert_called_once()

    def test_both_families_and_three_protocols_export_no_payload_or_extra_attributes(self):
        for family in (4, 6):
            for protocol, name in ((6, 'tcp'), (17, 'udp'), (1 if family == 4 else 58, 'icmp' if family == 4 else 'icmpv6')):
                with self.subTest(family=family, protocol=protocol):
                    row, = wire.decode(frame(family, protocol), (0, 0), PREFIXES)
                    self.assertEqual((row['family'], row['protocol'], row['decision']), (family, name, 'drop'))
                    self.assertEqual(row['observed_ns'], 1793500000123456000)
                    self.assertEqual(row['rule_id'], RULE['id'])
                    self.assertNotIn('PRIVATE', json.dumps(row))
                    self.assertNotIn('payload', row)
                    self.assertEqual(row['source_port'], 12345 if protocol in (6, 17) else None)

    def test_userspace_sender_cannot_claim_kernel_identity_in_the_header(self):
        data = frame()
        self.assertEqual(struct.unpack_from('=I', data, 12)[0], 0)
        for peer in ((1234, 0), (0, 1), (1234, 1)):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                wire.decode(data, peer, PREFIXES)

    def test_wrong_prefix_or_hook_cannot_become_a_default_deny_claim(self):
        for changes in ({'prefix': 'LN_D1_OTHER_F'}, {'hook': 1}, {'hook': 0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                wire.decode(frame(**changes), (0, 0), PREFIXES)

    def test_fragments_encryption_and_truncated_transport_are_rejected(self):
        for family in (4, 6):
            for data in (ip_packet(family, fragment=True), ip_packet(family, 50),
                         ip_packet(family)[:25 if family == 4 else 45]):
                with self.subTest(family=family), self.assertRaises(ValueError):
                    wire.tuple_fields(data, 2 if family == 4 else 10)

    def test_bounded_ipv6_extension_header_preserves_the_real_transport(self):
        row = wire.tuple_fields(ip_packet(6, extensions=True), 10)
        self.assertEqual((row['protocol'], row['source_port']), ('udp', 12345))
        data = bytearray(ip_packet(6, extensions=True))
        data[41] = 255
        with self.assertRaises(ValueError):wire.tuple_fields(bytes(data), 10)

    def test_duplicate_missing_nested_and_overlong_attributes_are_rejected(self):
        for value in (attribute(4, b'abcd')*2, b'\xff\xff\x01\x00',
                      attribute(0x8004, b'abcd'), b'\0', b''.join(attribute(i, b'') for i in range(33))):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):wire.attributes(value)
        with self.assertRaises(ValueError):wire.decode(frame(attrs=[(1, b'abcd')]), (0, 0), PREFIXES)

    def test_netlink_bounds_control_messages_and_multipart_group_are_checked(self):
        done = struct.pack('=IHHII', 20, 3, 0, 0, 0)+struct.pack('!BBH', 0, 0, wire.GROUP)
        self.assertEqual(len(wire.decode(frame()+done, (0, 0), PREFIXES)), 1)
        for data in (b'', frame()[:-1], frame()+b'\0', frame()*129, frame()+done[:-2]+b'\0\0'):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):wire.decode(data, (0, 0), PREFIXES)

    def test_generated_rules_have_stable_identity_and_unconditional_drop_after_sampling(self):
        original = config.render(minimal())['etc/nftables.conf']
        result, manifest = wire.instrument(original)
        self.assertEqual(wire.instrument(original), (result, manifest))
        additions = [line for line in result.splitlines() if 'LN_D1_' in line or line == '  counter drop']
        self.assertEqual(len(additions), 4)
        self.assertEqual('\n'.join(line for line in result.splitlines() if line not in additions)+'\n', original)
        self.assertEqual(len(manifest['prefixes']), 2)
        for index, line in enumerate(result.splitlines()):
            if 'LN_D1_' in line:
                self.assertIn('limit rate 8/second burst 16 packets log ', line)
                self.assertNotIn('drop', line)
                self.assertEqual(result.splitlines()[index+1], '  counter drop')
        with self.assertRaises(ValueError):wire.instrument(result)

    def test_replaced_or_ambiguous_tables_are_rejected(self):
        original = config.render(minimal())['etc/nftables.conf']
        for text in ('table inet arbitrary {}\n', original.replace('policy drop;', 'policy accept;'),
                     original+'table inet lanrith {\n}\n', original.replace(' chain input {', ' chain other {')):
            with self.subTest(length=len(text)), self.assertRaises(ValueError):wire.instrument(text)


if __name__ == '__main__':
    unittest.main()
