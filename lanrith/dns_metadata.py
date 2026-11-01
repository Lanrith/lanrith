"""Bounded dnstap/Frame Streams decoding; retain no DNS wire or TXT payloads.

Field numbers follow the CC0 dnstap.proto specification. Only the client edge
is exported; resolver and forwarder copies cannot become duplicate observations.
"""

import hashlib
import ipaddress
import struct


FRAME_LIMIT = 131072
CONTENT = b'protobuf:dnstap.Dnstap'
TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
         16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS'}
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset == len(data):
            raise ValueError('Truncated protobuf integer.')
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError('Protobuf integer overflow.')
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError('Protobuf integer overflow.')


def protobuf(data):
    if not isinstance(data, bytes) or len(data) > FRAME_LIMIT:
        raise ValueError('Protobuf frame bound.')
    result, offset = {}, 0
    while offset < len(data):
        if len(result) == 64:
            raise ValueError('Protobuf field count bound.')
        key, offset = varint(data, offset)
        field, wire = key >> 3, key & 7
        if not 1 <= field < 1 << 29 or field in result:
            raise ValueError('Ambiguous protobuf field.')
        if wire == 0:
            value, offset = varint(data, offset)
        else:
            if wire == 2:
                size, offset = varint(data, offset)
            elif wire in (1, 5):
                size = 8 if wire == 1 else 4
            else:
                raise ValueError('Unsupported protobuf field type.')
            if size > len(data)-offset:
                raise ValueError('Truncated protobuf field.')
            value = data[offset:offset+size]
            offset += size
            if wire == 5:
                value = struct.unpack('<I', value)[0]
        result[field] = (wire, value)
    return result


def field(value, number, wire, default=None):
    if number not in value:
        if default is None:
            raise ValueError('Missing dnstap field.')
        return default
    actual, result = value[number]
    if actual != wire:
        raise ValueError('Incorrect dnstap field type.')
    return result


def name(data, offset):
    labels, seen, end, length = [], set(), None, 0
    for _ in range(128):
        if offset >= len(data) or offset in seen:
            raise ValueError('DNS compression cycle or truncation.')
        seen.add(offset)
        size = data[offset]
        offset += 1
        if size & 0xc0 == 0xc0:
            if offset >= len(data):
                raise ValueError('Truncated DNS pointer.')
            target = ((size & 63) << 8) | data[offset]
            if target >= offset-1:
                raise ValueError('DNS pointer must refer to prior data.')
            if end is None:
                end = offset+1
            offset = target
            continue
        if size & 0xc0 or offset+size > len(data):
            raise ValueError('Invalid DNS label.')
        if not size:
            return '.'.join(labels) or '.', end if end is not None else offset
        length += size+1
        if length > 254:
            raise ValueError('DNS name bound.')
        # Escaped ASCII presentation cannot insert controls into logs or JSON.
        labels.append(''.join(chr(c) if 33 <= c <= 126 and c not in (46, 92) else '\\%03d' % c
                              for c in data[offset:offset+size]))
        offset += size
    raise ValueError('DNS compression depth bound.')


def message(data, response):
    if not isinstance(data, bytes) or not 12 <= len(data) <= 65535:
        raise ValueError('DNS message bound.')
    _, flags, qd, an, ns, ar = struct.unpack('!6H', data[:12])
    if bool(flags & 0x8000) != response or flags & 0x7800 or qd != 1 or an+ns+ar > 192:
        raise ValueError('Unsupported DNS message.')
    query, offset = name(data, 12)
    if offset+4 > len(data):
        raise ValueError('Truncated DNS question.')
    kind, qclass = struct.unpack_from('!HH', data, offset)
    offset += 4
    if qclass != 1:
        raise ValueError('Unsupported DNS question class.')
    records, rcode = [], flags & 15
    for index in range(an+ns+ar):
        owner, offset = name(data, offset)
        if offset+10 > len(data):
            raise ValueError('Truncated DNS record.')
        rrtype, rrclass, ttl, size = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        end = offset+size
        if end > len(data):
            raise ValueError('Truncated DNS RDATA.')
        answer = None
        if response and index < an and rrclass == 1 and len(records) < 16:
            if (rrtype == 1 and size == 4) or (rrtype == 28 and size == 16):
                answer = str(ipaddress.ip_address(data[offset:end]))
            elif rrtype in (2, 5, 12) or rrtype == 15 and size >= 3:
                target, consumed = name(data, offset+(2 if rrtype == 15 else 0))
                if consumed != end:
                    raise ValueError('DNS name RDATA length differs.')
                answer = (str(struct.unpack_from('!H', data, offset)[0])+' ' if rrtype == 15 else '')+target
        if answer is not None:
            records.append({'name': owner, 'type': TYPES[rrtype], 'value': answer, 'ttl': ttl})
        if response and index >= an+ns and rrtype == 41:
            rcode |= (ttl >> 24) << 4
        offset = end
    if offset != len(data):
        raise ValueError('Unexpected trailing DNS data.')
    return {'query': query, 'type': TYPES.get(kind, str(kind)),
            'result': RCODES.get(rcode, str(rcode)) if response else 'UNOBSERVED_RESPONSE',
            'answer_records': records, 'answer_count': an, 'answers_omitted': len(records) < an}


def normalize(frame, *, now_ns):
    envelope = protobuf(frame)
    if field(envelope, 15, 0) != 1:
        return None
    value = protobuf(field(envelope, 14, 2))
    phase = field(value, 1, 0)
    if phase not in (5, 6):
        return None
    family, protocol = field(value, 2, 0), field(value, 3, 0)
    address = ipaddress.ip_address(field(value, 4, 2))
    port = field(value, 6, 0)
    if family != (1 if address.version == 4 else 2):
        raise ValueError('dnstap address family differs.')
    if protocol not in (1, 2) or not 1 <= port <= 65535:
        raise ValueError('dnstap client transport differs.')
    response = phase == 6
    raw = field(value, 14 if response else 10, 2)
    seconds = field(value, 12 if response else 8, 0)
    nanoseconds = field(value, 13 if response else 9, 5, 0)
    observed = seconds*10**9+nanoseconds
    if nanoseconds >= 10**9 or not now_ns-6900*10**9 <= observed <= now_ns+5*10**9:
        raise ValueError('dnstap timestamp bound.')
    result = message(raw, response)
    # Only identifiers/metadata cross this boundary, never packet bytes.
    transaction = repr((str(address), port, protocol, raw[:2], result['query'].lower(), result['type'])).encode()
    result.update(schema=1, phase='response' if response else 'query', observed_ns=observed,
                  client_ip=str(address), client_port=port, protocol='udp' if protocol == 1 else 'tcp',
                  transaction=hashlib.sha256(transaction).hexdigest(), latency_ms=None,
                  query_observed_ns=observed if not response else None)
    if response and 8 in value:
        query_nanoseconds = field(value, 9, 5, 0)
        if query_nanoseconds >= 10**9:
            raise ValueError('dnstap query timestamp bound.')
        started = field(value, 8, 0)*10**9+query_nanoseconds
        if 0 <= observed-started <= 300*10**9:
            result['latency_ms'] = (observed-started)/10**6
            result['query_observed_ns'] = started
    return result


def control(kind, content=True):
    body = struct.pack('!I', kind)
    if content:
        body += struct.pack('!II', 1, len(CONTENT))+CONTENT
    return struct.pack('!II', 0, len(body))+body


class FrameStream:
    """A single strict READY -> START -> STOP bidirectional stream."""

    def __init__(self):
        self.buffer = bytearray()
        self.state = 'ready'

    def feed(self, data):
        if len(data)+len(self.buffer) > 2*FRAME_LIMIT:
            raise ValueError('Frame Streams buffer bound.')
        self.buffer.extend(data)
        frames, replies = [], []
        while len(self.buffer) >= 4:
            size = struct.unpack_from('!I', self.buffer)[0]
            prefix, is_control = 4, size == 0
            if is_control:
                if len(self.buffer) < 8:
                    break
                size, prefix = struct.unpack_from('!I', self.buffer, 4)[0], 8
            if size > FRAME_LIMIT or is_control and not 4 <= size <= 512:
                raise ValueError('Frame Streams frame bound.')
            if len(self.buffer) < prefix+size:
                break
            body = bytes(self.buffer[prefix:prefix+size])
            del self.buffer[:prefix+size]
            if is_control:
                kind = struct.unpack_from('!I', body)[0]
                if self.state == 'ready' and body == control(4)[8:]:
                    replies.append(control(1))
                    self.state = 'start'
                elif self.state == 'start' and body == control(2)[8:]:
                    self.state = 'data'
                elif self.state == 'data' and body == struct.pack('!I', 3):
                    replies.append(control(5, False))
                    self.state = 'finished'
                else:
                    raise ValueError('Unexpected Frame Streams control.')
            elif self.state != 'data':
                raise ValueError('Frame Streams data outside START/STOP.')
            else:
                frames.append(body)
        return frames, replies
