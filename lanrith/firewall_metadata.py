"""Bounded NFLOG tuple decoding for generated host default-deny observations.

This module grants no packet permission. A caller must verify the kernel socket
peer and bind prefixes to the exact generated, unconditional drop statement.
Packet bytes, MAC headers, marks, UID information and unknown attributes never
appear in the returned metadata. Fragmented/encrypted or unsupported headers
are rejected rather than guessed. No deployment endpoint is admitted here.
"""

import hashlib
import ipaddress
import ctypes
import os
from pathlib import Path
import socket
import struct
import time


GROUP = 19538
SNAPLEN = 128
MESSAGE = 4 << 8  # NFNL_SUBSYS_ULOG / NFULNL_MSG_PACKET
MAX_DATAGRAM = 65536


def discard_configuration_capability():
    """Nonroot receiver keeps no effective, permitted, inheritable or ambient cap.

    The unit's bounding set is NET_ADMIN only, needed for the initial group
    bind. NoNewPrivileges and empty permitted/ambient sets prevent regaining it
    through exec. Never run this long-lived receiver as UID zero.
    """
    def status():
        return dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    before = status()
    require(os.getuid() != 0 and os.geteuid() != 0 and int(before['CapBnd'], 16) == 1 << 12 and
            int(before['CapEff'], 16) == int(before['CapPrm'], 16) == 1 << 12)
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    libc.capset.argtypes = [ctypes.POINTER(Header), ctypes.POINTER(Data)]
    libc.capset.restype = ctypes.c_int
    # PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT / PR_CAP_AMBIENT_CLEAR_ALL.
    require(libc.prctl(38, 1, 0, 0, 0) == 0 and libc.prctl(47, 4, 0, 0, 0) == 0)
    require(libc.capset(ctypes.byref(Header(0x20080522, 0)), (Data*2)()) == 0)
    after = status()
    require(all(int(after[key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')) and
            after['NoNewPrivs'].strip() == '1')


def attribute(kind, data):
    length = len(data)+4
    return struct.pack('=HH', length, kind)+data+b'\0'*(align(length)-length)


def kernel_listener():
    """Bind only the fixed logging group; never unbind a different owner.

    NFLOG configuration needs NET_ADMIN at startup. A long-running caller must
    discard that capability after binding; this helper alone is not a service.
    The finite ACK check closes the socket on an occupied/unsupported group.
    """
    source = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, 12)
    try:
        source.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        source.bind((0, 0))
        source.settimeout(2)
        body = struct.pack('!BBH', 0, 0, GROUP)+b''.join(attribute(kind, data) for kind, data in (
            (1, b'\x01'), (2, struct.pack('!IBB', SNAPLEN, 2, 0)), (3, struct.pack('!I', 32768)),
            (4, struct.pack('!I', 1)), (5, struct.pack('!I', 1)), (6, struct.pack('!H', 1))))
        request = struct.pack('=IHHII', 16+len(body), MESSAGE+1, 5, 1, source.getsockname()[0])+body
        source.sendto(request, (0, 0))
        deadline = time.monotonic()+2
        # Packets may arrive after binding and before its ACK. This bounded
        # startup gap must not turn ordinary traffic into endless restart.
        for _ in range(128):
            require(time.monotonic() < deadline)
            source.settimeout(max(.001, deadline-time.monotonic()))
            data, ancillary, flags, sender = source.recvmsg(MAX_DATAGRAM)
            require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and sender == (0, 0) and 16 <= len(data) <= MAX_DATAGRAM)
            length, kind, flags, sequence, pid = struct.unpack_from('=IHHII', data)
            require(16 <= length <= len(data))
            if kind == MESSAGE:
                continue
            require(length >= 20 and kind == 2 and sequence == 1)
            error, = struct.unpack_from('=i', data, 16)
            if error:
                raise OSError(-error, 'Kernel rejected the fixed NFLOG group.')
            return source
        raise ValueError('Firewall observation configuration budget exhausted.')
    except BaseException:
        source.close()
        raise


def require(condition):
    if not condition:
        raise ValueError('Firewall observation differs from the kernel contract.')


def align(length):
    return (length+3) & ~3


def attributes(data):
    result, offset = {}, 0
    while offset < len(data):
        require(offset+4 <= len(data) and len(result) < 32)
        length, kind = struct.unpack_from('=HH', data, offset)
        require(4 <= length <= len(data)-offset and align(length) <= len(data)-offset)
        require(kind not in result and not kind & 0xc000)
        result[kind] = data[offset+4:offset+length]
        offset += align(length)
    return result


def tuple_fields(data, family):
    require(isinstance(data, bytes) and 0 < len(data) <= SNAPLEN)
    if family == 2:
        require(len(data) >= 20 and data[0] >> 4 == 4)
        offset = (data[0] & 15)*4
        total = struct.unpack_from('!H', data, 2)[0]
        fragments = struct.unpack_from('!H', data, 6)[0]
        require(20 <= offset <= 60 and offset <= len(data) and total >= offset and not fragments & 0xbfff)
        protocol, source, destination = data[9], data[12:16], data[16:20]
    elif family == 10:
        require(len(data) >= 40 and data[0] >> 4 == 6)
        payload = struct.unpack_from('!H', data, 4)[0]
        require(payload > 0)  # Jumbo payloads have a different length contract.
        total, offset = 40+payload, 40
        protocol, source, destination = data[6], data[8:24], data[24:40]
        extensions = 0
        while protocol in (0, 43, 60, 51):
            require(extensions < 4 and offset+2 <= min(len(data), total))
            length = (data[offset+1]+2)*4 if protocol == 51 else (data[offset+1]+1)*8
            require(length >= 8 and offset+length <= min(len(data), total))
            protocol, offset = data[offset], offset+length
            extensions += 1
    else:
        raise ValueError('Unsupported firewall observation family.')
    result = {'family': 4 if family == 2 else 6, 'source_ip': str(ipaddress.ip_address(source)),
              'destination_ip': str(ipaddress.ip_address(destination)), 'source_port': None, 'destination_port': None}
    if protocol in (6, 17):
        minimum = 20 if protocol == 6 else 8
        require(offset+minimum <= min(len(data), total))
        source_port, destination_port = struct.unpack_from('!HH', data, offset)
        if protocol == 17:
            length = struct.unpack_from('!H', data, offset+4)[0]
            require(8 <= length <= total-offset)
        else:
            length = (data[offset+12] >> 4)*4
            require(20 <= length <= total-offset and offset+length <= len(data))
        result.update(protocol='tcp' if protocol == 6 else 'udp', source_port=source_port, destination_port=destination_port)
    elif protocol == (1 if family == 2 else 58):
        require(offset+8 <= min(len(data), total))
        result.update(protocol='icmp' if family == 2 else 'icmpv6', icmp_type=data[offset], icmp_code=data[offset+1])
    else:
        raise ValueError('Unsupported or fragmented firewall observation protocol.')
    return result


def packet(data, prefixes):
    require(4 <= len(data) <= 4096)
    family, version, group = struct.unpack_from('!BBH', data)
    require(version == 0 and group == GROUP and family in (2, 10))
    fields = attributes(data[4:])
    require({1, 3, 4, 9, 10, 12} <= fields.keys())
    header, stamp, prefix = fields[1], fields[3], fields[10]
    require(len(header) == 4 and len(stamp) == 16 and 1 < len(prefix) <= 80 and prefix[-1:] == b'\0')
    require(b'\0' not in prefix[:-1])
    token = prefix[:-1].decode('ascii')
    require(token in prefixes)
    rule = prefixes[token]
    ethernet, hook, padding = struct.unpack('!HBB', header)
    require(padding == 0 and ethernet == (0x0800 if family == 2 else 0x86dd))
    require(hook == (1 if rule['hook'] == 'input' else 2) and rule['hook'] in ('input', 'forward'))
    seconds, microseconds = struct.unpack('!QQ', stamp)
    observed_ns = seconds*10**9+microseconds*1000
    require(seconds > 0 and microseconds < 1000000 and observed_ns <= 2**63-1)
    indices = {}
    for kind, name in ((4, 'in_ifindex'), (5, 'out_ifindex')):
        require(kind not in fields or len(fields[kind]) == 4)
        indices[name] = struct.unpack('!I', fields[kind])[0] if kind in fields else None
        require(indices[name] is None or 1 <= indices[name] < 2**31)
    require(indices['in_ifindex'] is not None and (hook != 2 or indices['out_ifindex'] is not None))
    require(len(fields[12]) == 4)
    return {'schema': 1, **tuple_fields(fields[9], family), **indices,
            'observed_ns': observed_ns, 'kernel_sequence': struct.unpack('!I', fields[12])[0],
            'hook': rule['hook'], 'rule_id': rule['id'], 'revision': rule['revision'],
            'decision': 'drop', 'scope': 'host-default-deny', 'sampling': 'rate-limited'}


def decode(data, sender, prefixes):
    """Decode one datagram only when recvmsg identifies the kernel as sender.

    The netlink header PID is not an authentication mechanism. The caller must
    supply the actual recvmsg peer; userspace peers are rejected even if their
    message header claims PID zero. Truncated datagrams must never be passed in.
    """
    require(sender == (0, 0) and isinstance(data, bytes) and 0 < len(data) <= MAX_DATAGRAM)
    result, offset, count = [], 0, 0
    while offset < len(data):
        require(offset+16 <= len(data) and count < 128)
        length, kind, flags, sequence, pid = struct.unpack_from('=IHHII', data, offset)
        require(16 <= length <= len(data)-offset and align(length) <= len(data)-offset)
        if kind == MESSAGE:
            result.append(packet(data[offset+16:offset+length], prefixes))
        else:
            require(kind == 3 and length == 20)  # NFLOG multipart terminator.
            require(data[offset+16:offset+20] == struct.pack('!BBH', 0, 0, GROUP))
        offset += align(length)
        count += 1
    return result


def instrument(text):
    """Place bounded logging immediately before two unconditional drops.

    This helper accepts the generated text, not owner configuration. Existing
    rules/policies are preserved. Earlier guards, owner denies, policy-agent and
    translator decisions, output and service namespaces remain outside coverage.
    Build/admission and collector integration remain separate work.
    """
    require(isinstance(text, str) and 0 < len(text) <= 8*1024*1024)
    require(text.startswith('#!/usr/sbin/nft -f\nflush ruleset\ntable inet lanrith {\n'))
    require(text.count('table inet lanrith {') == 1 and 'log prefix "LN_D1_' not in text and 'group '+str(GROUP) not in text)
    digest = hashlib.sha256(text.encode()).hexdigest()
    lines, prefixes = text.splitlines(), {}
    for hook, code in (('input', 'I'), ('forward', 'F')):
        declaration = ' chain '+hook+' { type filter hook '+hook+' priority filter; policy drop;'
        require(lines.count(declaration) == 1)
        start = lines.index(declaration)
        end = next((index for index in range(start+1, len(lines)) if lines[index] == ' }'), None)
        require(end is not None and not any(line.startswith(' chain ') for line in lines[start+1:end]))
        prefix = 'LN_D1_'+digest[:24]+'_'+code
        revision = hashlib.sha256((digest+':'+hook+':default-drop').encode()).hexdigest()
        prefixes[prefix] = {'hook': hook, 'id': 'native-default-drop:'+revision[:24], 'revision': revision}
        lines[end:end] = ['  limit rate 8/second burst 16 packets log prefix "'+prefix+'" group '+str(GROUP)+
                          ' snaplen '+str(SNAPLEN)+' queue-threshold 1', '  counter drop']
    return '\n'.join(lines)+'\n', {'schema': 1, 'native_firewall_sha256': digest, 'group': GROUP, 'prefixes': prefixes,
        'coverage': 'Rate-limited host input/forward default-deny only; no earlier guard, explicit-rule, policy-agent, translator, output or service-namespace coverage.'}
