"""Observe verified directory TLS without binding or reading a credential."""

import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import tempfile
import time

from .policy_runtime import decode, exact, read


MANIFEST = Path('/usr/share/lanrith/directory-health.json')
OBSERVATION = Path('/run/lanrith-directory-health/health.json')
HOST = re.compile(r'(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
                  r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z')
STARTTLS_OID = b'1.3.6.1.4.1.1466.20037'
STARTTLS_REQUEST = b'\x30\x1d\x02\x01\x01\x77\x18\x80\x16'+STARTTLS_OID
FIELDS = {'schema', 'boot_id', 'observed_monotonic_ns', 'observed_timestamp_seconds',
          'tls_verified', 'endpoints_total', 'endpoints_verified', 'certificate_not_after_seconds'}


class DirectoryHealthError(ValueError):
    """The immutable transport contract or bounded observation differs."""


def require(condition):
    if not condition:
        raise DirectoryHealthError('Directory health contract differs.')


def load(path=MANIFEST, *, owner=0):
    value = exact(decode(read(path, 16*1024, owner=owner), 16*1024),
                  {'schema', 'host', 'port', 'mode', 'addresses', 'ca_file'}, 'Directory health')
    require(type(value['schema']) is int and value['schema'] == 1 and
            type(value['port']) is int and 1 <= value['port'] <= 65535 and
            value['mode'] in ('ldaps', 'starttls') and isinstance(value['host'], str) and '%' not in value['host'] and
            isinstance(value['ca_file'], str) and
            re.fullmatch(r'/usr/share/lanrith/trust/[a-zA-Z0-9_.-]+\.pem', value['ca_file']) and
            isinstance(value['addresses'], list) and 1 <= len(value['addresses']) <= 8)
    require(all(isinstance(a, str) and '%' not in a for a in value['addresses']))
    addresses = [ip.ip_address(a) for a in value['addresses']]
    require(value['addresses'] == sorted(set(str(a) for a in addresses)))
    for address in addresses:
        require(not (address.is_multicast or address.is_unspecified or address.is_loopback or
                     address.is_link_local or address.version == 6 and address.ipv4_mapped))
    try:
        literal = ip.ip_address(value['host'])
    except ValueError:
        require(HOST.fullmatch(value['host']) is not None and not value['host'].replace('.', '').isdigit())
    else:
        require(value['addresses'] == [str(literal)])
    return value


def remaining(deadline):
    seconds = deadline-time.monotonic()
    if seconds <= 0:
        raise TimeoutError('Directory TLS deadline elapsed.')
    return seconds


def receive(stream, size, deadline):
    data = bytearray()
    while len(data) < size:
        stream.settimeout(remaining(deadline))
        chunk = stream.recv(size-len(data))
        if not chunk:
            raise DirectoryHealthError('Directory TLS response was truncated.')
        data.extend(chunk)
    return bytes(data)


def length(first, more):
    if first < 128:
        return first
    require(first in (129, 130) and len(more) == first-128 and more[0] != 0)
    size = int.from_bytes(more, 'big')
    require(128 <= size <= 4096 and (size > 255 or len(more) == 1))
    return size


def field(data, offset, tag):
    require(0 <= offset and offset+2 <= len(data) and data[offset] == tag)
    first = data[offset+1]
    width = first-128 if first >= 128 else 0
    require(0 <= width <= 2 and offset+2+width <= len(data))
    size = length(first, data[offset+2:offset+2+width])
    start = offset+2+width
    require(start+size <= len(data))
    return data[start:start+size], start+size


def starttls(stream, deadline):
    stream.settimeout(remaining(deadline))
    stream.sendall(STARTTLS_REQUEST)
    header = receive(stream, 2, deadline)
    require(header[0] == 0x30)
    width = header[1]-128 if header[1] >= 128 else 0
    require(0 <= width <= 2)
    size = length(header[1], receive(stream, width, deadline))
    require(size <= 4096)
    data = receive(stream, size, deadline)
    message, offset = field(data, 0, 0x02)
    require(message == b'\x01')
    response, offset = field(data, offset, 0x78)
    require(offset == len(data))
    result, offset = field(response, 0, 0x0a)
    require(result == b'\x00')
    _, offset = field(response, offset, 0x04)  # matchedDN; never log peer text
    _, offset = field(response, offset, 0x04)  # diagnosticMessage
    if offset < len(response):
        name, offset = field(response, offset, 0x8a)
        require(name == STARTTLS_OID)
    # RFC 4511 4.14: responseName may be present; responseValue is absent.
    # No referrals or unsolicited controls can substitute for success.
    require(offset == len(response))


def probe(policy):
    authority = read(Path(policy['ca_file']), 64*1024).decode('ascii')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=authority)
    deadline = time.monotonic()+16
    certificates = []
    for address in policy['addresses']:
        attempt = min(deadline, time.monotonic()+2)
        try:
            with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM) as stream:
                stream.settimeout(remaining(attempt))
                stream.connect((address, policy['port']))
                if policy['mode'] == 'starttls':
                    starttls(stream, attempt)
                stream.settimeout(remaining(attempt))
                with context.wrap_socket(stream, server_hostname=policy['host']) as secured:
                    certificates.append(int(ssl.cert_time_to_seconds(secured.getpeercert()['notAfter'])))
        except (OSError, ValueError, KeyError):
            continue
    verified = len(certificates) == len(policy['addresses'])
    return {'schema': 1, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'observed_monotonic_ns': time.monotonic_ns(), 'observed_timestamp_seconds': int(time.time()),
            'tls_verified': verified, 'endpoints_total': len(policy['addresses']),
            'endpoints_verified': len(certificates),
            'certificate_not_after_seconds': min(certificates) if verified else 0}


def publish(value, path=OBSERVATION):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')+b'\n'
    require(len(data) <= 4096)
    descriptor, temporary = tempfile.mkstemp(prefix='.health.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_observation(path=OBSERVATION, *, owner=None, now=None, boot_id=None):
    owner = pwd.getpwnam('lanrith-directory-health').pw_uid if owner is None else owner
    value = exact(decode(read(path, 4096, owner=owner), 4096), FIELDS, 'Directory observation')
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip() if boot_id is None else boot_id
    now = time.monotonic_ns() if now is None else now
    require(type(value['schema']) is int and value['schema'] == 1 and value['boot_id'] == boot_id and
            type(value['tls_verified']) is bool and
            all(type(value[k]) is int and 0 <= value[k] < 2**63 for k in
                ('observed_monotonic_ns', 'observed_timestamp_seconds', 'endpoints_total',
                 'endpoints_verified', 'certificate_not_after_seconds')) and
            0 <= now-value['observed_monotonic_ns'] <= 90*10**9 and
            1 <= value['endpoints_total'] <= 8 and 0 <= value['endpoints_verified'] <= value['endpoints_total'] and
            value['tls_verified'] == (value['endpoints_total'] == value['endpoints_verified']) and
            (value['certificate_not_after_seconds'] > 0 if value['tls_verified'] else
             value['certificate_not_after_seconds'] == 0))
    return value


def main():
    try:
        require(os.getuid() == os.geteuid() == pwd.getpwnam('lanrith-directory-health').pw_uid != 0 and
                len(os.sys.argv) == 1)
        publish(probe(load()))
    except (OSError, KeyError, TypeError, ValueError) as error:
        print('directory-health: '+type(error).__name__+'; observation unavailable', file=os.sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
