"""Authenticated rejecting RADIUS peer for offline native qualification."""
import hashlib
import hmac
import struct
import socket
import sys
from pathlib import Path

def radius_reject(data, password):
    # An authenticated rejecting upstream exercises proxy connectivity without
    # inventing a directory grant or admitting an unknown synthetic identity.
    if len(data) < 20 or data[0] != 1 or int.from_bytes(data[2:4], 'big') != len(data):
        return None
    offset, authenticators, proxy_state = 20, [], b''
    while offset < len(data):
        if offset+2 > len(data) or data[offset+1] < 2 or offset+data[offset+1] > len(data):
            return None
        if data[offset] == 80:
            if data[offset+1] != 18: return None
            authenticators.append(offset+2)
        if data[offset] == 33:
            proxy_state += data[offset:offset+data[offset+1]]
        offset += data[offset+1]
    if len(authenticators) != 1:
        return None
    offset = authenticators[0]
    signed = data[:offset]+b'\0'*16+data[offset+16:]
    if not hmac.compare_digest(data[offset:offset+16], hmac.digest(password, signed, 'md5')):
        return None
    header = bytes([3, data[1]])+struct.pack('!H', 38+len(proxy_state))
    attributes = bytes([80, 18])+b'\0'*16+proxy_state
    authenticator = hmac.digest(password, header+data[4:20]+attributes, 'md5')
    attributes = bytes([80, 18])+authenticator+proxy_state
    response = hashlib.md5(header+data[4:20]+attributes+password).digest()
    return header+response+attributes

def main():
    address, record = sys.argv[1:]
    password = sys.stdin.buffer.readline(257).rstrip(b'\n')
    assert 32 <= len(password) <= 256
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    count = 0
    with socket.socket(family, socket.SOCK_DGRAM) as server:
        server.bind((address, 1812))
        Path(record+".ready").touch()
        while True:
            data, peer = server.recvfrom(65536)
            Path(record+".received").touch()
            response = radius_reject(data, password)
            if response is not None:
                count += 1
                Path(record).write_text(str(count))
                server.sendto(response, peer)

if __name__ == "__main__": main()
