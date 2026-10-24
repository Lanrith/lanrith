"""Fixed-destination, bounded HTTP metrics proxy; never collect host metrics here."""

import asyncio
import ipaddress as ip
import json
from pathlib import Path
import re
import socket


MAXIMUM_CLIENTS = 32
MAXIMUM_RESPONSE = 16 * 1024 * 1024
FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def validate(settings):
    if not isinstance(settings, dict) or set(settings) != {'schema', 'listeners', 'backend', 'source'} or settings['schema'] != 1:
        raise ValueError('Invalid metrics manifest.')
    if not isinstance(settings['listeners'], list) or not 1 <= len(settings['listeners']) <= 3:
        raise ValueError('Invalid metrics listeners.')
    addresses = settings['listeners'] + [settings['backend'], settings['source']]
    if any(not isinstance(a, str) for a in addresses):
        raise ValueError('Invalid metrics address.')
    addresses = [ip.ip_address(a) for a in addresses]
    if any(str(address) != raw or address.version == 6 and address.scope_id for address, raw in
           zip(addresses, settings['listeners'] + [settings['backend'], settings['source']], strict=True)):
        raise ValueError('Metrics addresses must be canonical and unscoped.')
    if any(not a.is_global and not a.is_private or a.is_reserved or a.is_multicast or a.is_loopback or
           a.is_link_local or a.is_unspecified or a.version == 6 and a.ipv4_mapped for a in addresses):
        raise ValueError('Invalid metrics address scope.')
    if len(set(settings['listeners'])) != len(settings['listeners']) or settings['source'] not in settings['listeners'] or \
            addresses[-1].version != 4 or addresses[-2].version != 4 or settings['backend'] == settings['source']:
        raise ValueError('Invalid metrics backend source.')
    return dict(settings, listeners=list(settings['listeners']))


def valid_request(header):
    if len(header) > 16384:
        return False
    lines = header.split(b'\r\n')
    if lines[0] not in (b'GET /metrics HTTP/1.0', b'GET /metrics HTTP/1.1') or lines[-2:] != [b'', b'']:
        return False
    for line in lines[1:-2]:
        name, colon, value = line.partition(b':')
        if not colon or not FIELD_NAME.fullmatch(name) or name.lower() in (b'content-length', b'transfer-encoding') or \
                any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            return False
    return True


async def close(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, ConnectionError, TimeoutError):
            pass


async def serve(settings):
    settings = validate(settings)
    clients = set()

    async def proxy(reader, writer):
        task = asyncio.current_task()
        if len(clients) >= MAXIMUM_CLIENTS:
            await close(writer)
            return
        clients.add(task)
        backend = None
        try:
            async with asyncio.timeout(15):
                header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                if not valid_request(header):
                    writer.write(b'HTTP/1.0 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                    await writer.drain()
                    return
                response, backend = await asyncio.open_connection(settings['backend'], 9101,
                    local_addr=(settings['source'], 0), limit=32768)
                # Forward no client headers, credentials, request body or URL.
                backend.write(b'GET /metrics HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                await backend.drain()
                total = 0
                while data := await response.read(16384):
                    total += len(data)
                    if total > MAXIMUM_RESPONSE:
                        break
                    writer.write(data)
                    await writer.drain()
        except (OSError, ConnectionError, TimeoutError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            pass
        finally:
            await close(backend)
            await close(writer)
            clients.discard(task)

    servers = []
    try:
        for listener in settings['listeners']:
            # Separate family sockets prevent IPv4-mapped IPv6 ambiguity.
            family = socket.AF_INET if ip.ip_address(listener).version == 4 else socket.AF_INET6
            servers.append(await asyncio.start_server(proxy, listener, 9100, family=family, limit=16384, backlog=32))
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        for task in tuple(clients):
            task.cancel()
        await asyncio.gather(*clients, return_exceptions=True)


if __name__ == '__main__':
    path = Path('/usr/share/lanrith/metrics.json')
    if path.stat().st_size > 16384:
        raise ValueError('Metrics manifest exceeds its bound.')
    asyncio.run(serve(json.loads(path.read_text())))
