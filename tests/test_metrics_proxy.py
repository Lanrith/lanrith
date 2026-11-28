"""HTTP framing, shared legacy staging and failure accounting in the metrics relay."""

import asyncio
from contextlib import redirect_stderr
from http.client import HTTPResponse, IncompleteRead
import io
import unittest
from unittest.mock import AsyncMock, Mock, patch

from lanrith import metrics_runtime as relay


HEADER = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n'
CHUNKED = HEADER+b'Transfer-Encoding: chunked\r\n\r\n'
END = b'0\r\n\r\n'


def reader(content, *, eof=True):
    stream = asyncio.StreamReader(limit=relay.BLOCK_BYTES)
    stream.feed_data(content)
    if eof:
        stream.feed_eof()
    return stream


def chunk(data):
    return b'%x\r\n' % len(data)+data+b'\r\n'


class Writer:
    def __init__(self):
        self.data = io.BytesIO()
        self.closed = False

    def write(self, data):
        self.data.write(data)

    async def drain(self):
        pass

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        settings = {'schema': 1, 'listeners': ['10.15.0.2'], 'source': '10.15.0.2', 'backend': '10.15.0.1'}
        ready = asyncio.Event()

        async def start(proxy, *args, **kwargs):
            self.proxy = proxy
            ready.set()
            return Mock(serve_forever=asyncio.Event().wait, wait_closed=AsyncMock())

        self.backend = AsyncMock()
        self.enterContext(patch.object(asyncio, 'start_server', start))
        self.enterContext(patch.object(asyncio, 'open_connection', self.backend))
        self.log = self.enterContext(redirect_stderr(io.StringIO()))
        self.server = asyncio.create_task(relay.serve(settings))
        await asyncio.wait_for(ready.wait(), 1)
        self.addAsyncCleanup(self.stop)

    async def stop(self):
        self.server.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await self.server

    async def fetch(self, backend, version=b'1.1'):
        self.backend.return_value = (backend, Writer())
        output = Writer()
        await self.proxy(reader(b'GET /metrics HTTP/'+version+b'\r\n\r\n'), output)
        self.assertTrue(output.closed)
        sock = Mock()
        sock.makefile.return_value = io.BytesIO(output.data.getvalue())
        response = HTTPResponse(sock)
        response.begin()
        return response

    async def test_each_request_version_gets_identical_complete_bytes_and_explicit_framing(self):
        data = b'fixture_head 1\n'+b'# '+b'x'*32768+b'\nfixture_tail 1\n'
        fixed = HEADER+b'Content-Length: '+str(len(data)).encode()+b'\r\n\r\n'+data
        chunked = CHUNKED+chunk(data[:101])+chunk(data[101:])+END
        for version in (b'1.0', b'1.1'):
            for wire in (fixed, chunked):
                with self.subTest(version=version, fixed=wire==fixed):
                    response = await self.fetch(reader(wire), version)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.version, int(version.replace(b'.', b'')))
                    self.assertEqual(response.chunked, wire == chunked and version == b'1.1')
                    if not response.chunked:
                        self.assertEqual(response.length, len(data))
                    self.assertEqual(response.read(), data)

    async def test_unverifiable_responses_fail_and_counts_distinguish_errors(self):
        valid_prefix = b'fixture_head 1\n'
        for wire in (HEADER+b'\r\n'+valid_prefix, HEADER+b'Content-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n',
                     HEADER+b'Content-Length: 16777216\r\n\r\n'):
            self.assertEqual((await self.fetch(reader(wire))).status, 502)
        partial = CHUNKED+chunk(valid_prefix)
        with self.assertRaises(IncompleteRead):
            (await self.fetch(reader(partial))).read()
        self.assertEqual((await self.fetch(reader(partial), b'1.0')).status, 502)
        with patch.object(relay, 'REQUEST_SECONDS', .02), self.assertRaises(IncompleteRead):
            (await self.fetch(reader(partial, eof=False))).read()
        self.assertEqual((await self.fetch(reader(partial+END))).read(), valid_prefix)
        await self.stop()
        self.assertIn('size=1 timeout=1 backend=4', self.log.getvalue())

    async def test_chunk_terminator_and_framing_overhead_count_towards_completion(self):
        data = b'fixture_complete_family 1\n'
        wire = CHUNKED+chunk(data)+END
        with patch.object(relay, 'MAXIMUM_RESPONSE', len(wire)):
            self.assertEqual((await self.fetch(reader(wire))).read(), data)
            with self.assertRaises(IncompleteRead) as missing:
                (await self.fetch(reader(wire[:-2]))).read()
            self.assertEqual(missing.exception.partial, data)
        with patch.object(relay, 'MAXIMUM_RESPONSE', len(wire)-1), self.assertRaises(IncompleteRead) as oversized:
            (await self.fetch(reader(wire))).read()
        self.assertEqual(oversized.exception.partial, data)

    async def test_concurrent_legacy_staging_exhaustion_and_reuse(self):
        data = b'# '+b'x'*188+b'\n'
        initial = CHUNKED+chunk(data)
        waiting = reader(initial, eof=False)
        with patch.object(relay, 'MAXIMUM_RESPONSE', 320):
            held = asyncio.create_task(self.fetch(waiting, b'1.0'))
            try:
                # Wait until the relay has used the first fragment and is waiting for its successor.
                async with asyncio.timeout(1):
                    while waiting._buffer:
                        await asyncio.sleep(0)
                other = await self.fetch(reader(initial+END), b'1.0')
                self.assertEqual(other.status, 502)
                self.assertEqual((await self.fetch(reader(initial+END))).read(), data)
            finally:
                waiting.feed_data(END)
                waiting.feed_eof()
                self.assertEqual((await held).read(), data)
            self.assertEqual((await self.fetch(reader(initial+END), b'1.0')).read(), data)
