"""Real Prometheus scrape checks for the isolated metrics_native fixture."""

import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import multiprocessing
import os
import pwd
import socket
import subprocess
import time
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener


CYCLES = ('good', 'short', 'good', 'disconnect', 'good', 'size', 'good', 'deadline', 'good', 'omit', 'good')
FAILURES = {'short', 'disconnect', 'size', 'deadline'}


def counted_exporter(settings, gathers, ready):
    account = pwd.getpwnam('prometheus')
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def do_GET(self):
            assert self.client_address[0] == settings['source']
            assert self.requestline == 'GET /metrics HTTP/1.1'
            assert set(self.headers.keys()) == {'Host', 'Accept', 'Accept-Encoding', 'Connection'}
            assert self.headers['Host'] == 'localhost' and self.headers['Accept-Encoding'] == 'identity'
            with gathers.get_lock():
                gathers.value += 1
                cycle = gathers.value
            mode = CYCLES[cycle-1] if cycle <= len(CYCLES) else 'good'
            # Each prefix is a complete, valid Prometheus exposition on its own.
            head = f'fixture_head{{cycle="{cycle}"}} {cycle}\n'.encode()
            tail = f'fixture_tail{{cycle="{cycle}"}} {cycle}\n'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4')
            if mode == 'short':
                self.send_header('Content-Length', str(len(head)+len(tail)))
                self.end_headers()
                self.wfile.write(head)
                return
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            self.wfile.write(b'%x\r\n' % len(head)+head+b'\r\n')
            if mode == 'disconnect':
                return
            if mode == 'deadline':
                time.sleep(1.5)
                return
            if mode == 'size':
                # A second ordinary chunk crosses the fixture's 4 KiB body limit.
                excess = b'# '+b'x'*4093+b'\n'
                self.wfile.write(b'%x\r\n' % len(excess)+excess+b'\r\n')
            elif mode != 'omit':
                self.wfile.write(b'%x\r\n' % len(tail)+tail+b'\r\n')
            self.wfile.write(b'0\r\n\r\n')

    with HTTPServer((settings['backend'], 9101), Handler) as server:
        ready.set()
        server.serve_forever()


@contextlib.contextmanager
def client_namespace():
    # The guest starts with only loopback; metrics_native creates this client.
    with open('/proc/self/ns/net', 'rb') as previous, open('/run/netns/lan-test', 'rb') as client:
        os.setns(client.fileno(), 0)
        try:
            yield
        finally:
            os.setns(previous.fileno(), 0)


def tcp_probe(address):
    with socket.create_connection((address, 9100), timeout=2):
        pass


def qualify(root, settings, address, binary):
    context = multiprocessing.get_context('fork')
    gathers = context.Value('I', 0)
    ready = context.Event()
    backend = context.Process(target=counted_exporter, args=(settings, gathers, ready))
    backend.start()
    try:
        assert ready.wait(5), 'Counting exporter did not start'
        with client_namespace():
            deadline = time.monotonic()+5
            while True:
                try:
                    tcp_probe(address)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.05)
            return run_scraper(root, address, binary, gathers)
    finally:
        backend.terminate()
        backend.join(5)
        assert not backend.is_alive()


def run_scraper(root, address, binary, gathers):
    # Scraper and its TSDB/API stay in the client namespace.
    data = root/'scraper'
    data.mkdir()
    account = pwd.getpwnam('prometheus')
    os.chown(data, account.pw_uid, account.pw_gid)
    target = f'[{address}]:9100'
    config = data/'scraper.yml'
    config.write_text(json.dumps({'global': {'scrape_interval': '3s', 'scrape_timeout': '2800ms'},
        'scrape_configs': [{'job_name': 'router', 'static_configs': [{'targets': [target]}]}]}))
    opener = build_opener(ProxyHandler({}))

    def samples(query):
        url = 'http://127.0.0.1:9090/api/v1/query?'+urlencode({'query': query})
        with opener.open(url, timeout=2) as response:
            result = json.load(response)
        assert result['status'] == 'success'
        return result['data']['result']

    with (data/'scraper.log').open('w+') as log:
        scraper = subprocess.Popen([str(binary), '--config.file='+str(config), '--storage.tsdb.path='+str(data/'tsdb'),
                                    '--web.listen-address=127.0.0.1:9090'], cwd=data, user='prometheus',
                                   group='prometheus', extra_groups=(), stdout=log, stderr=log,
                                   env={**os.environ, 'GOMAXPROCS': '2'})
        try:
            seen = 0
            end = time.monotonic()+100
            while seen < len(CYCLES) and time.monotonic() < end:
                if scraper.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read()[-2048:])
                if gathers.value > seen:
                    tcp_probe(address)
                    seen += 1
                else:
                    time.sleep(.05)
            assert seen == len(CYCLES), f'Only {seen} gathers arrived'
            while time.monotonic() < end:
                up = samples('up{job="router"}[3m]')
                count = gathers.value
                if up and len(up[0]['values']) == count and count >= seen:
                    break
                time.sleep(.05)
            assert len(up) == 1
            points = up[0]['values']
            assert len(points) == count, 'TCP reachability checks triggered extra gathers'
            assert [int(v) for _, v in points[:seen]] == [int(mode not in FAILURES) for mode in CYCLES]
            for family in ('fixture_head', 'fixture_tail'):
                received = {int(s['metric']['cycle']): s['values'] for s in samples(family+'[3m]')}
                for cycle, mode in enumerate(CYCLES, 1):
                    expected = mode not in FAILURES and (family == 'fixture_head' or mode != 'omit')
                    if expected:
                        assert received[cycle] == [[points[cycle-1][0], str(cycle)]], (family, cycle, received)
                    else:
                        assert cycle not in received, (family, cycle, received)
            durations = samples('scrape_duration_seconds{job="router"}[3m]')[0]['values']
            assert all(float(v) < 2.8 for _, v in durations[:seen])
            return {'cycles': list(CYCLES), 'up': [int(v) for _, v in points[:seen]],
                    'target': target, 'tcp_probes_during_scrapes': seen, 'gathers': count,
                    'maximum_scrape_seconds': max(float(v) for _, v in durations[:seen])}
        finally:
            scraper.terminate()
            scraper.wait(timeout=10)
