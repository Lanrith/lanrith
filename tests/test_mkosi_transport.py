"""Execute the builder's actual fetch/checksum prefix against offline HTTPS."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
URL = 'https://snapshot.debian.org/archive/debian/20260912T080811Z/pool/main/m/mkosi/mkosi_27-1_all.deb'
SHA = '374b121fe598b89f1c2e3b99a65b305822b31b75e621ebda1f431a1e306766e9'


@unittest.skipUnless(shutil.which('curl') and shutil.which('openssl') and shutil.which('sha256sum'),
                     'Requires the builder transport tools.')
class MkosiTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='mkosi-https-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cert, key = self.root/'cert.pem', self.root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1', '-subj', '/CN=offline-mkosi',
            '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', str(key), '-out', str(self.cert)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        counts, payload = {}, b'synthetic immutable mkosi package bytes'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                counts[handler.path] = counts.get(handler.path, 0)+1
                if handler.path == '/downgrade':
                    handler.send_response(302)
                    handler.send_header('Location', 'http://127.0.0.1:'+str(handler.server.server_port)+'/plain')
                    handler.send_header('Content-Length', '0')
                    handler.end_headers()
                    return
                transient = handler.path == '/unavailable' and counts[handler.path] < 3
                partial = handler.path == '/permanent' or handler.path == '/interrupted' and counts[handler.path] < 3
                body = b'corrupt package' if handler.path == '/corrupt' else b'unavailable' if transient else payload
                handler.send_response(503 if transient else 200)
                handler.send_header('Content-Length', str(len(body)))
                handler.send_header('Connection', 'close')
                handler.end_headers()
                handler.wfile.write(body[:4] if partial else body)
                handler.wfile.flush()
                if partial:
                    handler.connection.shutdown(socket.SHUT_RDWR)
                    handler.connection.close()

            def log_message(handler, *_):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(cleanup)
        self.counts, self.payload = counts, payload
        self.url = 'https://127.0.0.1:'+str(server.server_port)
        source = (ROOT/'builders/mkosi/Containerfile').read_text()
        self.script = source[source.index('RUN curl ')+4:].split(' && dpkg-deb', 1)[0].strip().removesuffix('\\').strip()
        self.assertIn(URL, self.script)
        self.assertIn(SHA, self.script)
        self.assertIn('sha256sum --check --strict', self.script)
        self.target = self.root/'mkosi.deb'

    def fetch(self, path, *, trusted=True):
        # Substitute only fixture bytes, authority and destination. Retry and
        # TLS policy plus the shell checksum guard execute from the recipe.
        script = self.script.replace(URL, self.url+path).replace(SHA, hashlib.sha256(self.payload).hexdigest())
        script = script.replace('/tmp/mkosi.deb', shlex.quote(str(self.target)))
        if trusted:
            script = script.replace('curl ', 'curl --cacert '+shlex.quote(str(self.cert))+' ', 1)
        return subprocess.run(['/bin/sh', '-c', script], capture_output=True, timeout=30,
            env={**os.environ, 'HTTPS_PROXY': '', 'HTTP_PROXY': '', 'ALL_PROXY': '', 'NO_PROXY': '127.0.0.1'})

    def test_interrupted_transfers_retry_without_appending_partial_bytes(self):
        result = self.fetch('/interrupted')
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(self.counts['/interrupted'], 3)
        self.assertEqual(self.target.read_bytes(), self.payload)

    def test_temporary_http_failure_retries_and_succeeds(self):
        self.assertEqual(self.fetch('/unavailable').returncode, 0)
        self.assertEqual(self.counts['/unavailable'], 3)

    def test_persistent_partial_transfers_stop_at_the_configured_attempt_bound(self):
        self.assertNotEqual(self.fetch('/permanent').returncode, 0)
        self.assertEqual(self.counts['/permanent'], 4)

    def test_corrupt_complete_content_fails_the_original_checksum_guard(self):
        result = self.fetch('/corrupt')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'FAILED', result.stdout)
        self.assertEqual(self.counts['/corrupt'], 1)

    def test_redirect_cannot_downgrade_https(self):
        self.assertNotEqual(self.fetch('/downgrade').returncode, 0)
        self.assertNotIn('/plain', self.counts)

    def test_untrusted_certificate_is_never_accepted(self):
        self.assertNotEqual(self.fetch('/interrupted', trusted=False).returncode, 0)
        self.assertEqual(self.counts, {})


if __name__ == '__main__':
    unittest.main()
