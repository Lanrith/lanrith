"""Exercise the actual builder's APT policy against a disposable loopback archive."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import sys
import unittest

HELPER = Path('/usr/lib/apt/apt-helper')
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(HELPER.is_file() and shutil.which('apt-get'), 'Requires the matching Debian builder.')
class AptTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        counts, payload = {}, b'synthetic authenticated package bytes'
        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                counts[handler.path] = counts.get(handler.path, 0)+1
                success = not handler.path.startswith('/primary/') and (
                    (handler.path == '/transient' or handler.path.startswith('/delayed/')) and counts[handler.path] >= 3 or
                    handler.path.endswith('/corrupt') or handler.path.startswith('/alternate/'))
                body = b'corrupt package bytes' if handler.path.endswith('/corrupt') else payload if success else b'unavailable'
                handler.send_response(200 if success else 503)
                handler.send_header('Content-Length', str(len(body)))
                handler.send_header('Connection', 'close')
                handler.end_headers()
                handler.wfile.write(body)
            def log_message(handler, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(stop)
        self.counts, self.payload = counts, payload
        self.url = 'http://127.0.0.1:'+str(server.server_port)
        line = next(line for line in (ROOT/'builders/unbound/Containerfile').read_text().splitlines()
                    if line.endswith(' > /etc/apt/apt.conf.d/80-lanrith-transport'))
        policy = subprocess.run(shlex.split(line)[1:-2], check=True, capture_output=True, text=True).stdout
        for name in ('sources', 'lists/partial', 'archives/partial', 'logs'):
            (self.root/name).mkdir(parents=True)
        (self.root/'status').touch()
        (self.root/'sources.list').write_text('deb '+self.url+'/repository stable main\n')
        self.config = self.root/'apt.conf'
        self.config.write_text(policy+f'''Acquire::http::Proxy::127.0.0.1 "DIRECT";
Dir::Etc::sourcelist "{self.root}/sources.list";
Dir::Etc::sourceparts "{self.root}/sources";
Dir::State::lists "{self.root}/lists";
Dir::State::status "{self.root}/status";
Dir::Cache::archives "{self.root}/archives";
Dir::Log "{self.root}/logs";
''')

    def download(self, path):
        return subprocess.run([str(HELPER), '-c', str(self.config), 'download-file', self.url+path,
            str(self.root/'package.deb'), 'SHA256:'+hashlib.sha256(self.payload).hexdigest()],
            capture_output=True, env={**os.environ, 'LC_ALL': 'C'}, timeout=90)

    def test_temporary_archive_failure_retries_and_succeeds(self):
        self.assertEqual(self.download('/transient').returncode, 0)
        self.assertEqual(self.counts['/transient'], 3)
        self.assertEqual((self.root/'package.deb').read_bytes(), self.payload)

    def test_persistent_failure_is_bounded_and_still_fails(self):
        self.assertNotEqual(self.download('/permanent').returncode, 0)
        self.assertEqual(self.counts['/permanent'], 6)

    def test_retries_never_admit_a_corrupt_package(self):
        result = self.download('/corrupt')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Hash Sum mismatch', result.stdout+result.stderr)

    @unittest.skipUnless(os.environ.get('LANRITH_APT_SECURITY_TEST') == 'true',
                         'Runs inside the isolated security-patched builder probe')
    def test_concurrent_delayed_retries_complete_under_a_256_mib_address_space_limit(self):
        command = [str(HELPER), '-c', str(self.config), 'download-file']
        for index in range(4):
            command += [self.url+'/delayed/'+str(index), str(self.root/('package-'+str(index))),
                        'SHA256:'+hashlib.sha256(self.payload).hexdigest()]
        # A fresh single-threaded launcher sets its own limit before exec;
        # never change the test runner or owner host's process limits.
        launcher = 'import os,resource,sys; resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456)); os.execv(sys.argv[1],sys.argv[1:])'
        result = subprocess.run([sys.executable, '-c', launcher, *command], capture_output=True,
                                env={**os.environ, 'LC_ALL': 'C'}, timeout=45)
        self.assertEqual(result.returncode, 0, (result.stdout+result.stderr)[-2000:])
        self.assertNotIn(b'Tried to start delayed item', result.stdout+result.stderr)
        self.assertTrue(all((self.root/('package-'+str(i))).read_bytes() == self.payload for i in range(4)))

    def mirror_download(self, path):
        mirrors=self.root/'mirrors'
        mirrors.write_text(self.url+'/primary/\tpriority:1\n'+self.url+'/alternate/\tpriority:2\n')
        (self.root/'sources.list').write_text('deb mirror+file:'+str(mirrors)+' stable main\n')
        return subprocess.run([str(HELPER), '-c', str(self.config), '-o', 'Acquire::Retries=0',
            'download-file', 'mirror+file:'+str(mirrors)+'/'+path, str(self.root/'mirrored.deb'),
            'SHA256:'+hashlib.sha256(self.payload).hexdigest()],
            capture_output=True, env={**os.environ, 'LC_ALL': 'C'}, timeout=30)

    def test_mirror_transport_uses_the_next_origin_when_the_first_is_unavailable(self):
        result=self.mirror_download('package')
        self.assertEqual(result.returncode,0,(result.stdout+result.stderr)[-2000:])
        self.assertGreaterEqual(self.counts.get('/primary/package',0),1)
        self.assertGreaterEqual(self.counts.get('/alternate/package',0),1)
        self.assertEqual((self.root/'mirrored.deb').read_bytes(),self.payload)

    def test_mirror_fallback_does_not_accept_a_substituted_package(self):
        result=self.mirror_download('corrupt')
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'Hash Sum mismatch',result.stdout+result.stderr)

    def test_unavailable_index_cannot_be_reported_as_a_successful_update(self):
        result = subprocess.run(['apt-get', '-c', str(self.config), '-o', 'Acquire::Retries=0', 'update'],
            capture_output=True, env={**os.environ, 'LC_ALL': 'C'}, timeout=30)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
