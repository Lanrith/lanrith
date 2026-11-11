"""Transport fallback never authorizes a different Debian Release or origin."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lanrith import snapshot_metadata as snapshot


class SnapshotMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.body=b'synthetic locked Release\n'
        self.expected=hashlib.sha256(self.body).hexdigest()
        self.destination=self.root/'Release'
        self.urls=[]

    def runner(self, replies):
        def run(argv, **kwargs):
            self.urls.append(argv[-1])
            self.assertEqual(argv[0:2],['curl','--disable'])
            self.assertNotIn('--location',argv);self.assertNotIn('--insecure',argv)
            self.assertLessEqual(kwargs['timeout'],22)
            reply=replies.pop(0)
            if isinstance(reply,Exception):raise reply
            code,status,body,redirect=reply
            Path(argv[argv.index('--output')+1]).write_bytes(body)
            return subprocess.CompletedProcess(argv,code,str(status).zfill(3)+'\n'+redirect+'\n','private-canary')
        return run

    def fetch(self,replies):
        with patch.object(snapshot.subprocess,'run',side_effect=self.runner(replies)):
            return snapshot.fetch('debian','20261103T070000Z','trixie',self.expected,self.destination)

    def test_primary_success_is_digest_bound_and_does_not_consult_another_host(self):
        receipt=self.fetch([(0,200,self.body,'')])
        self.assertEqual(self.destination.read_bytes(),self.body)
        self.assertEqual(receipt['sha256'],self.expected);self.assertEqual(len(self.urls),1)
        self.assertNotIn('private-canary',str(receipt))

    def test_observed_504_failures_use_only_the_official_alternate_with_identical_bytes(self):
        receipt=self.fetch([(22,504,b'upstream failure',''),(22,504,b'upstream failure',''),(0,200,self.body,'')])
        self.assertEqual(len(self.urls),3)
        self.assertTrue(self.urls[2].startswith('https://snapshot-cloudflare.debian.org/archive/debian/20261103T070000Z/'))
        self.assertEqual(self.destination.read_bytes(),self.body)
        self.assertEqual([a['http_status'] for a in receipt['attempts']],[504,504,200])

    def test_both_mirrors_fail_closed_without_a_partial_release_file(self):
        with self.assertRaisesRegex(ValueError,'both official transports'):
            self.fetch([(22,503,b'error','')]*4)
        self.assertEqual(len(self.urls),4);self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.iterdir()),[])

    def test_wrong_successful_bytes_are_a_permanent_trust_failure(self):
        with self.assertRaisesRegex(ValueError,'reviewed lock'):
            self.fetch([(0,200,b'changed unreviewed Release','')])
        self.assertEqual(len(self.urls),1);self.assertFalse(self.destination.exists())

    def test_known_snapshot_redirect_can_select_only_an_older_same_archive_suite(self):
        url='https://snapshot.debian.org/archive/debian/20261103T065900Z/dists/trixie/Release'
        receipt=self.fetch([(0,302,b'',url),(0,200,self.body,'')])
        self.assertEqual(receipt['url'],url);self.assertEqual(self.destination.read_bytes(),self.body)

    def test_real_content_addressed_redirect_is_still_authorized_only_by_the_locked_sha256(self):
        url='https://snapshot-cloudflare.debian.org/file/'+('c'*40)+'/Release'
        receipt=self.fetch([(0,302,b'',url),(0,200,self.body,'')])
        self.assertEqual(receipt['sha256'],self.expected)
        self.destination.unlink()
        with self.assertRaisesRegex(ValueError,'reviewed lock'):
            self.fetch([(0,302,b'',url),(0,200,b'different Release','')])
        self.assertFalse(self.destination.exists())

    def test_known_locator_bypasses_the_failing_timestamp_lookup_only_for_an_exact_lock(self):
        key=('debian','20261103T070000Z','trixie',self.expected)
        with patch.object(snapshot,'LOCATORS',{key:'c'*40}):
            self.fetch([(0,200,self.body,'')])
            self.assertEqual(self.urls,['https://snapshot.debian.org/file/'+('c'*40)+'/Release'])
            self.destination.unlink();self.urls=[]
            receipt=snapshot.fetch
            with patch.object(snapshot.subprocess,'run',side_effect=self.runner([(0,200,self.body,'')])):
                receipt('debian','20261104T070000Z','trixie',self.expected,self.destination)
            self.assertIn('/archive/debian/20261104T070000Z/',self.urls[0])

    def test_hostile_redirect_is_rejected_before_a_second_network_request(self):
        for url in ('http://snapshot.debian.org/archive/debian/20261103T070000Z/dists/trixie/Release',
            'https://127.0.0.1/private-canary','https://private-canary@snapshot.debian.org/archive/debian/20261103T070000Z/dists/trixie/Release',
            'https://snapshot.debian.org/archive/debian/20261104T070000Z/dists/trixie/Release',
            'https://snapshot.debian.org/archive/debian/20261103T070000Z/dists/bookworm/Release',
            'https://snapshot.debian.org/archive/debian/20261103T070000Z/dists/trixie/Release?secret=value'):
            with self.subTest(url=url):
                self.urls=[]
                with self.assertRaises(ValueError):self.fetch([(0,302,b'',url)])
                self.assertEqual(len(self.urls),1);self.assertFalse(self.destination.exists())

    def test_tls_certificate_failure_and_missing_locked_file_are_not_hidden_by_fallback(self):
        for code,status in ((60,0),(22,404),(63,200)):
            with self.subTest(code=code,status=status):
                self.urls=[]
                with self.assertRaisesRegex(ValueError,'permanent HTTP or TLS'):
                    self.fetch([(code,status,b'not-admitted','')])
                self.assertEqual(len(self.urls),1)

    def test_timeout_and_truncated_transport_are_retried_without_accepting_partial_bytes(self):
        self.fetch([subprocess.TimeoutExpired('curl',20),(0,200,self.body,'')])
        self.assertEqual(self.destination.read_bytes(),self.body)
        self.destination.unlink();self.urls=[]
        self.fetch([(18,200,self.body[:3],''),(0,200,self.body,'')])
        self.assertEqual(self.destination.read_bytes(),self.body)

    def test_output_symlink_and_archive_suite_mismatch_make_no_network_call(self):
        target=self.root/'keep';target.write_bytes(b'keep');self.destination.symlink_to(target)
        with patch.object(snapshot.subprocess,'run') as run:
            with self.assertRaises(ValueError):snapshot.fetch('debian','20261103T070000Z','trixie',self.expected,self.destination)
            with self.assertRaises(ValueError):snapshot.fetch('debian-security','20261103T070000Z','trixie',self.expected,self.root/'new')
            run.assert_not_called()
        self.assertEqual(target.read_bytes(),b'keep')
