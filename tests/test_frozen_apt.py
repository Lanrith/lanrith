"""Frozen metadata, package universe and signature enforcement stay independent of mirrors."""
import base64
import configparser
import hashlib
import json
import lzma
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import frozen_apt, image
from lanrith.release import ReleaseError

ROOT=Path(__file__).resolve().parents[1]


class FrozenAptTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);(self.root/'builders/snapshots').mkdir(parents=True)
        self.raw=b'Package: fixture\nVersion: 1\nArchitecture: amd64\n\n';self.compressed=lzma.compress(self.raw)
        self.release=(b'Origin: Debian\nSHA256:\n '+hashlib.sha256(self.raw).hexdigest().encode()+b' '+str(len(self.raw)).encode()+
            b' main/binary-amd64/Packages\n '+hashlib.sha256(self.compressed).hexdigest().encode()+b' '+str(len(self.compressed)).encode()+b' main/binary-amd64/Packages.xz\n')
        self.signed=b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+self.release+b'-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n'
        self.expected=hashlib.sha256(self.release).hexdigest()
        self.record={'archive':'debian','snapshot':'20261103T070000Z','suite':'trixie','release_sha256':self.expected,
            'inrelease':{'sha256':hashlib.sha256(self.signed).hexdigest(),'size':len(self.signed),'locator':'a'*40},
            'index':{'sha256':hashlib.sha256(self.compressed).hexdigest(),'size':len(self.compressed),'locator':'b'*40}}
        (self.root/'builders/snapshots/trixie.InRelease').write_bytes(self.signed)
        self.lock=self.root/'builders/snapshot-transports.json';self.lock.write_text(json.dumps({'schema':1,'records':[self.record]}))
        frozen_apt.repository.cache_clear();frozen_apt._USED.clear()
        self.manager=patch.object(frozen_apt,'retained_hints',return_value=[]);self.manager.start();self.addCleanup(self.manager.stop)
        self.addCleanup(frozen_apt.repository.cache_clear)

    def resolve(self):return frozen_apt.repository(str(self.root),'debian','20261103T070000Z','trixie',self.expected)

    def test_original_signed_seed_and_signed_index_hashes_define_selection_not_live_metadata(self):
        with patch.object(frozen_apt,'request',return_value=self.compressed) as request:
            signed,index,record=self.resolve()
        self.assertEqual(signed,self.signed);self.assertEqual(index,self.compressed)
        self.assertEqual(request.call_count,1)
        self.assertIn('/by-hash/SHA256/'+self.record['index']['sha256'],request.call_args.args[0])
        self.assertEqual(base64.b64decode(record['inrelease_base64']),self.signed)
        self.assertEqual(frozen_apt.used(),[record])

    def test_same_reviewed_universe_can_reuse_a_hint_across_snapshot_cutoffs(self):
        with patch.object(frozen_apt,'request',return_value=self.compressed):
            signed,_,record=frozen_apt.repository(str(self.root),'debian','20261105T070000Z','trixie',self.expected)
        self.assertEqual(signed,self.signed);self.assertEqual(record['snapshot'],'20261105T070000Z')

    def test_changed_metadata_cannot_be_authorized_by_a_transport_hint(self):
        self.record['release_sha256']='c'*64
        self.lock.write_text(json.dumps({'schema':1,'records':[self.record]}))
        with patch.object(frozen_apt,'request',return_value=None):
            with self.assertRaisesRegex(ReleaseError,'signed repository metadata is unavailable'):self.resolve()

    def test_wrong_successful_live_index_does_not_get_masked_by_other_mirrors(self):
        with patch.object(frozen_apt,'request',return_value=b'corrupt') as request:
            with self.assertRaisesRegex(ReleaseError,'Package index differs'):self.resolve()
        self.assertEqual(request.call_count,1)

    def test_missing_live_hash_object_can_use_the_same_content_addressed_snapshot_bytes(self):
        with patch.object(frozen_apt,'request',side_effect=[None,self.compressed]) as request:
            self.resolve()
        self.assertIn('/file/'+self.record['index']['locator']+'/Packages.xz',request.call_args.args[0])

    def test_expanded_index_must_match_its_independent_signed_size_and_digest(self):
        bad=self.release.replace(hashlib.sha256(self.raw).hexdigest().encode(),b'd'*64)
        with self.assertRaises(ReleaseError):
            with patch.object(frozen_apt,'cleartext',return_value=bad):self.resolve()
        # A claimed small expanded size cannot permit a larger compressed stream.
        with patch.object(frozen_apt,'MAX_EXPANDED',len(self.raw)-1):
            with self.assertRaisesRegex(ReleaseError,'oversized'):self.resolve()

    def test_duplicate_and_oversized_signed_index_rows_are_rejected(self):
        with self.assertRaisesRegex(ReleaseError,'Ambiguous'):
            frozen_apt.index_records(self.release+self.release.split(b'SHA256:\n',1)[1])
        with self.assertRaisesRegex(ReleaseError,'oversized'):
            frozen_apt.index_records(self.release.replace(str(len(self.raw)).encode()+b' main/binary-amd64/Packages\n',b'999999999999 main/binary-amd64/Packages\n'))

    def test_no_controller_signature_claim_is_made_from_cleartext_extraction(self):
        # This fixture's fake signature is deliberately accepted only as a
        # payload parser; real APT denial is exercised by the hosted probe.
        self.assertEqual(frozen_apt.cleartext(self.signed),self.release)
        for value in (self.signed.replace(b'PGP SIGNATURE',b'OTHER SIGNATURE'),self.signed+b'garbage',self.signed.replace(b'\n',b'\r\n')):
            with self.subTest(value=value[:40]),self.assertRaises(ReleaseError):frozen_apt.cleartext(value)

    def test_unknown_origins_credentials_and_redirect_targets_make_no_network_call(self):
        for url in ('http://snapshot.debian.org/file/'+'a'*40+'/InRelease','https://169.254.169.254/latest/meta-data',
            'https://secret@snapshot.debian.org/file/'+'a'*40+'/InRelease',
            'https://snapshot.debian.org:444/file/'+'a'*40+'/InRelease',
            'https://deb.debian.org/debian/pool/unrelated?token=secret'):
            with self.subTest(url=url),patch.object(frozen_apt.subprocess,'run') as command:
                with self.assertRaises(ReleaseError):frozen_apt.request(url,1024)
                command.assert_not_called()

    def test_corrupt_cached_locator_data_cannot_replace_reviewed_source_seeds(self):
        bad=self.record|{'inrelease_base64':base64.b64encode(b'corrupt').decode()}
        with patch.object(frozen_apt,'retained_hints',return_value=[bad]) as retained,patch.object(frozen_apt,'request',return_value=self.compressed):
            self.assertEqual(self.resolve()[0],self.signed)
            retained.assert_not_called()

    def test_native_image_recipes_keep_snapshot_and_put_transport_in_mkosi_build_section(self):
        for config in (image.base_configuration('20261103T070000Z','0.1.20',['python3'],'/opt/lanrith-apt-bootstrap/sandbox'),
                       image.initrd_configuration('20261103T070000Z','/opt/lanrith-apt-bootstrap/sandbox')):
            parser=configparser.ConfigParser(strict=False);parser.read_string(config)
            self.assertEqual(parser['Distribution']['Snapshot'],'20261103T070000Z')
            self.assertEqual(parser['Build']['SandboxTrees'],'/opt/lanrith-apt-bootstrap/sandbox')
            self.assertNotIn('SandboxTrees',parser['Content'])

    def test_all_real_signed_seeds_still_match_the_previously_reviewed_release_hashes(self):
        records=json.loads((ROOT/'builders/snapshot-transports.json').read_bytes())['records']
        self.assertEqual(len(records),4)
        for record in records:
            path=ROOT/'builders/snapshots'/(record['suite']+'.InRelease')
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),record['inrelease']['sha256'])
            self.assertEqual(hashlib.sha256(frozen_apt.cleartext(path.read_bytes())).hexdigest(),record['release_sha256'])
