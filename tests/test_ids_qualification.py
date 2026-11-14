"""Exact detector subjects, native coverage and assessment-time/source validation."""

import copy
import datetime
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from lanrith import ids_qualification as qualification
from lanrith.release import ReleaseError
from ids_fixture import report, sources


NOW = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)


class IDSQualificationTests(unittest.TestCase):
    def archive(self, root, members):
        path = root/'base.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for change in members:
                data = change.pop('data', b'synthetic detector bytes')
                member = tarfile.TarInfo(change.pop('name', 'usr/bin/suricata'))
                member.mode = 0o755
                member.size = len(data)
                for key, value in change.items():
                    setattr(member, key, value)
                archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
        return path

    def test_exact_executable_is_read_without_extracting_the_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = b'reviewed synthetic component'
            path = self.archive(root, [{'name': './usr/bin/suricata', 'data': data}])
            self.assertEqual(qualification.base_binary(path), hashlib.sha256(data).hexdigest())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['base.tar.gz'])

    def test_duplicate_alias_link_nonexecutable_and_wrong_owner_subjects_are_rejected(self):
        cases = [[{}, {}], [{'name': 'usr//bin/suricata'}], [{'mode': 0o644}], [{'mode': 0o4755}],
                 [{'uid': 1000}], [{'gid': 1000}], [{'type': tarfile.SYMTYPE, 'size': 0, 'linkname': '/tmp/other'}],
                 [{'type': tarfile.LNKTYPE, 'size': 0, 'linkname': 'other'}], [{'name': 'usr/bin/../bin/suricata'}],
                 [{'name': 'usr/bin/another'}], [{'data': b''}]]
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as temporary:
                path = self.archive(Path(temporary), copy.deepcopy(members))
                with self.assertRaises(ReleaseError):
                    qualification.base_binary(path)

    def test_invalid_and_truncated_archives_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'base.tar.gz'
            for data in (b'not an archive', b'\x1f\x8b'+b'x'*30):
                path.write_bytes(data)
                with self.assertRaises(ReleaseError):
                    qualification.base_binary(path)

    def test_missing_coverage_subject_mismatch_and_invalid_metadata_are_rejected(self):
        good = report('a'*64, NOW)
        qualification.validate(good, 'a'*64, now=NOW)
        changes = [{'schema': True}, {'checks': []}, {'checks': good['checks']+[good['checks'][0]]},
                   {'filesystem_sha256': 'd'*64}, {'binary_sha256': 'd'*64}, {'base_binary_match': 1},
                   {'container_cleanup': 'unverified'}, {'container_runtime': 'unknown'},
                   {'builder_image_sha256': ''}, {'external_network': True}, {'image_boot_qualified': True},
                   {'daemon_working_directory': '/writable'}, {'assessed_at': 'invalid'},
                   {'no_new_privileges': False}, {'detector_uid': 0}, {'detector_uid': True},
                   {'effective_capabilities': (1 << 13)|1}, {'bounding_capabilities': (1 << 13)|1},
                   {'assessed_at': NOW.replace(tzinfo=None).isoformat()}, {'source_sha256': 'd'*64},
                   {'implementation_sha256': {}}, {'implementation_sha256': {name: 'not a digest' for name in qualification.IMPLEMENTATION}}]
        for change in changes:
            with self.subTest(fields=sorted(change)), self.assertRaises(ReleaseError):
                qualification.validate({**good, **change}, 'a'*64, now=NOW)
        for invalid in ([], None, True):
            with self.subTest(record=invalid), self.assertRaises(ReleaseError):
                qualification.validate(invalid, 'a'*64, now=NOW)

    def test_native_evidence_must_be_fresh_at_original_base_qualification(self):
        good = report('a'*64, NOW)
        for age in (datetime.timedelta(seconds=-1), datetime.timedelta(hours=6, seconds=1)):
            with self.subTest(age=age), self.assertRaises(ReleaseError):
                qualification.validate(good, 'a'*64, now=NOW+age)

    def test_changed_implementation_cannot_reuse_a_passing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            sources(project)
            good = report('a'*64, NOW, project)
            qualification.validate(good, 'a'*64, project=project, now=NOW)
            (project/'lanrith/ids.py').write_text('changed source after the native test')
            with self.assertRaises(ReleaseError):
                qualification.validate(good, 'a'*64, project=project, now=NOW)
