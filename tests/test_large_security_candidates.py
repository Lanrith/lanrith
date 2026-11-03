"""A kernel fix must keep all its authenticated advisories through staging."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import evidence, releases
from automation.common import MaintenanceError, canonical


class LargeSecurityCandidateTests(unittest.TestCase):
    def reasons(self):
        fixture=json.loads((Path(__file__).parent/'fixtures/kernel-advisories-20261103.json').read_bytes())
        return [{'id':identity,'type':'debian-security-fix','ecosystem':'Debian','package':'linux',
            'installed':fixture['installed'],'fixed':fixed,
            'source':'https://security-tracker.debian.org/tracker/data/json','evidence_sha256':digest}
            for identity,fixed,digest in fixture['advisories']]

    def record(self,reasons):
        return evidence.candidate('Lanrith/lanrith','a'*40,b'{}',
            {'build-inputs.json':b'old inputs','builders/build-inputs.lock':b'old lock'},
            {'build-inputs.json':b'new inputs','builders/build-inputs.lock':b'new lock'},reasons,'b'*40)

    def test_actual_631_advisories_survive_candidate_staging_without_omission(self):
        reasons=self.reasons();self.assertEqual(len(reasons),631)
        record=self.record(reasons)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);owner=root/'owner';(owner/'security').mkdir(parents=True)
            (owner/'builders').mkdir();(owner/'build-inputs.json').write_bytes(b'new inputs')
            (owner/'builders/build-inputs.lock').write_bytes(b'new lock')
            evidence.write(owner/evidence.CANDIDATE,record)
            releases.stage(owner,root/'staged')
            staged=evidence.validate_candidate(evidence.read(root/'staged'/evidence.CANDIDATE))
            self.assertEqual(staged['reasons'],reasons)
            self.assertEqual(staged['candidate_id'],record['candidate_id'])

    def test_a_changed_advisory_in_a_large_batch_invalidates_its_identity(self):
        record=self.record(self.reasons());changed=copy.deepcopy(record)
        changed['reasons'][-1]['fixed']='6.12.999-1'
        with self.assertRaisesRegex(MaintenanceError,'identity'):
            evidence.validate_candidate(changed)

    def test_advisory_count_budget_is_enforced_by_producer_and_consumer(self):
        reason=self.reasons()[0]
        with self.assertRaisesRegex(MaintenanceError,'reason budget'):
            self.record([reason]*(evidence.MAX_REASONS+1))
        record=self.record([reason]);record['reasons']=[reason]*(evidence.MAX_REASONS+1)
        with self.assertRaisesRegex(MaintenanceError,'coverage'):
            evidence.validate_candidate(record)

    def test_serialized_record_budget_is_enforced_by_producer_and_consumer(self):
        reason=self.reasons()[0];reason['source']='x'*evidence.MAX_CANDIDATE_BYTES
        with self.assertRaisesRegex(MaintenanceError,'byte budget'):
            self.record([reason])
        record=self.record(self.reasons());record['reasons'][0]['source']='x'*evidence.MAX_CANDIDATE_BYTES
        with self.assertRaisesRegex(MaintenanceError,'byte budget'):
            evidence.validate_candidate(record)

    def test_actual_batch_can_publish_bounded_pr_and_issue_descriptions(self):
        record=self.record(self.reasons())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);candidate=root/'candidate.json';body=root/'body.md'
            evidence.write(candidate,record)
            with patch.object(releases,'contents',return_value=canonical({
                    'proposal_branch':'automation/security-updates','proposer_login':'lanrith-dependency-updater[bot]'})), \
                    patch.object(releases,'pages',return_value=[]):
                self.assertTrue(releases.proposal_state('Lanrith/lanrith',candidate,body))
            self.assertLess(len(body.read_bytes()),32768)
            self.assertIn(record['candidate_id'],body.read_text())
            writes=[]
            with patch.object(releases,'pages',return_value=[]), \
                    patch.object(releases,'api',side_effect=lambda endpoint,**kwargs:writes.append(kwargs['payload'])), \
                    patch.dict('os.environ',{'GITHUB_RUN_ID':'123'}):
                releases.track('Lanrith/lanrith',candidate,53)
            self.assertLess(len(writes[0]['body'].encode()),32768)
            self.assertIn(record['candidate_id'],writes[0]['body'])
            self.assertEqual(evidence.read(candidate)['reasons'],record['reasons'])
