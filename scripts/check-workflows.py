#!/usr/bin/env python3
"""Enforce pinned actions and the absence of privileged PR signing paths."""

import hashlib
import json
from pathlib import Path
import re
import yaml

root = Path(__file__).resolve().parents[1]
assessment = json.loads((root/'security/slsa-assessment.json').read_bytes())
reviewed = assessment.get('reviewed_workflows', {})
assert set(reviewed) == {'.github/workflows/build-base.yml', '.github/workflows/release.yml',
    '.github/workflows/check.yml', '.github/workflows/restore-cache.yml',
    '.github/workflows/publish-release.yml', '.github/workflows/archive-evidence.yml',
    '.github/workflows/security-review.yml', '.github/workflows/security-proposal.yml'}, \
    'The reviewed workflow set is incomplete; review the platform assessment before building.'
for name, expected in reviewed.items():
    assert isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected) and \
        hashlib.sha256((root/name).read_bytes()).hexdigest() == expected, \
        'Assessed workflow hash differs: '+name+'. Review the workflow and update security/slsa-assessment.json before the package build.'

for path in (root/'.github/workflows').glob('*.yml'):
    text = path.read_text()
    value = yaml.safe_load(text)
    assert isinstance(value, dict) and 'permissions' in value, path.name
    assert 'pull_request_target' not in text, path.name
    assert value.get('cache-mode') in (None, 'none', 'read'), path.name
    if path.name == 'build-base.yml':
        jobs = value['jobs']
        assert jobs['packages']['permissions'] == {'contents': 'read'}, path.name
        assert '--phase packages' in str(jobs['packages']) and '--privileged' not in str(jobs['packages']), path.name
        assert '--phase image' in str(jobs['build']) and 'cache-artifact-id' not in jobs['build']['outputs'], path.name
        assert set(jobs['attest']['needs']) == {'build', 'packages'}, path.name
        handoff = next(step for step in jobs['attest']['steps'] if step.get('id') == 'cache-download')
        assert handoff['with']['artifact-ids'] == '${{ needs.packages.outputs.cache-artifact-id }}', path.name
        assert "needs.build.outputs.production-qualified == 'true'" in handoff['if'], path.name
    if path.name == 'package-check.yml':
        jobs = value['jobs']
        assert jobs['preflight']['uses'] == './.github/workflows/check.yml', path.name
        assert jobs['cache']['needs'] == 'preflight', 'Cache handoffs must wait for source qualification'
        assert set(jobs['packages']['needs']) == {'preflight', 'cache'} and \
            "needs.preflight.result == 'success'" in jobs['packages']['if'], \
            'Expensive package compilation must wait for successful source qualification'
        report = next(s for s in value['jobs']['build']['steps']
                      if s.get('name') == 'Retain small qualification reports, including on failure')
        # The privileged VM/storage work tree contains private authorities and
        # root-owned directories. Upload only the flat public report directory.
        assert report['if'] == 'always()', path.name
        assert set(report['with']['path'].splitlines()) == {
            '${{ runner.temp }}/lanrith-output/*.json',
            '${{ runner.temp }}/lanrith-output/*.txt'}, 'Qualification reports must not traverse the privileged work tree'
        assert report['with']['retention-days'] == 1, path.name
    if path.name == 'consumer.yml':
        call = value[True]['workflow_call']
        assert call['inputs']['signing-profile'] == {'type': 'string', 'default': 'protected'}, path.name
        assert set(call['secrets']) == {'LANRITH_BOOT_KEY', 'LANRITH_BOOT_CERTIFICATE',
            'LANRITH_SERIAL_PASSPHRASE_HASH', 'LANRITH_PCR_KEY', 'LANRITH_PCR_CERTIFICATE',
            'LANRITH_RECOVERY_PASSPHRASE_HASH', 'LANRITH_EVIDENCE_KEY', 'LANRITH_EVIDENCE_CERTIFICATE'}, path.name
        jobs = value['jobs']
        assert jobs['sign']['if'] == ("inputs.publish && github.ref == 'refs/heads/main' && "
            "(github.event_name == 'push' || github.event_name == 'workflow_dispatch')"), path.name
        for job, environment in (('sign', 'lanrith-signing'), ('evidence', 'lanrith-evidence')):
            assert jobs[job]['environment'] == "${{ inputs.signing-profile == 'protected' && '"+environment+"' || '' }}", path.name
        assert jobs['evidence']['needs'] == 'sign' and jobs['publish']['needs'] == 'evidence', path.name
        assert value.get('cache-mode') == 'none', path.name
        for job_name, job in jobs.items():
            for step in job.get('steps', []):
                for name in step.get('env', {}):
                    if name.startswith(('LANRITH_BOOT_', 'LANRITH_PCR_')) or name in (
                            'LANRITH_SERIAL_PASSPHRASE_HASH', 'LANRITH_RECOVERY_PASSPHRASE_HASH'):
                        assert job_name == 'sign' and 'consumer.py assemble' in step.get('run', ''), path.name
                    if name.startswith('LANRITH_EVIDENCE_'):
                        assert job_name == 'evidence' and 'private-evidence.py' in step.get('run', ''), path.name
    for action in re.findall(r'^\s+(?:-\s+)?uses:\s+(\S+)', text, re.MULTILINE):
        assert action.startswith('./.github/workflows/') or re.fullmatch(r'[^@ ]+@[0-9a-f]{40}', action), (path.name, action)
    for name, job in value.get('jobs', {}).items():
        assert job.get('cache-mode') in (None, 'none', 'read', 'write-only'), path.name
        if name in ('attest', 'sign', 'publish'):
            if 'uses' in job:
                assert job['uses'] == './.github/workflows/publish-release.yml' and path.name == 'build-base.yml', path.name
            else:
                assert job.get('runs-on') == 'ubuntu-24.04', path.name
        if name == 'attest':
            assert 'actions/checkout@' not in str(job) and 'setup-go@' not in str(job), path.name
        for step in job.get('steps', []):
            action = step.get('uses', '').split('@')[0]
            if action.startswith('actions/cache'):
                if action == 'actions/cache/restore':
                    assert path.name == 'restore-cache.yml' and name == 'restore', path.name
                    assert value.get('cache-mode') == 'read' and value['permissions'] == {'contents': 'read'}, path.name
                    following = job['steps'][job['steps'].index(step)+1:]
                    assert all(s.get('uses', '').startswith('actions/upload-artifact@') and 'run' not in s
                               for s in following), path.name
                elif action == 'actions/cache/save':
                    assert path.name == 'build-base.yml' and name == 'attest', path.name
                    assert job.get('cache-mode') == 'write-only' and \
                        step.get('if') == "steps.cache-bundle.outcome == 'success'", path.name
                else:
                    raise AssertionError('Implicit cache restore/save is not allowed: '+path.name)
    if path.name == 'security-review.yml':
        assert 'pull_request_target' not in text and 'pull_request:' not in text, path.name
        for job_name in ('inspect', 'admission', 'approve', 'finalize'):
            job = value['jobs'][job_name]
            checkouts = [s for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@')]
            assert checkouts and all(s['with'].get('repository') == '${{ job.workflow_repository }}' and
                s['with'].get('ref') == '${{ job.workflow_sha }}' and s['with'].get('persist-credentials') is False
                for s in checkouts), 'Reviewer must execute only its reviewed workflow source'
        assert {'approve', 'archive'} <= set(value['jobs']['finalize']['needs']), 'Merge gate must wait for durable approval evidence'
        approval = value['jobs']['approve']
        assert approval['environment'] == 'lanrith-review' and "outputs.mode == 'enforce'" in approval['if'], path.name
        assert "LANRITH_SECURITY_APPROVALS_ENABLED == 'true'" in approval['if'], path.name
        assert approval['permissions'] == {'contents': 'read'}, path.name
    if path.name == 'cleanup-artifacts.yml':
        assert value['jobs']['archive']['if'] == "needs.plan.outputs.has-artifacts == 'true'", 'Empty cleanup must not generate audit releases'
        upload = next(s for s in value['jobs']['plan']['steps'] if s.get('id') == 'upload')
        assert upload['if'] == "steps.plan.outputs.has-artifacts == 'true'", 'Empty cleanup must not upload its own artifacts'
    if path.name == 'security-proposal.yml':
        assert set(value['jobs']['publish']['needs']) == {'resolve', 'archive'}, 'PR publication must wait for immutable proposal evidence'
        assert value['jobs']['archive']['needs'] == 'resolve', 'Proposal archive must precede the publishing credential'
        assert 'request-review' not in text, 'Publishing a proposal must not request review before CI'
    if path.name == 'review-routing.yml':
        assert value['permissions'] == {} and set(value['jobs']) == {'signal'}, path.name
        assert value['jobs']['signal']['steps'] == [{'run': 'true'}], 'Untrusted PR routing can only signal, without checkout or write permissions'
        assert set(value[True]['pull_request']['types']) == {'opened', 'reopened', 'synchronize', 'ready_for_review'}, path.name
    if path.name == 'request-human-review.yml':
        job = value['jobs']['notify']
        assert "github.ref == 'refs/heads/main'" in job['if'] and 'environment' not in job, path.name
        assert job['permissions'] == {'contents': 'read', 'actions': 'read', 'pull-requests': 'write', 'issues': 'write'}, path.name
        assert value[True]['workflow_run']['workflows'] == ['Review routing', 'Check', 'Package qualification', 'CI'], path.name
        assert set(value[True]['workflow_run']['types']) == {'in_progress', 'completed'}, path.name
        checkout = next(s['with'] for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        assert checkout == {'repository': '${{ job.workflow_repository }}', 'ref': '${{ job.workflow_sha }}',
                            'path': 'tools', 'persist-credentials': False}, 'Notification must run only its trusted workflow source'
    if path.name in ('archive-evidence.yml', 'publish-release.yml'):
        assert '--draft' in text and '--draft=false' in text and '--clobber' not in text.replace('# No overwrite or --clobber path is available, including on retries.', ''), path.name
print('Workflow trust boundaries verified.')
