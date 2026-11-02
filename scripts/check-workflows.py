#!/usr/bin/env python3
"""Enforce pinned actions and the absence of privileged PR signing paths."""

from pathlib import Path
import re
import sys
import yaml

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from lanrith.assessment import validate_platform

validate_platform(root)

for path in (root/'.github/workflows').glob('*.yml'):
    text = path.read_text()
    value = yaml.safe_load(text)
    assert isinstance(value, dict) and 'permissions' in value, path.name
    assert 'pull_request_target' not in text, path.name
    assert value.get('cache-mode') in (None, 'none', 'read'), path.name
    if path.name == 'build-base.yml':
        jobs = value['jobs']
        assert jobs['packages']['permissions'] == {'contents': 'read'}, path.name
        version = jobs['version']
        assert version['needs'] == 'check' and version['permissions'] == {'contents': 'write'}, path.name
        assert version['runs-on'] == 'ubuntu-24.04' and version['timeout-minutes'] == 5, path.name
        assert version['if'] == ("github.repository == 'Lanrith/lanrith' && github.ref == 'refs/heads/main' && "
            "(github.event_name == 'push' || github.event_name == 'workflow_dispatch')"), 'Version selection must be trusted Main only'
        assert len(version['steps']) == 2, 'The version writer must not execute build or downloaded code'
        checkout, selector = version['steps']
        assert checkout['uses'].startswith('actions/checkout@') and checkout['with'] == {
            'repository': '${{ job.workflow_repository }}', 'ref': '${{ job.workflow_sha }}',
            'persist-credentials': False}, 'Version selection must use its exact reviewed workflow source'
        assert selector['id'] == 'version' and selector['run'] == 'python3 scripts/next-version.py' and \
            selector['env'] == {'GH_TOKEN': '${{ github.token }}'}, path.name
        assert version['outputs'] == {'value': '${{ steps.version.outputs.value }}'}, path.name
        assert set(jobs['packages']['needs']) == {'check', 'cache', 'version'} and \
            "needs.version.result == 'success'" in jobs['packages']['if'], path.name
        assert jobs['packages']['outputs']['version'] == '${{ needs.version.outputs.value }}', path.name
        assert 'next-version.py' not in str(jobs['packages']), 'Read-only compilation cannot enumerate reserved drafts'
        receiver = next(s for s in jobs['packages']['steps'] if s.get('env',{}).get('RELEASE_VERSION'))
        assert receiver['env'] == {'RELEASE_VERSION': '${{ needs.version.outputs.value }}'} and \
            're.fullmatch' in receiver['run'] and '${{' not in receiver['run'], 'Validate version data without shell interpolation'
        assert '--phase packages' in str(jobs['packages']) and '--privileged' not in str(jobs['packages']), path.name
        assert '--phase image' in str(jobs['build']) and 'cache-artifact-id' not in jobs['build']['outputs'], path.name
        assert set(jobs['attest']['needs']) == {'build', 'packages'}, path.name
        handoff = next(step for step in jobs['attest']['steps'] if step.get('id') == 'cache-download')
        assert handoff['with']['artifact-ids'] == '${{ needs.packages.outputs.cache-artifact-id }}', path.name
        assert "needs.build.outputs.production-qualified == 'true'" in handoff['if'], path.name
    if path.name in ('build-base.yml', 'package-check.yml'):
        for job_name, role in (('packages', 'packages'), ('build', 'native')):
            steps = value['jobs'][job_name]['steps']
            preparation = next(i for i, step in enumerate(steps) if step.get('id') == 'runner-disk')
            assert steps[preparation]['run'] == 'python3 scripts/prepare-runner.py', 'Build jobs must share the reviewed disk preparation'
            first_download = next(i for i, step in enumerate(steps) if step.get('uses', '').startswith('actions/download-artifact@'))
            assert preparation < first_download, 'Disk preparation must precede artifact downloads'
            report = steps[preparation+1]
            assert report['if'] == 'always()' and report['uses'].startswith('actions/upload-artifact@') and report['with'] == {
                'name': 'runner-disk-'+role+'-${{ github.run_attempt }}',
                'path': '${{ runner.temp }}/runner-disk.json', 'if-no-files-found': 'ignore', 'retention-days': 1}, \
                'Disk failures must retain bounded one-day diagnostics'
        preparation_source = (root/'scripts/prepare-runner.py').read_text()
        assert 'MINIMUM_FREE_BYTES = 60 * 1024**3' in preparation_source, 'The reviewed 60 GiB build budget must remain enforced'
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
    if path.name == 'retry-runner-capacity.yml':
        assert value['permissions'] == {} and value.get('cache-mode') == 'none', path.name
        assert value[True] == {'workflow_run': {'workflows': ['Release', 'Package qualification'], 'types': ['completed']}}, path.name
        assert value['concurrency'] == {'group': 'runner-capacity-${{ github.event.workflow_run.id }}', 'cancel-in-progress': False}, path.name
        jobs = value['jobs']
        assert set(jobs) == {'plan','archive-plan','retry','archive-result'}, path.name
        assert jobs['plan']['if'] == ("github.repository == 'Lanrith/lanrith' && github.ref == 'refs/heads/main' && "
            "github.event.workflow_run.conclusion == 'failure'"), 'Capacity planning must use trusted Main failure events only'
        assert jobs['plan']['permissions'] == {'contents':'read','actions':'read','pull-requests':'read'}, path.name
        assert jobs['retry']['permissions'] == {'contents':'read','actions':'write','pull-requests':'read'}, path.name
        assert jobs['archive-plan']['needs'] == 'plan' and jobs['archive-plan']['if'] == "needs.plan.outputs.archive == 'true'", 'Ignored capacity events must not create archives'
        upload = next(step for step in jobs['plan']['steps'] if step.get('id') == 'upload')
        assert upload['if'] == "steps.plan.outputs.archive == 'true'", 'Ignored capacity events must not upload temporary records'
        assert set(jobs['retry']['needs']) == {'plan','archive-plan'} and jobs['retry']['if'] == "needs.plan.outputs.eligible == 'true'", 'Retry must wait for archived eligible intent'
        for name in ('plan','retry'):
            job = jobs[name]
            assert job['runs-on'] == 'ubuntu-24.04' and job['timeout-minutes'] == 5 and \
                job['env']['LANRITH_TOOLS_SHA'] == '${{ github.workflow_sha }}', path.name
            checkout = job['steps'][0]
            assert checkout['uses'].startswith('actions/checkout@') and checkout['with'] == {
                'repository':'${{ job.workflow_repository }}','ref':'${{ job.workflow_sha }}',
                'path':'tools','persist-credentials':False}, 'Capacity recovery must never execute PR source'
            commands = [step['run'] for step in job['steps'] if 'run' in step]
            assert len(commands)==1 and commands[0].startswith('python3 tools/scripts/retry-runner-capacity.py '+('plan ' if name=='plan' else 'execute ')), path.name
            assert 'build-base.py' not in str(job) and 'setup-go@' not in str(job), path.name
        for name, topic in (('archive-plan','capacity-plan'),('archive-result','capacity-result')):
            assert jobs[name]['uses'] == './.github/workflows/archive-evidence.yml' and jobs[name]['with']['topic'] == topic, path.name
        assert jobs['archive-result']['if'] == "always() && needs.retry.outputs.result-id != ''", path.name
        assert 'MAX_ATTEMPTS = 3' in (root/'automation/capacity.py').read_text(), 'Capacity retries must remain bounded'
    if path.name == 'request-human-review.yml':
        job = value['jobs']['notify']
        assert "github.ref == 'refs/heads/main'" in job['if'] and 'environment' not in job, path.name
        assert job['permissions'] == {'contents': 'read', 'actions': 'read', 'pull-requests': 'write', 'issues': 'write'}, path.name
        assert value[True]['workflow_run']['workflows'] == ['Review routing', 'Check', 'Package qualification', 'CI'], path.name
        assert set(value[True]['workflow_run']['types']) == {'in_progress', 'completed'}, path.name
        checkout = next(s['with'] for s in job['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        assert checkout == {'repository': '${{ job.workflow_repository }}', 'ref': '${{ job.workflow_sha }}',
                            'path': 'tools', 'persist-credentials': False}, 'Notification must run only its trusted workflow source'
    if path.name == 'publish-release.yml':
        assert value['jobs']['publish']['if'] == ("github.ref == 'refs/heads/main' && "
            "(github.event_name == 'push' || github.event_name == 'workflow_dispatch')"), 'Publication must be trusted Main only'
        steps = value['jobs']['publish']['steps']
        assert len(steps) == 4, 'The publisher must only check out trusted tools, download data, publish and upload verification'
        checkout, download, publisher, upload = steps
        assert checkout['uses'].startswith('actions/checkout@') and checkout['with'] == {
            'repository': '${{ job.workflow_repository }}', 'ref': '${{ job.workflow_sha }}',
            'path': 'tools', 'persist-credentials': False}, 'The publisher must use its exact reviewed workflow source'
        assert download['uses'].startswith('actions/download-artifact@') and download['with']['path'] == 'release', path.name
        assert download['with']['artifact-ids'] == '${{ inputs.artifact-id }}', path.name
        assert publisher['run'] == 'python3 tools/scripts/publish-release.py', 'Never execute publisher code from the downloaded artifact'
        assert upload['uses'].startswith('actions/upload-artifact@'), path.name
        text = (root/'scripts/publish-release.py').read_text()
    if path.name in ('archive-evidence.yml', 'publish-release.yml'):
        assert '--draft' in text and '--draft=false' in text and '--clobber' not in text.replace('# No overwrite or --clobber path is available, including on retries.', ''), path.name
print('Workflow trust boundaries verified.')
