#!/usr/bin/env python3
"""Enforce pinned actions and the absence of privileged PR signing paths."""

from pathlib import Path
import re
import yaml

root = Path(__file__).resolve().parents[1]
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
    if path.name == 'consumer.yml':
        call = value[True]['workflow_call']
        assert call['inputs']['signing-profile'] == {'type': 'string', 'default': 'protected'}, path.name
        assert set(call['secrets']) == {'LANRITH_BOOT_KEY', 'LANRITH_BOOT_CERTIFICATE',
            'LANRITH_SERIAL_PASSPHRASE_HASH', 'LANRITH_EVIDENCE_KEY', 'LANRITH_EVIDENCE_CERTIFICATE'}, path.name
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
                    if name.startswith('LANRITH_BOOT_') or name == 'LANRITH_SERIAL_PASSPHRASE_HASH':
                        assert job_name == 'sign' and 'consumer.py assemble' in step.get('run', ''), path.name
                    if name.startswith('LANRITH_EVIDENCE_'):
                        assert job_name == 'evidence' and 'private-evidence.py' in step.get('run', ''), path.name
    for action in re.findall(r'^\s+(?:-\s+)?uses:\s+(\S+)', text, re.MULTILINE):
        assert action.startswith('./.github/workflows/') or re.fullmatch(r'[^@ ]+@[0-9a-f]{40}', action), (path.name, action)
    for name, job in value.get('jobs', {}).items():
        assert job.get('cache-mode') in (None, 'none', 'read', 'write-only'), path.name
        if name in ('attest', 'sign', 'publish'):
            assert 'runs-on' in job and job['runs-on'] == 'ubuntu-24.04', path.name
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
print('Workflow trust boundaries verified.')
