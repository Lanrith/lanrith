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
    for action in re.findall(r'^\s+uses:\s+(\S+)', text, re.MULTILINE):
        assert action.startswith('./.github/workflows/') or re.fullmatch(r'[^@ ]+@[0-9a-f]{40}', action), (path.name, action)
    for name, job in value.get('jobs', {}).items():
        if name in ('attest', 'sign', 'publish'):
            assert 'runs-on' in job and job['runs-on'] == 'ubuntu-24.04', path.name
        if name == 'attest':
            assert 'actions/checkout@' not in str(job) and 'setup-go@' not in str(job), path.name
print('Workflow trust boundaries verified.')
