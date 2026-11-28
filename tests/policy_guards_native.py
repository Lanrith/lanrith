#!/usr/bin/env python3
"""Guard reloads are atomic and preserve live identity data without renewal."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import policy_runtime as runtime

assert os.geteuid() == 0
if '--isolated' not in sys.argv:
    subprocess.run(['unshare', '--net', '--', sys.executable, __file__, '--isolated'], check=True)
    raise SystemExit(0)

nft = shutil.which('nft')
assert nft

def apply(text):
    result = subprocess.run([nft, '-f', '-'], input=text, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr

def listing():
    return json.loads(subprocess.check_output([nft, '-j', 'list', 'ruleset']))['nftables']

def rules(objects):
    return [{key: value for key, value in item['rule'].items() if key != 'handle'}
            for item in objects if 'rule' in item]

def expiry(objects):
    entry = next(item['set'] for item in objects if 'set' in item and item['set']['name'] == 'tp_bound4')
    return entry['elem'][0]['elem']['expires']

with tempfile.TemporaryDirectory(prefix='lanrith-guards.') as temporary:
    with mock.patch.object(runtime.time, 'monotonic', side_effect=(0, 46)):
        try:
            runtime.wait_interfaces({'guard_interfaces': ['lo', 'absent1', 'absent2']})
        except runtime.GuardReadinessError as error:
            assert str(error) == 'Missing policy guard interfaces: absent1, absent2'
        else:
            raise AssertionError('Expected the signed missing-link diagnosis.')
    directory = Path(temporary)
    path = directory/'guards.nft'
    guards = ('table netdev lanrith_identity {\n'
              ' set tp_bound4 { type ipv4_addr; flags timeout; }\n'
              ' chain tp_identity { ip saddr @tp_bound4 return; drop; }\n'
              ' chain tp_egress_0 { type filter hook egress device "lo" priority 0; policy accept;\n'
              '  jump tp_identity\n }\n}\n')
    path.write_text(guards)
    path.chmod(0o400)
    contract = {'nft_executable': nft, 'profile_directory': temporary, 'guard_interfaces': ['lo']}
    pins = {'guards_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    with mock.patch.object(runtime, 'load_contract', return_value=contract), \
            mock.patch.object(runtime, 'metadata', return_value=pins), \
            mock.patch.object(runtime, 'wait_interfaces'):
        runtime.install_guards()
        apply('table inet unrelated {\n chain untouched {\n counter\n }\n}\n'
              'add element netdev lanrith_identity tp_bound4 { 192.0.2.7 timeout 60s }\n')
        before = listing()
        assert len(rules(before)) == 4 and 0 < expiry(before) <= 60
        try:
            runtime.verify_guard_hooks({**contract, 'guard_interfaces': ['another']})
        except runtime.GuardReadinessError as error:
            assert 'another' in str(error)
        else:
            raise AssertionError('A hook for a different device passed readiness.')
        # Positive control reproduces the former append-on-restart behavior.
        apply(guards)
        assert len(rules(listing())) == 7
        try:
            runtime.verify_guard_hooks(contract)
        except runtime.GuardReadinessError:
            pass
        else:
            raise AssertionError('Duplicate guard jump passed readiness.')
        time.sleep(1)
        runtime.install_guards()
        repaired = listing()
        assert rules(repaired) == rules(before)
        assert 0 < expiry(repaired) < expiry(before)
        runtime.install_guards()
        assert rules(listing()) == rules(before)
        # A failed replacement must not expose the flushed intermediate state.
        path.write_text(guards+'add rule netdev lanrith_identity tp_identity jump absent_chain\n')
        pins['guards_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            runtime.install_guards()
        except runtime.PolicyRuntimeError:
            pass
        else:
            raise AssertionError('Invalid atomic guard replacement unexpectedly succeeded.')
        assert rules(listing()) == rules(before)
        assert 0 < expiry(listing()) <= expiry(repaired)
print('Native guard reloads preserve rules, identity expiry and unrelated tables; failed batches are atomic.')
