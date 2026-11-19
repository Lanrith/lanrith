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
    directory = Path(temporary)
    path = directory/'guards.nft'
    guards = ('table netdev lanrith_identity {\n'
              ' set tp_bound4 { type ipv4_addr; flags timeout; }\n'
              ' chain target { ip saddr @tp_bound4 return; drop; }\n}\n')
    path.write_text(guards)
    path.chmod(0o400)
    contract = {'nft_executable': nft, 'profile_directory': temporary}
    pins = {'guards_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    with mock.patch.object(runtime, 'load_contract', return_value=contract), \
            mock.patch.object(runtime, 'metadata', return_value=pins), \
            mock.patch.object(runtime, 'wait_interfaces'):
        runtime.install_guards()
        apply('table inet unrelated {\n chain untouched {\n counter\n }\n}\n'
              'add element netdev lanrith_identity tp_bound4 { 192.0.2.7 timeout 60s }\n')
        before = listing()
        assert len(rules(before)) == 3
        # Positive control reproduces the former append-on-restart behavior.
        apply(guards)
        assert len(rules(listing())) == 5
        time.sleep(1)
        runtime.install_guards()
        repaired = listing()
        assert rules(repaired) == rules(before)
        assert 0 < expiry(repaired) < expiry(before)
        runtime.install_guards()
        assert rules(listing()) == rules(before)
        # A failed replacement must not expose the flushed intermediate state.
        path.write_text(guards+'add rule netdev lanrith_identity target jump absent_chain\n')
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
