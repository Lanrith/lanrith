"""Cleanup cannot proceed on a mutable or incorrectly archived audit plan."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT=Path(__file__).resolve().parents[1]


class AuditPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow=yaml.safe_load((ROOT/'.github/workflows/archive-evidence.yml').read_text())
        step=next(s for s in workflow['jobs']['publish']['steps'] if s.get('run'))
        cls.program=step['run'].split("python3 - <<'PYVERIFY'\n",1)[1].rsplit('\nPYVERIFY',1)[0]

    def execute(self, *, immutable=True, wrong_bytes=False):
        with tempfile.TemporaryDirectory() as temporary,contextlib.chdir(temporary):
            root=Path('evidence');root.mkdir()
            raw=b'{"schema":1,"kind":"temporary-artifact-cleanup"}\n'
            (root/'cleanup-record.json').write_bytes(raw)
            published={'immutable':immutable,'draft':False,'prerelease':True,
                'assets':[{'name':'cleanup-record.json','digest':'sha256:'+('f'*64 if wrong_bytes else hashlib.sha256(raw).hexdigest())}]}
            response=subprocess.CompletedProcess([],0,json.dumps(published),'')
            with patch.dict(os.environ,{'GITHUB_REPOSITORY':'Lanrith/lanrith','TOPIC':'cleanup','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}),patch('subprocess.run',return_value=response):
                exec(compile(self.program,'archive-evidence.yml','exec'),{})

    def test_exact_immutable_audit_allows_the_dependent_cleanup(self):
        self.execute()

    def test_disabled_immutability_and_mismatched_asset_bytes_block_cleanup(self):
        for arguments in ({'immutable':False},{'wrong_bytes':True}):
            with self.subTest(arguments=arguments),self.assertRaises(AssertionError):self.execute(**arguments)
