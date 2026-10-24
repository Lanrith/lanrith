"""Idle cleanup must not create an endless audit handoff cycle."""

import copy
import datetime
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from automation import cleanup,common

ROOT=Path(__file__).resolve().parents[1]


class IdleCleanupTests(unittest.TestCase):
    def test_cleanup_ignores_its_own_small_one_day_handoffs(self):
        clock=datetime.datetime(2026,10,23,12,tzinfo=datetime.timezone.utc)
        artifacts=[{'id':n,'name':name,'size_in_bytes':100,'expired':False,'workflow_run':{'id':n}}
                   for n,name in enumerate(('cleanup-plan','cleanup-result','attested-maintenance-cleanup-1','qualified-release'),1)]
        def get(endpoint,**kwargs):
            if kwargs.get('paginate'):return [{'artifacts':artifacts}]
            return {'name':'Release' if endpoint.endswith('/4') else 'Clean completed Actions handoffs',
                    'status':'completed','updated_at':(clock-datetime.timedelta(hours=3)).isoformat()}
        value=cleanup.plan('Lanrith/lanrith',get=get,clock=clock)
        self.assertEqual([a['id'] for a in value['artifacts']],[4])

    def test_cli_marks_an_empty_plan_as_no_work_for_the_workflow_gate(self):
        spec=importlib.util.spec_from_file_location('security_updates_cli',ROOT/'scripts/security-updates.py')
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);output=root/'plan.json';flags=root/'outputs'
            with patch.object(sys,'argv',['security-updates.py','cleanup','--repository','Lanrith/lanrith','--output',str(output)]),patch.dict(os.environ,{'GITHUB_OUTPUT':str(flags)}),patch.object(cli.cleanup,'plan',return_value={'schema':1,'artifacts':[],'bytes':0}):
                cli.main()
            self.assertEqual(flags.read_text(),'has-artifacts=false\n')

    def test_paginated_api_limit_does_not_shrink_to_the_source_input_limit(self):
        raw=b'{"padding":"'+b'x'*(9*1024*1024)+b'"}'
        with self.assertRaises(common.MaintenanceError):common.document(raw)
        result=subprocess.CompletedProcess([],0,raw,b'')
        with patch('subprocess.run',return_value=result):
            self.assertEqual(len(common.api('repos/Lanrith/lanrith/releases')['padding']),9*1024*1024)
