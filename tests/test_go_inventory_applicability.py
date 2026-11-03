"""Inventory-only advisory changes must still pass mandatory source scanning."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from automation import go_dependencies as go, inputs, proposal
from automation.common import MaintenanceError, canonical

MODULE = 'golang.org/x/crypto'
ADVISORY = {'id':'GO-2026-5932','affected':[{'package':{'name':MODULE,'ecosystem':'Go'},
    'ranges':[{'events':[{'introduced':'0'},{'fixed':'0.58.1-0.20261009181718-2f1f834330b2'}]}],
    'ecosystem_specific':{'imports':[{'path':MODULE+'/openpgp'}]}}]}


class InventoryApplicabilityTests(unittest.TestCase):
    def resolve(self, root, scan, *, imported=b'example.test/router\ngolang.org/x/crypto/md4\n', advisory=ADVISORY):
        files={'go.mod':b'module example.test/router\n\ngo 1.27.3\n', 'go.sum':b'', '.go-version':b'1.27.3\n',
            'security/update-policy.json':canonical({'repository':'Lanrith/router-policy-agent','paid_ai':False,
                'automatic_minor_security_updates':True,'go_branches':['1.26','1.27'],'maximum_changes':30})}
        for name,data in files.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        for args in (['init','-q'],['add','.'],['-c','user.name=Fixture','-c','user.email=fixture@example.test',
            '-c','core.hooksPath=/dev/null','commit','-qm','Fixture']):
            subprocess.run(['git',*args],cwd=root,capture_output=True,check=True)
        actual=subprocess.run
        def command(args,**kwargs):
            if args==['govulncheck','./...']:
                return scan(args,**kwargs)
            return actual(args,**kwargs)
        with patch.object(go,'module',return_value={'Require':[{'Path':MODULE,'Version':'v0.56.0'}]}), \
                patch.object(go,'osv_queries',return_value=[{'vulns':[{'id':ADVISORY['id']}]}]), \
                patch.object(go,'fetch_json',return_value=advisory), \
                patch.object(go,'run',side_effect=lambda *args,**kwargs:self.import_graph(args,imported)), \
                patch.object(inputs,'go_security_update',side_effect=lambda version,branches:(version,[])), \
                patch.object(proposal.subprocess,'run',side_effect=command):
            result=proposal.propose(root,root,'Lanrith/router-policy-agent','a'*40)
        self.assertEqual({n:(root/n).read_bytes() for n in files},files)
        return result

    def import_graph(self,args,imported):
        self.assertEqual(args,('go','list','-deps','-test','-f','{{.ImportPath}}','./...'))
        return subprocess.CompletedProcess(args,0,imported,b'')

    def test_inventory_only_pseudoversion_fix_leaves_inputs_unchanged_after_clean_source_scan(self):
        calls=[]
        def clean(args,**kwargs):
            calls.append(args);return subprocess.CompletedProcess(args,0,b'No vulnerabilities found.',b'')
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(self.resolve(Path(temporary),clean))
        self.assertEqual(calls,[['govulncheck','./...']])

    def test_reachable_advisory_or_failed_scanner_still_blocks_the_proposal(self):
        for code,stdout,stderr in ((3,b'GO-2026-5932 affects imported OpenPGP code.',b''),
                                   (1,b'',b'Scanner could not load source.')):
            calls=[]
            def failed(args,**kwargs):
                calls.append(args);return subprocess.CompletedProcess(args,code,stdout,stderr)
            with self.subTest(code=code),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(MaintenanceError,'Reachable Go vulnerability or incomplete source scan'):
                    self.resolve(Path(temporary),failed)
            self.assertEqual(calls,[['govulncheck','./...']])

    def test_imported_affected_packages_or_missing_advisory_paths_require_review(self):
        for imported,advisory in ((b'example.test/router\ngolang.org/x/crypto/openpgp\n',ADVISORY),
                (b'example.test/router\n',{'affected':[{'package':{'name':MODULE},
                    'ranges':[{'events':[{'fixed':'0.58.1-0.20261009181718-2f1f834330b2'}]}]}]})):
            def unexpected(args,**kwargs):
                raise AssertionError('Unknown or imported advisory cannot reach a clean-result claim.')
            with self.subTest(imported=imported),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(MaintenanceError,'reviewed module migration'):
                    self.resolve(Path(temporary),unexpected,imported=imported,advisory=advisory)

    def test_empty_or_malformed_import_inventory_cannot_clear_an_advisory(self):
        for imported in (b'',b'not a package path\n'):
            with self.subTest(imported=imported),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(MaintenanceError,'import inventory'):
                    self.resolve(Path(temporary),lambda *args,**kwargs:self.fail('Scanner must not mask an invalid graph'),
                        imported=imported)
