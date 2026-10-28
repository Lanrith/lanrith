"""Bootstrap preserves independent human approval and last-push protection."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('maintenance_setup',ROOT/'scripts/setup-maintenance.py')
setup=importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.head,self.tree,self.created='a'*40,'b'*40,'c'*40
        self.tamper=False
        self.calls=[]

    def app(self, endpoint, key, identity, **kwargs):
        self.assertEqual(identity,5355607)
        if endpoint=='app':
            return {'id':5355607,'permissions':{'contents':'write','pull_requests':'write','metadata':'read'}}
        if endpoint.endswith('/installation'):
            return {'id':99,'account':{'login':'Lanrith'},'repository_selection':'selected'}
        self.assertEqual(kwargs['value']['permissions'],{'contents':'write'})
        self.assertEqual(kwargs['value']['repositories'],['lanrith'])
        return {'token':'synthetic-local-test-token'}

    def request(self, endpoint, token, **kwargs):
        self.calls.append((endpoint,kwargs))
        if '/ref/heads/' in endpoint:return {'object':{'sha':self.head}}
        if endpoint.endswith('/commits/'+self.head):return {'tree':{'sha':self.tree}}
        if endpoint.endswith('/commits'):
            self.assertEqual(kwargs['value']['tree'],self.tree)
            self.assertEqual(kwargs['value']['parents'],[self.head])
            return {'sha':self.created,'tree':{'sha':'f'*40 if self.tamper else self.tree},'parents':[{'sha':self.head}]}
        self.assertEqual(kwargs['method'],'PATCH')
        self.assertEqual(kwargs['value'],{'sha':self.created,'force':False})
        return {'object':{'sha':self.created}}

    def bind(self):
        with patch.object(setup,'app_request',side_effect=self.app),patch.object(setup,'token_request',side_effect=self.request):
            return setup.bind_bootstrap_push('Lanrith/lanrith','security/verified-update-automation',b'local-test-key')

    def test_owner_can_review_an_app_push_without_changing_source_or_forcing_a_ref(self):
        self.assertEqual(self.bind(),self.created)
        self.assertTrue(self.calls[-1][0].endswith('/refs/heads/security/verified-update-automation'))

    def test_unexpected_source_changes_never_update_the_branch(self):
        self.tamper=True
        with self.assertRaises(ValueError):self.bind()
        self.assertFalse(any(value.get('method')=='PATCH' for _,value in self.calls))

    def test_missing_updater_key_cannot_fall_back_to_the_owner_pushing(self):
        with self.assertRaises(ValueError):
            setup.bind_bootstrap_push('Lanrith/lanrith','security/verified-update-automation',None)


class ReviewerInstallationTests(unittest.TestCase):
    def validate(self, registered, installed):
        def app(endpoint, key, identity, **kwargs):
            self.assertEqual(identity, 5444158)
            if endpoint == 'app':
                return {'id': identity, 'permissions': registered}
            return {'id': 99, 'account': {'login': 'Lanrith'},
                    'repository_selection': 'selected', 'permissions': installed}
        with patch('sys.argv', ['setup-maintenance.py', '--reviewer-id', '5444158', '--reviewer-key', '/local/test.pem']), \
                patch.object(setup, 'key_file', return_value=b'local-test-key'), \
                patch.object(setup, 'app_request', side_effect=app), patch.object(setup, 'gh') as mutate, \
                patch('builtins.print'):
            try:
                setup.main()
            finally:
                mutate.assert_not_called()

    def test_registered_write_permission_without_installation_consent_is_rejected(self):
        expected = json.loads((ROOT/'.github/apps/security-reviewer.json').read_bytes())['default_permissions']
        self.assertEqual(expected['contents'], 'write')
        pending = dict(expected, contents='read')
        with self.assertRaisesRegex(ValueError, 'Accept the reviewer permission update'):
            self.validate(expected, pending)

    def test_the_old_read_only_app_cannot_be_reconfigured_as_a_counted_approver(self):
        expected = json.loads((ROOT/'.github/apps/security-reviewer.json').read_bytes())['default_permissions']
        old = dict(expected, contents='read')
        with self.assertRaisesRegex(ValueError, 'Reviewer App permissions differ'):
            self.validate(old, old)

    def test_exact_accepted_permissions_pass_without_changing_any_repository(self):
        expected = json.loads((ROOT/'.github/apps/security-reviewer.json').read_bytes())['default_permissions']
        self.validate(expected, expected)
