"""Processing budgets follow selected native components, without new authority."""

import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import config, policy_agent, policy_runtime
from test_policy_agent import declaration


class ProcessingBudgetTests(unittest.TestCase):
    def test_native_translation_selection_changes_only_supported_processing_budget(self):
        accounts = {'router-policy-reader': SimpleNamespace(pw_uid=1701),
                    'router-policy-operator': SimpleNamespace(pw_uid=1702)}
        ordinary = None
        for nat64, nat46 in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(nat64=nat64, nat46=nat46):
                value = declaration()
                value['translation'] = {'nat64': {'enabled': nat64}, 'nat46': {'enabled': nat46,
                    'mappings': {'service': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:10::80'}}}}
                contract = policy_agent.runtime_contract(config.normalize(value))
                before = copy.deepcopy(contract)
                with patch.object(policy_runtime.pwd, 'getpwnam', side_effect=accounts.__getitem__), \
                        patch.object(policy_runtime, 'atomic') as publish, \
                        patch.object(policy_runtime, 'nat64_pin', return_value=None):
                    policy_runtime.publish_runtime(contract, {'floor_sha256': 'a'*64, 'profile_sha256': 'b'*64}, 'c'*64)
                self.assertEqual(contract, before)
                helper = publish.call_args_list[0].args[1]
                self.assertEqual(helper.pop('request_timeout_ms'), 10000 if nat64 or nat46 else 5000)
                if ordinary is None:
                    ordinary = helper
                self.assertEqual(helper, ordinary)
                self.assertEqual(publish.call_count, 2)


if __name__ == '__main__':
    unittest.main()
