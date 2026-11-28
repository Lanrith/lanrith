"""Check the read-only admission and capacity boundaries with synthetic observations."""

import ipaddress
import unittest
from unittest.mock import patch

from lanrith import kea_observer as observer

MAC = '02:00:00:00:00:01'
REQUEST = {'command': 'lease4-get-by-hw-address', 'arguments': {'hw-address': MAC}}
PREFIX = ipaddress.IPv4Network('192.0.2.0/24')
ROW = {'ip-address': '192.0.2.15', 'subnet-id': 7, 'hw-address': MAC,
       'state': 0, 'cltt': 100, 'valid-lft': 3600, 'hostname': 'synthetic-private'}


class KeaObserverTests(unittest.TestCase):
    def test_only_the_compiled_scope_and_lease_fields_are_returned(self):
        foreign = dict(ROW, **{'subnet-id': 8, 'ip-address': '198.51.100.9'})
        with patch.object(observer, 'backend', return_value={'result': 0, 'arguments': {'leases': [foreign, ROW]}}):
            observed = observer.lease(REQUEST, 7, PREFIX, 1)['arguments']['leases']
        self.assertEqual(observed, [{key: ROW[key] for key in observer.FIELDS}])
        for response in ({'result': 3}, {'result': 3, 'arguments': {'leases': []}},
                         {'result': 0, 'arguments': {'leases': [foreign]}}):
            with self.subTest(response=response), patch.object(observer, 'backend', return_value=response):
                self.assertEqual(observer.lease(REQUEST, 7, PREFIX, 1), {'result': 3})

    def test_rejects_unknown_operations_scopes_and_extra_fields_before_backend(self):
        with patch.object(observer, 'backend') as backend:
            for request in (dict(REQUEST, command='unsupported'), dict(REQUEST, service=['dhcp4']),
                            dict(REQUEST, arguments={'hw-address': MAC, 'subnet-id': 8}),
                            dict(REQUEST, arguments={'from': '0.0.0.0', 'limit': 128})):
                with self.subTest(request=request), self.assertRaises(ValueError):
                    observer.lease(request, 7, PREFIX, 1)
            backend.assert_not_called()

    def test_unavailable_or_inconsistent_backend_never_returns_partial_observations(self):
        for response in ({'result': 1}, {'result': 0, 'arguments': {'leases': [ROW]*17}},
                         {'result': 0, 'arguments': {'leases': [ROW, dict(ROW, **{'ip-address': '198.51.100.9'})]}}):
            with self.subTest(response=response), patch.object(observer, 'backend', return_value=response), self.assertRaises(ValueError):
                observer.lease(REQUEST, 7, PREFIX, 1)
        with patch.object(observer, 'backend', side_effect=TimeoutError), self.assertRaises(TimeoutError):
            observer.lease(REQUEST, 7, PREFIX, 1)

    def test_missing_pool_statistics_is_an_error(self):
        with self.assertRaises(KeyError):
            observer.capacity([{'id': 5, 'pools': [{'pool-id': 100}]}], {'result': 0, 'arguments': {}}, 1)


    def test_recount_ignores_reservations_and_reclaimed_rows_and_rejects_churn(self):
        scopes = [{'id': 7, 'pools': [{'pool-id': 10, 'pool': '192.0.2.10-192.0.2.19'}]}]
        rows = [ROW, dict(ROW, **{'ip-address': '192.0.2.20'}), dict(ROW, **{'ip-address': '192.0.2.17', 'state': 2})]
        with patch.object(observer, 'backend', return_value={'result': 0, 'arguments': {'leases': rows}}):
            self.assertEqual(observer.recount(scopes, {7: 2}, 1), {(7, 10): 1})
            with self.assertRaises(ValueError):
                observer.recount(scopes, {7: 3}, 1)
