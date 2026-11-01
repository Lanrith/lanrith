"""NAT64 producer and helper use the same clock after host suspension."""

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import nat64_runtime as runtime
from lanrith.release import ReleaseError


class Nat64RuntimeClockTests(unittest.TestCase):
    def test_readiness_uses_kernel_boot_time_and_expires_across_suspend(self):
        configuration = b'synthetic immutable translator configuration\n'
        manifest = {'interface': 'nat64', 'state_directory': '/synthetic-state'}
        component = {'pending_set': 'native_n64_0_pending'}
        observation = {'pid': 123, 'start_ticks': '456', 'monotonic': 100000,
                       'configuration_sha256': hashlib.sha256(configuration).hexdigest()}

        def read(path, maximum):
            return configuration if path.name == 'tayga.conf' else json.dumps(observation).encode()

        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/uptime':
                return '100000.00 111111.11\n'
            if path.name == 'stat':
                return '123 (tayga) '+' '.join(['S']+['0']*18+['456'])
            if path.name == 'status':
                return 'Uid:\t1001\t1001\t1001\t1001\nCapEff:\t0000000000000000\n'
            raise AssertionError('Unexpected clock or process input: '+str(path))

        with ExitStack() as stack:
            for target, attribute, options in (
                    (runtime.translation_runtime, 'status', {}),
                    (runtime.allocations, 'secure_state_directory', {}),
                    (runtime.allocations, 'load', {'return_value': {}}),
                    (runtime.allocations, 'configuration', {'return_value': configuration}),
                    (runtime, 'read', {'side_effect': read}),
                    (runtime.time, 'monotonic', {'return_value': 10}),
                    (runtime.pwd, 'getpwnam', {'return_value': SimpleNamespace(pw_uid=1001)}),
                    (Path, 'read_text', {'autospec': True, 'side_effect': read_text}),
                    (Path, 'read_bytes', {'return_value': b'/usr/sbin/tayga\0--nodetach\0--config\0/run/lanrith-nat64/tayga.conf\0'})):
                stack.enter_context(patch.object(target, attribute, **options))
            runtime.status(manifest, component)
            for timestamp in (10, 99995.99, 100000.01):
                with self.subTest(timestamp=timestamp):
                    observation['monotonic'] = timestamp
                    with self.assertRaisesRegex(ReleaseError, 'stale'):
                        runtime.status(manifest, component)


if __name__ == '__main__':
    unittest.main()
