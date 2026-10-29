"""The synthetic serial drill distinguishes automatic and manual selection."""

import contextlib
import io
from types import SimpleNamespace
import unittest

import qualify_failure_serial_vm as fixture


class FailureSerialModesTests(unittest.TestCase):
    def test_manual_fixture_does_not_invoke_automatic_fallback(self):
        calls = []
        console = SimpleNamespace(automatic_fallback=lambda: calls.append('automatic'))
        exec(fixture.console_hook(False), {'console': console})
        self.assertFalse(console.automatic_fallback())
        self.assertEqual(calls, [])

    def test_automatic_fixture_executes_the_real_callback(self):
        calls = []
        console = SimpleNamespace(automatic_fallback=lambda: calls.append('automatic') or True)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            exec(fixture.console_hook(True), {'console': console})
            self.assertTrue(console.automatic_fallback())
        self.assertEqual(calls, ['automatic'])
        self.assertIn('VM automatic console fallback entered', output.getvalue())

    def test_modes_require_boolean(self):
        with self.assertRaises(ValueError):
            fixture.console_hook('yes')

    def test_synthetic_state_override_is_observation_only(self):
        namespace = {}
        exec(fixture.synthetic_state_override(), namespace)
        result = namespace['observe_rollback_compatibility']({})
        self.assertEqual(result, {'scope': 'rollback-compatibility-observation', 'authorized_to_boot': False})


if __name__ == '__main__':
    unittest.main()
