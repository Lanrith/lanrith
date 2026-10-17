"""Runtime diagnostics identify the failure without exposing owner data."""

from contextlib import redirect_stderr
import io
import unittest
from unittest.mock import patch

from lanrith import runtime


class RuntimeDiagnosticTests(unittest.TestCase):
    def test_unexpected_failures_report_categories_without_paths_or_input(self):
        secret = 'private-owner-data-that-must-not-be-logged'
        for error in (FileNotFoundError(2, secret, '/private/'+secret), KeyError(secret), ValueError(secret)):
            with self.subTest(exception=type(error).__name__), patch.object(runtime, 'status', side_effect=error):
                output = io.StringIO()
                with redirect_stderr(output):
                    self.assertEqual(runtime.main(['status']), 1)
                message = output.getvalue()
                self.assertIn('operation=status', message)
                self.assertIn('exception='+type(error).__name__, message)
                if isinstance(error, OSError):
                    self.assertIn('errno=2', message)
                self.assertNotIn(secret, message)
                self.assertNotIn('/private/', message)
