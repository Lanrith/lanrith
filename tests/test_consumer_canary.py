"""The disposable canary must not run as a production signing path."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from lanrith.release import ReleaseError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('consumer_canary', ROOT/'scripts/qualify-consumer.py')
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


class CanaryBoundaryTests(unittest.TestCase):
    def test_only_the_isolated_repository_can_use_disposable_qualification(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'Lanrith/config-template'}, clear=True), \
                self.assertRaisesRegex(ReleaseError, 'isolated canary'):
            canary.qualification(Path('/unused'), Path('/unused'))

    def test_deployment_secrets_are_rejected_before_any_build_or_key_generation(self):
        for name in ('LANRITH_BOOT_KEY', 'LANRITH_EVIDENCE_KEY', 'LANRITH_SERIAL_PASSPHRASE_HASH'):
            with self.subTest(name=name), patch.dict(os.environ,
                    {'GITHUB_REPOSITORY': 'Lanrith/config-template-qualification', name: 'fixture'}, clear=True), \
                    self.assertRaisesRegex(ReleaseError, 'must not receive deployment credentials'):
                canary.qualification(Path('/unused'), Path('/unused'))
