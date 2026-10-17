"""Boot acceptance requires an active watchdog owned by the system manager."""

from pathlib import Path
import tempfile
import unittest

from lanrith import runtime
from lanrith.release import ReleaseError


class WatchdogTests(unittest.TestCase):
    def test_optional_and_required_hardware_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            for mode in ('auto', 'disabled'):
                runtime.watchdog_health({'mode': mode, 'device': '/dev/watchdog0'}, sysfs=sysfs)
            with self.assertRaisesRegex(ReleaseError, 'absent'):
                runtime.watchdog_health({'mode': 'required', 'device': '/dev/watchdog0'}, sysfs=sysfs)

    def test_inactive_unowned_or_different_watchdog_cannot_admit_a_boot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sysfs, fds = root/'sysfs', root/'fds'
            watchdog = sysfs/'watchdog1'
            watchdog.mkdir(parents=True)
            fds.mkdir()
            policy = {'mode': 'auto', 'device': '/dev/watchdog1'}
            (watchdog/'state').write_text('inactive\n')
            with self.assertRaisesRegex(ReleaseError, 'not active'):
                runtime.watchdog_health(policy, sysfs=sysfs, manager_fds=fds)
            (watchdog/'state').write_text('active\n')
            with self.assertRaisesRegex(ReleaseError, 'does not own'):
                runtime.watchdog_health(policy, sysfs=sysfs, manager_fds=fds)
            (fds/'9').symlink_to('/dev/watchdog0')
            with self.assertRaisesRegex(ReleaseError, 'does not own'):
                runtime.watchdog_health(policy, sysfs=sysfs, manager_fds=fds)
            (fds/'9').unlink()
            (fds/'9').symlink_to('/dev/watchdog1')
            runtime.watchdog_health(policy, sysfs=sysfs, manager_fds=fds)
