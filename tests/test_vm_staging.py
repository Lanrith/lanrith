"""Exercise the fault observer against real disposable GPT files and children."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from lanrith import update
from lanrith.release import ReleaseError
from vm import StagingFaultError, interrupt_staging


@unittest.skipUnless(shutil.which('sfdisk'), 'Requires sfdisk for real regular-file GPT fixtures.')
class StagingInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.disk = Path(self.temporary.name)/'disposable.raw'
        with self.disk.open('xb') as stream:
            stream.truncate(32*1024*1024)
        entries = ['label: gpt', 'size=1MiB,type=U,name=ESP']
        for sequence in (9, 10):
            for role in ('root', 'verity', 'verity-sig'):
                entries.append(f'size=1MiB,type={update.GUIDS[role]},name=l_{sequence}_{role.replace("-", "_")}')
        entries.append('size=4MiB,type=L,name=state')
        subprocess.run(['sfdisk', str(self.disk)], input='\n'.join(entries)+'\n',
                       text=True, capture_output=True, timeout=10, check=True)

    def guest(self, *, node=2, label='_empty', delay=0.2, noisy=False, exit_code=None):
        program = '''import os, subprocess, sys, time
disk, node, label, delay, noisy, code = sys.argv[1:]
if noisy == 'True':
    os.write(1, b'x'*262144)
    os.write(2, b'private-fixture-data'*16384)
time.sleep(float(delay))
if code != 'None':
    sys.exit(int(code))
subprocess.run(['sfdisk', '--part-label', disk, node, label], check=True, capture_output=True)
time.sleep(60)
'''
        return SimpleNamespace(environment=dict(os.environ), close=Mock(),
            ssh_arguments=Mock(return_value=[sys.executable, '-c', program, str(self.disk),
                                            str(node), label, str(delay), str(noisy), str(exit_code)]))

    def labels(self):
        return json.loads(subprocess.run(['sfdisk', '--json', str(self.disk)], capture_output=True,
            check=True, timeout=5).stdout)['partitiontable']['partitions']

    def test_real_inactive_write_cuts_power_and_preserves_accepted_gpt(self):
        before = self.labels()
        guest = self.guest()
        result = interrupt_staging(guest, self.disk, 11, 10, timeout=5)
        guest.close.assert_called_once_with()
        guest.ssh_arguments.assert_called_once_with('sudo lanrith-runtime stage /var/lib/lanrith/update-inbox/11')
        self.assertTrue(result['inactive_write_observed'] and result['power_cut'])
        self.assertEqual([p for p in self.labels() if p['name'].startswith('l_10_')],
                         [p for p in before if p['name'].startswith('l_10_')])

    def test_full_child_output_cannot_block_observation_or_leak_into_report(self):
        guest = self.guest(noisy=True)
        result = interrupt_staging(guest, self.disk, 11, 10, timeout=5)
        self.assertTrue(result['power_cut'])
        self.assertNotIn('private-fixture-data', json.dumps(result))

    def test_admission_delay_is_not_confused_with_an_inactive_write(self):
        guest = self.guest(delay=0.7)
        result = interrupt_staging(guest, self.disk, 11, 10, timeout=5)
        self.assertGreaterEqual(result['elapsed_seconds'], 0.7)
        self.assertGreater(result['observations'], 1)
        guest.close.assert_called_once_with()

    def test_no_write_fails_closed_with_bounded_public_metadata(self):
        guest = self.guest(delay=60, noisy=True)
        with self.assertRaises(StagingFaultError) as failure:
            interrupt_staging(guest, self.disk, 11, 10, timeout=0.3)
        self.assertEqual(failure.exception.diagnostic['reason'], 'staging-deadline-without-inactive-write')
        self.assertFalse(failure.exception.diagnostic['power_cut'])
        self.assertNotIn('private-fixture-data', str(failure.exception))
        guest.close.assert_not_called()

    def test_early_staging_exit_never_counts_as_a_power_cut(self):
        for code in (0, 17):
            with self.subTest(code=code):
                guest = self.guest(noisy=True, exit_code=code)
                with self.assertRaises(StagingFaultError) as failure:
                    interrupt_staging(guest, self.disk, 11, 10, timeout=5)
                self.assertEqual(failure.exception.diagnostic['exit_code'], code)
                self.assertEqual(failure.exception.diagnostic['reason'], 'staging-exited-before-fault')
                self.assertNotIn('private-fixture-data', str(failure.exception))
                guest.close.assert_not_called()

    def test_accepted_slot_mutation_is_rejected_instead_of_becoming_the_fault(self):
        guest = self.guest(node=5)
        with self.assertRaises(StagingFaultError) as failure:
            interrupt_staging(guest, self.disk, 11, 10, timeout=5)
        self.assertEqual(failure.exception.diagnostic['reason'], 'accepted-slot-or-geometry-changed')
        guest.close.assert_not_called()

    def test_preexisting_empty_slot_cannot_satisfy_the_fault_observer(self):
        subprocess.run(['sfdisk', '--part-label', str(self.disk), '2', '_empty'],
                       check=True, capture_output=True, timeout=5)
        guest = self.guest()
        with self.assertRaises(ReleaseError):
            interrupt_staging(guest, self.disk, 11, 10, timeout=5)
        guest.ssh_arguments.assert_not_called()
        guest.close.assert_not_called()
