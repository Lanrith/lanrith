"""Privilege failures block qualification and retain public diagnostics only."""

import ast
import json
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from lanrith.release import ReleaseError
from lanrith import config, runtime_plan
from vm import (FIREWALL_LISTENERS, INACTIVE_OPTIONAL_UNITS, PrivilegeBoundaryError,
                check_process_capabilities, firewall_failure, unprivileged_control_boundary)


class PrivilegeBoundaryTests(unittest.TestCase):
    def test_required_core_services_are_not_misclassified_as_inactive_optional_units(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        required = set(runtime_plan.required_units(value))
        self.assertIn('chrony.service', required)
        self.assertFalse(required & set(INACTIVE_OPTIONAL_UNITS))
        infrastructure = {'nftables.service', 'systemd-networkd.service', 'lanrith-services.service'}
        self.assertEqual(set(FIREWALL_LISTENERS), required-infrastructure)
        self.assertIn('chronyd-restricted.service', INACTIVE_OPTIONAL_UNITS)
        self.assertIn('chrony-wait.service', INACTIVE_OPTIONAL_UNITS)

    def guest(self, failed=None, stderr=b''):
        results = [SimpleNamespace(returncode=255, stdout=b'', stderr=b'')]
        results += [SimpleNamespace(returncode=1 if name == failed else 0,
                                    stdout=b'private-disposable-recovery-key', stderr=stderr)
                    for name in ('administrator', 'services', 'postconditions')]
        return SimpleNamespace(ssh=Mock(side_effect=results))

    def test_each_failed_boundary_blocks_and_excludes_private_remote_output(self):
        for stage in ('administrator', 'services', 'postconditions'):
            guest = self.guest(stage, b'private-owner-data\nA non-root process holds an undeclared capability.')
            with self.subTest(stage=stage):
                with self.assertRaises(PrivilegeBoundaryError) as failure:
                    unprivileged_control_boundary(guest)
                diagnostic = failure.exception.diagnostic
                self.assertEqual(diagnostic[stage]['exit_code'], 1)
                self.assertIn('undeclared-process-capability', diagnostic[stage]['categories'])
                self.assertNotIn('private-', str(failure.exception))
                self.assertNotIn('private-', json.dumps(diagnostic))
                self.assertEqual(guest.ssh.call_count, 4)

    def test_success_requires_all_three_boundaries_and_denied_root_login(self):
        guest = self.guest()
        unprivileged_control_boundary(guest)
        self.assertEqual(guest.ssh.call_count, 4)
        # Compile the actual serialized remote program, including its shared
        # verifier, before an expensive VM build can reach it.
        script = shlex.split(guest.ssh.call_args.args[0])[3]
        program = script.split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
        compile(program, '<remote-privilege-postconditions>', 'exec')
        guest = SimpleNamespace(ssh=Mock(return_value=SimpleNamespace(returncode=0)))
        with self.assertRaisesRegex(ReleaseError, 'Direct root SSH login succeeded'):
            unprivileged_control_boundary(guest)
        self.assertEqual(guest.ssh.call_count, 1)

    def test_oversized_remote_diagnostics_are_not_retained_or_classified(self):
        guest = self.guest('postconditions', b'A non-root process holds an undeclared capability.'+b'x'*65536)
        with self.assertRaises(PrivilegeBoundaryError) as failure:
            unprivileged_control_boundary(guest)
        self.assertEqual(failure.exception.diagnostic['postconditions']['categories'], [])
        self.assertLess(len(str(failure.exception)), 512)

    def test_firewall_probe_serializes_every_required_core_listener(self):
        receipt = {'result': 'pass', 'stopped_with_firewall': True,
                   'blocked_on_firewall_failure': True, 'effective_kernel_hardening': True}
        guest = Mock()
        guest.ssh.side_effect = [SimpleNamespace(returncode=0),
                                SimpleNamespace(returncode=0, stdout=json.dumps(receipt).encode())]
        firewall_failure(guest)
        outer = shlex.split(guest.ssh.call_args_list[0].args[0])[3]
        program = shlex.split(outer)[-1]
        tree = ast.parse(program)
        listeners = next(ast.literal_eval(node.value) for node in tree.body
                         if isinstance(node, ast.Assign) and
                         any(isinstance(name, ast.Name) and name.id == 'listeners'
                             for name in node.targets))
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        infrastructure = {'nftables.service', 'systemd-networkd.service', 'lanrith-services.service'}
        self.assertEqual(set(listeners), set(runtime_plan.required_units(value))-infrastructure)
        guest.ready.assert_called_once_with()


class ProcessCapabilityTests(unittest.TestCase):
    def process(self, proc, pid, uid, group, *, fields=None):
        directory = proc/str(pid)
        directory.mkdir(exist_ok=True)
        caps = dict.fromkeys(('CapEff', 'CapPrm', 'CapInh', 'CapAmb'), 0)
        caps.update(fields or {})
        (directory/'status').write_text(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n'+
            ''.join(f'{key}:\t{value:016x}\n' for key, value in caps.items()))
        (directory/'cgroup').write_text('0::'+group+'\n')
        return directory

    def policy(self):
        return {'chrony.service': {'pid': 101, 'uid': 105, 'mask': (1 << 10) | (1 << 25),
                                   'group': '/system.slice/chrony.service'}}

    def test_main_daemon_and_workers_share_only_their_declared_service_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            self.process(proc, 101, 105, '/system.slice/chrony.service', fields={'CapEff': 1 << 25})
            self.process(proc, 102, 105, '/system.slice/chrony.service',
                         fields={'CapPrm': 1 << 25, 'CapInh': 1 << 10})
            self.process(proc, 103, 1000, '/user.slice/session.scope')
            check_process_capabilities(self.policy(), proc=proc)

    def test_same_uid_or_similar_service_group_cannot_authorize_another_process(self):
        for uid, group in ((105, '/user.slice/session.scope'), (106, '/system.slice/chrony.service'),
                           (105, '/system.slice/chrony.service.evil'), (105, '/system.slice/chrony.service/child')):
            with self.subTest(uid=uid, group=group), tempfile.TemporaryDirectory() as temporary:
                proc = Path(temporary)
                self.process(proc, 101, 105, '/system.slice/chrony.service')
                self.process(proc, 102, uid, group, fields={'CapEff': 1 << 25})
                with self.assertRaisesRegex(SystemExit, 'undeclared capability'):
                    check_process_capabilities(self.policy(), proc=proc)

    def test_every_retained_capability_set_rejects_extra_authority(self):
        for field in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                proc = Path(temporary)
                self.process(proc, 101, 105, '/system.slice/chrony.service')
                self.process(proc, 102, 105, '/system.slice/chrony.service', fields={field: 1 << 21})
                with self.assertRaisesRegex(SystemExit, 'undeclared capability'):
                    check_process_capabilities(self.policy(), proc=proc)

    def test_service_leader_identity_and_live_process_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            self.process(proc, 101, 106, '/system.slice/chrony.service')
            with self.assertRaisesRegex(SystemExit, 'identity is invalid'):
                check_process_capabilities(self.policy(), proc=proc)
            self.process(proc, 101, 105, '/system.slice/chrony.service')
            child = self.process(proc, 102, 105, '/system.slice/chrony.service', fields={'CapEff': 1 << 25})
            (child/'cgroup').unlink()
            with self.assertRaisesRegex(SystemExit, 'cgroup could not be verified'):
                check_process_capabilities(self.policy(), proc=proc)
            with patch.object(Path, 'read_text', side_effect=PermissionError):
                with self.assertRaisesRegex(SystemExit, 'capability record could not be verified'):
                    check_process_capabilities(self.policy(), proc=proc)
