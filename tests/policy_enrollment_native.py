#!/usr/bin/env python3
"""Interrupt policy first-install commits on disposable private Linux storage."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import policy_runtime as runtime


def interrupt_after(contract, owner, method, matches):
    original = getattr(owner, method)
    pid = os.fork()
    if pid == 0:
        def interrupted(*args, **kwargs):
            result = original(*args, **kwargs)
            if matches(*args, **kwargs):
                os._exit(79)
            return result

        with patch.object(owner, method, interrupted):
            runtime.enroll_or_recover(contract)
        os._exit(1)
    assert os.waitpid(pid, 0)[1] == 79 << 8, method


def exercise(root):
    state = root/'state'
    state.mkdir(mode=0o700)
    control = root/'control'
    control.mkdir(mode=0o700)
    marker = control/'enrolled'
    contract = {'state_directory': str(state), 'recover_executable': '/fixture/recover'}
    expected = {'state.json': b'{"fixture":"empty"}',
                'ownership-epoch.json': b'{"schema_version":1,"last":0}'}
    history = state/'state.json'
    counter = state/'ownership-epoch.json'

    def recover(args):
        assert args[0] == contract['recover_executable']
        try:
            json.loads(history.read_bytes())
        except (OSError, ValueError):
            raise runtime.PolicyRuntimeError('fixture recovery refused damaged history') from None

    def rejects(label):
        try:
            runtime.enroll_or_recover(contract)
        except runtime.EnrollmentError as error:
            assert label in str(error), str(error)
        else:
            raise AssertionError(label)

    with ExitStack() as stack:
        stack.enter_context(patch.object(runtime, 'ENROLLMENT', marker))
        stack.enter_context(patch.object(runtime, 'initial_records', return_value=expected))
        stack.enter_context(patch.object(runtime, 'command', recover))
        for entry in (history, counter, state/'.lock', state/'unrecognized'):
            entry.touch(mode=0o600)
            rejects('Unacknowledged')
            assert not marker.exists()
            entry.unlink()

        interrupt_after(contract, os, 'setxattr', lambda fd, name, value, flags: flags == os.XATTR_CREATE)
        assert not marker.exists() and not list(state.iterdir())
        interrupt_after(contract, runtime, 'atomic', lambda path, value: value != runtime.ENROLLED)
        assert marker.read_bytes().startswith(b'installing-v2 ') and not list(state.iterdir())
        state.rename(root/'original')
        state.mkdir(mode=0o700)
        rejects('does not match')
        assert not list(state.iterdir())
        state.rmdir()
        (root/'original').rename(state)
        (state/'other').touch()
        rejects('unrecognized')
        (state/'other').unlink()

        # Interrupt once after the helper's durable-store lock is acquired.
        interrupt_after(contract, runtime.fcntl, 'flock',
                        lambda fd, flags: flags == runtime.fcntl.LOCK_EX | runtime.fcntl.LOCK_NB)
        assert [p.name for p in state.iterdir()] == ['.lock']
        runtime.atomic(counter, expected[counter.name])
        rejects('state.json is missing')
        counter.unlink()
        with (state/'.lock').open('rb') as lock:
            runtime.fcntl.flock(lock, runtime.fcntl.LOCK_EX | runtime.fcntl.LOCK_NB)
            try:
                runtime.enroll_or_recover(contract)
            except BlockingIOError:
                pass
            else:
                raise AssertionError('Active helper lock was ignored')

        interrupt_after(contract, runtime, 'install_record', lambda directory, name, value: name == history.name)
        assert history.read_bytes() == expected[history.name] and not counter.exists()
        inode = history.stat().st_ino
        history.chmod(0o640)
        rejects('state.json differs')
        history.chmod(0o600)
        os.chown(history, 42, 42)
        rejects('state.json differs')
        os.chown(history, 0, 0)
        history.write_text('{"cohort":["fixture"]}')
        rejects('state.json differs')
        assert not counter.exists()
        history.write_bytes(expected[history.name])
        interrupt_after(contract, runtime, 'install_record', lambda directory, name, value: name == counter.name)
        assert history.stat().st_ino == inode
        zero_inode = counter.stat().st_ino
        counter.write_text('{"schema_version":1,"last":7}')
        rejects('ownership-epoch.json differs')
        counter.write_bytes(expected[counter.name])
        interrupt_after(contract, runtime, 'atomic', lambda path, value: value == runtime.ENROLLED)
        assert marker.read_bytes() == runtime.ENROLLED
        interrupt_after(contract, os, 'setxattr', lambda fd, name, value, flags: flags == os.XATTR_REPLACE)
        runtime.enroll_or_recover(contract)
        assert os.getxattr(state, runtime.INSTALL_ID) == b'enrolled'
        assert (history.stat().st_ino, counter.stat().st_ino) == (inode, zero_inode)
        assert counter.read_bytes() == expected[counter.name]

        # The installed v1 layout predates the directory identity attribute.
        os.removexattr(state, runtime.INSTALL_ID)
        marker.write_bytes(b'unknown-enrollment')
        rejects('does not match')
        marker.write_bytes(runtime.ENROLLED)
        counter.write_text('{"schema_version":1,"last":7}')
        runtime.enroll_or_recover(contract)
        assert json.loads(counter.read_bytes())['last'] == 7
        counter.unlink()
        for _ in range(2):
            rejects('ownership-epoch.json')
            assert not counter.exists()
        for content in (b'{}', b'{"schema_version":1,"last":-1}', b'{"schema_version":1,"last":true}'):
            runtime.atomic(counter, content)
            rejects('ownership-epoch.json')
            assert counter.read_bytes() == content
        runtime.atomic(counter, expected[counter.name])
        history.unlink()
        rejects('state.json')
        assert not history.exists()
        runtime.atomic(history, b'{')
        rejects('state.json')
        assert history.read_bytes() == b'{'
        counter.unlink()
        history.unlink()
        rejects('state.json')
        assert marker.read_bytes() == runtime.ENROLLED

    print('PASS interrupted enrollment, native lock, store substitution, v1 compatibility and damaged records')


def reader_retry(root):
    ca = root/'ca.pem'
    ca.write_bytes(b'synthetic CA')
    destination = root/'reader'
    contract = {'directory': {'ca_file': str(ca), 'url': 'ldaps://example.test',
                              'base_dn': 'dc=example,dc=test', 'bind_dn': 'cn=fixture'}}
    identity = SimpleNamespace(pw_uid=42, pw_gid=42)
    with patch.object(runtime, 'READER', destination), patch.object(runtime.pwd, 'getpwnam', return_value=identity):
        pid = os.fork()
        if pid == 0:
            chown = os.chown
            def stop_after_chown(*args):
                chown(*args)
                os._exit(73)
            with patch.object(os, 'chown', stop_after_chown):
                runtime.prepare_reader(contract, 'synthetic')
            os._exit(1)
        assert os.waitpid(pid, 0)[1] == 73 << 8
        assert not destination.exists()
        runtime.prepare_reader(contract, 'synthetic')
        info = destination.stat()
        assert (info.st_uid, info.st_gid, info.st_mode & 0o7777) == (42, 42, 0o700)
        for path in destination.iterdir():
            info = path.stat()
            assert (info.st_uid, info.st_gid, info.st_mode & 0o7777) == (42, 42, 0o600)
        assert json.loads((destination/'credentials.json').read_bytes())['password'] == 'synthetic'
        os.chown(destination, 0, 0)
        try:
            runtime.prepare_reader(contract, 'changed')
        except runtime.PolicyRuntimeError:
            pass
        else:
            raise AssertionError('Unexpected reader directory owner accepted')
        assert json.loads((destination/'credentials.json').read_bytes())['password'] == 'synthetic'
    print('PASS reader publication resumes after process exit and rejects unexpected ownership')


if __name__ == '__main__':
    assert os.geteuid() == 0, 'Use an isolated Linux user namespace or disposable guest'
    with tempfile.TemporaryDirectory() as temporary:
        exercise(Path(temporary))
        reader_retry(Path(temporary))
