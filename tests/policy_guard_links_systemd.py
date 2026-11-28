#!/usr/bin/env python3
"""Exercise policy link arrival, loss and networkd restarts in an offline PID 1 guest."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import firewall_activation as firewall, policy_runtime
import policy_bindings_component_native as bindings_test
import policy_observer_component_native as base

GUARDS = 'lanrith-policy-guards.service'
BOOTSTRAP = base.DEPENDENCIES[0]
TIMER = 'lanrith-policy-guard-retry.timer'
NETWORKD = 'systemd-networkd.service'
LATE = 'test-wan'


def systemctl(*args, check=True):
    return base.run('systemctl', *args, check=check, timeout=70).stdout.decode().strip()


def active(unit):
    return systemctl('is-active', unit, check=False) == 'active'


def wait_for_helper(previous_guard=None):
    # The link job has a 45-second deadline. After arrival, the notify-type
    # helper gets its own startup budget for clock and kernel initialization.
    def ready():
        return active(base.HELPER) and (previous_guard is None or
            previous_guard != systemctl('show', '-p', 'InvocationID', '--value', GUARDS))

    started = time.monotonic()
    bindings_test.wait(ready, seconds=200)
    print(f'Helper ready after {time.monotonic()-started:.2f} seconds', flush=True)


def elements(name):
    rows = json.loads(base.run('nft', '-j', '-n', 'list', 'set', 'inet', 'lanrith', name).stdout)
    return next(row['set'].get('elem', []) for row in rows['nftables'] if 'set' in row)


def grants():
    return [entry for family in (4, 6) for entry in elements('tp_grants'+str(family))]


def arrive():
    base.run('ip', 'link', 'add', LATE, 'type', 'dummy')
    base.run('ip', 'link', 'set', LATE, 'up')
    base.run('udevadm', 'settle')


def repeated_events():
    for _ in range(3):
        base.run('udevadm', 'trigger', '--action=change', '/sys/class/net/'+LATE)
    base.run('udevadm', 'settle')


def configure(value):
    value['hardware']['interfaces']['wan']['name'] = LATE
    value['groups'] = {}
    value['access']['rules'] = [{'action': 'allow', 'from': 'devices', 'to': 'uplink'}]
    return value


class LinkFixture:
    def install(self, candidate, contract, files, metadata, units):
        self.contract = contract
        policy_runtime.ENROLLMENT.parent.mkdir(mode=0o700, parents=True)
        assert Path(contract['profile_metadata']).is_file()
        # The synthetic reader submits over its authenticated socket only when
        # this test requests it. No directory refresh can renew a prior grant.
        for name, data in files.items():
            prefix = 'usr/lib/systemd/system/'
            unit = name.removeprefix(prefix)
            if name.startswith(prefix) and (unit.startswith(('sys-subsystem-net-devices-', GUARDS, 'lanrith-policy-guard-retry.')) or
                                           unit == BOOTSTRAP):
                path = units/unit
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
        for name in (firewall.FLOOR, firewall.FORWARDING, firewall.HARDENING, '/etc/nftables.conf',
                     '/usr/lib/systemd/system/lanrith-firewall-floor.service',
                     '/etc/systemd/system/systemd-networkd.service.d/60-lanrith-firewall-floor.conf',
                     '/etc/systemd/system/nftables.service.d/60-lanrith-activation.conf'):
            path = Path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(files[name.lstrip('/')])
        shutil.copyfile(ROOT/'lanrith/firewall_activation.py', '/usr/lib/lanrith/lanrith/firewall_activation.py')
        # The fixture owns test interface addressing. Keep the daemon running
        # with no address changes when testing its process lifetime.
        path = Path('/run/systemd/network/01-fixture.network')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[Match]\nName=*\n[Link]\nUnmanaged=yes\n')
        gate = Path('/run/allow-test-networkd')
        gate.touch()
        start = units/(NETWORKD+'.d')/'10-fixture.conf'
        start.parent.mkdir(exist_ok=True)
        start.write_text(f'[Service]\nExecStartPre=/usr/bin/test -f {gate}\nRestart=no\n')
        base.run('ip', 'link', 'delete', LATE)
        base.run('udevadm', 'settle')
        systemctl('log-target', 'journal-or-kmsg')
        systemctl('log-level', 'info')
        systemctl('daemon-reload')
        systemctl('start', NETWORKD, 'nftables.service')
        assert not elements('tp_started') and not grants()
        device = base.run('systemd-escape', '--path', '--suffix=device', '/sys/subsystem/net/devices/'+LATE).stdout.strip().decode()
        waiting = time.monotonic()
        result = base.run('systemctl', 'start', base.HELPER, check=False, timeout=65)
        assert 43 < time.monotonic()-waiting < 60
        assert result.returncode and not active(GUARDS) and not active(BOOTSTRAP) and not active(base.HELPER)
        journal = base.run('journalctl', '--no-pager', '-b', '-u', device, '-o', 'cat').stdout
        assert b'timed out' in journal.lower() and LATE.encode() in journal, journal
        assert not elements('tp_started') and not policy_runtime.ENROLLMENT.exists()
        base.run('ip', 'link', 'add', 'unlisted', 'type', 'dummy')
        base.run('udevadm', 'settle')
        assert not active(TIMER) and not active(GUARDS) and not elements('tp_started')

        # All interfaces can exist even if their manager fails startup.
        gate.unlink()
        base.run('systemctl', 'restart', NETWORKD, check=False)
        arrive()
        bindings_test.wait(lambda: systemctl('is-failed', GUARDS, check=False) == 'failed', seconds=20)
        assert not active(NETWORKD) and not active(BOOTSTRAP) and not active(base.HELPER)
        assert not elements('tp_started') and not policy_runtime.ENROLLMENT.exists()

        base.run('ip', 'link', 'delete', LATE)
        base.run('udevadm', 'settle')
        gate.touch()
        systemctl('reset-failed', NETWORKD, 'systemd-networkd.socket')
        systemctl('start', NETWORKD)
        # No manual policy start is allowed between this event and readiness.
        arrive()
        wait_for_helper()
        assert active(GUARDS) and active(BOOTSTRAP) and policy_runtime.ENROLLMENT.is_file()
        policy_runtime.verify_guard_hooks(contract)
        assert elements('tp_started') and not grants()
        print('PASS late signed link, failed manager, unrelated link and boot admission', flush=True)

    def submit(self):
        return base.request(base.PROPOSAL, bindings_test.snapshot(), uid=1701, gid=1701,
                            response_timeout=7)['reply']

    def networkd_restart(self):
        units = (GUARDS, BOOTSTRAP, base.DEPENDENCIES[1], base.HELPER)
        def invocations():
            return {u: systemctl('show', '-p', 'InvocationID', '--value', u) for u in units}
        def program():
            rows = json.loads(base.run('nft', '-j', '-n', '-t', 'list', 'ruleset').stdout)['nftables']
            # Terse listings exclude mutable set elements. Counter values can
            # increase from guest traffic while their rules and handles persist.
            for row in rows:
                for expression in row.get('rule', {}).get('expr', []):
                    if 'counter' in expression and isinstance(expression['counter'], dict):
                        expression['counter'] = {}
            return rows

        original = invocations()
        installed = program()
        assert base.run('systemctl', 'reload', 'nftables.service', check=False).returncode != 0
        old = systemctl('show', '-p', 'MainPID', '--value', NETWORKD)
        repeated_events()
        systemctl('restart', NETWORKD)
        assert old != systemctl('show', '-p', 'MainPID', '--value', NETWORKD)
        assert all(active(u) for u in units) and invocations() == original and installed == program()
        policy_runtime.verify_guard_hooks(self.contract)

    def observed(self, stage, value, files):
        if stage == 'applied':
            before = {str(item['elem']['val']): item['elem']['expires'] for item in grants()}
            def snapshot():
                return base.request(policy_runtime.OBSERVATIONS, base.OBSERVE)['reply']['snapshot']

            issued = snapshot()
            assert before and issued['grants']
            self.networkd_restart()
            after = {str(item['elem']['val']): item['elem']['expires'] for item in grants()}
            assert after.keys() == before.keys() and all(0 < after[k] < before[k] for k in before)
            retained = snapshot()
            assert issued['generation'] == retained['generation'] and issued['grants'] == retained['grants']
            print('PASS authenticated grant deadline across events and networkd restart',
                  min(before.values()), min(after.values()), 'seconds remaining', flush=True)

    def qualify(self):
        assert grants()
        bindings_test.wait(lambda: not grants(), seconds=100)
        self.networkd_restart()
        assert not grants() and policy_runtime.cohort(self.contract) == [bindings_test.MAC]
        print('PASS expired grant and classified history across networkd restart', flush=True)
        # Replacing the same name creates a different ifindex. Let systemd
        # stop the old graph, close the startup set and install its new hook.
        base.run('ip', 'link', 'delete', LATE)
        bindings_test.wait(lambda: systemctl('show', '-p', 'ActiveState', '--value', GUARDS) == 'inactive')
        assert not active(base.HELPER) and not elements('tp_started')
        arrive()
        wait_for_helper()
        policy_runtime.verify_guard_hooks(self.contract)
        assert elements('tp_started') and not grants()
        assert policy_runtime.cohort(self.contract) == [bindings_test.MAC]
        before = systemctl('show', '-p', 'InvocationID', '--value', GUARDS)
        base.run('ip', 'link', 'delete', LATE)
        arrive()
        wait_for_helper(previous_guard=before)
        policy_runtime.verify_guard_hooks(self.contract)
        assert elements('tp_started') and not grants()
        print('PASS both settled and rapid device replacement restore coverage without replay', flush=True)

        base.run('ip', 'link', 'delete', LATE)
        bindings_test.wait(lambda: systemctl('show', '-p', 'ActiveState', '--value', GUARDS) == 'inactive')
        pinned = Path(self.contract['profile_directory'])/'guards.nft'
        pinned.write_bytes(pinned.read_bytes()+b'# synthetic pin mismatch\n')
        arrive()
        bindings_test.wait(lambda: systemctl('is-failed', GUARDS, check=False) == 'failed')
        assert not active(BOOTSTRAP) and not active(base.HELPER) and not elements('tp_started') and not grants()
        print('PASS a link event cannot replace the pinned guard program', flush=True)

    def close(self):
        # The enclosing fixture removes every originally created link.
        if not Path('/sys/class/net', LATE).exists():
            arrive()


def main(candidate):
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert Path('/usr/bin/lanrith-fixture-run').is_file() and not Path('/usr/share/lanrith/installed.json').exists()
    assert [row['ifname'] for row in json.loads(base.run('ip', '-j', 'link').stdout)] == ['lo']
    # Reuse the component graph's isolated fixture checks and private mount.
    Path('/run/.containerenv').touch()
    base.run('mount', '--bind', '/var', '/var')
    base.run('sysctl', '-w', 'net.core.wmem_max=16777216', 'net.core.rmem_max=16777216')
    timex = (ctypes.c_long*64)()
    timex[0] = 0x1c
    assert ctypes.CDLL(None, use_errno=True).adjtimex(ctypes.byref(timex)) == 0
    for path in map(Path, ('/usr/sbin/conntrack', '/usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so.3',
                           '/usr/lib/x86_64-linux-gnu/libnfnetlink.so.0')):
        if not path.exists():
            shutil.copy2(Path('/opt/fixture-platform')/path.relative_to('/'), path)
    pin = json.loads((ROOT/'build-inputs.json').read_bytes())['component_releases']['router-policy-agent']
    assert json.loads((candidate/'candidate.json').read_bytes())['source_commit'] == pin['source_commit']
    graph = LinkFixture()
    try:
        bindings_test.qualify(candidate, bindings_test.sha(candidate/'router-policy-collector'), Path('/run/guard-result.json'),
            access_backend='tun', configure=configure, service_graph=graph, observe_stage=graph.observed,
            admission_test=graph.qualify)
    except BaseException:
        subprocess.run(['journalctl', '--no-pager', '-n', '70', '-o', 'short-monotonic'])
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    main(parser.parse_args().candidate)
