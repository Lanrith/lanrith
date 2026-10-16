#!/usr/bin/env python3
"""Image-owned SNMP activation, encrypted state, and authenticated polling."""

from contextlib import ExitStack
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile

import credential_runtime
from credential_runtime import Activation, read_json
import snmp_credentials as credentials
from snmp_credentials import SNMPError
from systemd_service import Service as SystemdService


ROOT = Path('/var/lib/lanrith/snmp')
POLICY = Path('/etc/lanrith/integrations/snmp-runtime-policy.json')
WORK = Path('/run/lanrith-snmp')
PERSISTENT = Path('/var/lib/snmp')
FILENAME = 'snmpd.conf'


def policy_value(value):
    if (not isinstance(value, dict) or set(value) != {'schema', 'server', 'username'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['username'] != 'librenms-router'):
        raise SNMPError('SNMP runtime image policy is unsupported.', 76)
    credentials.listener_address(value['server'])
    return value


def load_policy():
    try:
        return policy_value(read_json(POLICY.read_bytes()))
    except (OSError, ValueError, TypeError) as error:
        raise SNMPError('SNMP runtime image policy is unavailable or invalid.', 76) from error


class State(credential_runtime.State):
    Error = SNMPError

    def __init__(self, root=ROOT, owner=0, group=0):
        super().__init__(root, owner, group)

    def validate(self, raw):
        return credentials.configuration(credentials.parse(raw))

    @classmethod
    def names(cls, values):
        if super().names(values) != [FILENAME]:
            raise SNMPError('SNMP activation journal contains an unapproved file.', 70)
        return values


def private_state():
    """Adopt only the exact legacy root-owned layout, without changing values."""
    if ROOT.resolve() != ROOT:
        raise SNMPError('SNMP state directory contains a symlink.')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with ExitStack() as stack:
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, directory)
        info = os.fstat(directory)
        # The legacy group's numeric ID may differ in the new image. Mode
        # 0600 and root ownership protect the file regardless of that group.
        if (info.st_uid != 0 or not (stat.S_IMODE(info.st_mode) == 0o750
                or (info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700))):
            raise SNMPError('SNMP state directory has unsafe ownership or mode.')
        try:
            descriptor = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            descriptor = None
        if descriptor is not None:
            stream = stack.enter_context(os.fdopen(descriptor, 'rb'))
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 4097):
                raise SNMPError('SNMP credential file has unsafe metadata.')
            if info.st_gid != 0:
                credentials.parse(stream.read(4098))
                os.fchown(stream.fileno(), 0, 0)
                os.fsync(stream.fileno())
        info = os.fstat(directory)
        if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            os.fchown(directory, 0, 0)
            os.fchmod(directory, 0o700)
            os.fsync(directory)
    return State()


def persistent_directory():
    # Keep Net-SNMP's USM engine identity and monotonic boot counter. Credential
    # rollback must never restore a snapshot of this daemon-owned directory.
    if PERSISTENT.resolve() != PERSISTENT:
        raise SNMPError('SNMP persistent engine directory contains a symlink.')
    PERSISTENT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with ExitStack() as stack:
        descriptor = os.open(PERSISTENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, descriptor)
        directory = os.fstat(descriptor)
        if stat.S_IMODE(directory.st_mode) not in {0o700, 0o750, 0o755}:
            raise SNMPError('SNMP persistent engine directory has unsafe permissions.')
        account = pwd.getpwnam('Debian-snmp')
        files = []
        for path in PERSISTENT.glob('snmpd*.conf'):
            if not re.fullmatch(r'snmpd(?:\.[0-9]{1,2})?\.conf', path.name) or len(files) >= 32:
                raise SNMPError('SNMP persistent engine configuration contains unsupported files.')
            file = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, file)
            info = os.fstat(file)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid not in {0, directory.st_uid, account.pw_uid}
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1048576):
                raise SNMPError('SNMP persistent engine file has unsafe metadata.')
            files.append((file, info))
        # Validate every file before changing any ownership. Never replace
        # engine data or decrement the boot counter during credential rollback.
        for file, info in files:
            if (info.st_uid, info.st_gid) != (account.pw_uid, account.pw_gid):
                os.fchown(file, account.pw_uid, account.pw_gid)
                os.fsync(file)
        os.fchown(descriptor, account.pw_uid, account.pw_gid)
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)


class Service(SystemdService):
    def __init__(self, policy):
        super().__init__('snmpd.service', SNMPError, start_timeout=85)
        self.policy = policy

    def socket_inventory(self):
        result = []
        for family in ('6', '4'):
            inspection = self.run(['/usr/bin/ss', '-H', '-lun' + family, 'sport = :161'], 10, capture=True)
            if inspection.returncode:
                raise SNMPError('SNMP socket inventory could not be inspected.', 69)
            result.append(inspection.stdout)
        return result

    def probe(self, value):
        config = credentials.parse(value)
        State(WORK).directory(WORK, create=True)
        with tempfile.TemporaryDirectory(prefix='.acceptance.', dir=WORK) as temporary:
            path = Path(temporary) / 'snmp.conf'
            path.write_text('defSecurityLevel authPriv\n'
                            f'defSecurityName {config["username"]}\n'
                            f'defAuthType {config["auth_protocol"]}\n'
                            f'defPrivType {config["priv_protocol"]}\n'
                            f'defAuthPassphrase "{config["auth_password"]}"\n'
                            f'defPrivPassphrase "{config["priv_password"]}"\n')
            path.chmod(0o600)
            result = self.run(['/usr/bin/snmpget', '-v3', '-r1', '-t1', '-Oqvt',
                               f'udp6:[{self.policy["server"]}]:161', '.1.3.6.1.2.1.1.3.0'],
                              10, capture=True, env={'PATH': '/usr/bin:/bin', 'MIBS': '',
                                                    'SNMPCONFPATH': temporary,
                                                    'SNMP_PERSISTENT_DIR': temporary})
            value = result.stdout.strip()
            return result.returncode == 0 and len(value) <= 10 and value.isdigit() and int(value) <= 4294967295

    def preflight(self, values):
        value = credentials.parse(values[FILENAME])
        if value['username'] != self.policy['username']:
            raise SNMPError('SNMP request does not match the image-authorized user.')
        if not os.access('/usr/bin/snmpget', os.X_OK):
            raise SNMPError('The image lacks the required SNMP acceptance client.', 76)

    def verify(self, values):
        try:
            status = self.status()
            ipv6, ipv4 = self.socket_inventory()
            if values[FILENAME] is None:
                return (status['ActiveState'] in {'inactive', 'failed'} and status['MainPID'] == '0'
                        and status['SubState'] in {'dead', 'failed'} and not ipv6.strip() and not ipv4.strip())
            if status['ActiveState'] != 'active' or status['SubState'] != 'running' or status['MainPID'] == '0':
                return False
            credentials.listeners(ipv6, ipv4, self.policy['server'])
            return self.probe(values[FILENAME])
        except (OSError, subprocess.SubprocessError, SNMPError):
            return False

    def rollback_values(self, values):
        status = self.status()
        if (status['ActiveState'] in {'inactive', 'failed'} and status['MainPID'] == '0'
                and status['SubState'] in {'dead', 'failed'}):
            return values
        if self.verify(values):
            return values
        raise SNMPError('SNMP has no verified rollback credentials; the running daemon was preserved.', 70)


def apply(policy, request):
    value = credentials.configuration(request)
    if request['username'] != policy['username']:
        raise SNMPError('SNMP request does not match the image-authorized user.')
    state = private_state()
    service = Service(policy)
    return Activation(state, service, service.preflight).apply({FILENAME: value})


def prepare(policy):
    """ExecCondition: recover before start, or skip the unit when unprovisioned."""
    state = private_state()
    with ExitStack() as stack:
        owned = True
        try:
            stack.enter_context(state.lock())
        except SNMPError as error:
            if error.code != 75:
                raise
            owned = False
            data = state.metadata()
            if data is not None and data['phase'] in {'writing', 'restoring'}:
                raise SNMPError('SNMP activation is between credential sets.', 75) from error
        if owned:
            Activation(state, None, None).recover(boot=True)
        value = state.values([FILENAME])[FILENAME]
        if value is None:
            return False
        if credentials.parse(value)['username'] != policy['username']:
            raise SNMPError('SNMP credentials do not match the image-authorized user.')
        persistent_directory()
        return True
