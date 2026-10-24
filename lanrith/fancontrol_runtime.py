"""Control selected hwmon PWM outputs without network or compiler dependencies.

Only a short bootstrap runs as root. The loop owns pre-opened PWM descriptors
and drops to an otherwise unprivileged, dedicated account before controlling fans.
"""

import argparse
import copy
import grp
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import signal
import socket
import stat
import sys
import threading

from .release import canonical, read, require, unique


MANIFEST = Path('/usr/share/lanrith/fancontrol.json')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,47}\Z')
CHIP = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
TEMP = re.compile(r'temp[1-9][0-9]{0,2}_input\Z')
PWM = re.compile(r'pwm[1-9][0-9]?\Z')
TACH = re.compile(r'fan[1-9][0-9]?_input\Z')


def exact(value, allowed, required=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(allowed),
            'Invalid fan control fields.')


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, 'Invalid fan control numeric range.')


def selector(value):
    exact(value, {'name', 'device'}, {'name'})
    require(isinstance(value['name'], str) and CHIP.fullmatch(value['name']),
            'Invalid hwmon chip name.')
    if 'device' in value:
        device = value['device']
        require(isinstance(device, str) and 1 <= len(device) <= 256 and
                re.fullmatch(r'[A-Za-z0-9_.:/+-]+', device) and
                not device.startswith('/') and str(PurePosixPath(device)) == device and
                not any(p in ('.', '..') or re.fullmatch(r'hwmon[0-9]+', p)
                        for p in device.split('/')), 'Use a stable device path relative to /sys/devices.')


def validate(value):
    """Validate and copy a bounded compiled contract; used at both boundaries."""
    value = copy.deepcopy(value)
    exact(value, {'schema', 'interval_seconds', 'startup_seconds', 'hysteresis_c', 'sensors', 'fans'},
          {'schema', 'sensors', 'fans'})
    require(type(value['schema']) is int and value['schema'] == 1, 'Invalid fan control schema.')
    for key, default, lower, upper in (('interval_seconds', 5, 1, 10),
                                     ('startup_seconds', 3, 1, 30), ('hysteresis_c', 3, 0, 20)):
        integer(value.setdefault(key, default), lower, upper)
    sensors, fans = value['sensors'], value['fans']
    for entries in (sensors, fans):
        require(isinstance(entries, dict) and 1 <= len(entries) <= 32 and
                all(isinstance(k, str) and NAME.fullmatch(k) for k in entries),
                'Fan control requires named sensors and fans.')
    for sensor in sensors.values():
        exact(sensor, {'hwmon', 'interface', 'inputs', 'minimum_c', 'maximum_c'}, {'minimum_c', 'maximum_c'})
        require(('hwmon' in sensor) != ('interface' in sensor), 'Select one temperature device source.')
        if 'hwmon' in sensor:
            selector(sensor['hwmon'])
        else:
            require(isinstance(sensor['interface'], str) and
                    re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', sensor['interface']),
                    'Invalid NIC temperature interface.')
        inputs = sensor.setdefault('inputs', 'all')
        require(inputs == 'all' or isinstance(inputs, list) and 1 <= len(inputs) <= 128 and
                all(isinstance(i, str) and TEMP.fullmatch(i) for i in inputs) and
                len(set(inputs)) == len(inputs), 'Invalid hwmon temperature channels.')
        integer(sensor['minimum_c'], -20, 149)
        integer(sensor['maximum_c'], -19, 150)
        require(sensor['minimum_c'] < sensor['maximum_c'], 'Temperature thresholds must increase.')
    used = set()
    for fan in fans.values():
        exact(fan, {'hwmon', 'pwm', 'sensors', 'minimum_pwm', 'tachometer', 'minimum_rpm'},
              {'hwmon', 'pwm', 'sensors'})
        selector(fan['hwmon'])
        require(isinstance(fan['pwm'], str) and PWM.fullmatch(fan['pwm']), 'Invalid PWM output.')
        integer(fan.setdefault('minimum_pwm', 128), 1, 254)
        selected = fan['sensors']
        require(isinstance(selected, list) and 1 <= len(selected) <= len(sensors) and
                all(isinstance(s, str) and s in sensors for s in selected) and
                len(set(selected)) == len(selected), 'Fan references an unknown or duplicate temperature source.')
        used.update(selected)
        if 'tachometer' in fan:
            require(isinstance(fan['tachometer'], str) and TACH.fullmatch(fan['tachometer']),
                    'Invalid fan tachometer channel.')
            integer(fan.setdefault('minimum_rpm', 1), 1, 100000)
        else:
            require('minimum_rpm' not in fan, 'Minimum RPM requires a tachometer.')
    require(used == set(sensors), 'Every configured temperature source must affect a fan.')
    require(len(canonical(value)) <= 65536, 'Fan control contract exceeds its size bound.')
    return value


def load(path=MANIFEST, *, owner=0):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
            'Fan control manifest is not protected.')
    raw = read(path, 65536)
    value = json.loads(raw, object_pairs_hook=unique)
    require(canonical(value) == raw, 'Fan control manifest is not canonical JSON.')
    validated = validate(value)
    require(validated == value, 'Fan control manifest is not fully compiled.')
    return validated


def text(path):
    with path.open('rb') as stream:
        raw = stream.read(257)
    require(0 < len(raw) <= 256, 'Invalid hwmon reading length.')
    return raw.decode('ascii').strip()


def number(path, lower, upper):
    raw = text(path)
    require(re.fullmatch(r'-?[0-9]{1,9}', raw), 'Invalid hwmon numeric reading.')
    result = int(raw)
    integer(result, lower, upper)
    return result


class Hwmon:
    def __init__(self, sysfs=Path('/sys')):
        self.root = sysfs.resolve(strict=True)
        self.devices = self.root/'devices'

    def confined(self, path):
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(self.devices), 'Hwmon device escapes the kernel device tree.')
        return resolved

    def chips(self):
        result = []
        for path in sorted((self.root/'class/hwmon').glob('hwmon[0-9]*')):
            if not re.fullmatch(r'hwmon[0-9]+', path.name):
                continue
            chip = self.confined(path)
            # name and every attribute are files on this device, never arbitrary
            # filesystem links supplied by a writable configuration location.
            name = text(self.attribute(chip, 'name'))
            device = self.confined(chip/'device') if (chip/'device').exists() else chip.parent.parent
            require(device.is_relative_to(self.devices), 'Invalid hwmon parent device.')
            result.append((chip, name, device))
            require(len(result) <= 256, 'Too many hwmon devices.')
        return result

    def match(self, selected):
        if 'interface' in selected:
            device = self.confined(self.root/'class/net'/selected['interface']/'device')
            return [chip for chip, _, parent in self.chips()
                    if parent == device or parent.is_relative_to(device)]
        match = selected['hwmon']
        device = self.devices/match['device'] if 'device' in match else None
        return [chip for chip, name, parent in self.chips()
                if name == match['name'] and (device is None or parent == device)]

    def attribute(self, chip, name):
        path = chip/name
        require(not path.is_symlink() and self.confined(path) == path and path.is_file(),
                'Invalid hwmon attribute.')
        return path

    def temperatures(self, selected):
        chips = self.match(selected)
        require(chips, 'A configured temperature device is missing.')
        result = []
        for chip in chips:
            names = selected['inputs']
            if names == 'all':
                names = [p.name for p in sorted(chip.glob('temp*_input')) if TEMP.fullmatch(p.name)]
            require(names, 'A configured device has no temperature inputs.')
            result.extend(self.attribute(chip, name) for name in names)
        require(len(result) <= 256, 'Too many temperature channels.')
        return result

    def inspect(self):
        """Read-only inventory for selecting build-time mappings; never probes PWM."""
        return [{'name': name, 'device': device.relative_to(self.devices).as_posix(),
                 'temperatures': [{
                     'input': p.name, 'millidegrees_c': number(self.attribute(chip, p.name), -40000, 150000),
                     **({'label': text(self.attribute(chip, p.name.replace('_input', '_label')))}
                        if (chip/p.name.replace('_input', '_label')).exists() else {})}
                     for p in sorted(chip.glob('temp*_input')) if TEMP.fullmatch(p.name)],
                 'pwm': [p.name for p in sorted(chip.glob('pwm*')) if PWM.fullmatch(p.name)],
                 'tachometers': [p.name for p in sorted(chip.glob('fan*_input')) if TACH.fullmatch(p.name)]}
                for chip, name, device in self.chips()]


def reading(path):
    stem = path.name.removesuffix('_input')
    for suffix in ('_fault', '_alarm', '_crit_alarm', '_emergency_alarm'):
        flag = path.with_name(stem+suffix)
        if flag.exists():
            require(not flag.is_symlink() and number(flag, 0, 1) == 0, 'Hwmon reports a sensor fault or alarm.')
    return number(path, -40000, 150000)


class Output:
    def __init__(self, hwmon, selected):
        self.descriptors = []
        self.pwm = self.enable = None
        chips = hwmon.match({'hwmon': selected['hwmon']})
        require(len(chips) == 1, 'Fan output device is missing or ambiguous.')
        chip = chips[0]
        self.path = hwmon.attribute(chip, selected['pwm'])
        # A missing tachometer must not prevent the usable PWM from being
        # opened and driven to its safe duty. Read validation happens later.
        self.tachometer = chip/selected['tachometer'] if 'tachometer' in selected else None
        try:
            self.pwm = self.open(self.path)
            enable = chip/(selected['pwm']+'_enable')
            if enable.exists():
                self.enable = self.open(hwmon.attribute(chip, enable.name))
        except BaseException:
            self.close()
            raise

    def open(self, path):
        descriptor = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.descriptors.append(descriptor)
        return descriptor

    @staticmethod
    def write(descriptor, value):
        data = (str(value)+'\n').encode('ascii')
        os.lseek(descriptor, 0, os.SEEK_SET)
        require(os.write(descriptor, data) == len(data), 'Incomplete PWM write.')

    def full(self):
        # Try preloading full duty before selecting manual mode, then verify it
        # after the switch. Never change polarity or PWM frequency.
        try:
            self.write(self.pwm, 255)
        except OSError:
            # Some drivers reject duty writes until manual mode is selected.
            pass
        if self.enable is not None:
            self.write(self.enable, 1)
        self.drive(255)

    def drive(self, value):
        self.write(self.pwm, value)
        require(number(self.path, 0, 255) == value, 'PWM output did not accept its requested duty.')
        if self.enable is not None:
            os.lseek(self.enable, 0, os.SEEK_SET)
            require(os.read(self.enable, 32).strip() == b'1', 'PWM manual mode changed unexpectedly.')

    def close(self):
        for descriptor in self.descriptors:
            os.close(descriptor)
        self.descriptors.clear()


def demand(temperature, selected, minimum):
    lower, upper = selected['minimum_c']*1000, selected['maximum_c']*1000
    if temperature <= lower:
        return minimum
    if temperature >= upper:
        return 255
    # Round up: a fractional cooling demand must never select a lower duty.
    return minimum + ((temperature-lower)*(255-minimum)+(upper-lower)-1)//(upper-lower)


class Controller:
    def __init__(self, policy, hwmon):
        self.policy = validate(policy)
        self.hwmon = hwmon
        self.outputs = {}
        self.inputs = {}
        self.previous = {}

    def open(self):
        errors = []
        for key, selected in self.policy['fans'].items():
            try:
                self.outputs[key] = Output(self.hwmon, selected)
            except (OSError, ValueError) as error:
                errors.append(error)
        paths = [output.path for output in self.outputs.values()]
        require(len(set(paths)) == len(paths), 'Two fan mappings resolve to the same PWM output.')
        # Set every output we could resolve safely to full speed even when a
        # different mapping is absent. Never guess among ambiguous candidates.
        self.full()
        require(not errors, 'A configured fan cannot be opened safely.')

    def prepare_inputs(self):
        self.inputs = {key: self.hwmon.temperatures(selected)
                       for key, selected in self.policy['sensors'].items()}
        require(sum(map(len, self.inputs.values())) <= 256, 'Too many monitored temperature channels.')
        self.temperatures()

    def temperatures(self):
        result = {}
        for key, paths in self.inputs.items():
            current = max(reading(p) for p in paths)
            previous = self.previous.get(key, current)
            if current < previous and previous-current < self.policy['hysteresis_c']*1000:
                current = previous
            self.previous[key] = result[key] = current
        return result

    def tick(self):
        try:
            temperatures = self.temperatures()
            for key, output in self.outputs.items():
                selected = self.policy['fans'][key]
                if output.tachometer is not None:
                    require(reading(output.tachometer) >= selected['minimum_rpm'], 'A configured fan has stalled.')
                output.drive(max(demand(temperatures[s], self.policy['sensors'][s], selected['minimum_pwm'])
                                 for s in selected['sensors']))
        except (OSError, ValueError):
            self.full()
            raise

    def full(self):
        errors = []
        for output in self.outputs.values():
            try:
                output.full()
            except (OSError, ValueError) as error:
                errors.append(error)
        require(not errors, 'Unable to set every configured fan to full speed.')

    def close(self):
        try:
            self.full()
        finally:
            for output in self.outputs.values():
                output.close()
            self.outputs.clear()


def drop_privileges():
    require(os.getuid() == os.geteuid() == 0, 'Fan control bootstrap requires root.')
    account = pwd.getpwnam('lanrith-fancontrol')
    group = grp.getgrnam('lanrith-fancontrol')
    require(account.pw_uid != 0 and account.pw_gid != 0 and account.pw_shell in
            ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') and
            group.gr_gid == account.pw_gid and not group.gr_mem and
            sum(entry.pw_uid == account.pw_uid for entry in pwd.getpwall()) == 1,
            'Fan control account is not isolated.')
    os.setgroups([])
    os.setresgid(account.pw_gid, account.pw_gid, account.pw_gid)
    os.setresuid(account.pw_uid, account.pw_uid, account.pw_uid)
    require(os.getresuid() == (account.pw_uid,)*3 and os.getresgid() == (account.pw_gid,)*3 and
            not os.getgroups(), 'Fan control failed to discard privileges.')
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith(('CapInh:', 'CapPrm:', 'CapEff:', 'CapAmb:')):
            require(int(line.split()[1], 16) == 0, 'Fan control retained a process capability.')


def notify(message):
    destination = os.environ.get('NOTIFY_SOCKET')
    if destination:
        if destination.startswith('@'):
            destination = '\x00'+destination[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
            stream.sendto(message.encode('ascii'), destination)


def run(policy, *, failsafe=False):
    require(os.getuid() == os.geteuid() == 0, 'Fan control bootstrap requires root.')
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    controller = Controller(policy, Hwmon())
    try:
        controller.open()
        drop_privileges()
        if failsafe:
            return
        controller.prepare_inputs()
        if stop.wait(policy['startup_seconds']):
            return
        controller.tick()
        notify('READY=1\nSTATUS=Monitoring configured temperature sources\nWATCHDOG=1')
        while not stop.wait(policy['interval_seconds']):
            controller.tick()
            notify('WATCHDOG=1')
    finally:
        controller.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'failsafe', 'inspect'))
    args = parser.parse_args(argv)
    try:
        if args.action == 'inspect':
            print(json.dumps(Hwmon().inspect(), sort_keys=True, indent=2))
        else:
            require(os.getuid() == os.geteuid() == 0, 'Fan control bootstrap requires root.')
            run(load(), failsafe=args.action == 'failsafe')
        return 0
    except (OSError, ValueError, KeyError):
        # Kernel paths and arbitrary sensor contents never become log records.
        print('Fan control fault; configured outputs require full-speed fallback.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
