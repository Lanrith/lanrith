"""Reserve hosted-runner resources outside the unprivileged compiler cgroup."""

from contextlib import contextmanager
import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess

GIB = 1024**3
CGROUP_ROOT = Path('/sys/fs/cgroup')
POLICY = {'reserve_memory_bytes': 2*GIB, 'minimum_build_memory_bytes': 4*GIB,
          'maximum_build_memory_bytes': 8*GIB, 'reserve_cpus': 1,
          'maximum_build_cpus': 2, 'maximum_tasks': 2048, 'swap_bytes': 0}
UNIT = re.compile(r'lanrithbuild[1-9][0-9]{0,18}a[1-9][0-9]{0,3}(?:probe[0-9a-f]{16})?\.slice')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def hosted_packages():
    return (os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('GITHUB_JOB') == 'packages')


def host():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ('MemTotal', 'MemAvailable', 'SwapTotal'):
            require(re.fullmatch(r'\s*[0-9]+ kB\s*', value), 'Invalid hosted memory measurement.')
            values[key] = int(value.split()[0])*1024
    require(set(values) == {'MemTotal', 'MemAvailable', 'SwapTotal'}, 'Incomplete hosted memory measurement.')
    return {'memory_total_bytes': values['MemTotal'], 'memory_available_bytes': values['MemAvailable'],
            'swap_total_bytes': values['SwapTotal'], 'cpus': len(os.sched_getaffinity(0))}


def limits(measured):
    require(set(measured) == {'memory_total_bytes', 'memory_available_bytes', 'swap_total_bytes', 'cpus'} and
            all(type(v) is int and v >= 0 for v in measured.values()) and
            0 < measured['memory_available_bytes'] <= measured['memory_total_bytes'] <= 1024*GIB and
            2 <= measured['cpus'] <= 1024, 'Hosted build needs valid memory and at least two CPUs.')
    memory = min(POLICY['maximum_build_memory_bytes'],
                 measured['memory_available_bytes']-POLICY['reserve_memory_bytes'])
    memory = memory//1024**2*1024**2
    require(memory >= POLICY['minimum_build_memory_bytes'], 'Insufficient available memory after reserving 2 GiB for the runner.')
    return {'memory_bytes': memory, 'cpus': min(POLICY['maximum_build_cpus'], measured['cpus']-1),
            'tasks': POLICY['maximum_tasks'], 'swap_bytes': POLICY['swap_bytes']}


def unit_name():
    identity, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch(r'[1-9][0-9]{0,18}', identity) and re.fullmatch(r'[1-9][0-9]{0,3}', attempt),
            'Invalid hosted resource group identity.')
    return 'lanrithbuild'+identity+'a'+attempt+'.slice'


def create_group(unit, budget):
    """A new flat transient slice contains only this job's compiler children."""
    require(UNIT.fullmatch(unit) and not (CGROUP_ROOT/unit).exists() and not (CGROUP_ROOT/unit).is_symlink(),
            'Refusing an existing or foreign resource group.')
    require(set(budget) == {'memory_bytes','cpus','tasks','swap_bytes'} and
            all(type(v) is int for v in budget.values()) and 64*1024**2 <= budget['memory_bytes'] <= 8*GIB and
            1 <= budget['cpus'] <= 2 and 1 <= budget['tasks'] <= 2048 and budget['swap_bytes'] == 0,
            'Invalid finite compiler resource limits.')
    anchor = unit[:-6]+'anchor.service'
    subprocess.run(['sudo', 'systemd-run', '--quiet', '--unit='+anchor, '--slice='+unit,
        '--property=Type=oneshot', '--property=RemainAfterExit=yes', '/usr/bin/true'], check=True, timeout=30)
    subprocess.run(['sudo', 'systemctl', 'set-property', '--runtime', unit,
        'MemoryMax='+str(budget['memory_bytes']), 'MemorySwapMax='+str(budget['swap_bytes']),
        'CPUQuota='+str(100*budget['cpus'])+'%', 'TasksMax='+str(budget['tasks'])], check=True, timeout=30)
    enforce(unit, budget)


def text(path):
    with path.open() as stream:
        value = stream.read(4097)
    require(len(value) <= 4096, 'Resource counter exceeds its bound.')
    return value.strip()


def enforce(unit, budget):
    require(UNIT.fullmatch(unit), 'Foreign resource group.')
    root = CGROUP_ROOT/unit
    require(not root.is_symlink() and text(root/'memory.max') == str(budget['memory_bytes']) and
            text(root/'memory.swap.max') == str(budget['swap_bytes']) and
            text(root/'pids.max') == str(budget['tasks']), 'Compiler memory, swap or task limit was not enforced.')
    cpu = text(root/'cpu.max').split()
    require(len(cpu) == 2 and all(v.isdecimal() for v in cpu) and int(cpu[1]) > 0 and
            int(cpu[0]) == int(cpu[1])*budget['cpus'], 'Compiler CPU quota was not enforced.')


def write(path, value):
    require(not path.is_symlink(), 'Resource diagnostics cannot replace a symlink.')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
                'Unsafe resource diagnostic file.')
        os.ftruncate(stream.fileno(), 0)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def prepare():
    if not hosted_packages():
        return {'state': 'not-a-hosted-compiler-job'}
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    destination = temporary/'runner-build-resources.json'
    require(not destination.exists() and not destination.is_symlink(), 'Resource preparation must start fresh.')
    measured = host()
    budget, unit = limits(measured), unit_name()
    create_group(unit, budget)
    record = {'schema': 1, 'kind': 'hosted-compiler-resource-group', 'policy': POLICY,
              'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'host': measured, 'limits': budget, 'unit': unit}
    write(destination, record)
    print(f"Compiler budget: {budget['memory_bytes']/GIB:.2f} GiB, {budget['cpus']} CPUs; runner reserve: 2 GiB and one CPU.", flush=True)
    return record


def configuration():
    if not hosted_packages():
        return None
    path = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)/'runner-build-resources.json'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                0 < info.st_size <= 65536, 'Invalid owned resource configuration.')
        raw = stream.read(65537)
        require(len(raw) <= 65536, 'Resource configuration exceeds its bound.')
        def unique(pairs):
            result = {}
            for key, item in pairs:
                require(key not in result, 'Duplicate resource configuration field.')
                result[key] = item
            return result
        value = json.loads(raw, object_pairs_hook=unique)
    require(set(value) == {'schema', 'kind', 'created_at', 'host', 'limits', 'unit', 'policy'} and
            value['schema'] == 1 and value['kind'] == 'hosted-compiler-resource-group' and value['policy'] == POLICY and
            value['unit'] == unit_name() and value['limits'] == limits(value['host']), 'Resource configuration changed.')
    enforce(value['unit'], value['limits'])
    return value


def arguments(engine='docker'):
    value = configuration()
    if value is None:
        return []
    require(engine == 'docker', 'Hosted resource-controlled compilation requires Docker.')
    return ['--cgroup-parent', value['unit']]


def compiler_environment():
    value = configuration()
    if value is None:
        return {}
    # This is a per-Go-process soft target inside the hard aggregate limit.
    return {'GOMAXPROCS': str(value['limits']['cpus']),
            'GOMEMLIMIT': str(value['limits']['memory_bytes']//4//1024**2)+'MiB', 'GOFLAGS': '-p=1'}


def counters(value):
    enforce(value['unit'], value['limits'])
    root = CGROUP_ROOT/value['unit']
    record = {}
    for name in ('memory.current', 'memory.peak', 'memory.swap.current', 'pids.current', 'pids.peak'):
        path = root/name
        if path.exists():
            raw = text(path)
            require(raw.isdecimal(), 'Invalid resource counter.')
            record[name] = int(raw)
    for name, allowed in [('memory.events', {'low','high','max','oom','oom_kill','oom_group_kill'}),
                          ('cpu.stat', {'usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec'})]:
        record[name] = {}
        for line in text(root/name).splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] in allowed:
                require(fields[1].isdecimal(), 'Invalid resource event counter.')
                record[name][fields[0]] = int(fields[1])
    return record


@contextmanager
def recording(destination):
    value, failed = configuration(), False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        if value:
            report = {'schema': 1, 'kind': 'hosted-compiler-resources', 'configuration': value,
                      'build_failed': failed, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            error = None
            try:
                report['counters'] = counters(value)
                require(failed or report['counters']['memory.events'].get('oom_kill', 0) == 0,
                        'A compiler was killed by its resource limit; inspect the retained resource diagnostics.')
            except (OSError, RuntimeError) as exception:
                error = exception
                report['observation_error'] = type(exception).__name__
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                require(destination.parent.resolve() == destination.parent, 'Resource diagnostic parent is aliased.')
                write(destination, report)
                observed = report.get('counters', {})
                print('Compiler resource diagnostics: peak_bytes='+str(observed.get('memory.peak'))+
                      '; oom_kills='+str(observed.get('memory.events', {}).get('oom_kill')), flush=True)
            except (OSError, RuntimeError):
                if not failed:
                    raise
            if error and not failed:
                raise error
