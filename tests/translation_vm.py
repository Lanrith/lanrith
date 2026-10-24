#!/usr/bin/env python3
"""Run translator packet fixtures with a cached base, no disks or external NICs.

This is a disposable kernel/runtime test. It is not signed image, upgrade or
rollback qualification. The caller supplies the separately admitted base archive.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile

import yaml


INIT = b'''#!/usr/bin/python3
import ctypes,os,pathlib,subprocess,traceback
os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
def run(*args):
 subprocess.run(args,check=True)
try:
 for name in ('proc','sys','dev','run','tmp'):
  pathlib.Path('/'+name).mkdir(exist_ok=True)
 run('mount','-t','proc','proc','/proc')
 run('mount','-t','sysfs','sysfs','/sys')
 run('mount','-t','devtmpfs','devtmpfs','/dev')
 run('mount','-t','tmpfs','tmpfs','/run')
 run('mount','-t','tmpfs','tmpfs','/tmp')
 pathlib.Path('/dev/net').mkdir(exist_ok=True)
 if not pathlib.Path('/dev/net/tun').exists():os.mknod('/dev/net/tun',0o20666,os.makedev(10,200))
 # This minimal PID 1 has no udev. Match the standard net/tun device mode;
 # the kernel still enforces the owner of each persistent TUN.
 os.chmod('/dev/net/tun',0o666)
 run('modprobe','tun')
 run('modprobe','veth')
 run('python3','/work/tests/nat46_native.py')
 print('LANRITH_TRANSLATION_VM_PASS',flush=True)
except BaseException:
 traceback.print_exc()
 print('LANRITH_TRANSLATION_VM_FAIL',flush=True)
os.sync()
ctypes.CDLL(None).reboot(0x4321fedc)
'''


def record(stream, number, name, mode, data=b'', *, uid=0, gid=0, major=0, minor=0):
    name = name.encode()+b'\0'
    fields = [number, mode, uid, gid, 1, 0, len(data), 0, 0, major, minor, len(name), 0]
    header = b'070701'+b''.join(f'{item:08x}'.encode() for item in fields)
    stream.write(header+name+b'\0'*((-(len(header)+len(name))) % 4))
    stream.write(data+b'\0'*((-len(data)) % 4))


def prepare(base, destination, fixture='nat46', *, snmp_gua=False, snmp_core=False, snmp_legacy=False):
    assert fixture in ('nat46', 'nat64', 'combined', 'snmp')
    assert fixture == 'snmp' or not (snmp_gua or snmp_core or snmp_legacy)
    init = INIT.replace(b"'/work/tests/nat46_native.py'",
                        b"'/work/tests/nat64_native.py','--with-nat46'" if fixture == 'combined' else
                        ("'/work/tests/"+fixture+"_native.py'").encode())
    if fixture == 'snmp':
        arguments = ''.join(", '"+argument+"'" for argument, selected in
                            (('--gua', snmp_gua), ('--with-core-services', snmp_core),
                             ('--legacy-custody', snmp_legacy)) if selected)
        init = init.replace(b"'/work/tests/snmp_native.py'", ("'/work/tests/snmp_native.py'"+arguments).encode())
    entries = {}
    commands = {'python3', 'python3.13', 'bash', 'sh', 'env', 'mount', 'umount', 'ip', 'nft',
                'nsenter', 'ping', 'sysctl', 'modprobe', 'kmod', 'tayga'}
    if fixture == 'snmp':
        commands.update({'snmpd', 'snmpget', 'snmpset', 'ss', 'systemd-analyze'})
    with tarfile.open(base) as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            path = PurePosixPath(name)
            assert not path.is_absolute() and '..' not in path.parts
            if name.startswith('boot/vmlinuz-') and member.isfile():
                (destination/'vmlinuz').write_bytes(archive.extractfile(member).read())
            wanted = (name in ('lib', 'lib64', 'bin', 'sbin', 'usr/lib64', 'etc/passwd', 'etc/group',
                               'etc/nsswitch.conf', 'etc/protocols', 'etc/services', 'usr/lib/lanrith/tayga-internal') or
                      name.startswith(('usr/lib/modules/', 'usr/lib/x86_64-linux-gnu/', 'usr/lib/python3.13/', 'usr/lib64/')) or
                      str(path.parent) in ('usr/bin', 'usr/sbin') and path.name in commands)
            if fixture == 'snmp':
                wanted = wanted or name.startswith('usr/lib/systemd/')
            if not wanted or member.isdir():
                continue
            if member.isfile():
                entries[name] = (stat.S_IFREG | member.mode, archive.extractfile(member).read(), member.uid, member.gid)
            elif member.issym():
                entries[name] = (stat.S_IFLNK | 0o777, member.linkname.encode(), member.uid, member.gid)
            elif member.islnk():
                target = member.linkname.removeprefix('./')
                if target in entries:
                    entries[name] = entries[target]
                else:
                    entries[name] = (stat.S_IFREG | member.mode, archive.extractfile(member).read(), member.uid, member.gid)
    # PyYAML is a compiler dependency. Include its pure Python implementation
    # only; never copy host credentials, accounts or network configuration.
    yaml_root = Path(yaml.__file__).parent
    for path in yaml_root.glob('*.py'):
        entries['usr/lib/python3.13/yaml/'+path.name] = (stat.S_IFREG | 0o644, path.read_bytes(), 0, 0)
    source = Path(__file__).resolve().parents[1]
    runtime_sources = {}
    if fixture == 'snmp':
        for name in ('snmp-runtime', 'snmp_service.py', 'snmp_credentials.py', 'credential_runtime.py', 'systemd_service.py'):
            path = source/'mkosi/base/mkosi.extra/usr/lib/lanrith'/name
            target = 'usr/lib/lanrith/'+name
            entries[target] = (stat.S_IFREG | (0o755 if name == 'snmp-runtime' else 0o644), path.read_bytes(), 0, 0)
            runtime_sources[target] = hashlib.sha256(path.read_bytes()).hexdigest()
    for directory, suffix in (('lanrith', '*.py'), ('examples', '*.yaml'), ('tests', '*.py')):
        for path in (source/directory).glob(suffix):
            entries['work/'+directory+'/'+path.name] = (stat.S_IFREG | 0o644, path.read_bytes(), 0, 0)
    entries['init'] = (stat.S_IFREG | 0o755, init, 0, 0)
    assert (destination/'vmlinuz').is_file()
    directories = {'dev', 'proc', 'sys', 'tmp', 'run', 'var', 'etc'}
    for name in entries:
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')
    with gzip.open(destination/'initrd.cpio.gz', 'wb', compresslevel=1) as stream:
        number = 1
        for name in sorted(directories, key=lambda name: (name.count('/'), name)):
            if name not in entries:
                record(stream, number, name, stat.S_IFDIR | 0o755)
                number += 1
        record(stream, number, 'dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
        number += 1
        for name, (mode, data, uid, gid) in sorted(entries.items()):
            record(stream, number, name, mode, data, uid=uid, gid=gid)
            number += 1
        record(stream, number, 'TRAILER!!!', 0)
    with base.open('rb') as stream:
        base_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    inputs = {'schema': 1, 'base_archive_sha256': base_digest,
              'sources': {name.removeprefix('work/'): hashlib.sha256(data).hexdigest()
                          for name, (_, data, _, _) in entries.items() if name.startswith('work/')},
              'init_sha256': hashlib.sha256(init).hexdigest(), 'fixture': fixture}
    if runtime_sources:
        inputs['runtime_sources'] = runtime_sources
        inputs['snmp_options'] = {'provider_gua': snmp_gua, 'dns_ntp_configured': snmp_core,
                                 'retained_credential_format': snmp_legacy}
    for name in ('vmlinuz', 'initrd.cpio.gz'):
        with (destination/name).open('rb') as stream:
            inputs[name+'_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    (destination/'inputs.json').write_text(json.dumps(inputs, indent=2, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--fixture', choices=('nat46', 'nat64', 'combined', 'snmp'), default='nat46')
    parser.add_argument('--gua', action='store_true')
    parser.add_argument('--with-core-services', action='store_true')
    parser.add_argument('--legacy-custody', action='store_true')
    args = parser.parse_args()
    assert not args.work.exists(), 'Choose a new disposable work directory.'
    assert args.base.is_file() and shutil.which('qemu-system-x86_64')
    args.work.mkdir(mode=0o700, parents=True)
    prepare(args.base, args.work, args.fixture, snmp_gua=args.gua,
            snmp_core=args.with_core_services, snmp_legacy=args.legacy_custody)
    with (args.work/'console.log').open('wb') as log:
        result = subprocess.run([
            'qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
            '-nodefaults', '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-no-reboot', '-kernel', str(args.work/'vmlinuz'), '-initrd', str(args.work/'initrd.cpio.gz'),
            '-append', 'console=ttyS0 rdinit=/init panic=1 loglevel=4'
        ], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=240)
    data = (args.work/'console.log').read_text(errors='replace')
    assert result.returncode == 0 and 'LANRITH_TRANSLATION_VM_PASS' in data and \
        'LANRITH_TRANSLATION_VM_FAIL' not in data, data[-10000:]
    records = [json.loads(line) for line in data.splitlines() if line.startswith('{"result":')]
    assert len(records) == 1 and records[0]['result'] == 'pass'
    evidence = {**records[0], 'schema': 1, 'signed_image_qualified': False,
                'external_network': False, 'persistent_state_migration_qualified': False,
                'console_sha256': hashlib.sha256((args.work/'console.log').read_bytes()).hexdigest(),
                'inputs_sha256': hashlib.sha256((args.work/'inputs.json').read_bytes()).hexdigest()}
    (args.work/'qualification.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
    print('Offline '+args.fixture+' VM passed; this does not qualify a private image.')


if __name__ == '__main__':
    main()
