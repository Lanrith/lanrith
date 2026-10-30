"""Build admitted platform inputs on an owner's local container controller."""

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import uuid

from . import admission, archive, config, extensions, owner_inputs, release, trust


@contextmanager
def signing_space(engine, name):
    private = Path(tempfile.mkdtemp(prefix=name+'.', dir='/dev/shm'))
    private.chmod(0o700)
    body_error = None
    try:
        yield private
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            # Stop only this transaction's container before removing its keys.
            # Podman reports a missing container with 125; Docker commonly uses
            # 1. The diagnostic must still prove absence, because 125 also
            # represents engine failures.
            observed = subprocess.run([engine, 'inspect', '--format',
                '{{index .Config.Labels "io.lanrith.local.owner"}}', name], capture_output=True, timeout=30)
            if observed.returncode == 0:
                release.require(observed.stdout.decode().strip() == name,
                                'Local build container ownership changed.')
                subprocess.run([engine, 'rm', '--force', name], check=True, capture_output=True, timeout=60)
            else:
                diagnostic = observed.stderr.decode(errors='replace').lower()
                release.require(observed.returncode in (1, 125) and
                                any(text in diagnostic for text in ('no such object', 'no such container')),
                                'Container cleanup is unconfirmed; owned private tmpfs retained at '+str(private))
            shutil.rmtree(private)
        except BaseException as cleanup_error:
            if body_error is None:
                raise
            body_error.add_note('Signing cleanup also failed; private material may require managed recovery: '
                                +str(cleanup_error))


def consumer():
    path = Path(__file__).resolve().parents[1]/'scripts/consumer.py'
    spec = importlib.util.spec_from_file_location('lanrith_consumer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inputs(owner, platform, sequence, serial_hash=None, boot_options=None):
    """Bind the request to exact owner bytes, not a mutable working directory."""
    release.require(owner.is_dir() and owner.resolve() == owner.absolute() and not owner.is_symlink(),
                    'Owner directory must be canonical.')
    selection = trust.lock(owner/'platform.lock')
    value = config.load(owner/'config.yaml')
    owner_options, owner_records = owner_inputs.load(owner, value)
    release.require(type(sequence) is int and value.get('release', {}).get('sequence_floor', 0) < sequence <= 999999999,
                    'Deployment sequence must exceed the configured floor.')
    release.require(value['hardware'].get('machine_id'), 'Initialize the permanent owner machine identity first.')
    pins = consumer().integration_pins(owner, value)
    names = {'config.yaml', 'platform.lock', 'trust/boot.crt'}
    names.update(owner_records)
    release.public_key(owner/'trust/boot.crt')
    if (owner/'extensions.lock').exists():
        names.add('extensions.lock')
    for identity, (directory, _) in pins.items():
        names.add(f'extensions/{identity}/extension.json')
        names.update(path.relative_to(owner).as_posix() for path in (directory/'root').rglob('*') if path.is_file())
    records = {}
    for name in sorted(names):
        path = owner/name
        release.require(not any(parent.is_symlink() for parent in path.parents if parent != owner.parent),
                        'Owner input has a linked parent.')
        records[name] = {**release.file_record(path), 'mode': stat.S_IMODE(path.stat().st_mode)}
    integration_digests = {name: pin[1] for name, pin in pins.items()}
    release.require(all(all(records[name][key] == expected for key, expected in record.items())
                        for name, record in owner_records.items()), 'Owner build inputs changed during admission.')
    serial_digest = release.file_record(serial_hash)['sha256'] if serial_hash else None
    result = {'schema': 1, 'purpose': 'local-owner-build', 'deployment_sequence': sequence,
            'configuration_sha256': hashlib.sha256(release.canonical(value)).hexdigest(),
            'effective_configuration_sha256': config.effective_digest(value, integration_digests, serial_digest),
            'integration_digests': integration_digests,
            'files': records, 'platform_files': selection['files'],
            'platform_manifest_sha256': selection['manifest_sha256'],
            'compiler_source_commit': selection['source_commit'],
            'builder': selection['builder']+'@sha256:'+selection['builder_digest'],
            'serial_provisioning_sha256': serial_digest,
            'assessment_sha256': release.file_record(platform/'security-assessment.json')['sha256']
                if (platform/'security-assessment.json').exists() else None}
    from . import build_inputs
    boot_record = build_inputs.record(boot_options or {}, certificate=owner/'trust/boot.crt',
        image_id=value.get('release', {}).get('image_id', 'lanrith'), sequence=sequence,
        tpm_required=value['hardware']['boot'].get('tpm', 'required') == 'required')
    if boot_options is not None or build_inputs.digest_fields(boot_record):
        result['boot_inputs'] = boot_record
    result['effective_configuration_sha256'] = config.effective_digest(value, integration_digests,
        serial_digest, boot_inputs=build_inputs.digest_fields(boot_record), **owner_options)
    if owner_records:
        result['owner_inputs'] = owner_records
    return result


def admit(owner, platform, sequence, engine, serial_hash=None, boot_options=None):
    selection = trust.lock(owner/'platform.lock')
    trust.verify(platform, selection)
    reference = trust.verify_builder(selection, platform/'builder.intoto.jsonl')
    admission.assess(platform, selection)
    subprocess.run([engine, 'pull', reference], check=True, stdin=subprocess.DEVNULL, timeout=600)
    release.require(not config.load(owner/'config.yaml')['administration']['serial']['enabled'] or serial_hash is not None,
                    'Serial administration needs its provisioning hash during preflight.')
    return inputs(owner, platform, sequence, serial_hash, **({'boot_options': boot_options} if boot_options is not None else {}))


def private_copy(source, destination, maximum):
    """Read a caller-owned private regular file without following a link."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        release.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                        not info.st_mode & 0o077 and 0 < info.st_size <= maximum,
                        'Signing input must be a private caller-owned regular file.')
        data = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
        release.require(len(data) == info.st_size and
                        (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                        'Signing input changed while being read.')
    with destination.open('xb') as output:
        destination.chmod(0o600)
        output.write(data)


def assemble(owner, platform, request, work, output, *, key, certificate, serial_hash=None, engine='podman', boot_options=None):
    expected = json.loads(release.read(request, 1024*1024), object_pairs_hook=release.unique)
    release.require(not work.exists() and not work.is_symlink() and not output.exists() and not output.is_symlink(),
                    'Local workspace and output must be new.')
    release.require(work != output and work not in output.parents and output not in work.parents,
                    'Local workspace and output must be separate.')
    release.require(all(path.parent.is_dir() and path.parent.resolve() == path.parent.absolute()
                        for path in (work, output)), 'Build destinations need existing canonical parent directories.')
    # Every network operation precedes the first private-file read.
    extra = {'boot_options': boot_options} if boot_options is not None else {}
    actual = admit(owner, platform, expected['deployment_sequence'], engine, serial_hash, **extra)
    release.require(actual == expected, 'Local build inputs differ from the reviewed preflight request.')
    release.require(Path('/dev/shm').is_mount(), 'Signing requires a private tmpfs.')
    work.mkdir(mode=0o700, parents=True)
    snapshot, tools = work/'owner', work/'tools'
    snapshot.mkdir(mode=0o700)
    for name, record in actual['files'].items():
        target = snapshot/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(owner/name, target)
        target.chmod(record['mode'])
        release.require(release.file_record(target)['sha256'] == record['sha256'], 'Owner input changed during snapshot.')
    tools.mkdir(mode=0o700)
    tools_archive = work/'platform-tools.tar.gz'
    shutil.copyfile(platform/'tools.tar.gz', tools_archive)
    release.require(release.file_record(tools_archive)['sha256'] == actual['platform_files']['tools.tar.gz'],
                    'Compiler archive changed after admission.')
    archive.extract(tools_archive, tools, entries=10000, maximum_size=64*1024*1024,
                    maximum_file=4*1024*1024, nested=True)
    release.require(inputs(snapshot, platform, actual['deployment_sequence'], serial_hash, **extra) == actual,
                    'Owner snapshot differs from preflight.')
    name = 'lanrith-local-'+uuid.uuid4().hex
    with signing_space(engine, name) as private:
        private_copy(key, private/'boot.key', 65536)
        # The public certificate is separately bound to the reviewed owner trust.
        data = release.read(certificate, 65536)
        release.require(data.strip() == release.read(snapshot/'trust/boot.crt', 65536).strip(),
                        'Boot certificate differs from reviewed owner trust.')
        (private/'boot.crt').write_bytes(data)
        (private/'boot.crt').chmod(0o600)
        public = subprocess.run(['openssl', 'pkey', '-in', str(private/'boot.key'), '-pubout'],
                                check=True, capture_output=True, timeout=15).stdout
        release.require(public.strip() == release.public_key(private/'boot.crt').strip(),
                        'Boot key does not match reviewed owner trust.')
        if boot_options is not None:
            from . import build_inputs
            build_inputs.stage(boot_options, actual['boot_inputs'], private=private, work=work, private_copy=private_copy)
        if config.load(snapshot/'config.yaml')['administration']['serial']['enabled']:
            release.require(serial_hash is not None, 'Serial administration needs its private provisioning hash.')
            private_copy(serial_hash, private/'serial.hash', 512)
            release.require(release.file_record(private/'serial.hash')['sha256'] == actual['serial_provisioning_sha256'],
                            'Serial provisioning changed after preflight.')
        (private/'admitted.json').write_bytes(release.canonical({
            'platform_lock_sha256': actual['files']['platform.lock']['sha256'],
            'configuration_sha256': actual['configuration_sha256'], 'files': actual['platform_files'],
            'effective_configuration_sha256': actual['effective_configuration_sha256'],
            'serial_provisioning_sha256': actual['serial_provisioning_sha256'],
            'integration_digests': actual['integration_digests'], 'assessment_sha256': actual['assessment_sha256'],
            **({'owner_inputs': actual['owner_inputs']} if 'owner_inputs' in actual else {}),
            **({'boot_inputs': actual['boot_inputs']} if 'boot_inputs' in actual else {})}))
        (private/'admitted.json').chmod(0o600)
        # Normalize ownership inside this isolated mount only. Rootless Podman's
        # namespace root is the caller; rootful Docker needs the host numeric IDs.
        uid, gid = (0, 0) if engine == 'podman' else (os.getuid(), os.getgid())
        script = (
            'import os,subprocess,sys\n'
            'try:\n'
            ' r=subprocess.run(["python3","scripts/assemble-offline.py",*sys.argv[3:]])\n'
            'finally:\n'
            ' for root,dirs,files in os.walk("/work"):\n'
            '  for item in [root,*[os.path.join(root,n) for n in dirs+files]]:\n'
            '   os.chown(item,int(sys.argv[1]),int(sys.argv[2]),follow_symlinks=False)\n'
            'sys.exit(r.returncode)\n')
        subprocess.run([engine, 'run', '--rm', '--pull=never', '--name', name, '--label', 'io.lanrith.local.owner='+name,
                '--network', 'none', '--privileged', '-v', str(private)+':'+str(private)+':ro',
                '-v', str(work)+':/work', '-v', str(platform)+':/platform:ro',
                '-w', '/work/tools', actual['builder'], 'python3', '-c', script, str(uid), str(gid),
                '--owner', '/work/owner', '--platform', '/platform', '--private', str(private),
                '--workspace', '/work/image', '--output', '/work/update',
                '--sequence', str(actual['deployment_sequence']),
                *(['--fallback-release', '/work/fallback'] if boot_options and 'fallback_release' in boot_options else [])],
                check=True, stdin=subprocess.DEVNULL, timeout=7200)
        image_id = config.load(snapshot/'config.yaml').get('release', {}).get('image_id', 'lanrith')
        for purpose in ('update', 'factory'):
            release.verify(work/purpose, private/'boot.crt', purpose=purpose, image_id=image_id)
    output.mkdir(mode=0o700, parents=True)
    for purpose in ('update', 'factory'):
        shutil.move(work/purpose, output/purpose)
    (output/'build-request.json').write_bytes(release.canonical(actual))
    (output/'build-request.json').chmod(0o600)
    return actual
