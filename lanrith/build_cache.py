"""Authenticate optional CI acceleration data before importing it into a build."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

from . import archive
from .release import ReleaseError, canonical, file_record, read, require, unique

PREFIX = 'lanrith-build-v1-Linux-X64-'
REPOSITORY = 'Lanrith/lanrith'
WORKFLOW = REPOSITORY+'/.github/workflows/build-base.yml'
COMPILER_LIMIT = 4*1024**3
PAYLOAD_LIMIT = 5*1024**3
EXPANDED_LIMIT = 12*1024**3
COMPONENTS = {'mkosi', 'vpp', 'unbound', 'tayga', 'pam', 'alloy'}


class LimitedWriter:
    def __init__(self, output):
        self.output = output

    def write(self, data):
        require(self.output.tell()+len(data) <= PAYLOAD_LIMIT, 'Compressed build cache exceeds its limit.')
        return self.output.write(data)

    def flush(self):
        self.output.flush()


def producer_files(project):
    """The independently checked code that can populate a cache, including signing."""
    paths = [p for p in project.rglob('*.py') if not any(part in
             ('.git', '__pycache__', '.venv', 'work', 'output') for part in p.relative_to(project).parts)]
    paths += list((project/'builders').rglob('Containerfile'))
    # Go cache entries are only compatible with the exact reviewed Alloy/Beyla
    # sources and patches that produced them, even when native package pins or
    # Debian snapshot timestamps change. The installed toolchain is checked too.
    paths += [p for p in (project/'builders/alloy').rglob('*') if p.is_file()]
    paths += list((project/'.github/workflows').glob('*.yml'))
    paths += [project/name for name in ('requirements.txt', 'pyproject.toml')]
    return {p.relative_to(project).as_posix(): p.read_bytes() for p in sorted(paths)
            if p.is_file() and '__pycache__' not in p.parts}


def key(project):
    inputs = {'producer': {name: hashlib.sha256(data).hexdigest()
                           for name, data in producer_files(project).items()},
              'selection': file_record(project/'build-inputs.json')['sha256']}
    return PREFIX+hashlib.sha256(canonical(inputs)).hexdigest()


def compiler_key(arguments, payload):
    # The probe runs inside the image. Bind its result to the independently
    # reviewed OCI inputs so a different base cannot spoof an equal fingerprint.
    return hashlib.sha256(canonical({'payload_sha256': payload,
        'images': {name: arguments[name] for name in ('DEBIAN_IMAGE', 'GO_IMAGE', 'NODE_IMAGE')}})).hexdigest()


def ordinary(path, limit):
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid() and
            0 < value.st_size <= limit, 'Invalid build cache file.')


def verify(candidate, project):
    """Cache names and branch scope are hints; signatures and source identity authorize reuse."""
    require(candidate.is_dir() and not candidate.is_symlink() and candidate.resolve() == candidate,
            'Invalid build cache directory.')
    require({p.name for p in candidate.iterdir()} == {'cache.json', 'cache.tar.gz', 'cache.intoto.jsonl'},
            'Incomplete build cache handoff.')
    for name, limit in (('cache.json', 65536), ('cache.intoto.jsonl', 4*1024**2),
                        ('cache.tar.gz', PAYLOAD_LIMIT)):
        ordinary(candidate/name, limit)
    metadata = json.loads(read(candidate/'cache.json', 65536), object_pairs_hook=unique)
    require(isinstance(metadata, dict) and set(metadata) == {
        'schema', 'source_commit', 'key', 'payload', 'images', 'compiler_identity'} and
        metadata['schema'] == 1 and isinstance(metadata['source_commit'], str) and
        re.fullmatch(r'[0-9a-f]{40}', metadata['source_commit']) and
        isinstance(metadata['key'], str) and re.fullmatch(re.escape(PREFIX)+r'[0-9a-f]{64}', metadata['key']),
        'Unsupported build cache identity.')
    require(metadata['payload'] == file_record(candidate/'cache.tar.gz'), 'Build cache payload changed.')
    require(isinstance(metadata['images'], dict) and metadata['images'] and
            set(metadata['images']) <= COMPONENTS, 'Invalid cached image selection.')
    for component, tag in metadata['images'].items():
        name = 'alloy-builder' if component == 'alloy' else component
        require(isinstance(tag, str) and re.fullmatch(r'(localhost/)?lanrith-'+name+r':[0-9a-f]{64}', tag),
                'Invalid cached image identity.')
    require(metadata['compiler_identity'] is None or isinstance(metadata['compiler_identity'], str) and
            re.fullmatch(r'[0-9a-f]{64}', metadata['compiler_identity']), 'Invalid cached compiler identity.')
    for name in ('cache.json', 'cache.tar.gz'):
        result = subprocess.run(['gh', 'attestation', 'verify', str(candidate/name), '--bundle',
            str(candidate/'cache.intoto.jsonl'), '--repo', REPOSITORY, '--signer-workflow', WORKFLOW,
            '--source-digest', metadata['source_commit'], '--signer-digest', metadata['source_commit'],
            '--source-ref', 'refs/heads/main', '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
            '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1'],
            capture_output=True, timeout=60)
        require(result.returncode == 0, 'Build cache provenance verification failed.')
    # Do not accept an arbitrary historical version of the named workflow. Check
    # its producer code against this reviewed checkout using GitHub's source API,
    # independently of every value supplied by the cache or its build worker.
    response = subprocess.run(['gh', 'api', 'repos/'+REPOSITORY+'/git/trees/'+
        metadata['source_commit']+'?recursive=1'], capture_output=True, check=True, timeout=60)
    require(len(response.stdout) <= 4*1024**2, 'Cached source inventory exceeds its bound.')
    tree = json.loads(response.stdout, object_pairs_hook=unique)
    require(isinstance(tree, dict) and tree.get('truncated') is False and isinstance(tree.get('tree'), list),
            'Cached source inventory is incomplete.')
    selected = {}
    for item in tree['tree']:
        require(isinstance(item, dict) and isinstance(item.get('path'), str), 'Invalid cached source entry.')
        if item.get('type') == 'tree':
            continue
        name = item['path']
        if (name.endswith('.py') or name.startswith('builders/alloy/') or
            name.startswith('builders/') and name.endswith('/Containerfile') or
            name.startswith('.github/workflows/') and name.endswith('.yml') or
            name in ('requirements.txt', 'pyproject.toml')):
            require(item['type'] == 'blob' and item['mode'] in ('100644', '100755') and name not in selected,
                    'Invalid cached source entry.')
            selected[name] = item['sha']
    # These are Git object IDs from the authenticated GitHub API, not signatures
    # supplied by the cache. Payload authentication above uses SHA-256 provenance.
    expected = {name: hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data,
                                 usedforsecurity=False).hexdigest()
                for name, data in producer_files(project).items()}
    require(selected == expected, 'Cached producer implementation differs from the reviewed build.')
    return metadata


def state():
    value = os.environ.get('LANRITH_BUILD_CACHE')
    if not value:
        return None, None
    root = Path(value)
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root and
            root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o777 == 0o700,
            'Invalid owned build cache workspace.')
    return root, json.loads(read(root/'state.json', 65536), object_pairs_hook=unique)


def save_state(root, value):
    (root/'state.json').write_bytes(canonical(value))


def validate_images(path, images):
    """A Docker import may only create the explicitly selected Lanrith cache tags."""
    with tarfile.open(path, 'r:') as stream:
        count, manifests = 0, []
        for member in stream:
            count += 1
            require(count <= 10000, 'Docker cache inventory exceeds its bound.')
            if member.name == 'manifest.json':
                require(member.isfile() and member.size <= 65536, 'Invalid Docker cache manifest.')
                manifests.append(json.loads(stream.extractfile(member).read(), object_pairs_hook=unique))
        require(len(manifests) == 1 and isinstance(manifests[0], list), 'Missing Docker cache manifest.')
        require(0 < len(manifests[0]) <= len(COMPONENTS) and all(isinstance(image, dict) and
                isinstance(image.get('RepoTags'), list) and image['RepoTags'] and
                all(isinstance(tag, str) for tag in image['RepoTags']) for image in manifests[0]),
                'Invalid Docker cache image inventory.')
        tags = [tag for image in manifests[0] for tag in image.get('RepoTags', [])]
        require(len(tags) == len(set(tags)) and set(tags) == set(images.values()),
                'Docker cache attempts to replace an unselected image.')


def initialize(project, work, candidate, environment):
    os.environ.pop('LANRITH_BUILD_CACHE', None)
    enabled = environment.get('GITHUB_ACTIONS') == 'true' and \
        environment.get('GITHUB_REPOSITORY') == REPOSITORY and \
        environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    require(candidate is None or enabled, 'Cross-run cache input is limited to hosted Lanrith CI.')
    if not enabled:
        return {'status': 'disabled'}
    root = work/'build-cache'
    root.mkdir(mode=0o700)
    record = {'status': 'miss', 'source_commit': None, 'metadata_sha256': None}
    current = {'capture': environment.get('GITHUB_REF') == 'refs/heads/main' and
        environment.get('GITHUB_WORKFLOW_REF') == REPOSITORY+'/.github/workflows/release.yml@refs/heads/main' and
        environment.get('LANRITH_REUSABLE_WORKFLOW_REPOSITORY') == REPOSITORY and
        environment.get('LANRITH_REUSABLE_WORKFLOW_SHA') == environment.get('GITHUB_SHA'),
        'key': key(project), 'restored_images': {}, 'images': {}, 'compiler_identity': None}
    if candidate is not None:
        incoming = root/'incoming'
        incoming.mkdir(mode=0o700)
        try:
            metadata = verify(candidate.absolute(), project)
            names = archive.extract(candidate/'cache.tar.gz', incoming, entries=100000,
                maximum_size=EXPANDED_LIMIT, maximum_file=8*1024**3, nested=True)
            require('images.tar' in names and all(name == 'images.tar' or re.fullmatch(
                r'compiler/[0-9a-f]{2}/[0-9a-f]{64}-[ad]', name) for name in names),
                'Build cache contains an unexpected payload.')
            require(metadata['compiler_identity'] is not None or not (incoming/'compiler').exists(),
                    'Compiler cache has no toolchain identity.')
            require(sum(p.stat().st_size for p in (incoming/'compiler').glob('*/*')) <= COMPILER_LIMIT,
                    'Compiler cache exceeds its retention limit.')
            validate_images(incoming/'images.tar', metadata['images'])
            subprocess.run(['docker', 'load', '--input', str(incoming/'images.tar')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
            (incoming/'images.tar').unlink()
            current.update(restored_images=metadata['images'], compiler_identity=metadata['compiler_identity'])
            record.update(status='verified', source_commit=metadata['source_commit'],
                          metadata_sha256=file_record(candidate/'cache.json')['sha256'])
        except (ReleaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError):
            shutil.rmtree(incoming)
            record['status'] = 'rejected'
            print('Build cache could not be authenticated; using a clean build.')
        finally:
            # This is the workflow's disposable download, not a user-selected
            # local input. Release its large compressed copy before compiling.
            temporary = environment.get('RUNNER_TEMP')
            if temporary and candidate.absolute() == Path(temporary)/'lanrith-cache-candidate' and \
                    candidate.is_dir() and not candidate.is_symlink() and candidate.resolve() == candidate.absolute():
                try:
                    (candidate/'cache.tar.gz').unlink(missing_ok=True)
                except OSError:
                    pass
    current['receipt'] = record
    save_state(root, current)
    os.environ['LANRITH_BUILD_CACHE'] = str(root)
    return record


def image_arguments(component):
    _, value = state()
    arguments = ['--build-arg', 'BUILDKIT_INLINE_CACHE=1'] if value else []
    if value and component in value['restored_images']:
        arguments += ['--cache-from', value['restored_images'][component]]
    return arguments


def record_image(component, tag):
    root, value = state()
    if value:
        value['images'][component] = tag
        save_state(root, value)


def reuse_image(component, tag):
    root, value = state()
    if value and value['restored_images'].get(component) == tag:
        value['images'][component] = tag
        save_state(root, value)
        print('Reusing authenticated '+component+' image with identical inputs.')
        return True
    return False


def restore_compiler(destination, identity):
    root, value = state()
    if value and value['compiler_identity'] == identity and (root/'incoming/compiler').is_dir():
        require(destination.is_dir() and not any(destination.iterdir()), 'Compiler destination must be new.')
        destination.rmdir()
        (root/'incoming/compiler').rename(destination)
        return True
    return False


def retain_compiler(source, identity):
    root, value = state()
    if not value or not value['capture']:
        return
    destination = root/'compiler'
    destination.mkdir(mode=0o700)
    files = []
    for path in source.glob('*/*'):
        relative = path.relative_to(source).as_posix()
        if re.fullmatch(r'[0-9a-f]{2}/[0-9a-f]{64}-[ad]', relative):
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                    'Compiler cache contains an unsafe file.')
            files.append((info.st_mtime_ns, relative, info.st_size, path))
    total = 0
    for _, relative, size, path in sorted(files, reverse=True):
        if total+size > COMPILER_LIMIT:
            continue
        target = destination/relative
        target.parent.mkdir(mode=0o700, exist_ok=True)
        path.rename(target)
        target.chmod(0o600)
        total += size
    value['compiler_identity'] = identity
    save_state(root, value)


def export(project, destination, environment):
    """Snapshot package-stage data before privileged filesystem and VM work."""
    root, value = state()
    if not value or not value['capture']:
        return False
    require(not destination.exists(), 'Cache export destination must be new.')
    destination.mkdir(mode=0o700)
    image_tar = root/'images.tar'
    try:
        require(shutil.disk_usage(root).free >= 13*1024**3, 'Insufficient spare disk for optional cache export.')
        subprocess.run(['docker', 'save', '--output', str(image_tar), *value['images'].values()],
                       check=True, timeout=300)
        ordinary(image_tar, 8*1024**3-1)
        payload = destination/'cache.tar.gz'
        with payload.open('xb') as output, gzip.GzipFile(filename='', fileobj=LimitedWriter(output),
                mode='wb', compresslevel=1, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as stream:
                for path in [image_tar, *sorted((root/'compiler').glob('*/*'))]:
                    member = stream.gettarinfo(str(path), path.relative_to(root).as_posix())
                    member.uid = member.gid = member.mtime = 0
                    member.uname = member.gname = ''
                    member.mode = 0o600
                    with path.open('rb') as content:
                        stream.addfile(member, content)
        ordinary(payload, PAYLOAD_LIMIT)
        metadata = {'schema': 1, 'source_commit': environment['GITHUB_SHA'], 'key': value['key'],
            'images': value['images'], 'compiler_identity': value['compiler_identity'],
            'payload': file_record(payload)}
        (destination/'cache.json').write_bytes(canonical(metadata))
        seal = {'key': value['key'], 'files': {name: file_record(destination/name)
                for name in ('cache.json', 'cache.tar.gz')}}
        # Compiler objects are now in the sealed archive. Keep them out of the
        # later privileged stages and release their disk allocation.
        shutil.rmtree(root/'compiler', ignore_errors=True)
        shutil.rmtree(root/'incoming', ignore_errors=True)
        return seal
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError):
        shutil.rmtree(destination)
        print('Optional cache export unavailable; the qualified release is unchanged.')
        return False
    finally:
        image_tar.unlink(missing_ok=True)


def offer(destination, seal, environment):
    """After qualification, offer only the byte-identical package-stage snapshot."""
    if not seal:
        return False
    require(destination.is_dir() and not destination.is_symlink() and
            {p.name for p in destination.iterdir()} == set(seal['files']) and
            all(file_record(destination/name) == expected for name, expected in seal['files'].items()),
            'Package-stage cache data changed during privileged qualification.')
    if environment.get('GITHUB_OUTPUT'):
        with open(environment['GITHUB_OUTPUT'], 'a') as output:
            output.write('cache-key='+seal['key']+'\ncache-ready=true\n')
    return True
