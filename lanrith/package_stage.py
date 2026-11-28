"""Bound the immutable, same-run handoff from compilation to image qualification."""

import io
import json
from pathlib import Path
import re
import shutil
import tarfile

from . import archive
from .release import canonical, file_record, read, require, unique


OUTPUT_FILES = ('builder.tar', 'build-cache.json', 'custom-security.json', 'package-checkpoint.json')


def valid_stage_file(name):
    if name in OUTPUT_FILES:
        return True
    return (re.fullmatch(r'packages/[A-Za-z0-9][A-Za-z0-9._+-]{0,99}', name) is not None or
            len(name) <= len('packages/') + 100 and archive.DEBIAN_PACKAGE_PATH.fullmatch(name) is not None)


def write(project, work, output, builder, version, commit):
    files = {name: output/name for name in OUTPUT_FILES}
    files.update({'packages/'+p.name: p for p in sorted((work/'packages').iterdir()) if p.is_file()})
    require(all(map(valid_stage_file, files)), 'Unexpected package-stage filename.')
    metadata = {'schema': 1, 'source_commit': commit, 'version': version, 'builder': builder,
        'inputs_sha256': file_record(project/'build-inputs.json')['sha256'],
        'files': {name: file_record(path) for name, path in files.items()}}
    data = canonical(metadata)
    with tarfile.open(output/'package-stage.tar.gz', 'w:gz', compresslevel=1, format=tarfile.USTAR_FORMAT) as stream:
        entry = tarfile.TarInfo('stage.json')
        entry.mode, entry.size = 0o600, len(data)
        stream.addfile(entry, io.BytesIO(data))
        for name, path in files.items():
            entry = stream.gettarinfo(str(path), name)
            entry.mode = path.stat().st_mode & 0o755
            entry.uid = entry.gid = entry.mtime = 0
            entry.uname = entry.gname = ''
            with path.open('rb') as content:
                stream.addfile(entry, content)


def restore(source, project, work, output, version, commit):
    directory = work/'package-stage'
    directory.mkdir(mode=0o700)
    names = archive.extract(source, directory, entries=512, maximum_size=16*1024**3,
                            maximum_file=8*1024**3-1, nested=True, debian_packages=True)
    value = json.loads(read(directory/'stage.json', 65536), object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {
        'schema', 'source_commit', 'version', 'builder', 'inputs_sha256', 'files'} and
        value['schema'] == 1 and value['source_commit'] == commit and value['version'] == version and
        value['inputs_sha256'] == file_record(project/'build-inputs.json')['sha256'] and
        isinstance(value['builder'], str) and re.fullmatch(r'lanrith-mkosi:[0-9a-f]{64}', value['builder']),
        'Package stage differs from this source, version or reviewed input selection.')
    require(isinstance(value['files'], dict) and names == {'stage.json', *value['files']} and
        all(map(valid_stage_file, value['files'])) and
        all(file_record(directory/name) == expected for name, expected in value['files'].items()),
        'Package-stage file inventory changed or contains an unexpected path.')
    require({'builder.tar', 'build-cache.json', 'custom-security.json', 'package-checkpoint.json',
             'packages/pam_rssh.so', 'packages/pam-rssh.notices.txt', 'packages/alloy-beyla.scan'} <= names and
            any(name.startswith('packages/alloy_') and name.endswith('.deb') for name in names),
            'Package stage is incomplete.')
    (directory/'packages').rename(work/'packages')
    for name in OUTPUT_FILES:
        shutil.move(directory/name, output/name)
    shutil.copyfile(output/'custom-security.json', work/'custom-security.json')
    shutil.rmtree(directory)
    return value['builder']
