"""Stage exact base nft userspace only inside the isolated native fixture."""

import os
from pathlib import Path
import shutil
import stat
import tempfile

from lanrith import firewall_qualification as gate
from lanrith.release import file_record, require


def isolated():
    require(os.geteuid() == 0 and (Path('/run/.containerenv').is_file() or Path('/.dockerenv').is_file()),
            'Base userspace staging requires the root disposable container.')
    for kind in ('NET', 'MNT'):
        outer = os.environ.get('LANRITH_FIXTURE_OUTER_'+kind, '')
        require(outer.isdecimal() and os.stat('/proc/self/ns/'+kind.lower()).st_ino != int(outer),
                'Base userspace staging refuses the outer namespace.')


def install(source, name, digest):
    require(name == gate.NFT or gate.library_path(name), 'Invalid staged userspace target.')
    target = Path('/')/name
    require(target.resolve(strict=True) == target and target.is_file() and not target.is_symlink(),
            'Staged userspace target must be its canonical ordinary file.')
    for parent in target.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                'Staged userspace ancestor is not root-controlled.')
    info = target.lstat()
    require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o7022 and
            file_record(source)['sha256'] == digest, 'Staged userspace custody or source differs.')
    if file_record(target)['sha256'] == digest:
        return
    descriptor, temporary = tempfile.mkstemp(prefix='.nft-subject.', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output, source.open('rb') as incoming:
            shutil.copyfileobj(incoming, output, 1024*1024)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), stat.S_IMODE(source.stat().st_mode))
        require(file_record(Path(temporary))['sha256'] == digest, 'Staged userspace copy differs.')
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def stage(archive):
    isolated()
    for key in tuple(os.environ):
        if key.startswith('LD_'):
            del os.environ[key]
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    with tempfile.TemporaryDirectory(prefix='nft-subject.', dir='/run') as temporary:
        candidate = Path(temporary)
        selected = gate.subject(archive, destination=candidate)
        install(candidate/'nft', gate.NFT, selected[gate.NFT])
    # Trace after installing the executable, stage its base dependency bytes,
    # then trace again. A changed transitive closure needs another bounded pass;
    # every actually loaded file must match the base before evidence can pass.
    dependencies = gate.library_inventory()
    for _ in range(4):
        with tempfile.TemporaryDirectory(prefix='nft-libraries.', dir='/run') as temporary:
            candidate = Path(temporary)
            userspace = gate.subject(archive, dependencies, destination=candidate, extract_libraries=True)
            for name in dependencies:
                install(candidate/name, name, userspace[name])
        actual = gate.library_inventory()
        exact = gate.subject(archive, actual)
        if exact == {gate.NFT: selected[gate.NFT], **actual}:
            require(file_record(Path('/')/gate.NFT)['sha256'] == selected[gate.NFT],
                    'Staged nft changed during dependency qualification.')
            return selected, actual, exact
        dependencies = actual
    raise ValueError('Staged nft dependency closure did not converge to the exact base.')
