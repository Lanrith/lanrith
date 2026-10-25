"""Check the platform's component command interface before source compilation."""

from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from .release import require


REQUIRED_BINARIES = {
    'discovery-bridge': frozenset({'discovery-bridge'}),
    'router-policy-agent': frozenset({
        'router-policy-reader', 'router-policy-collector', 'router-policy-helper',
        'router-policy-check', 'router-policy-status', 'router-policy-recover',
        'router-policy-profile',
    }),
}


class PayloadReader:
    def __init__(self, stream):
        self.stream = stream
        self.remaining = 512 * 1024 * 1024

    def read(self, size):
        data = self.stream.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        require(self.remaining >= 0, 'Component package payload exceeds the inspection limit.')
        return data


def validate_binaries(component, packages):
    """Inspect authenticated .deb data without extracting or executing the payload."""
    require(component in REQUIRED_BINARIES, 'Unknown platform component interface.')
    packages = list(packages)
    require(packages, 'Component selection contains no native packages.')
    found = set()
    for package in packages:
        package = Path(package)
        require(package.is_file() and not package.is_symlink() and
                0 < package.stat().st_size <= 64 * 1024 * 1024,
                'Component package is not a bounded regular file.')
        process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(package)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            reader = PayloadReader(process.stdout)
            with tarfile.open(fileobj=reader, mode='r|') as archive:
                for member in archive:
                    name = member.name.removeprefix('./').rstrip('/')
                    require(not name.startswith('/') and '..' not in PurePosixPath(name).parts,
                            'Component package contains an unsafe path.')
                    path = PurePosixPath(name)
                    if path.parent.as_posix() not in ('usr/bin', 'usr/sbin', 'bin', 'sbin'):
                        continue
                    require(path.parent.as_posix() == 'usr/bin' and member.isfile() and
                            member.size > 0 and member.mode & 0o111 and not member.mode & 0o7000,
                            'Component command is not a regular unprivileged executable.')
                    require(path.name not in found, 'Component command occurs more than once: '+path.name)
                    found.add(path.name)
            # Consume tar padding and any remaining decompressor output under the same bound.
            while reader.read(1024 * 1024):
                pass
            require(process.wait(timeout=30) == 0, 'Component package inspection failed.')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)
    expected = REQUIRED_BINARIES[component]
    require(found == expected,
            'Component '+component+' executables differ from the platform contract; missing: '+
            ', '.join(sorted(expected-found))+'; unexpected: '+', '.join(sorted(found-expected)))
    return sorted(found)
