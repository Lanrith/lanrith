#!/usr/bin/env python3
"""Offline media custody rehearsal with disposable files and recovery keyrings."""

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import local


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=30, **kwargs).stdout


def main():
    with tempfile.TemporaryDirectory(prefix='synthetic-custody.') as temp:
        root = Path(temp)
        # Make traversal possible so the file-level denial is measured independently.
        root.chmod(0o755)
        release = root/'release'
        release.mkdir()
        media = release/'synthetic.root.raw'
        media.write_bytes(os.urandom(4096))
        expected = hashlib.sha256(media.read_bytes()).digest()
        local.restrict_release(release)
        assert release.stat().st_mode & 0o777 == 0o700
        assert media.stat().st_mode & 0o777 == 0o600
        if os.geteuid() == 0:
            isolated = root/media.name
            shutil.copy2(media, isolated)
            denied = subprocess.run(['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
                'python3', '-c', 'import sys; open(sys.argv[1], "rb")', str(isolated)], capture_output=True)
            assert denied.returncode and b'PermissionError' in denied.stderr
        homes = [root/name for name in ('recovery', 'backup', 'unrelated')]
        for home in homes:
            home.mkdir(mode=0o700)
        recovery, backup, unrelated = homes
        def gpg(home, *args):
            return ['gpg', '--no-options', '--homedir', str(home), '--batch', *args]
        try:
            run(*gpg(recovery, '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                     'Disposable media restore', 'rsa2048', 'encrypt', '1d'))
            recipient = root/'recipient.gpg'
            recipient.write_bytes(run(*gpg(recovery, '--export', 'Disposable media restore')))
            archive = root/'release.tar.gpg'
            with archive.open('xb') as out:
                os.fchmod(out.fileno(), 0o600)
                # The backup role holds only the public recipient certificate.
                with subprocess.Popen(['tar', '-C', str(release), '-cf', '-', '.'],
                                      stdout=subprocess.PIPE) as tar:
                    subprocess.run(gpg(backup, '--recipient-file', str(recipient), '--encrypt'),
                                   stdin=tar.stdout, stdout=out, stderr=subprocess.PIPE, check=True, timeout=30)
                    tar.stdout.close()
                    assert tar.wait(timeout=30) == 0
            for home in (backup, unrelated):
                result = subprocess.run(gpg(home, '--decrypt', str(archive)), capture_output=True, timeout=30)
                assert result.returncode and not result.stdout
            restored = run(*gpg(recovery, '--decrypt', str(archive)))
            with tarfile.open(fileobj=io.BytesIO(restored)) as tar:
                assert hashlib.sha256(tar.extractfile('./'+media.name).read()).digest() == expected
            print('Separate recovery key restored the synthetic release. Archive-only readers could not decrypt.')
            if os.geteuid() == 0:
                print('The unrelated UID could not open the copied individual artifact.')
        finally:
            for home in homes:
                subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'],
                               capture_output=True, timeout=10)


if __name__ == '__main__':
    main()
