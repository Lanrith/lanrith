"""Check the release identity reported by the executable in a node-exporter package."""

import argparse
from contextlib import contextmanager
from http.client import HTTPResponse
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from .release import file_record, require


@contextmanager
def local_scrape(binary, *arguments):
    """Start a real exporter with a private Unix listener and yield its metrics reader."""
    with tempfile.TemporaryDirectory(prefix='exporter.') as temporary:
        address = Path(temporary)/'metrics.sock'
        process = subprocess.Popen(['systemd-socket-activate', '--listen='+str(address), str(binary),
                                    '--web.systemd-socket', '--collector.disable-defaults', *arguments],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        try:
            def scrape():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(10)
                    deadline = time.monotonic()+10
                    while True:
                        try:
                            client.connect(str(address))
                            break
                        except (FileNotFoundError, ConnectionRefusedError):
                            require(process.poll() is None and time.monotonic() < deadline,
                                    'Exporter listener failed to start.')
                            time.sleep(.02)
                    client.sendall(b'GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    with HTTPResponse(client) as response:
                        response.begin()
                        require(response.status == 200, 'Exporter qualification scrape failed.')
                        return response.read().decode()

            yield scrape
        finally:
            process.terminate()
            process.wait(timeout=10)


def qualify_package(package, pin, expected_binary):
    """Match control metadata, embedded binary digest, CLI and build-info sample."""
    release = subprocess.check_output(['dpkg-deb', '--field', package, 'Version'], text=True).strip()
    require(release and release == pin['package_version'], 'Node exporter package release differs from pin.')
    revision = pin['commit']+'-modified'
    with tempfile.TemporaryDirectory(prefix='exporter-package.') as temporary:
        subprocess.run(['dpkg-deb', '--extract', package, temporary], check=True)
        binary = Path(temporary)/'usr/bin/prometheus-node-exporter'
        require(file_record(binary)['sha256'] == expected_binary, 'Packaged exporter differs from assessed binary.')
        cli = subprocess.check_output([binary, '--version'], stderr=subprocess.STDOUT, text=True)
        match = re.search(r'^node_exporter, version (\S+) \(branch: [^,\n]*, revision: ([^()\s]+)\)$', cli, re.M)
        require(match and match.groups() == (release, revision), 'Node exporter CLI identity differs from pin.')
        with local_scrape(binary) as scrape:
            samples = re.findall(r'^node_exporter_build_info\{([^}\n]*)\} 1$', scrape(), re.M)
        require(len(samples) == 1, 'Expected one exporter build-info sample.')
        labels = dict(re.findall(r'(?:^|,)(\w+)="([^"]*)"', samples[0]))
        require(labels.get('version') == release and labels.get('revision') == revision,
                'Node exporter metric identity differs from pin.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('pin', type=Path)
    parser.add_argument('binary_sha256')
    args = parser.parse_args()
    qualify_package(args.package, json.loads(args.pin.read_text()), args.binary_sha256)
