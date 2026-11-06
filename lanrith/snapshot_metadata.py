"""Fetch locked Release bytes through bounded, official snapshot transports."""
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.parse

from .release import require

HOSTS = ('snapshot.debian.org', 'snapshot-cloudflare.debian.org')
TRANSIENT_HTTP = {429, 500, 502, 503, 504}
TRANSIENT_CURL = {5, 6, 7, 18, 28, 52, 55, 56}
MAXIMUM_BYTES = 4*1024*1024
# Optional locators recovered from the already reviewed Release bytes. They
# bypass a failing timestamp lookup, never replace SHA-256 authentication, and
# apply only to the exact archive/date/suite/hash tuple. New snapshot updates
# without a locator still use the bounded archive lookup below.
LOCATORS = {
    ('debian','20261103T070000Z','trixie','ed56aac47e7911e65ee63aae8d67e29f20e023f840e49f8ed037043a33de138a'):
        '441fafd5eecf075d660c2495a16fa13252c80790',
    ('debian-security','20261103T070000Z','trixie-security','3305e8cbc049a83531191f9ad9706436f0a0e419e0610bd37307061792d65975'):
        'c023b111db487ba975ceaf35847a4ec0a3166db5',
    ('debian','20261103T070000Z','bookworm','abcf5882746e0f68171f41adbb4ac01b74b49d62d203379befb9265804311a4f'):
        '15f2be9ee108a3156330423d8bead85eac3698ff',
    ('debian-security','20261103T070000Z','bookworm-security','24865a99c7600a949e1ac78111dcfe336b19487af096fb170ac8e805b75228b5'):
        '9d50f9f5e9eeb358e999f9929ce8b19d19c328d0',
}


def validate_url(url, archive, snapshot, suite):
    require(isinstance(url,str) and not re.search(r'[\x00-\x20\x7f]',url), 'Invalid snapshot URL characters.')
    value = urllib.parse.urlsplit(url)
    require(value.scheme == 'https' and value.hostname in HOSTS and value.port in (None,443) and
            value.username is None and value.password is None and not value.query and not value.fragment,
            'Snapshot metadata left its approved HTTPS origins.')
    match = re.fullmatch(r'/archive/'+re.escape(archive)+r'/([0-9]{8}T[0-9]{6}Z)/dists/'+
                         re.escape(suite)+r'/Release', value.path)
    # Snapshot redirects archive paths to legacy content-addressed locators.
    # Their SHA-1 spelling is only a locator; the reviewed SHA-256 still
    # authenticates every successful response before it can be used.
    content = re.fullmatch(r'/file/[0-9a-f]{40}(?:/Release)?', value.path)
    require(content or match and match[1] <= snapshot, 'Snapshot metadata left the locked archive, suite or date.')


def fetch(archive, snapshot, suite, expected, destination):
    require(archive in ('debian','debian-security') and
            re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', snapshot) and
            suite in ('trixie','trixie-security','bookworm','bookworm-security') and
            (archive == 'debian-security') == suite.endswith('-security') and
            re.fullmatch(r'[0-9a-f]{64}', expected), 'Invalid locked snapshot metadata identity.')
    require(not destination.exists() and not destination.is_symlink() and
            destination.parent.resolve() == destination.parent, 'Snapshot metadata destination must be new and canonical.')
    deadline = time.monotonic()+90
    attempts = []
    with tempfile.TemporaryDirectory(prefix='.snapshot-metadata.',dir=destination.parent) as temporary:
        output = Path(temporary)/'Release'
        for host in HOSTS:
            locator = LOCATORS.get((archive,snapshot,suite,expected))
            initial = (f'https://{host}/file/{locator}/Release' if locator else
                       f'https://{host}/archive/{archive}/{snapshot}/dists/{suite}/Release')
            for retry in range(2):
                current = initial
                for redirect in range(4):
                    validate_url(current,archive,snapshot,suite)
                    remaining = min(20, int(deadline-time.monotonic()))
                    require(remaining > 0, 'Locked snapshot metadata transport deadline expired.')
                    command = ['curl','--disable','--proto','=https','--tlsv1.2',
                        '--fail','--silent','--show-error','--connect-timeout','5','--max-time',str(remaining),
                        '--max-filesize',str(MAXIMUM_BYTES),'--output',str(output),
                        '--write-out','%{response_code}\n%{redirect_url}\n','--url',current]
                    try:
                        result = subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,
                                                text=True,timeout=remaining+2)
                    except subprocess.TimeoutExpired:
                        result = subprocess.CompletedProcess(command,28,'000\n\n')
                    require(len(result.stdout) <= 4096, 'Snapshot transport response exceeds its metadata bound.')
                    lines = result.stdout.splitlines()
                    require(lines and re.fullmatch(r'[0-9]{3}',lines[0]), 'Snapshot transport status is malformed.')
                    status = int(lines[0])
                    attempts.append({'url':current,'curl_exit':result.returncode,'http_status':status})
                    print('Snapshot metadata: '+urllib.parse.urlsplit(current).hostname+' '+suite+
                          ' HTTP '+str(status)+'; transport exit '+str(result.returncode),flush=True)
                    if result.returncode == 0 and status == 200:
                        require(output.is_file() and not output.is_symlink() and
                                0 < output.stat().st_size <= MAXIMUM_BYTES, 'Snapshot Release exceeds its size bound.')
                        actual = hashlib.sha256(output.read_bytes()).hexdigest()
                        # A wrong successful response is a trust failure, not a
                        # transport outage to hide by consulting another mirror.
                        require(actual == expected, 'Debian snapshot Release differs from the reviewed lock.')
                        output.replace(destination)
                        return {'sha256':actual,'url':current,'attempts':attempts}
                    if result.returncode == 0 and status in (301,302,303,307,308):
                        require(len(lines) == 2 and redirect < 3, 'Snapshot redirect budget expired.')
                        validate_url(lines[1],archive,snapshot,suite)
                        current = lines[1]
                        continue
                    require(status in TRANSIENT_HTTP and result.returncode == 22 or
                            status in (0,200) and result.returncode in TRANSIENT_CURL,
                            'Locked snapshot metadata failed a permanent HTTP or TLS check.')
                    break
    require(False, 'Locked snapshot Release unavailable from both official transports; no build is admitted.')
