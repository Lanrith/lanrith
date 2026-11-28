"""Stage one Suricata backport authenticated by Debian's frozen AMD64 index."""
import json
import lzma
import re

from . import apt_security, frozen_apt
from .release import require, unique

PACKAGE = '1:8.0.8-1~bpo13+2'
ENGINE = PACKAGE.split(':')[1].split('-')[0]


def selected(index, version):
    filename = 'suricata_' + version.split(':')[1] + '_amd64.deb'
    matches = []
    for entry in lzma.decompress(index).decode().split('\n\n'):
        if entry.startswith('Package: suricata\n'):
            fields = unique(line.split(': ', 1) for line in entry.splitlines()
                          if line and line[0] != ' ' and ': ' in line)
            matches.append(fields)
    require(len(matches) == 1, 'Debian index must contain one Suricata package.')
    fields = matches[0]
    require(fields['Version'] == version and fields['Architecture'] == 'amd64' and
            fields['Filename'] == 'pool/main/s/suricata/' + filename and
            re.fullmatch(r'[0-9a-f]{64}', fields['SHA256']) and
            0 < int(fields['Size']) <= 16 * 1024**2,
            'Unexpected Suricata version, architecture or Debian package path.')
    return {'filename': filename, 'size': int(fields['Size']), 'sha256': fields['SHA256']}


def stage(project, context):
    selection = json.loads((context/'ids-package.json').read_text(), object_pairs_hook=unique)
    require(set(selection) == {'snapshot', 'release_sha256', 'package_sha256', 'package_locator'} and
            re.fullmatch(r'[0-9a-f]{40}', selection['package_locator']) and
            re.fullmatch(r'[0-9a-f]{64}', selection['package_sha256']), 'Invalid Suricata package selection.')
    signed, index, _ = frozen_apt.repository(str(project), 'debian', selection['snapshot'],
        'trixie-backports', selection['release_sha256'])
    package = selected(index, PACKAGE)
    require(package['sha256'] == selection['package_sha256'], 'Suricata content differs from the reviewed package.')
    directory = context/'sensor-package'
    directory.mkdir()
    (directory/'InRelease').write_bytes(signed)
    apt_security.download({**package, 'locator': selection['package_locator']}, directory/package['filename'])
    (directory/'SHA256SUMS').write_text(package['sha256']+'  '+package['filename']+'\n')
