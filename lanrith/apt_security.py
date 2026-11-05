"""Stage checksum-locked Debian APT fixes before a builder's first network use."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .release import canonical, require, unique

HOSTS = ('snapshot.debian.org', 'snapshot-cloudflare.debian.org')
PACKAGES = {'trixie': {'apt', 'libapt-pkg7.0', 'apt-utils'},
            'bookworm': {'apt', 'libapt-pkg6.0'}}


def selected(project, distribution):
    require(distribution in PACKAGES, 'Unsupported APT bootstrap distribution.')
    raw = (project/'builders/apt-security.json').read_bytes()
    require(len(raw) <= 16384, 'APT security lock exceeds its bound.')
    value = json.loads(raw, object_pairs_hook=unique)
    require(set(value) == {'schema','advisory','memory_bug','distributions'} and value['schema'] == 1 and
            set(value['distributions']) == set(PACKAGES), 'Invalid reviewed APT security lock.')
    pin = value['distributions'][distribution]
    require(set(pin) == {'version','inrelease_sha256','package_index_sha256','packages'} and
            re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}',pin['version']) and
            all(re.fullmatch(r'[0-9a-f]{64}',pin[k]) for k in ('inrelease_sha256','package_index_sha256')) and
            set(pin['packages']) == PACKAGES[distribution], 'Invalid reviewed APT package set.')
    for name, item in pin['packages'].items():
        require(set(item) == {'filename','sha256','size','locator'} and
                item['filename'] == name+'_'+pin['version']+'_amd64.deb' and
                re.fullmatch(r'[0-9a-f]{64}',item['sha256']) and re.fullmatch(r'[0-9a-f]{40}',item['locator']) and
                type(item['size']) is int and 0 < item['size'] <= 4*1024**2,
                'APT package identity differs from the reviewed stable lock.')
    return pin


def download(item, destination):
    require(not destination.exists() and not destination.is_symlink(), 'APT bootstrap download must be new.')
    for host in HOSTS:
        with tempfile.TemporaryDirectory(prefix='.apt-security.',dir=destination.parent) as temporary:
            output = Path(temporary)/'package.deb'
            url = 'https://'+host+'/file/'+item['locator']+'/'+item['filename']
            result = subprocess.run(['curl','--disable','--proto','=https','--tlsv1.2','--fail','--silent',
                '--show-error','--connect-timeout','5','--max-time','30','--retry','1','--retry-max-time','35',
                '--max-filesize',str(item['size']),'--output',str(output),'--write-out','%{http_code}','--url',url],
                stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=70)
            if result.returncode == 0 and result.stdout == '200':
                require(output.is_file() and not output.is_symlink() and output.stat().st_size == item['size'] and
                        hashlib.sha256(output.read_bytes()).hexdigest() == item['sha256'],
                        'APT security package differs from its authenticated reviewed SHA-256 lock.')
                output.replace(destination)
                return
            require(result.returncode in (5,6,7,18,22,28,52,55,56) and
                    result.stdout in ('000','429','500','502','503','504','200'),
                    'APT security bootstrap failed a permanent HTTP or TLS check.')
    require(False, 'Pinned APT security packages unavailable; no unpatched builder is admitted.')


def stage(project, context, distribution):
    pin = selected(project, distribution)
    directory = context/'lanrith-apt-bootstrap'
    require(context.resolve() == context and not directory.exists() and not directory.is_symlink(),
            'APT bootstrap requires a new canonical context directory.')
    directory.mkdir()
    for item in pin['packages'].values():
        download(item, directory/item['filename'])
    (directory/'SHA256SUMS').write_text(''.join(item['sha256']+'  '+item['filename']+'\n'
        for name,item in sorted(pin['packages'].items())))
    shutil.copyfile(project/'builders/install-apt-security.sh',directory/'install.sh')
    shutil.copyfile(project/'builders/configure-apt-snapshots.sh',directory/'configure-snapshots.sh')
    (directory/'distribution').write_text(distribution+'\n')
    (directory/'version').write_text(pin['version']+'\n')
    (directory/'packages').write_text(' '.join(sorted(pin['packages']))+'\n')
    locks = {}
    for line in (project/'builders/build-inputs.lock').read_text().splitlines():
        if line and not line.startswith('#'):
            key, separator, value = line.partition('=')
            require(separator and key not in locks, 'Invalid snapshot build lock.')
            locks[key] = value
    prefix = 'DEBIAN_BOOKWORM' if distribution == 'bookworm' else 'DEBIAN'
    for archive, suffix in [('debian',''),('debian-security','_SECURITY')]:
        stamp = locks[prefix+suffix+'_SNAPSHOT']
        require(re.fullmatch(r'[0-9]{8}T[0-9]{6}Z',stamp), 'Invalid locked APT snapshot date.')
        (directory/(archive+'.snapshot')).write_text(stamp+'\n')
        (directory/(archive+'.mirrors')).write_text(''.join(
            'https://'+host+'/archive/'+archive+'/'+stamp+'/\tpriority:'+str(index+1)+'\n'
            for index,host in enumerate(HOSTS)))
    (directory/'sources.list').write_text(''.join('deb [check-valid-until=no] mirror+file:/etc/apt/mirrors/'+
        archive+'.mirrors '+distribution+suffix+' main\n'
        for archive,suffix in [('debian',''),('debian-security','-security')]))
    (directory/'snapshot.pref').write_text('Package: *\nPin: release o=Debian\nPin-Priority: 1001\n')
    return hashlib.sha256(canonical({p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir())})).hexdigest()
