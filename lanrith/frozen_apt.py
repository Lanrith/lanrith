"""Recover the exact signed APT universe independently of timestamp lookup."""
import base64
import functools
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.parse

from .release import ReleaseError, canonical, require, unique

SNAPSHOT_HOSTS = ('snapshot.debian.org', 'snapshot-cloudflare.debian.org')
ORIGINS = {'debian':'https://deb.debian.org/debian',
           'debian-security':'https://security.debian.org/debian-security'}
SUITES = {'trixie','trixie-security','bookworm','bookworm-security'}
MAX_SIGNED = 512*1024
MAX_COMPRESSED = 16*1024**2
MAX_EXPANDED = 128*1024**2
_USED = {}


def identity(archive, stamp, suite, expected):
    require(archive in ORIGINS and suite in SUITES and
            (archive == 'debian-security') == suite.endswith('-security') and
            re.fullmatch(r'[0-9]{8}T[0-9]{6}Z',stamp) and re.fullmatch(r'[0-9a-f]{64}',expected),
            'Invalid locked APT repository identity.')


def records(value):
    require(isinstance(value,list) and len(value)<=8, 'Oversized transport hint list.')
    for item in value:
        require(isinstance(item,dict) and set(item) in (
            {'archive','snapshot','suite','release_sha256','inrelease','index'},
            {'archive','snapshot','suite','release_sha256','inrelease','index','inrelease_base64'}),
            'Invalid transport hint fields.')
        identity(item['archive'],item['snapshot'],item['suite'],item['release_sha256'])
        for field,maximum in [('inrelease',MAX_SIGNED),('index',MAX_COMPRESSED)]:
            pin=item[field]
            require(isinstance(pin,dict) and set(pin)=={'sha256','size','locator'} and
                    re.fullmatch(r'[0-9a-f]{64}',pin['sha256']) and re.fullmatch(r'[0-9a-f]{40}',pin['locator']) and
                    type(pin['size']) is int and 0<pin['size']<=maximum, 'Invalid bounded transport artifact hint.')
        if 'inrelease_base64' in item:
            require(isinstance(item['inrelease_base64'],str) and len(item['inrelease_base64'])<=4*MAX_SIGNED//3+4,
                    'Oversized cached signed repository metadata.')
    return value


@functools.lru_cache(maxsize=1)
def retained_hints():
    # This is an optional data cache, not authority: no cached value can replace
    # the reviewed Release digest or APT's Debian archive signature checks.
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REPOSITORY')!='Lanrith/lanrith' or not shutil.which('gh'):
        return []
    def api(endpoint, maximum, binary=False):
        argv=['gh','api','repos/Lanrith/lanrith/'+endpoint]
        if binary:argv+=['-H','Accept: application/octet-stream']
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
        require(result.returncode==0 and len(result.stdout)<=maximum, 'Optional retained metadata is unavailable.')
        return result.stdout
    try:
        release=json.loads(api('releases/latest',1024**2),object_pairs_hook=unique)
        require(release.get('immutable') is True and not release['prerelease'] and not release['draft'] and
                re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',release['tag_name']), 'Not an immutable stable hint source.')
        assets=[a for a in release['assets'] if a['name']=='package-checkpoint.json']
        require(len(assets)==1 and type(assets[0]['id']) is int and 0<assets[0]['size']<=1024**2,
                'Bounded prior checkpoint missing.')
        raw=api('releases/assets/'+str(assets[0]['id']),1024**2,True)
        require(assets[0].get('digest')=='sha256:'+hashlib.sha256(raw).hexdigest(),'Retained hint asset digest differs.')
        checkpoint=json.loads(raw,object_pairs_hook=unique)
        return records(checkpoint.get('snapshot_transports',[]))
    except (OSError,subprocess.SubprocessError,ValueError,TypeError,KeyError,ReleaseError):
        return []


def cleartext(signed):
    """Extract only to compare the reviewed digest; APT still verifies PGP."""
    require(0<len(signed)<=MAX_SIGNED and b'\r' not in signed and b'\0' not in signed,
            'Invalid bounded signed repository metadata.')
    header,separator,rest=signed.partition(b'\n\n')
    require(separator and header in (b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256',
                                    b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512') and
            rest.count(b'-----BEGIN PGP SIGNATURE-----')==1 and
            signed.endswith(b'-----END PGP SIGNATURE-----\n'), 'Malformed clear-signed repository metadata.')
    body,separator,signature=rest.partition(b'\n-----BEGIN PGP SIGNATURE-----')
    require(separator and signature.strip(), 'Missing Debian archive signature.')
    # OpenPGP cleartext canonicalization excludes the last LF from the signed
    # body. Debian's corresponding Release file includes precisely that LF.
    return b'\n'.join(line[2:] if line.startswith(b'- ') else line for line in body.split(b'\n'))+b'\n'


def validate_url(url):
    value=urllib.parse.urlsplit(url)
    require(value.scheme=='https' and value.hostname in (*SNAPSHOT_HOSTS,'deb.debian.org','security.debian.org') and
            value.port in (None,443) and value.username is None and value.password is None and
            not value.query and not value.fragment and not re.search(r'[\x00-\x20\x7f]',url),
            'Repository metadata left its fixed official HTTPS origins.')
    path=value.path
    file_path=re.fullmatch(r'/file/[0-9a-f]{40}/(?:InRelease|Packages.xz|[0-9a-f]{64})',path)
    archive_path=re.fullmatch(r'/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z/dists/(?:trixie|bookworm)(?:-security)?/(?:InRelease|main/binary-amd64/(?:Packages.xz|by-hash/SHA256/[0-9a-f]{64}))',path)
    live_path=re.fullmatch(r'/(?:debian|debian-security)/dists/(?:trixie|bookworm)(?:-security)?/(?:InRelease|main/binary-amd64/by-hash/SHA256/[0-9a-f]{64})',path)
    require(file_path if value.hostname in SNAPSHOT_HOSTS and path.startswith('/file/') else
            archive_path if value.hostname in SNAPSHOT_HOSTS else live_path, 'Unexpected repository metadata path.')


def request(url, maximum):
    with tempfile.TemporaryDirectory(prefix='lanrith-apt-metadata.') as temporary:
        output=Path(temporary)/'data'
        for _ in range(4):
            validate_url(url)
            result=subprocess.run(['curl','--disable','--proto','=https','--tlsv1.2','--fail','--silent','--show-error',
                '--connect-timeout','5','--max-time','20','--max-filesize',str(maximum),'--output',str(output),
                '--write-out','%{http_code}\n%{redirect_url}\n','--url',url],stdin=subprocess.DEVNULL,
                capture_output=True,text=True,timeout=25)
            require(len(result.stdout)<=4096,'Oversized transport status.')
            lines=result.stdout.splitlines();require(lines and re.fullmatch(r'[0-9]{3}',lines[0]),'Invalid transport status.')
            status=int(lines[0])
            if result.returncode==0 and status==200:
                require(output.is_file() and not output.is_symlink() and 0<output.stat().st_size<=maximum,
                        'Repository metadata exceeds its bound.')
                return output.read_bytes()
            if result.returncode==0 and status in (301,302,303,307,308):
                require(len(lines)==2,'Malformed repository redirect.');url=lines[1];continue
            require(result.returncode in (5,6,7,18,22,28,52,55,56) and status in (0,200,404,429,500,502,503,504),
                    'Repository metadata failed a permanent HTTP or TLS check.')
            return None
    require(False,'Repository metadata redirect budget exhausted.')


def index_records(release):
    section=release.decode('ascii').split('\nSHA256:\n',1)
    require(len(section)==2,'Release has no unique SHA-256 index section.')
    result={}
    for line in section[1].splitlines():
        if not line.startswith(' '):break
        fields=line.split();require(len(fields)==3,'Malformed SHA-256 index row.')
        if fields[2] in ('main/binary-amd64/Packages','main/binary-amd64/Packages.xz'):
            require(fields[2] not in result and re.fullmatch(r'[0-9a-f]{64}',fields[0]) and fields[1].isdigit(),
                    'Ambiguous locked package index.')
            result[fields[2]]={'sha256':fields[0],'size':int(fields[1])}
    require(set(result)=={'main/binary-amd64/Packages','main/binary-amd64/Packages.xz'} and
            0<result['main/binary-amd64/Packages']['size']<=MAX_EXPANDED and
            0<result['main/binary-amd64/Packages.xz']['size']<=MAX_COMPRESSED, 'Missing or oversized package index.')
    return result


@functools.lru_cache(maxsize=8)
def repository(project_string, archive, stamp, suite, expected):
    identity(archive,stamp,suite,expected);project=Path(project_string)
    source_path=project/'builders/snapshot-transports.json'
    require(source_path.is_file() and not source_path.is_symlink() and source_path.stat().st_size<=128*1024,'Unsafe source transport hints.')
    source=json.loads(source_path.read_bytes(),object_pairs_hook=unique)
    require(set(source)=={'schema','records'} and type(source['schema']) is int and source['schema']==1,'Invalid source transport hints.')
    hints=[h for h in records(source['records']) if (h['archive'],h['suite'],h['release_sha256'])==(archive,suite,expected)]
    if not hints:
        hints=[h for h in retained_hints() if (h['archive'],h['suite'],h['release_sha256'])==(archive,suite,expected)]
    hint=hints[0] if hints else None;signed=None
    if hint and 'inrelease_base64' in hint:
        signed=base64.b64decode(hint['inrelease_base64'],validate=True)
    elif hint:
        seed=project/'builders/snapshots'/(suite+'.InRelease')
        if seed.is_file() and not seed.is_symlink() and seed.stat().st_size==hint['inrelease']['size']:
            candidate=seed.read_bytes()
            if hashlib.sha256(candidate).hexdigest()==hint['inrelease']['sha256']:signed=candidate
    if signed is None and hint:
        for host in SNAPSHOT_HOSTS:
            signed=request('https://'+host+'/file/'+hint['inrelease']['locator']+'/InRelease',MAX_SIGNED)
            if signed is not None:break
    if signed is not None and hint:
        require(len(signed)==hint['inrelease']['size'] and hashlib.sha256(signed).hexdigest()==hint['inrelease']['sha256'],
                'Recovered signed metadata differs from its bounded hint.')
    if signed is None:
        candidate=request(ORIGINS[archive]+'/dists/'+suite+'/InRelease',MAX_SIGNED)
        if candidate is not None and hashlib.sha256(cleartext(candidate)).hexdigest()==expected:signed=candidate
    if signed is None:
        for host in SNAPSHOT_HOSTS:
            candidate=request('https://'+host+'/archive/'+archive+'/'+stamp+'/dists/'+suite+'/InRelease',MAX_SIGNED)
            if candidate is not None:
                require(hashlib.sha256(cleartext(candidate)).hexdigest()==expected,'Snapshot returned another repository universe.')
                signed=candidate;break
    require(signed is not None,'The exact signed repository metadata is unavailable; no build is admitted.')
    release=cleartext(signed)
    require(hashlib.sha256(release).hexdigest()==expected,'Signed repository payload differs from the reviewed Release lock.')
    indexes=index_records(release);pin=indexes['main/binary-amd64/Packages.xz']
    urls=[ORIGINS[archive]+'/dists/'+suite+'/main/binary-amd64/by-hash/SHA256/'+pin['sha256']]
    if hint and hint['index']['sha256']==pin['sha256']:
        urls += ['https://'+host+'/file/'+hint['index']['locator']+'/Packages.xz' for host in SNAPSHOT_HOSTS]
    urls += ['https://'+host+'/archive/'+archive+'/'+stamp+'/dists/'+suite+'/main/binary-amd64/Packages.xz' for host in SNAPSHOT_HOSTS]
    compressed=None
    for url in urls:
        compressed=request(url,pin['size'])
        if compressed is not None:
            require(len(compressed)==pin['size'] and hashlib.sha256(compressed).hexdigest()==pin['sha256'],
                    'Package index differs from the reviewed Release SHA-256 and size.')
            break
    require(compressed is not None,'The exact frozen package index is unavailable; no build is admitted.')
    decoder=lzma.LZMADecompressor(memlimit=64*1024**2)
    expanded=decoder.decompress(compressed,max_length=MAX_EXPANDED+1)
    require(decoder.eof and not decoder.unused_data,'Invalid or excessive package index compression.')
    raw=indexes['main/binary-amd64/Packages']
    require(len(expanded)==raw['size'] and hashlib.sha256(expanded).hexdigest()==raw['sha256'],
            'Expanded package index differs from its reviewed Release hash.')
    record={'archive':archive,'snapshot':stamp,'suite':suite,'release_sha256':expected,
        'inrelease':{'sha256':hashlib.sha256(signed).hexdigest(),'size':len(signed),'locator':hashlib.sha1(signed).hexdigest()},
        'index':{'sha256':pin['sha256'],'size':len(compressed),'locator':hashlib.sha1(compressed).hexdigest()},
        'inrelease_base64':base64.b64encode(signed).decode('ascii')}
    _USED[(archive,suite,expected)]=record
    print('Frozen APT metadata: '+suite+' matches reviewed Release and index hashes; Debian signature verification remains mandatory in APT.',flush=True)
    return signed,compressed,record


def used():
    return list(_USED.values())
