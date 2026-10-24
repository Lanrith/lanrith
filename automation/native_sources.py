"""Prepare signed native security sources; source upgrades still require human review."""

import os
from pathlib import Path
import re
import tempfile

from .common import digest, fetch, require, run, version
from .inputs import changed_fields, lock_values, stable_patch


def unbound(old_raw, selected):
    old = lock_values(old_raw)
    match = re.fullmatch(r'([0-9]+\.[0-9]+\.[0-9]+)-0\+deb13u[0-9]+', selected)
    require(match, 'Unbound requires a reviewed Debian 13 source version.')
    upstream = match[1]
    if selected == old['UNBOUND_VERSION']:
        return old_raw
    stable_patch(old['UNBOUND_UPSTREAM_VERSION'], upstream,
                 ['.'.join(map(str, version(old['UNBOUND_UPSTREAM_VERSION'])[:2]))])
    require(old['UNBOUND_SOURCE_BASE_URL'] == 'https://security.debian.org/debian-security/pool/main/u/unbound' and
            old['UNBOUND_RELEASE_KEY_URL'] == 'https://nlnetlabs.nl/downloads/keys/releases-g2.asc',
            'Unbound source authorities differ from their reviewed origins.')
    dsc_name = 'unbound_'+selected+'.dsc'
    dsc = fetch(old['UNBOUND_SOURCE_BASE_URL']+'/'+dsc_name, maximum=256*1024)
    text = dsc.decode()
    require(re.search(r'^Source: unbound$', text, re.MULTILINE) and
            re.search(r'^Version: '+re.escape(selected)+r'$', text, re.MULTILINE), 'Debian source identity differs.')
    checksums = {name: checksum for checksum, size, name in
                 re.findall(r'^ ([0-9a-f]{64}) +([0-9]+) +([^\s]+)$', text, re.MULTILINE)}
    names = {'ORIG': 'unbound_'+upstream+'.orig.tar.gz',
             'ORIG_SIGNATURE': 'unbound_'+upstream+'.orig.tar.gz.asc',
             'DEBIAN_TAR': 'unbound_'+selected+'.debian.tar.xz'}
    require(set(names.values()) <= set(checksums), 'Signed source descriptor lacks complete source digest coverage.')
    with tempfile.TemporaryDirectory(prefix='lanrith-unbound-source.') as temporary:
        root = Path(temporary)
        dsc_path = root/dsc_name
        dsc_path.write_bytes(dsc)
        keyring = os.environ.get('LANRITH_DEBIAN_KEYRING')
        if not keyring:
            # Ubuntu's packaged keyring can predate the already pinned signer.
            # The public key is part of the human-reviewed tooling revision;
            # the lock's existing signing fingerprint remains the authority.
            public_key = Path(__file__).resolve().parents[1]/'security/debian-source-signers.asc'
            keyring = str(root/'debian.gpg')
            run('gpg', '--batch', '--no-options', '--homedir', str(root), '--dearmor',
                '--output', keyring, str(public_key), capture_output=True)
        verified = run('gpgv', '--status-fd', '1', '--keyring', keyring, str(dsc_path), capture_output=True).stdout
        require(('[GNUPG:] VALIDSIG '+old['UNBOUND_DEBIAN_SIGNER_FINGERPRINT']+' ').encode() in verified,
                'Debian source signer changed; independent key review is required.')
        for key, name in names.items():
            raw = fetch(old['UNBOUND_SOURCE_BASE_URL']+'/'+name, maximum=16*1024*1024)
            require(digest(raw) == checksums[name], 'Source archive differs from its signed Debian descriptor.')
            (root/name).write_bytes(raw)
        key = fetch(old['UNBOUND_RELEASE_KEY_URL'], maximum=1024*1024)
        require(digest(key) == old['UNBOUND_RELEASE_KEY_SHA256'], 'Upstream release key bytes changed.')
        (root/'release.asc').write_bytes(key)
        run('gpg', '--batch', '--no-options', '--homedir', str(root), '--dearmor', '--output', str(root/'release.gpg'),
            str(root/'release.asc'), capture_output=True)
        verified = run('gpgv', '--status-fd', '1', '--keyring', str(root/'release.gpg'),
                       str(root/names['ORIG_SIGNATURE']), str(root/names['ORIG']), capture_output=True).stdout
        require(('[GNUPG:] VALIDSIG '+old['UNBOUND_RELEASE_KEY_FINGERPRINT']+' ').encode() in verified,
                'Upstream release signature differs from the reviewed signing key.')
    values = {'UNBOUND_VERSION': selected, 'UNBOUND_UPSTREAM_VERSION': upstream,
              'UNBOUND_DSC': dsc_name, 'UNBOUND_DSC_SHA256': digest(dsc)}
    for key, name in names.items():
        values['UNBOUND_'+key] = name
        values['UNBOUND_'+key+'_SHA256'] = checksums[name]
    result = old_raw.decode()
    for key, value in values.items():
        result, count = re.subn(r'^'+key+r'=.+$', key+'='+value, result, flags=re.MULTILINE)
        require(count == 1, 'Unbound source lock is incomplete.')
    return result.encode()


def validate_unbound(old_raw, new_raw, reasons):
    old, new = lock_values(old_raw), lock_values(new_raw)
    require(changed_fields(old, new) <= {
        'UNBOUND_VERSION', 'UNBOUND_UPSTREAM_VERSION', 'UNBOUND_DSC', 'UNBOUND_DSC_SHA256',
        'UNBOUND_ORIG', 'UNBOUND_ORIG_SHA256', 'UNBOUND_ORIG_SIGNATURE', 'UNBOUND_ORIG_SIGNATURE_SHA256',
        'UNBOUND_DEBIAN_TAR', 'UNBOUND_DEBIAN_TAR_SHA256'}, 'Source recipe changed its signing authority or commands.')
    require(any(r['type'] == 'debian-security-fix' and r['package'] == 'unbound' and
                r['installed'] == old['UNBOUND_VERSION'] and r['fixed'] == new['UNBOUND_VERSION'] for r in reasons),
            'Unbound source upgrade has no matching Debian security reason.')
    require(unbound(old_raw, new['UNBOUND_VERSION']) == new_raw, 'Native source inputs differ from authenticated resolution.')
