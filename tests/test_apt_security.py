"""APT fixes are authenticated before first use and cannot be silently bypassed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from lanrith import apt_security as security
from lanrith.release import ReleaseError

ROOT = Path(__file__).resolve().parents[1]


class AptSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.body=b'authenticated package fixture'
        self.item={'filename':'apt_3.0.4_amd64.deb','locator':'a'*40,
                   'sha256':hashlib.sha256(self.body).hexdigest(),'size':len(self.body)}
        self.calls=[]

    def runner(self,replies):
        def run(argv,**kwargs):
            self.calls.append(argv)
            self.assertEqual(argv[:2],['curl','--disable'])
            self.assertNotIn('--location',argv);self.assertNotIn('--insecure',argv)
            code,status,body=replies.pop(0)
            Path(argv[argv.index('--output')+1]).write_bytes(body)
            return subprocess.CompletedProcess(argv,code,status,'private-upstream-canary')
        return run

    def test_package_hash_not_legacy_content_locator_authorizes_download(self):
        with patch.object(security.subprocess,'run',side_effect=self.runner([(0,'200',self.body)])):
            security.download(self.item,self.root/'package')
        self.assertEqual((self.root/'package').read_bytes(),self.body)
        self.assertEqual(len(self.calls),1)

    def test_transient_outage_can_use_only_the_official_alternate(self):
        with patch.object(security.subprocess,'run',side_effect=self.runner([(22,'504',b'error'),(0,'200',self.body)])):
            security.download(self.item,self.root/'package')
        self.assertTrue(self.calls[1][-1].startswith('https://snapshot-cloudflare.debian.org/file/'))

    def test_altered_or_oversized_success_never_uses_fallback(self):
        for body in (b'x'*len(self.body),self.body+b'x'):
            with self.subTest(body=body),patch.object(security.subprocess,'run',side_effect=self.runner([(0,'200',body)])):
                with self.assertRaisesRegex(ReleaseError,'SHA-256'):security.download(self.item,self.root/'package')
                self.assertFalse((self.root/'package').exists())

    def test_tls_redirect_and_missing_package_fail_without_fallback(self):
        for code,status in ((60,'000'),(0,'302'),(22,'404'),(63,'200')):
            self.calls=[]
            with self.subTest(code=code),patch.object(security.subprocess,'run',side_effect=self.runner([(code,status,b'')])):
                with self.assertRaisesRegex(ReleaseError,'permanent'):security.download(self.item,self.root/'package')
                self.assertEqual(len(self.calls),1)

    def test_both_origins_unavailable_and_symlink_destination_fail_closed(self):
        with patch.object(security.subprocess,'run',side_effect=self.runner([(22,'503',b'')]*2)):
            with self.assertRaisesRegex(ReleaseError,'unpatched'):security.download(self.item,self.root/'package')
        self.assertFalse((self.root/'package').exists())
        target=self.root/'target';target.write_bytes(b'keep');(self.root/'package').symlink_to(target)
        with patch.object(security.subprocess,'run') as command:
            with self.assertRaises(ReleaseError):security.download(self.item,self.root/'package')
            command.assert_not_called()
        self.assertEqual(target.read_bytes(),b'keep')

    def test_reviewed_lock_binds_distribution_version_names_and_package_sizes(self):
        (self.root/'builders').mkdir();original=json.loads((ROOT/'builders/apt-security.json').read_bytes())
        lock=self.root/'builders/apt-security.json'
        for change in (lambda v:v['distributions']['trixie']['packages']['apt'].update(filename='../unreviewed'),
                       lambda v:v['distributions']['trixie']['packages']['apt'].update(size=True),
                       lambda v:v['distributions']['trixie']['packages'].pop('libapt-pkg7.0'),
                       lambda v:v['distributions']['trixie'].update(version='3.0.4;unexpected')):
            value=json.loads(json.dumps(original));change(value);lock.write_text(json.dumps(value))
            with self.subTest(change=change),self.assertRaises(ReleaseError):security.selected(self.root,'trixie')
        lock.write_text(json.dumps(original));self.assertEqual(security.selected(self.root,'trixie')['version'],'3.0.4')
        with self.assertRaises(ReleaseError):security.selected(self.root,'untrusted')

    def test_stage_identity_covers_patch_binaries_script_and_lock_version(self):
        context=self.root/'context';context.mkdir()
        def download(item,destination):destination.write_bytes(item['sha256'].encode())
        with patch.object(security,'download',side_effect=download), patch.object(security.frozen_apt,'repository',return_value=(b'signed fixture',b'index fixture',{})):
            identity=security.stage(ROOT,context,'trixie')
            self.assertEqual(len(identity),64)
            names={p.name for p in (context/'lanrith-apt-bootstrap').iterdir()}
            self.assertTrue({'install.sh','version','distribution','SHA256SUMS','apt-utils_3.0.4_amd64.deb'}<=names)
            mirrors=(context/'lanrith-apt-bootstrap/debian.mirrors').read_text()
            self.assertEqual(len(mirrors.splitlines()),4)
            self.assertIn('file:/etc/apt/lanrith-repositories/debian/\tpriority:1 type:index',mirrors)
            self.assertIn('https://deb.debian.org/debian/\tpriority:2 type:deb',mirrors)
            self.assertIn('https://snapshot.debian.org/archive/debian/20261103T070000Z/\tpriority:3 type:deb',mirrors)
            self.assertIn('https://snapshot-cloudflare.debian.org/archive/debian/20261103T070000Z/\tpriority:4 type:deb',mirrors)
            self.assertIn('mirror+file:',(context/'lanrith-apt-bootstrap/sources.list').read_text())
            self.assertIn('Pin: release o=Debian',(context/'lanrith-apt-bootstrap/snapshot.pref').read_text())
            with self.assertRaises(ReleaseError):security.stage(ROOT,context,'trixie')

    def test_each_debian_build_stage_is_patched_before_its_first_apt_call(self):
        count=0
        for component in ('mkosi','alloy','pam','vpp','unbound','tayga'):
            text=(ROOT/'builders'/component/'Containerfile').read_text()
            for stage in text.split('\nFROM ')[1:]:
                if 'apt-get' in stage:
                    count+=1
                    self.assertLess(stage.index('/bin/sh /opt/lanrith-apt-bootstrap/install.sh'),stage.index('apt-get'))
        self.assertEqual(count,9)
        script=(ROOT/'builders/install-apt-security.sh').read_text()
        self.assertIn('sha256sum --check --strict',script)
        self.assertIn('dpkg --compare-versions "$current" ge "$version"',script)
        self.assertIn('Pin-Priority: 1002',script)
        self.assertNotIn('apt-get',script)


@unittest.skipUnless(os.environ.get('GITHUB_ACTIONS')=='true' and
    os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Linux',
    'Requires the disposable hosted Linux Docker worker')
class HostedAptSecurityTests(unittest.TestCase):
    def test_exact_pinned_builder_images_use_fixed_apt_before_network_and_pass_retry_tests(self):
        spec=importlib.util.spec_from_file_location('apt_security_test_base',ROOT/'scripts/build-base.py')
        base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
        inputs=base.locks(ROOT/'builders/build-inputs.lock')
        for distribution,image in [('trixie',inputs['MKOSI_BUILDER_OCI']),('bookworm',inputs['PAM_RSSH_BUILDER_OCI'])]:
            with self.subTest(distribution=distribution),tempfile.TemporaryDirectory(prefix='lanrith-apt-probe.') as temporary:
                context=Path(temporary);security.stage(ROOT,context,distribution)
                tag='lanrith-apt-security-probe:'+uuid.uuid4().hex
                try:
                    (context/'Dockerfile').write_text('FROM '+image+'\nCOPY lanrith-apt-bootstrap /opt/lanrith-apt-bootstrap\nRUN /bin/sh /opt/lanrith-apt-bootstrap/install.sh\nRUN apt-get update && apt-get install --yes --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*\n')
                    subprocess.run(['docker','build','--memory','2g','--tag',tag,str(context)],check=True,timeout=300)
                    subprocess.run(['docker','run','--rm','--network','none',tag,'sh','-c',
                        '/bin/sh /opt/lanrith-apt-bootstrap/configure-snapshots.sh '+
                        inputs['DEBIAN_BOOKWORM_SNAPSHOT' if distribution=='bookworm' else 'DEBIAN_SNAPSHOT']+' '+
                        inputs['DEBIAN_BOOKWORM_SECURITY_SNAPSHOT' if distribution=='bookworm' else 'DEBIAN_SECURITY_SNAPSHOT']+
                        ' && apt-get update'],check=True,timeout=120)
                    # Corrupt only the signature in a fresh isolated container.
                    # Controller payload hashing must never replace APT's PGP gate.
                    configure='/bin/sh /opt/lanrith-apt-bootstrap/configure-snapshots.sh '+inputs['DEBIAN_BOOKWORM_SNAPSHOT' if distribution=='bookworm' else 'DEBIAN_SNAPSHOT']+' '+inputs['DEBIAN_BOOKWORM_SECURITY_SNAPSHOT' if distribution=='bookworm' else 'DEBIAN_SECURITY_SNAPSHOT']
                    corrupt="import hashlib;from pathlib import Path;p=Path('/etc/apt/lanrith-repositories/debian/dists/"+distribution+"/InRelease');p.write_bytes(p.read_bytes().replace(b'-----BEGIN PGP SIGNATURE-----',b'-----BEGIN PGP SIGNATURE-----\\n\\nAAAA',1));Path('/etc/apt/lanrith-repositories/debian/inrelease.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'\\n')"
                    negative=subprocess.run(['docker','run','--rm','--network','none',tag,'sh','-c',
                        configure+' && python3 -c '+__import__('shlex').quote(corrupt)+' && apt-get update'],capture_output=True,text=True,timeout=120)
                    self.assertNotEqual(negative.returncode,0,'APT accepted corrupted archive signature metadata.')
                    self.assertTrue(any(word in (negative.stdout+negative.stderr).lower() for word in
                        ('gpg','signature','not signed','sqv')),'Rejection did not exercise the archive signature gate.')
                    substitute="from pathlib import Path;p=next(Path('/var/lib/apt/lists').glob('*debian.mirrors_dists_"+distribution+"_InRelease'));p.write_bytes(Path('/etc/apt/lanrith-repositories/debian-security/dists/"+distribution+"-security/InRelease').read_bytes());print('SIGNED-REPOSITORY-SUBSTITUTED',flush=True)"
                    changed=subprocess.run(['docker','run','--rm','--network','none',tag,'sh','-c',
                        configure+' && apt-get update && python3 -c '+__import__('shlex').quote(substitute)+
                        ' && /bin/sh /etc/apt/verify-lanrith-snapshots'],capture_output=True,text=True,timeout=120)
                    self.assertIn('SIGNED-REPOSITORY-SUBSTITUTED',changed.stdout,'The replacement fixture did not reach the metadata verification hook.')
                    self.assertEqual(changed.returncode,1,'A different signed repository replaced the reviewed package universe.')
                    subprocess.run(['docker','run','--rm','--network','none','--memory','512m','--pids-limit','256',
                        '--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--env','LANRITH_APT_SECURITY_TEST=true',
                        '--volume',str(ROOT)+':/source:ro','--workdir','/source',tag,
                        'python3','-m','unittest','discover','-s','tests','-p','test_apt_transport.py','-v'],check=True,timeout=180)
                    print('APT security probe: '+distribution+' authenticated fixed APT installed before network; bounded retry, corruption and delayed-item tests passed.',flush=True)
                finally:
                    subprocess.run(['docker','image','rm',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
