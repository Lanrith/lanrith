"""Image assembly keeps one compiler selection through extension projection."""

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from lanrith import boot_health, build, config, nat64_runtime, translation_runtime
from lanrith.release import ReleaseError
from test_extension_network import manifest
from test_extension_observations import settings


class TunAssemblyTests(unittest.TestCase):
    def test_extension_listeners_and_observers_preserve_tun_and_retained_sources(self):
        value = settings()
        value['translation'] = {'nat64': {'enabled': True}}
        retained = {'fd42:1234:5678:10::84': '10.255.223.200'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension = root/'extension'
            extension.mkdir()
            pin = manifest(extension, network={'listeners': [{
                'user': 'example-agent', 'network': 'home', 'address': '192.168.10.1',
                'sources': ['192.168.10.0/24'], 'protocol': 'tcp', 'port': 8443}]},
                observations=[{'service': service, 'user': 'example-agent'}
                              for service in ('policy', 'firewall')])
            base = root/'base.tar'
            with tarfile.open(base, 'w') as archive:
                for name, data in {'etc/passwd': b'root:*:0:0:root:/root:/bin/bash\n',
                                   'etc/group': b'root:x:0:\n'}.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            build.assembly(value, base, root/'image', version='0.1.0', sequence=9,
                integrations={'example-observer': (extension, pin)},
                access_backend='tun', retained_allocations=retained)
            output = root/'image/mkosi.extra'
            firewall = (output/'etc/nftables.conf').read_text()
            self.assertIn('tcp dport 8443', firewall)
            self.assertIn('jump tp_identity', firewall)
            self.assertIn('10.255.223.200', firewall)
            self.assertNotIn('chain n64_first', firewall)
            runtime = json.loads((output/'etc/router-policy-agent/runtime/runtime.json').read_text())
            self.assertEqual(runtime['backend'], 'tun')
            self.assertEqual(runtime['observer']['user'], 'example-agent')
            self.assertEqual((output/'usr/lib/lanrith-build/policy-backend').read_text(), 'tun\n')
            for relative in ('usr/lib/lanrith/lanrith/config.py', 'usr/lib/lanrith/lanrith/tun_policy.py',
                             'etc/router-policy-agent/nat64-runtime/runtime.json'):
                self.assertFalse((output/relative).exists(), relative)
            self.assertFalse(any(path.suffix in ('.yaml', '.yml') for path in output.rglob('*')))
            installed = json.loads((output/'usr/share/lanrith/installed.json').read_text())
            health = json.loads((output/'usr/share/lanrith/health.json').read_text())
            self.assertIs(health['native_translation'], True)
            expected = config.effective_digest(value, {'example-observer': pin},
                retained_allocations=retained, access_backend='tun')
            self.assertEqual(installed['configuration_sha256'], expected)
            self.assertEqual((output/'usr/share/lanrith/configuration.sha256').read_text().strip(), expected)

    def test_backend_changes_build_identity_without_mutating_owner_intent(self):
        value = settings()
        before = json.dumps(value, sort_keys=True)
        for function, args in ((config.rendered_digest, (value,)),
                               (config.effective_digest, (value, {'example-observer': 'a'*64}))):
            self.assertEqual(function(*args), function(*args, access_backend='legacy'))
            self.assertNotEqual(function(*args), function(*args, access_backend='tun'))
            with self.assertRaises(ReleaseError):
                function(*args, access_backend='unknown')
        self.assertEqual(json.dumps(value, sort_keys=True), before)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/'output'
            digest = config.write(value, output, access_backend='tun')
            self.assertEqual((output/'usr/share/lanrith/configuration.sha256').read_text().strip(), digest)
            self.assertEqual(digest, config.rendered_digest(value, access_backend='tun'))

    def test_native_boot_probes_do_not_require_legacy_allocation_supervisor(self):
        value = settings()
        value['translation'] = {'nat64': {'enabled': True}}
        files = config.render(config.normalize(value), access_backend='tun')
        plan = json.loads(files['usr/share/lanrith/health.json'])
        def command(arguments):
            if arguments[:2] == ['systemctl', 'is-active']: return 'active'
            addresses = next(item['addresses'] for item in plan['interfaces'] if item['name'] == arguments[-1])
            return json.dumps([{'addr_info': [{'local': address} for address in addresses]}])
        def read(path, maximum):
            return files[str(path).lstrip('/')].encode()
        with patch.object(boot_health, 'read', side_effect=read), patch.object(boot_health, 'command', side_effect=command), \
                patch.object(translation_runtime, 'status') as native, patch.object(nat64_runtime, 'status') as legacy:
            boot_health.check(plan)
            self.assertEqual([call.args[0]['interface'] for call in native.call_args_list], ['nat64', 'nat64-internal'])
            legacy.assert_not_called()
            for invalid in (False, 1, 'native'):
                with self.subTest(invalid=invalid), self.assertRaises(ReleaseError):
                    boot_health.check({**plan, 'native_translation': invalid})


if __name__ == '__main__':
    unittest.main()
