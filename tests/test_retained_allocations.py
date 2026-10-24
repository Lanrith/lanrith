"""Reviewed migration identities must reach the image and its provenance."""

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import yaml

from lanrith import build, cli, config
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['translation'] = {'nat64': {'enabled': True}}
    value['access']['rules'] = [{
        'action': 'allow', 'from': {'addresses': 'fd42:1234:5678:10::84'},
        'to': {'translation': 'nat64'}, 'authorization': 'owner'}]
    return value


class RetainedAllocationTests(unittest.TestCase):
    def test_retained_and_retired_addresses_reach_the_image_without_granting_access(self):
        value = declaration()
        retained = {'fd42:1234:5678:10::84': '10.255.223.132', 'fd42:1234:5678:10::85': '10.255.223.133'}
        files = config.render(value, retained_allocations=retained)
        manifest = json.loads(files['usr/share/lanrith/nat64-internal.json'])
        self.assertEqual(manifest['source_allocations']['reserved'], retained)
        self.assertEqual(manifest['source_allocations']['active'],
                         {'fd42:1234:5678:10::84': '10.255.223.132'})
        self.assertIn('map 10.255.223.133 fd42:1234:5678:10::85', files['etc/tayga-nat64-internal.conf'])
        self.assertEqual(files['etc/nftables.conf'], config.render(value)['etc/nftables.conf'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            result = build.assembly(value, base, root/'image', version='0.1.0', sequence=9,
                                    retained_allocations=retained)
            overlay = root/'image/mkosi.extra'
            self.assertEqual(json.loads((overlay/'usr/share/lanrith/nat64-internal.json').read_text()), manifest)
            self.assertEqual(result['configuration_sha256'],
                             config.effective_digest(value, {}, retained_allocations=retained))
            changed = {**retained, 'fd42:1234:5678:10::84': '10.255.223.134'}
            self.assertNotEqual(result['configuration_sha256'],
                                config.effective_digest(value, {}, retained_allocations=changed))

    def test_disabled_duplicate_and_out_of_pool_bindings_fail_before_writing(self):
        for retained, enabled in (
                ({'fd42:1234:5678:10::84': '10.255.223.132'}, False),
                ({'fd42:1234:5678:10::84': '10.255.200.2'}, True),
                ({'fd42:1234:5678:10::84': '10.255.223.132',
                  'fd42:1234:5678:10::85': '10.255.223.132'}, True)):
            value = declaration()
            value['translation']['nat64']['enabled'] = enabled
            if not enabled:
                value['access']['rules'] = []
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)/'output'
                with self.assertRaises(ReleaseError):
                    config.write(value, output, retained_allocations=retained)
                self.assertFalse(output.exists())

    def test_cli_requires_the_exact_reviewed_input_and_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configuration, snapshot, output = root/'configuration.yaml', root/'allocations.json', root/'output'
            configuration.write_text(yaml.safe_dump(declaration()))
            snapshot.write_text('{"fd42:1234:5678:10::84":"10.255.223.132"}\n')
            arguments = ['render', str(configuration), '--output', str(output),
                         '--translation-allocations', str(snapshot)]
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(arguments), 1)
                self.assertFalse(output.exists())
                self.assertEqual(cli.main(arguments+['--translation-allocations-sha256', '0'*64]), 1)
                self.assertFalse(output.exists())
                digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                self.assertEqual(cli.main(arguments+['--translation-allocations-sha256', digest]), 0)
                original = (output/'usr/share/lanrith/nat64-internal.json').read_bytes()
                snapshot.write_text('{"x":"one","x":"two"}')
                digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                self.assertEqual(cli.main(arguments+['--translation-allocations-sha256', digest]), 1)
                self.assertEqual((output/'usr/share/lanrith/nat64-internal.json').read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
