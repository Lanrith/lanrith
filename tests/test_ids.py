"""IDS captures only the selected WAN and grants no forwarding permission."""

import unittest
from pathlib import Path
import tempfile

import yaml

from lanrith import build, config, firewall, ids
from test_intent import minimal


class IDSTests(unittest.TestCase):
    def test_capture_configuration_has_no_inline_or_download_path(self):
        value = minimal()
        value['observability'] = {'ids': {'enabled': True}}
        normalized = config.normalize(value)
        files = ids.render(normalized)
        settings = yaml.safe_load(files['etc/suricata/lanrith.yaml'])
        self.assertEqual(settings['rule-files'], ['suricata.rules'])
        self.assertEqual(settings['default-rule-path'], '/usr/share/lanrith')
        self.assertEqual([entry['interface'] for entry in settings['af-packet']], ['wan'])
        self.assertNotIn('copy-mode', settings['af-packet'][0])
        self.assertNotIn('nfq', settings)
        unit = files['usr/lib/systemd/system/lanrith-ids.service']
        self.assertIn('User=lanrith-ids', unit)
        self.assertIn('CapabilityBoundingSet=CAP_NET_RAW\n', unit)
        self.assertIn('MemoryMax=512M', unit)
        self.assertIn('TasksMax=32', unit)
        before = firewall.render(normalized)
        value['observability']['ids']['enabled'] = False
        disabled = config.normalize(value)
        self.assertEqual(ids.render(disabled), {})
        self.assertEqual(firewall.render(disabled), before)

    def test_enabled_detector_is_an_explicit_boot_health_requirement(self):
        value = minimal()
        value['observability'] = {'ids': {'enabled': True}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            build.assembly(value, base, root/'enabled', version='0.1.0', sequence=9)
            overlay = root/'enabled/mkosi.extra'
            self.assertIn('lanrith-ids.service',
                          (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text())
            self.assertTrue((overlay/'etc/systemd/system/lanrith-ids.service').is_symlink())
            value['observability']['ids']['enabled'] = False
            files = config.render(value)
            self.assertFalse(any('suricata' in name or 'lanrith-ids' in name for name in files))


if __name__ == '__main__':
    unittest.main()
