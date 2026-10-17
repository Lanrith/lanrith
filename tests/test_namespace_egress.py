"""Declared service identities constrain namespace address and proxy cleanup."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NamespaceEgressTests(unittest.TestCase):
    def exercise(self, service, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root/'commands.jsonl'
            ip = root/'ip'
            ip.write_text('''#!/usr/bin/python3
import json,os,sys
a=sys.argv[1:]
with open(os.environ['SYNTHETIC_COMMAND_LOG'],'a') as f: f.write(json.dumps(a)+'\\n')
if a==['netns','list']: print('services')
elif 'address' in a and 'show' in a:
 print('1: lo inet6 2001:db8:abc:1::2a/128 scope global')
 print('1: lo inet6 2001:db8:abc:1::2b/128 scope global')
elif 'neigh' in a and 'show' in a:
 print('2001:db8:abc:1::2a dev uplink proxy')
 print('2001:db8:abc:1::2b dev uplink proxy')
elif 'route' in a and 'show' in a: print('2001:db8:abc:1::/64 via fd00::2')
''')
            ip.chmod(0o755)
            sysctl = root/'sysctl'
            sysctl.write_text('#!/bin/sh\nprintf "1\\n"\n')
            sysctl.chmod(0o755)
            profile = root/'profile.sh'
            profile.write_text('''lanrith_wan_mode='''+mode+'''
lanrith_service_namespace=services
lanrith_service_host_link=svc-host
lanrith_service_namespace_link=svc-peer
lanrith_service_ipv6_namespace_address=fd00::2
lanrith_service_ipv6_host_address=fd00::1
lanrith_wan_interface=uplink
lanrith_unbound_service_id=2a
lanrith_chrony_service_id=2b
lanrith_service_ipv6_cleanup_prefix=2001:db8:abc
lanrith_unbound_static_address=2001:db8:abc:2::2a/128
lanrith_unbound_static_prefix=2001:db8:abc:2::/64
lanrith_chrony_static_address=2001:db8:abc:2::2b/128
lanrith_service_gua_prefix() { printf '2001:db8:abc:2::/64\\n'; }
lanrith_service_gua_service_address() { printf '2001:db8:abc:2::%s\\n' "$1"; }
''')
            environment = {**os.environ, 'PATH': str(root)+':'+os.environ['PATH'],
                'LANRITH_NETWORK_PROFILE': str(profile), 'SYNTHETIC_COMMAND_LOG': str(log)}
            for action in ('enable', 'disable'):
                script = ROOT/'mkosi/base/mkosi.extra/usr/lib/lanrith'/f'{action}-{service}-network'
                result = subprocess.run(['/bin/sh', str(script)], env=environment, capture_output=True, timeout=15)
                if mode == 'invalid':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(log.exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            if mode == 'invalid':
                return
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            own, other = ('2a','2b') if service == 'unbound' else ('2b','2a')
            mutations = [a for a in commands if any(x in a for x in ('del','replace'))]
            self.assertTrue(any('2001:db8:abc:2::'+own+'/128' in a for a in mutations))
            self.assertFalse(any(any(token.endswith('::'+other) or token.endswith('::'+other+'/128')
                                     for token in a) for a in mutations))
            if mode == 'static':
                self.assertFalse(any('neigh' in a for a in mutations))
            else:
                self.assertTrue(any('neigh' in a and 'del' in a and
                                    '2001:db8:abc:1::'+own in a for a in mutations))

    def test_static_routed_and_delegated_profiles_use_owner_selected_ids(self):
        for service in ('unbound', 'chrony'):
            for mode in ('static', 'routed', 'delegated'):
                with self.subTest(service=service, mode=mode):
                    self.exercise(service, mode)

    def test_unknown_modes_fail_before_network_commands(self):
        for service in ('unbound', 'chrony'):
            with self.subTest(service=service):
                self.exercise(service, 'invalid')
