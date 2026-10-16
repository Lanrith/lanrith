"""Media read-back preserves partition identity after GPT backup relocation."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import media, release
from lanrith.release import ReleaseError


class MediaTests(unittest.TestCase):
    def test_readback_checks_partition_bytes_then_admits_complete_media_with_independent_trust(self):
        original = {'label':'gpt','id':'synthetic-disk','sectorsize':512,
                    'partitions':[{'start':1,'size':1,'type':'synthetic-root','uuid':'synthetic-root-id'}]}
        written = copy.deepcopy(original)
        written['partitions'].append({'start':3,'size':1,'name':'lanrith-factory-media',
            'type':'0FC63DAF-8483-4772-8E79-3D69D8477DE4','uuid':'SYNTHETIC-PAYLOAD-ID'})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target, certificate = root/'factory.raw', root/'target.raw', root/'controller.crt'
            source.write_bytes(b'x'*1024)
            target.write_bytes(source.read_bytes()+b'y'*1024)
            manifest = {'artifacts':[{'role':'disk','name':'factory.raw'}], 'image_id':'lanrith',
                        'platform_version':'0.1.0','configuration_sha256':'a'*64}
            def command(*args):
                if args[0] == 'sfdisk':
                    return json.dumps({'partitiontable':original if args[-1] == str(source) else written})
                if args[0] == 'lsblk':
                    return json.dumps({'blockdevices':[{'type':'part','partuuid':'synthetic-payload-id',
                                                       'name':'/dev/synthetic-payload'}]})
                return ''
            with patch.object(media, 'command', side_effect=command) as calls, \
                    patch.object(release, 'verify', autospec=True, return_value=manifest) as admit:
                media.verify(str(target), root, certificate, manifest)
                self.assertEqual(admit.call_args.kwargs['expected_configuration'], 'a'*64)
                self.assertEqual(admit.call_args.args[1], certificate)
                self.assertTrue(any(call.args[:3] == ('mount','-o','ro,noload,nodev,nosuid,noexec')
                                    for call in calls.call_args_list))
                admit.reset_mock()
                with target.open('r+b') as stream:
                    stream.seek(512)
                    stream.write(b'tampered')
                with self.assertRaises(ReleaseError):
                    media.verify(str(target), root, certificate, manifest)
                admit.assert_not_called()

    def test_partition_mutation_overlap_and_extra_partition_rejected(self):
        original = {'label': 'gpt', 'id': 'synthetic-disk', 'sectorsize': 512,
                    'partitions': [{'start': 2048, 'size': 4096, 'type': 'synthetic-root', 'uuid': 'synthetic-root-id'}]}
        written = copy.deepcopy(original)
        written['lastlba'] = 100000
        written['partitions'].append({'start': 8192, 'size': 4096, 'name': 'lanrith-factory-media',
            'type': '0fc63daf-8483-4772-8e79-3d69d8477de4', 'uuid': 'synthetic-media-id'})
        self.assertEqual(media.partitions(original, written)[0], original['partitions'])
        uppercase = copy.deepcopy(written)
        uppercase['partitions'][-1]['type'] = uppercase['partitions'][-1]['type'].upper()
        self.assertEqual(media.partitions(original, uppercase)[0], original['partitions'])
        for change in ('uuid', 'start', 'size', 'type'):
            value = copy.deepcopy(written)
            value['partitions'][0][change] = 1 if change in ('start', 'size') else 'changed'
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                media.partitions(original, value)
        value = copy.deepcopy(written)
        value['partitions'][-1]['start'] = 4096
        with self.assertRaises(ReleaseError):
            media.partitions(original, value)
        with self.assertRaises(ReleaseError):
            media.partitions(original, {**written, 'partitions': written['partitions']*2})
