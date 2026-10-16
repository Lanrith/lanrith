"""Persistence checks follow Kea's logical lease records through file cleanup."""

import csv
from pathlib import Path
import tempfile
import unittest

from vm import lease_snapshot


class LeasePersistenceTests(unittest.TestCase):
    def row(self, **changes):
        return {'address':'192.0.2.123','hwaddr':'02:00:00:00:02:01','client_id':'',
                'valid_lifetime':'3600','expire':'4102444800','subnet_id':'1',
                'fqdn_fwd':'0','fqdn_rev':'0','hostname':'synthetic','state':'0',
                'user_context':'','pool_id':'0'} | changes

    def write(self, path, rows, *, legacy=False):
        fields=list(self.row())
        if legacy:
            fields.remove('pool_id')
        with path.open('w', newline='') as stream:
            writer=csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore', lineterminator='\n')
            writer.writeheader()
            writer.writerows(rows)

    def test_schema_migration_and_file_rotation_preserve_the_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'leases.csv'
            self.write(path,[self.row()],legacy=True)
            before=lease_snapshot(path)
            self.write(Path(str(path)+'.2'),[self.row()])
            self.write(path,[])
            self.assertEqual(lease_snapshot(path),before)
            self.assertEqual(before,{'192.0.2.123':self.row()})

    def test_completed_generation_supersedes_inputs_and_current_updates_win(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'leases.csv'
            self.write(Path(str(path)+'.2'),[self.row(hostname='obsolete')])
            self.write(Path(str(path)+'.1'),[self.row(hostname='also-obsolete')])
            self.write(Path(str(path)+'.completed'),[self.row(hostname='completed')])
            self.write(path,[])
            self.assertEqual(lease_snapshot(path)['192.0.2.123']['hostname'],'completed')
            self.write(path,[self.row(hostname='current')])
            self.assertEqual(lease_snapshot(path)['192.0.2.123']['hostname'],'current')

    def test_missing_changed_and_deleted_leases_cannot_match_the_original_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'leases.csv'
            self.write(Path(str(path)+'.2'),[self.row()])
            self.write(path,[])
            before=lease_snapshot(path)
            self.write(path,[self.row(valid_lifetime='0')])
            self.assertEqual(lease_snapshot(path),{})
            self.assertNotEqual(lease_snapshot(path),before)
            self.write(path,[self.row(hwaddr='02:00:00:00:02:02')])
            self.assertNotEqual(lease_snapshot(path),before)

    def test_incomplete_and_unknown_rows_fail_instead_of_disappearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'leases.csv'
            self.write(path,[self.row()])
            valid=path.read_text()
            for value in ('address\n192.0.2.123\n', valid+'broken,row\n',
                          valid.replace(',3600,',',invalid,')):
                with self.subTest(value=value):
                    path.write_text(value)
                    with self.assertRaises(ValueError):
                        lease_snapshot(path)
