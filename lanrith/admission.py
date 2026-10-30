"""Admission distinguishes authenticated inputs from production qualification."""

import datetime
import json

from .release import file_record, read, require, unique


def assess(directory, selection, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    value = json.loads(read(directory/'security.json', 4*1024*1024), object_pairs_hook=unique)
    require(value.get('schema') == 1 and value.get('inventory_sha256') == selection['files'].get('inventory.json') and
            file_record(directory/'inventory.json')['sha256'] == value['inventory_sha256'],
            'Security assessment does not describe the admitted inventory.')
    fresh = value
    if (directory/'security-assessment.json').exists():
        fresh = json.loads(read(directory/'security-assessment.json', 4*1024*1024), object_pairs_hook=unique)
        require(fresh.get('schema') == 1 and fresh.get('inventory_sha256') == value['inventory_sha256'] and
                fresh.get('result') == 'pass', 'The retained platform failed its current security assessment.')
        require(not set(selection['files'].values()) & set(fresh.get('revoked_sha256', [])),
                'A selected platform artifact has been revoked.')
    assessed = datetime.datetime.fromisoformat(fresh['assessed_at'])
    require(assessed.tzinfo is not None and datetime.timedelta(0) <= now-assessed <= datetime.timedelta(hours=24),
            'Platform security assessment is stale or future-dated.')
    require(value.get('production_qualified') is True, 'Platform is a qualification build, not a supported production release.')
    require(value.get('slsa_build_level') == 3 and value.get('slsa_spec') == '1.2' and
            value.get('qualification', {}).get('result') == 'pass',
            'Platform lacks the required SLSA and native qualification assessment.')
    record = json.loads(read(directory/'qualification.json', 4*1024*1024), object_pairs_hook=unique)
    require(record.get('schema') == 1 and record.get('result') == 'pass' and
            record.get('specification') == 'SLSA v1.2' and record.get('build_level') == 3 and
            record.get('source_commit') == selection['source_commit'] and
            record.get('workflow') == 'Lanrith/lanrith/.github/workflows/build-base.yml' and
            record.get('runner_environment') == 'github-hosted' and
            file_record(directory/'qualification.json')['sha256'] ==
            value['qualification'].get('record_sha256') == selection['files'].get('qualification.json'),
            'Platform qualification is not bound to its authenticated source and build platform.')
    for field, name in (('native_sha256', 'native-qualification.json'),
                        ('storage_sha256', 'storage-qualification.json'),
                        ('logs_sha256', 'logs-qualification.json'),
                        ('directory_sha256', 'directory-qualification.json'),
                        ('credentials_sha256', 'credential-qualification.json'),
                        ('filesystem_sha256', 'lanrith-base.tar.gz'),
                        ('initrd_sha256', 'lanrith-initrd-base.tar.gz')):
        require(record.get(field) == selection['files'].get(name) == file_record(directory/name)['sha256'],
                'Qualification describes different artifacts or native evidence.')
    native = json.loads(read(directory/'native-qualification.json', 4*1024*1024), object_pairs_hook=unique)
    require(native.get('result') == 'pass' and native.get('filesystem_sha256') == record['filesystem_sha256'] and
            native.get('initrd_sha256') == record['initrd_sha256'], 'Native evidence does not describe this base.')
    return value
