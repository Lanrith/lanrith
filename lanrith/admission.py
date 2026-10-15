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
    return value
