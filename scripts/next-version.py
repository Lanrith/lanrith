#!/usr/bin/env python3
"""Choose a patch version without reusing published or draft reservations."""
import json
import os
from pathlib import Path
import re
import subprocess

def version(text):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', text):
        raise ValueError('Invalid version')
    return tuple(map(int, text.split('.')))

desired = version(Path('VERSION').read_text().strip())
result = subprocess.run(['gh', 'api', '--paginate', '--slurp',
                        'repos/'+os.environ['GITHUB_REPOSITORY']+'/releases?per_page=100'],
                        check=True, capture_output=True, text=True)
pages = json.loads(result.stdout)
if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
    raise ValueError('Published release enumeration is malformed.')
releases = [item for page in pages for item in page
            if re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['tag_name'])]
published = [version(item['tag_name'][1:]) for item in releases if not item['draft']]
if published and desired <= max(published):
    last = max(published)
    desired = (last[0], last[1], last[2]+1)
# A partial upload can leave an unpublished draft tied to another source.
# Preserve that reservation and its evidence. Future-major drafts must not
# move this build to another release series before that series is published.
reserved = [version(item['tag_name'][1:]) for item in releases
            if version(item['tag_name'][1:])[:2] == desired[:2]]
if reserved and desired <= max(reserved):
    last = max(reserved)
    desired = (last[0], last[1], last[2]+1)
selected='.'.join(map(str, desired))
Path(os.environ['RUNNER_TEMP']+'/lanrith-version').write_text(selected+'\n')
with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
    stream.write('value='+'.'.join(map(str, desired))+'\n')
print(f'Selected {selected}; checked {len(published)} published versions and {len(reserved)} reservations in this release series.')
