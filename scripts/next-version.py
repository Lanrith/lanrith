#!/usr/bin/env python3
"""Choose the next patch version without overwriting a published tag."""
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
result = subprocess.run(['gh', 'api', 'repos/'+os.environ['GITHUB_REPOSITORY']+'/releases?per_page=100'],
                        check=True, capture_output=True, text=True)
published = [version(item['tag_name'][1:]) for item in json.loads(result.stdout)
             if not item['draft'] and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['tag_name'])]
if published and desired <= max(published):
    last = max(published)
    desired = (last[0], last[1], last[2]+1)
selected='.'.join(map(str, desired))
Path(os.environ['RUNNER_TEMP']+'/lanrith-version').write_text(selected+'\n')
with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
    stream.write('value='+'.'.join(map(str, desired))+'\n')
