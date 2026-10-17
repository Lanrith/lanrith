#!/usr/bin/env python3
"""Emit the cache lookup hint; it never authorizes cached content."""

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.build_cache import key

value = key(Path(__file__).resolve().parents[1])
with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
    output.write('key='+value+'\n')
