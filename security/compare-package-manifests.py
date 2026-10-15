#!/usr/bin/env python3
"""Compare the Debian package records in two mkosi JSON manifests."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def package_records(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as stream:
        document = json.load(stream)
    records = document.get("packages")
    if not isinstance(records, list) or not records:
        raise SystemExit("Package manifest has no package records.")
    return sorted(json.dumps(record, sort_keys=True, separators=(",", ":"))
                  for record in records)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: compare-package-manifests.py PUBLIC SIGNED")
    if package_records(Path(sys.argv[1])) != package_records(Path(sys.argv[2])):
        raise SystemExit("Signed package manifest differs from the audited public package set.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
