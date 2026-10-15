#!/usr/bin/python3
"""Fail unless an mkosi JSON package manifest meets the release policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn

SCANNER_VERSION = "2"


def fail(message: str) -> NoReturn:
    print(f"Package-manifest gate failed: {message}", file=sys.stderr)
    raise SystemExit(65)


def regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        fail(f"missing file: {path}")
    if not stat.S_ISREG(mode):
        fail(f"not a regular file: {path}")


def load_json(path: Path) -> dict[str, object]:
    regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    return value


def string_map(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            fail(f"{label} must map strings to strings")
        result[key] = item
    return result


def string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        fail(f"{label} must be an array of strings")
    return list(value)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exclusive_text_file(path: Path, label: str):
    if path.exists() or path.is_symlink():
        fail(f"refusing to overwrite {label}")
    if not path.parent.is_dir() or path.parent.is_symlink():
        fail(f"{label} directory is unsafe")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    return os.fdopen(descriptor, "w", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--status", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    policy = load_json(args.policy)
    if policy.get("schema_version") != 1:
        fail("unsupported policy schema")
    if manifest.get("manifest_version") != 1:
        fail("unsupported mkosi manifest schema")

    expected_image = string_map(policy.get("image"), "image")
    config = manifest.get("config")
    if not isinstance(config, dict):
        fail("manifest config is missing")
    for field, expected in expected_image.items():
        if config.get(field) != expected:
            fail(f"manifest config {field!r} is not {expected!r}")
    if config.get("version") != args.release:
        fail("manifest release version does not match the artifact directory")

    raw_packages = manifest.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        fail("manifest package list is empty")
    packages: dict[str, str] = {}
    for entry in raw_packages:
        if not isinstance(entry, dict):
            fail("manifest contains a non-object package entry")
        if entry.get("type") != "deb":
            fail("manifest contains a non-Debian package")
        name = entry.get("name")
        version = entry.get("version")
        architecture = entry.get("architecture")
        if not all(isinstance(item, str) and item for item in (name, version, architecture)):
            fail("manifest contains an incomplete package entry")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name):
            fail(f"manifest contains an invalid package name {name!r}")
        if "\n" in version or "\r" in version:
            fail(f"manifest contains an invalid version for {name!r}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture):
            fail(f"manifest contains an invalid architecture for {name!r}")
        if name in packages:
            fail(f"manifest contains duplicate package name {name!r}")
        packages[name] = version

    required_exact = string_map(
        policy.get("required_exact_packages"), "required_exact_packages"
    )
    for name, expected_version in required_exact.items():
        if packages.get(name) != expected_version:
            fail(f"{name} is not exactly version {expected_version}")

    required = string_list(policy.get("required_packages"), "required_packages")
    for name in required:
        if name not in packages:
            fail(f"required package {name!r} is absent")

    forbidden = string_list(policy.get("forbidden_packages"), "forbidden_packages")
    for name in forbidden:
        if name in packages:
            fail(f"forbidden package {name!r} is present")

    suffixes = string_list(
        policy.get("forbidden_package_suffixes"), "forbidden_package_suffixes"
    )
    for name in packages:
        if any(name.endswith(suffix) for suffix in suffixes):
            fail(f"debug package {name!r} is present")

    regular_file(args.manifest)
    regular_file(args.policy)
    status = {
        "schema_version": 1,
        "result": "pass",
        "scanner": "lanrith-package-manifest",
        "scanner_version": SCANNER_VERSION,
        "scanner_sha256": sha256(Path(__file__)),
        "release": args.release,
        "package_count": len(packages),
        "manifest_sha256": sha256(args.manifest),
        "policy_sha256": sha256(args.policy),
        "required_exact_packages": required_exact,
    }
    with exclusive_text_file(args.status, "package-policy status") as stream:
        json.dump(status, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"Package-manifest gate passed for {len(packages)} packages.")


if __name__ == "__main__":
    main()
