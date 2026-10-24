#!/usr/bin/python3
"""Gate an mkosi package manifest against Debian's release-aware tracker."""

from __future__ import annotations

import argparse
import collections
import functools
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import NoReturn, TextIO


MAX_APT_METADATA_BYTES = 128 * 1024 * 1024
MAX_TRACKER_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_TRACKER_JSON_BYTES = 128 * 1024 * 1024
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9+.-]+")
ARCHITECTURE_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
SOURCE_RE = re.compile(r"([a-z0-9][a-z0-9+.-]+)(?: \(([^()\s]+)\))?")
BUILT_USING_RE = re.compile(r"([a-z0-9][a-z0-9+.-]+)\s*\(\s*=\s*([^()\s,]+)\s*\)")
KERNEL_PAYLOAD_RE = re.compile(r"linux-image-[0-9][a-z0-9.+~:-]*")
SCANNER_VERSION = "3"


def fail(message: str) -> NoReturn:
    print(f"Debian vulnerability gate failed: {message}", file=sys.stderr)
    raise SystemExit(65)


def regular_file(path: Path, maximum_bytes: int | None = None) -> int:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"missing file: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"not a regular file: {path}")
    if metadata.st_size < 1:
        fail(f"empty file: {path}")
    if maximum_bytes is not None and metadata.st_size > maximum_bytes:
        fail(f"file exceeds the size limit: {path}")
    return metadata.st_size


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, object]:
    regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    return value


def exclusive_text_file(path: Path, label: str) -> TextIO:
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


@functools.lru_cache(maxsize=4096)
def compare_debian_versions(left: str, right: str) -> int:
    """Use dpkg's installed Debian version semantics, with bounded argv calls."""
    if not shutil.which("dpkg"):
        fail("dpkg --compare-versions is unavailable")
    if any(not isinstance(value, str) or not value or any(char.isspace() for char in value)
           for value in (left, right)):
        fail("package version is malformed")
    for operator, result in (("lt", -1), ("gt", 1)):
        try:
            completed = subprocess.run(
                ["dpkg", "--compare-versions", left, operator, right],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"dpkg --compare-versions failed: {error}")
        if completed.returncode == 0:
            return result
        if completed.returncode != 1:
            fail("dpkg --compare-versions returned an invalid status")
    return 0


def version_less(left: str, right: str) -> bool:
    return compare_debian_versions(left, right) < 0


def valid_package_record(entry: object) -> tuple[str, str, str]:
    if not isinstance(entry, dict) or entry.get("type") != "deb":
        fail("manifest contains a non-Debian package entry")
    name = entry.get("name")
    version = entry.get("version")
    architecture = entry.get("architecture")
    if not all(isinstance(item, str) and item for item in (name, version, architecture)):
        fail("manifest contains an incomplete package entry")
    if not PACKAGE_RE.fullmatch(name):
        fail(f"manifest contains an invalid package name {name!r}")
    if "\n" in version or "\r" in version:
        fail(f"manifest contains an invalid version for {name!r}")
    if not ARCHITECTURE_RE.fullmatch(architecture):
        fail(f"manifest contains an invalid architecture for {name!r}")
    return name, version, architecture


def manifest_packages(manifest: dict[str, object], release: str) -> list[tuple[str, str, str]]:
    if manifest.get("manifest_version") != 1:
        fail("unsupported mkosi manifest schema")
    config = manifest.get("config")
    if not isinstance(config, dict) or config.get("version") != release:
        fail("manifest release version does not match the artifact directory")
    entries = manifest.get("packages")
    if not isinstance(entries, list) or not entries:
        fail("manifest package list is empty")
    packages = [valid_package_record(entry) for entry in entries]
    if len({name for name, _, _ in packages}) != len(packages):
        fail("manifest contains duplicate package names")
    return sorted(packages)


def local_sources(policy: dict[str, object]) -> dict[str, tuple[str, str]]:
    raw = policy.get("local_package_sources")
    if not isinstance(raw, dict):
        fail("policy local_package_sources must be an object")
    result: dict[str, tuple[str, str]] = {}
    for package, mapping in raw.items():
        if not isinstance(package, str) or not PACKAGE_RE.fullmatch(package):
            fail("policy contains an invalid local package name")
        if not isinstance(mapping, dict):
            fail(f"local source mapping for {package!r} must be an object")
        source = mapping.get("source")
        version = mapping.get("version")
        if not isinstance(source, str) or not PACKAGE_RE.fullmatch(source):
            fail(f"local source mapping for {package!r} has an invalid source")
        if not isinstance(version, str) or not version or "\n" in version or "\r" in version:
            fail(f"local source mapping for {package!r} has an invalid version")
        result[package] = (source, version)
    return result


def deb822_records(path: Path) -> list[dict[str, str]]:
    regular_file(path, MAX_APT_METADATA_BYTES)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot read APT metadata: {error}")
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_field: str | None = None
    for line in [*lines, ""]:
        if not line:
            if current:
                records.append(current)
                current = {}
            last_field = None
            continue
        if line[0].isspace():
            if last_field is None:
                fail("APT metadata continuation has no field")
            current[last_field] += (" " if current[last_field] else "") + line.strip()
            continue
        name, separator, value = line.partition(":")
        if not separator or not name:
            fail("APT metadata contains a malformed field")
        if name in current:
            fail("APT metadata contains a duplicate field")
        current[name] = value.lstrip()
        last_field = name
    return records


def kernel_payload_version(version: str) -> str:
    if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*-[A-Za-z0-9.+~]+", version):
        fail("signed kernel payload has an invalid Debian version")
    compare_debian_versions(version, version)
    return re.sub(r"\+b[0-9]+$", "", version)


def advisory_source(record: dict[str, str]) -> tuple[str, str]:
    source, version = record["source"], record["source_version"]
    if KERNEL_PAYLOAD_RE.fullmatch(record.get("package", "")):
        payload_version = kernel_payload_version(record.get("version", ""))
        if source.startswith("linux-signed-"):
            # Debian's signing wrapper has its own source version. Its payload's
            # authenticated binary version identifies the underlying linux build.
            # This also covers retained maps without rewriting their signed bytes.
            return "linux", payload_version
        if source != "linux" or version != payload_version:
            fail("kernel payload source does not identify its Linux build")
    return source, version


def source_from_record(record: dict[str, str]) -> tuple[str, str] | None:
    name = record.get("Package")
    version = record.get("Version")
    architecture = record.get("Architecture")
    if not name or not version or not architecture:
        return None
    source_field = record.get("Source")
    if source_field is None:
        if KERNEL_PAYLOAD_RE.fullmatch(name):
            fail("APT kernel metadata is missing its source identity")
        return name, version
    match = SOURCE_RE.fullmatch(source_field)
    if match is None:
        fail(f"APT metadata has an invalid Source field for {name!r}")
    source, source_version = match.groups()
    if KERNEL_PAYLOAD_RE.fullmatch(name) and source.startswith("linux-signed-"):
        entries = [BUILT_USING_RE.fullmatch(entry.strip())
                   for entry in record.get("Built-Using", "").split(",")]
        if not entries or any(entry is None for entry in entries):
            fail("signed kernel metadata has invalid Built-Using provenance")
        linux = [entry.group(2) for entry in entries if entry.group(1) == "linux"]
        if linux != [kernel_payload_version(version)]:
            fail("signed kernel Built-Using does not match its Linux payload version")
    return source, source_version or version


def build_source_map(
    packages: list[tuple[str, str, str]],
    metadata_path: Path,
    local: dict[str, tuple[str, str]],
) -> list[dict[str, str]]:
    available: dict[tuple[str, str, str], set[tuple[str, str]]] = {}
    for record in deb822_records(metadata_path):
        source = source_from_record(record)
        if source is None:
            continue
        key = (record["Package"], record["Version"], record["Architecture"])
        available.setdefault(key, set()).add(source)

    mapped: list[dict[str, str]] = []
    package_names = {name for name, _, _ in packages}
    unknown_local = sorted(set(local) - package_names)
    if unknown_local:
        fail(f"local source policy names absent packages: {', '.join(unknown_local)}")
    for name, version, architecture in packages:
        if name in local:
            source, source_version = local[name]
            provenance = "local-policy"
        else:
            candidates = available.get((name, version, architecture), set())
            if len(candidates) != 1:
                fail(f"APT metadata does not map exactly {name} {version} {architecture}")
            source, source_version = next(iter(candidates))
            provenance = "debian-metadata"
        mapped.append(
            {
                "package": name,
                "version": version,
                "architecture": architecture,
                "source": source,
                "source_version": source_version,
                "provenance": provenance,
            }
        )
    return mapped


def validate_source_map(
    value: dict[str, object],
    packages: list[tuple[str, str, str]],
    release: str,
    manifest_hash: str,
    policy_hash: str,
    local: dict[str, tuple[str, str]],
) -> list[dict[str, str]]:
    if value.get("schema_version") != 1 or value.get("release") != release:
        fail("signed package source map has an invalid identity")
    if value.get("manifest_sha256") != manifest_hash or value.get("policy_sha256") != policy_hash:
        fail("signed package source map does not match its manifest and policy")
    raw_records = value.get("packages")
    if not isinstance(raw_records, list) or len(raw_records) != len(packages):
        fail("signed package source map has an invalid package count")
    records: list[dict[str, str]] = []
    expected = {record for record in packages}
    observed: set[tuple[str, str, str]] = set()
    for raw in raw_records:
        if not isinstance(raw, dict):
            fail("signed package source map contains a non-object entry")
        fields = ("package", "version", "architecture", "source", "source_version", "provenance")
        if set(raw) != set(fields) or not all(isinstance(raw.get(field), str) for field in fields):
            fail("signed package source map contains an incomplete entry")
        package = raw["package"]
        version = raw["version"]
        architecture = raw["architecture"]
        source = raw["source"]
        source_version = raw["source_version"]
        provenance = raw["provenance"]
        if (package, version, architecture) not in expected:
            fail("signed package source map contains an unexpected package")
        if not PACKAGE_RE.fullmatch(source) or not source_version or "\n" in source_version:
            fail(f"signed package source map has an invalid source for {package!r}")
        expected_provenance = "local-policy" if package in local else "debian-metadata"
        if provenance != expected_provenance:
            fail(f"signed package source map has invalid provenance for {package!r}")
        if package in local and (source, source_version) != local[package]:
            fail(f"signed package source map conflicts with local policy for {package!r}")
        observed.add((package, version, architecture))
        records.append({field: raw[field] for field in fields})
    if observed != expected or len(observed) != len(records):
        fail("signed package source map is incomplete or duplicated")
    return sorted(records, key=lambda item: item["package"])


def load_tracker(path: Path) -> tuple[dict[str, object], int, str]:
    compressed_bytes = regular_file(path, MAX_TRACKER_COMPRESSED_BYTES)
    try:
        with gzip.open(path, "rb") as stream:
            raw = stream.read(MAX_TRACKER_JSON_BYTES + 1)
    except (OSError, gzip.BadGzipFile) as error:
        fail(f"cannot decompress Debian tracker data: {error}")
    if len(raw) > MAX_TRACKER_JSON_BYTES:
        fail("decompressed Debian tracker data exceeds the size limit")
    try:
        tracker = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse Debian tracker data: {error}")
    if not isinstance(tracker, dict) or not tracker:
        fail("Debian tracker data must contain a JSON object")
    return tracker, compressed_bytes, sha256(path)


def evaluate(
    records: list[dict[str, str]], tracker: dict[str, object], suite: str
) -> tuple[
    list[tuple[str, str, str, str, str]],
    int,
    collections.Counter[str],
    int,
    int,
]:
    sources: dict[str, str] = {}
    for record in records:
        source, version = advisory_source(record)
        previous = sources.setdefault(source, version)
        if previous != version:
            fail(f"installed binaries disagree on source version for {source!r}")

    actionable: list[tuple[str, str, str, str, str]] = []
    evaluated = 0
    unresolved: collections.Counter[str] = collections.Counter()
    undetermined = 0
    tracked_sources = 0
    for source, installed in sorted(sources.items()):
        raw_cves = tracker.get(source)
        if source == "linux" and not raw_cves:
            fail("Debian tracker does not cover the installed Linux source")
        if raw_cves is None:
            continue
        if not isinstance(raw_cves, dict):
            fail(f"Debian tracker has malformed data for {source!r}")
        tracked_sources += 1
        for cve, raw_details in raw_cves.items():
            if not isinstance(cve, str) or not isinstance(raw_details, dict):
                fail(f"Debian tracker has a malformed record for {source!r}")
            releases = raw_details.get("releases")
            if not isinstance(releases, dict) or suite not in releases:
                continue
            release = releases[suite]
            if not isinstance(release, dict):
                fail(f"Debian tracker has malformed {suite!r} data for {source!r}")
            status = release.get("status")
            if status not in {"open", "resolved", "undetermined"}:
                fail(f"Debian tracker has an unknown status for {source!r} {cve}")
            evaluated += 1
            if status != "resolved":
                urgency = release.get("urgency")
                allowed_urgencies = {
                    "end-of-life",
                    "high",
                    "low",
                    "medium",
                    "not yet assigned",
                    "unimportant",
                }
                if urgency not in allowed_urgencies:
                    fail(f"Debian tracker has an unknown urgency for {source!r} {cve}")
                unresolved[urgency] += 1
                if status == "undetermined":
                    undetermined += 1
                if urgency in {"end-of-life", "high", "medium"}:
                    actionable.append((cve, source, installed, "none", urgency))
                continue
            fixed = release.get("fixed_version", "")
            if not isinstance(fixed, str):
                fail(f"Debian tracker has an invalid fixed version for {source!r} {cve}")
            if fixed and fixed != "0" and version_less(installed, fixed):
                actionable.append((cve, source, installed, fixed, "available-fix"))
    return actionable, evaluated, unresolved, undetermined, tracked_sources


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--tracker", required=True, type=Path)
    parser.add_argument("--tracker-url", required=True)
    parser.add_argument("--status", required=True, type=Path)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--apt-metadata", type=Path)
    source_group.add_argument("--source-map", type=Path)
    parser.add_argument("--source-map-output", type=Path)
    args = parser.parse_args()

    if args.suite != "trixie":
        fail("only the approved trixie suite may be scanned")
    if args.tracker_url != "https://security-tracker.debian.org/tracker/data/json":
        fail("Debian tracker URL is not approved")
    if (args.apt_metadata is None) == (args.source_map_output is not None):
        fail("APT metadata requires one source-map output; audit mode requires neither")

    manifest = load_json(args.manifest)
    policy = load_json(args.policy)
    packages = manifest_packages(manifest, args.release)
    local = local_sources(policy)
    manifest_hash = sha256(args.manifest)
    policy_hash = sha256(args.policy)
    if args.apt_metadata is not None:
        records = build_source_map(packages, args.apt_metadata, local)
    else:
        records = validate_source_map(
            load_json(args.source_map),
            packages,
            args.release,
            manifest_hash,
            policy_hash,
            local,
        )

    tracker, feed_bytes, feed_hash = load_tracker(args.tracker)
    actionable, evaluated, unresolved, undetermined, tracked_sources = evaluate(
        records, tracker, args.suite
    )
    if actionable:
        for cve, source, installed, fixed, reason in actionable:
            if reason == "available-fix":
                detail = f"is older than fixed {fixed}"
            else:
                detail = f"has unresolved Debian urgency {reason}"
            print(f"{cve}: {source} {installed} {detail}", file=sys.stderr)
        fail(
            f"{len(actionable)} installed source-package vulnerabilities violate policy"
        )

    source_map = {
        "schema_version": 1,
        "release": args.release,
        "manifest_sha256": manifest_hash,
        "policy_sha256": policy_hash,
        "packages": records,
    }
    if args.source_map_output is not None:
        with exclusive_text_file(args.source_map_output, "package source map") as stream:
            json.dump(source_map, stream, indent=2, sort_keys=True)
            stream.write("\n")
        source_map_hash = sha256(args.source_map_output)
    else:
        source_map_hash = sha256(args.source_map)

    source_count = len({record["source"] for record in records})
    scanner_hash = sha256(Path(__file__))
    status_lines = [
        "schema_version=2",
        "result=pass",
        f"suite={args.suite}",
        "policy=available-fix-or-high-medium-eol",
        "actionable_findings=0",
        "scanner=lanrith-debian-tracker",
        f"scanner_version={SCANNER_VERSION}",
        f"scanner_sha256={scanner_hash}",
        f"manifest_sha256={manifest_hash}",
        f"policy_sha256={policy_hash}",
        f"binary_package_count={len(records)}",
        f"source_package_count={source_count}",
        f"advisory_source_package_count={len({advisory_source(record)[0] for record in records})}",
        "kernel_advisory_mapping=authenticated-linux-payload-version",
        f"tracked_source_package_count={tracked_sources}",
        f"cves_evaluated={evaluated}",
        f"unresolved_tracker_records={sum(unresolved.values())}",
        f"unresolved_high_urgency={unresolved['high']}",
        f"unresolved_medium_urgency={unresolved['medium']}",
        f"unresolved_low_urgency={unresolved['low']}",
        f"unresolved_unimportant={unresolved['unimportant']}",
        f"unresolved_unassigned={unresolved['not yet assigned']}",
        f"unresolved_end_of_life={unresolved['end-of-life']}",
        f"undetermined_records={undetermined}",
        f"feed_url={args.tracker_url}",
        "feed_compression=gzip",
        f"feed_bytes={feed_bytes}",
        f"feed_sha256={feed_hash}",
        f"source_map_sha256={source_map_hash}",
    ]
    with exclusive_text_file(args.status, "vulnerability status") as stream:
        stream.write("\n".join(status_lines) + "\n")
    print(
        "Debian vulnerability gate passed: "
        f"{len(records)} binary packages, {source_count} source packages, "
        "no installed source package older than an available trixie fix."
    )


if __name__ == "__main__":
    main()
