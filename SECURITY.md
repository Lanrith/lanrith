# Security

Do not publish credentials, private network configuration, exploit details or
private build logs in an issue. Use this repository's **Report a vulnerability**
security advisory form for confidential reports. Include affected release and
artifact digests, reproduction steps and the impact you observed.

Initial OS releases are qualification prereleases and have no production
support claim. Supported production releases will identify their qualified
profiles and evidence. Production admission rejects stale, revoked,
incompletely scanned and unqualified inputs. A signature identifies an
artifact's build or owner authority; it does not certify its configuration.

Dependency updates are proposals requiring review. New advisories trigger
independent retained-release assessment. Boot signing, public provenance and
private deployment evidence use separate trust purposes. See
[build and trust](docs/build-and-trust.md) for verification and
[operations](docs/operations.md) for recovery and rotation.
