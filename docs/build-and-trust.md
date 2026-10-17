# Build and trust

There are three distinct authorities: public build provenance, the owner's
boot/verity/manifest certificate, and private deployment evidence. Trust is
supplied independently. Never trust a certificate only because it accompanies
a downloaded image.

Public build jobs run on fresh GitHub-hosted runners without OIDC signing
permissions. The trusted reusable workflow passes immutable artifact IDs to a
fresh attestation job. That job does not check out source, run caller commands,
or execute downloaded artifacts. The publisher receives already-attested
files. The builder is addressed by OCI digest and attested separately. Actions
and tool/source inputs are pinned. Review the
[SLSA assessment](../security/slsa-assessment.json) alongside actual run evidence;
a signature alone does not establish Build L3.

The assessment records every requirement in
[SLSA v1.2](https://slsa.dev/spec/v1.2/build-requirements), including separate
signing authority, fresh hosted jobs, cache isolation and enumerated caller
parameters. Its workflow hashes must match the reviewed files. The native
runner must pass against the exact filesystem and initrd before a hosted
main release can record eligibility. Local and PR builds cannot enable it.
Consumers then verify the signed qualification record, its native subjects
and both file and OCI provenance. This is a project assessment, not a
third-party certification. Current qualification scope is the x86-64 UEFI
VM core with TPM2 and manual state encryption; other hardware and enabled
advanced integrations require their own qualification.

After changing a release workflow, reassess its controls and update the hashes
in `security/slsa-assessment.json`. A stale assessment blocks publication.

GitHub Actions caching saves package-builder images with BuildKit's inline
cache metadata, plus up to 4 GiB of Alloy compiler objects. It does not retain
owner inputs, signing keys, test VMs, filesystem output or security reports.
Each compressed cache handoff is limited to 5 GiB; cache storage remains subject
to GitHub's repository quota and eviction policy. No paid storage is enabled by
the workflow. The first build and an evicted cache require a full build.

The cache service is an untrusted download source. A separate runner restores
its archive and forwards only opaque files by immutable artifact ID. The fresh
build VM verifies both cache subjects with GitHub/Sigstore provenance, requiring
this repository, hosted runners, `main`, and the exact source and signer commit.
It independently checks the producer's Python code, container recipes, Alloy
source definitions and workflows against GitHub's source tree. A signature from
an incompatible historical workflow is insufficient. Cached Docker imports can
create only the selected Lanrith tags; they cannot replace pinned base images.

An image with the same complete input identity is reused directly. BuildKit
matches other available image layers against their build inputs. Alloy compiler reuse
also requires identical reviewed source definitions and a fingerprint of the
installed tools, headers, C libraries, loader configuration and symlink choices.
The compiler key also includes the reviewed Debian, Go and Node OCI digests;
a different base cannot substitute matching probe output.
A new Debian snapshot can reuse compiler data when those actual bytes remain
identical. A compiler, library or Alloy source change forces the affected work
to rebuild. Source checkouts and dependency verification remain fresh. Alloy's
behavior tests use `-count=1` so a compiler cache cannot suppress test execution.

Package compilation runs without privileged containers on its own VM. It seals
and uploads package and cache data by immutable artifact ID. Image assembly and
VM qualification run on a different fresh VM, which cannot change the compiler
job's artifact or its control-plane output. The attestation job receives cache
data directly from the compiler job, and signs it only after production
qualification succeeds. It then saves that authenticated data to Actions caching.
Build jobs have no cache-write capability; PRs receive read-only cache access
and cannot publish cache entries. Every release still assembles new filesystems,
fetches current vulnerability data, scans the actual binaries, runs native
boot and update qualification, and signs the resulting subjects independently.
Missing, corrupt, unverifiable or unavailable cache data causes a clean build.
Cache export failure does not block an otherwise qualified release.

The manual Package qualification workflow accepts `cold_build: true` to ignore
cross-run data. Use it to compare a clean qualification with a warm run. The
release's `build-cache.json` records cache admission, and Alloy evidence records
whether its compiler cache was used. Cache hits alone are not a performance
measurement; compare completed hosted runs before reporting a time saving.

`platform.lock` pins the Lanrith repository, release, source commit, signer
workflow commit, security workflow commit, manifest, all selected files and the
matching builder digest. `gh attestation verify` enforces the repository,
trusted workflow, exact source/signer commits, GitHub OIDC issuer and hosted
runners. Replacing a mutable tag does not replace those trusted bytes.

Alloy is built with its complete component registry, embedded UI and matching
Beyla source. Reviewed dependency patches, supported compiler versions and
unstripped Go symbols keep the binary scanner's coverage precise. The embedded
Beyla executable is retained outside the router filesystem as an independent
scan subject. Packaging and base admission both verify its digest and unique
byte range inside the actual Alloy executable. The deployed image contains
one embedded Beyla payload; it does not need a duplicate scan-only executable. UI, Cargo,
Java and upstream-source advisory checks supplement Go and Debian coverage.
The SBOM records these dependency graphs; package notices retain upstream
licenses, including any reviewed correction for an omitted archive notice.

Daily proposals refresh immutable Debian snapshots, qualified components and
supported toolchain patches. Upstream source candidates appear in
`docs/upstream-proposals.json`; their patches and behavior need review before
the selected source revision changes. Proposals do not merge themselves or
grant security exceptions. A source branch that is no longer supported blocks
the resolver until its migration is reviewed.

The Debian proposal uses the current UTC hour so security fixes do not wait for
the next day's snapshot. Missing archive metadata blocks the proposal. For a
focused security update, use `scripts/refresh-inputs.py --debian-only --snapshot
YYYYMMDDTHHMMSSZ`; this retains component and toolchain selections. Future and
backwards snapshot proposals are rejected. The build still authenticates the
archive signatures and assesses the actual installed package inventory before
an image can be published.

The proposal job uses a GitHub App installed only on this repository, with
Contents and Pull requests read/write access and no protection bypass. Store
its numeric App ID as `LANRITH_UPDATE_APP_ID` and its existing private key as
`LANRITH_UPDATE_APP_PRIVATE_KEY` in the `lanrith-updates` environment. Restrict
that environment to protected `main`; it contains no image-signing authority.
The action requests a short-lived token for this repository only. App-authored
proposals trigger normal PR checks and still need an independent review.
Keep default workflow permissions read-only and GitHub's shared option to
create and approve PRs disabled. Missing App credentials block proposals
clearly; they do not weaken protection or silently skip security updates.

Admission also requires complete current scanner coverage, an inventory-bound
successful assessment within 24 hours, no selected revoked digest, and passing
native and SLSA qualification. Retained releases are rescanned independently.
Missing success after 48 hours triggers the watchdog. Unavailable or malformed
advisory data fails closed; it is not a clean scan.

Debian packages resolve from the reviewed immutable archive snapshot and use
the authenticated archive's actual source versions for backport checks. Custom
packages have separate exact source and artifact pins. Avoid treating ordinary
archive packages as local overrides: that would freeze security revisions and
misidentify the source examined by the vulnerability gate.

Owner builds run network and provenance checks before keys are materialized.
Assembly runs offline in the admitted builder with keys in private tmpfs.
Compiler inputs cannot install packages or execute owner hooks. GitHub owner
boot signing and evidence signing use separate protected environments and
keys. The evidence job validates the owner signature and request identities
without executing an image or builder. Its DSSE SLSA statement remains private;
no public transparency log is used by default.

For a local build, authenticate the compiler using the release's pinned file
provenance. Download the platform files and their verification bundles into
`platform/`. Install GitHub CLI and rootless Podman (or select `--engine docker`).
Use existing keys from your established secret-management process:

```sh
python3 scripts/build-local.py preflight \
  --owner /private/config --platform /private/platform \
  --request /private/build-request.json --sequence 1

python3 scripts/build-local.py assemble \
  --owner /private/config --platform /private/platform \
  --request /private/build-request.json \
  --work /private/work --output /private/release \
  --boot-certificate /private/owner.crt --boot-key /private/owner.key
```

Review the exact request before assembly. If serial administration is enabled,
supply `--serial-hash /private/serial.hash` to both commands. The hash is bound
to the request; pass only its path. Preflight authenticates the files, security
qualification and OCI builder. Assembly repeats those checks before reading
keys, snapshots owner inputs, then runs mkosi with networking disabled. It
retains independently verified `update/` and `factory/` directories. Keep the
workspace private: it contains the effective owner configuration.

Signing uses private tmpfs and an owned container. Cleanup stops that container
before removing keys; an unavailable container engine retains the owned tmpfs
for recovery. The local path does not claim hosted SLSA qualification for the
owner image. Public platform provenance remains independently verified. Use a
separate owner evidence authority for any deployment-evidence signing.

Local signing is appropriate when repository or environment protections cannot
be enforced. Do not put keys, hashes, credentials or private configuration into
a public repository, command arguments or CI logs.

The template checks actual private-repository and environment capabilities.
It does not assume GitHub Enterprise. Public keyless owner provenance would
expose repository identity and is outside the default private workflow.

The Debian appliance installs only explicit packages and their required
dependencies (`WithRecommends=no`). Build tools stay in the separate builder:
UKI creation, EROFS creation and container tools are not runtime requirements.
The deployed storage formats are EROFS, ext4 and FAT; Btrfs and alternative
partition editors are omitted. Runtime disk installation and recovery retain
`systemd-repart`, `sfdisk`, filesystem checks and encryption tools.

Finalization removes package caches and databases, package-manager executables,
manuals, examples, translations, Python bytecode caches and unused legacy
initramfs files. Copyright, license and third-party notices remain, as do the
C.UTF-8 locale, kernel modules, firmware supplied by the selected package set,
and operational diagnostics. Full supported router services remain installed
and inactive until selected; minimization does not remove optional features.
Authenticated APT metadata, inventories and scan subjects are release evidence
outside the deployed filesystem. The inventory describes the installed package
closure before file pruning; `image-footprint.json` records payload pruning.
Package and filesystem gates reject build tools and scan-only payloads, and
native qualification tests the pruned image before publication.

Debian's `freeradius-config` requires `make` to generate example certificates
during package installation. The package inventory retains that dependency,
but finalization removes the Make executable. Enabled RADIUS integrations
supply their own reviewed credentials; they do not generate shared example
certificates on the router. The filesystem gate checks this distinction.
