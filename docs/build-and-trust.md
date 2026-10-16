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

`platform.lock` pins the Lanrith repository, release, source commit, signer
workflow commit, security workflow commit, manifest, all selected files and the
matching builder digest. `gh attestation verify` enforces the repository,
trusted workflow, exact source/signer commits, GitHub OIDC issuer and hosted
runners. Replacing a mutable tag does not replace those trusted bytes.

Alloy is built with its complete component registry, embedded UI and matching
Beyla source. Reviewed dependency patches, supported compiler versions and
unstripped Go symbols keep the binary scanner's coverage precise. The embedded
Beyla executable is also retained as an independent scan subject. UI, Cargo,
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
