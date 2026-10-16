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

For a local build, install the authenticated compiler and enter an isolated
matching builder using your established secret-management process:

```sh
python3 -m lanrith build config.yaml \
  --base platform/lanrith-base.tar.gz \
  --initrd-base platform/lanrith-initrd-base.tar.gz \
  --platform-lock platform.lock --platform-bundle platform \
  --workspace work --output update --version 0.1.0 --sequence 1 \
  --certificate /private/owner.crt --key /private/owner.key
```

Authenticate the compiler and builder before invoking this command. Local
signing is appropriate when repository or environment protections cannot be
enforced. Do not put keys, hashes, credentials or private configuration into a
public repository, command arguments or CI logs.

The template checks actual private-repository and environment capabilities.
It does not assume GitHub Enterprise. Public keyless owner provenance would
expose repository identity and is outside the default private workflow.
