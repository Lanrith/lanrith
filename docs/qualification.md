# Qualification

A source check or passing parser test does not qualify a deployment. Every
production release needs evidence tied to its exact source, workflow, builder,
package inventory, artifacts and profile.

| Gate | Required evidence |
| --- | --- |
| Public boundary | Reviewed source export; no owner topology, policy, identities, secrets, state or private history |
| Packages | Complete inventory/SBOM, source/backport policy, current Debian and custom-source/binary coverage |
| Assembly | Matching mkosi BaseTrees and initrd; offline signed final tree; identities and native unit transaction |
| Hardware | x86-64 VM and each claimed physical profile; NIC selectors, disk budgets, TPM/manual encryption, console |
| Boot | Owner Secure Boot trust, valid dm-verity, encrypted persistent state and acknowledged offline recovery |
| Privilege boundary | Direct root login denied; administrator elevation reauthenticated; root-only controls denied to administrator-before-elevation and every service identity |
| Factory | Wrong trust, mismatched payload, ambiguous/mounted target and interrupted installation rejection; read-back |
| Network | Two unrelated synthetic topologies; explicit administration, default deny, DHCP/RA/DNS, optional services off |
| Advanced integration | Routing, translation, policy enforcement, discovery, directory, telemetry and acceleration tests for enabled profiles |
| Updates | Valid upgrade, inactive-slot protection, tamper/replay rejection, interrupted staging and UKI-last publication |
| Acceptance | Fresh counted boot, health, stable entry, explicit default promotion and automatic failed-candidate fallback |
| State | Existing leases, journals, credentials, enrollment, SSH identity and owner-specific state survive upgrade and rollback |
| Provenance | Verified file/OCI subjects, exact identities and requirement-by-requirement SLSA v1.2 Build L3 assessment |
| Automation | Reviewed input proposal, merged build, retained rescan, signing failure and watchdog failure exercised |

Qualification prereleases remain ineligible for production until these gates
pass. Private owner topologies and their evidence stay in the owner's repository.
Do not transplant qualification claims from an earlier repository or release.

`tests/packets.py` exercises the generated firewall using real IPv4 and IPv6
connections in disposable namespaces. It checks management access, unsolicited
uplink traffic, inter-network isolation, directional port grants, disabled
service ports, spoof rejection, NAT44 and IPv6 source preservation. These
results cover the generic compiler policy. Advanced integrations and physical
hardware still need their own candidate-specific tests.

`tests/storage.py` creates a signed synthetic EROFS image and expands it with
the matching builder's `systemd-repart`. It verifies that the second slot and
state appear without moving or changing signed data, hashes or signatures.
It uses regular files and a disposable test authority. TPM and encrypted-state
boot behavior remain separate qualification requirements.

`tests/vm.py` is the native UEFI qualification runner used by the full base
build. It creates regular-file disks, a disposable TPM, its own SSH agent and
a test signing authority in tmpfs. Restricted guest networking permits only
loopback administration. It exercises installation read-back, Secure Boot,
verity, TPM and manual state encryption, recovery acknowledgment, SSH/PAM,
automatic boot observation and inactive optional services,
one-shot updates, explicit acceptance, replay and tamper rejection,
interrupted staging, failed-health fallback and populated state. Only the
bounded JSON result is retained publicly; test disk images, recovery keys,
serial transcripts and test credentials are not release artifacts. Adding
this runner does not establish a passing result: the actual candidate must
complete it before production admission can be enabled.

The root boundary and its residual risk are defined in `security-model.md`.
Native qualification's `unprivileged-control-boundary` check exercises the
administrator without a forwarded credential and all installed non-root
accounts. Root policy mutation is a positive control on a disposable clone,
not a promise that the running kernel can constrain unrestricted root.
