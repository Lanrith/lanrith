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
