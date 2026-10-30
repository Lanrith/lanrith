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
| Boot | Owner Secure Boot trust, valid dm-verity, encrypted persistent state, acknowledged offline recovery, read-only-at-rest ESP and bounded updater/blessing write windows |
| Privilege boundary | Direct root login denied; administrator elevation reauthenticated; root-only controls denied to administrator-before-elevation and every service identity |
| Service confinement | Live Unbound, Kea, Chrony and networkd identities match their capability, no-new-privileges and seccomp contracts; unused cron, hostname and alternate SSH units remain masked |
| Fan control (when enabled) | CPU/NIC sensor ownership, calibrated PWM/RPM, full-speed fault/crash fallback, unprivileged loop, sandbox and failed-acceptance checks from [fancontrol.md](fancontrol.md) |
| Factory | Wrong trust, mismatched payload, ambiguous/mounted target and interrupted installation rejection; read-back |
| Network | Two unrelated synthetic topologies; explicit administration, default deny, DHCP/RA/DNS, optional services off |
| Advanced integration | Routing, translation, policy enforcement, discovery, directory, telemetry and acceleration tests for enabled profiles |
| Updates | Valid upgrade, inactive-slot protection, tamper/replay rejection, interrupted staging and UKI-last publication |
| Acceptance | Fresh counted boot, health, stable entry, explicit default promotion and automatic failed-candidate fallback |
| State | Existing leases, journals, credentials, enrollment, SSH identity and owner-specific state survive upgrade and rollback |
| Resource and fault handling | Full blocks and inodes, bounded memory/tasks/descriptors and network-state tables, malformed state, service restarts, and backward/forward clock changes |
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

`tests/logs_native.py` qualifies the selected Alloy binary in an offline
namespace. It imports a synthetic systemd journal, checks redaction and
self-log exclusion, exceeds the production 64 MiB logical queue, kills and
restarts the exporter, then verifies delivery to an authenticated HTTPS
collector with a disposable CA. Overflow rejects records; this test does not
promise lossless delivery. Physical queue storage has a separate tested bound
of 160 MiB. The result records the binary and implementation digests and is a
required, provenance-bound input to base qualification and consumer admission.

The generated `alloy.service` uses notify readiness and a watchdog. Its
supervisor requires every root graph component to be healthy before reporting
readiness and exits if a component fails later. Alloy's HTTP readiness and
health endpoints alone are insufficient: they can return success after the
exporter component has exited. An unavailable remote collector uses the retry
queue and does not by itself make the component graph unhealthy.

Alloy retains its state under `/var/lib/lanrith/alloy`. Its unit exposes that
directory at `/var/lib/lanrith-alloy` inside the service's mount namespace, so
the unprivileged exporter can use it while `/var/lib/lanrith` remains root-only.
The native test exercises that mount and permission boundary separately from
the journal delivery pipeline. It also verifies that the supervisor's queue and
failure observations reach a capability-free reader through the exporter group,
while that reader cannot read the exporter credential and unrelated service
identities cannot read the observation. The health collector rejects stale or
previous-boot observations; it does not replace unavailable counters with zero.

`tests/directory_native.py` qualifies the directory reader's generated host
egress and the separate TLS observer in an offline namespace. Synthetic peers
exercise both address families, LDAPS, StartTLS, incorrect names and authorities,
expired certificates, plaintext refusal and slow peers. Working alternate
listeners and interfaces provide positive controls before enforcement denies
other users, sources, destinations, ports and egress interfaces. The probe sends
no LDAP Bind request. StartTLS framing follows
[RFC 4511 section 4.14](https://www.rfc-editor.org/rfc/rfc4511#section-4.14).
The result binds the test, fixture, compiler and runtime digests, and is required
by base qualification and consumer admission. Actual directory authentication,
grants and the owner's complete image remain separate qualification work.

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

The separate `rootless-administration` native profile compiles
`administration.root_access: disabled`, boots the signed result, and confirms
that direct root login, sudo, su, agent forwarding, set-user-ID/set-group-ID
files, file capabilities and source YAML are absent. Its unprivileged SSH
session can inspect status and stage upload bytes in its bounded temporary
directory, but cannot invoke a privileged runtime or service-control operation.
It also checks the running SSH master for the rootless unit's
`NoNewPrivileges`, seccomp, capability and filesystem restrictions. The
root-enabled profiles deliberately do not apply that SSH restriction to the
post-`sudo` session because successful elevation enters the trusted root
boundary described in `security-model.md`.

Boot-authority qualification inventories firmware `db`/`dbx`, shim and MOK
trust separately for OVMF and each supported physical profile. It records every
boot entry and tests unsigned and broadly vendor-signed alternate loaders,
fallback paths, `BootOrder`, loader default and boot-count manipulation, plus a
complete older signed UKI/root/verity set. Record which images remain authorized
to unlock state, including the intended compatible fallback, and reject silent
acceptance of an unexpected image. Test revocation separately: the shared PCR
signing authority does not provide TPM NV anti-rollback for older signed images.
It also observes the ESP read-only during ordinary operation, writable only
inside staging/blessing, and read-only again after success and every injected
failure. Source checks for the mount policy are not hardware evidence.

Telemetry qualification uses a collector outside the router. It verifies the
TLS server identity and credential, receives the boot observation and at least
two one-minute heartbeats, and checks their boot, release and configuration
identities against the candidate. The collector must alert when Alloy stops,
the route or collector becomes unavailable, a heartbeat is replayed or stale,
or an unexpected identity arrives. Independent probes must also alert on
changed listeners and enforcement behavior; a plausible heartbeat supplied by
compromised root is not evidence that live policy remains intact. Qualification
records queue saturation/eviction behavior, collector outage recovery and
redaction fixtures without retaining credentials.

Compromise-recovery qualification starts with populated state and credentials,
then assumes their bytes were stolen. It injects forged, stale, oversized and
malformed leases, DNS journals, directory grants/history, RADIUS fallback,
translation allocations, update inboxes, SSH identity and enabled extension
state. The signed recovery boots with `/var` `nodev,nosuid,noexec`, rotates the
SSH key using a fresh unpredictable generation, and admits only explicitly
migrated data. Tests from a separate host confirm that every old directory,
TSIG, BGP, RADIUS, log, SNMP and extension/console credential is rejected after
external rotation. Expired grants and unused automation identities remain
denied. Populated-state upgrade and rollback still pass for the non-compromise
path; recovery deliberately does not promise to retain exposed authority.

Resource and fault qualification is a candidate test, not a source-inspection
claim. Run it on an isolated clone with representative leases, DNS journals,
policy grants, translation allocations, log queues and an admitted update.
Exhaust blocks and inodes independently for state, update, journal and telemetry
paths; drive each enabled daemon to its signed `MemoryMax`, `TasksMax` and
`LimitNOFILE`; fill bounded nftables/conntrack/neighbour/DHCP/policy structures;
then inject truncated, oversized and malformed durable records. Move the wall
clock both behind and ahead of directory observations and release evidence,
including across a reboot that resets the monotonic clock. A fault may reduce
availability, but must not create a permit, revive an expired grant, replace a
retained translation identity, admit an old sequence, select an unauthenticated
boot entry or publish a partial state file. Record recovery time, dropped work,
queue eviction and externally observed alarms as limits. The campaign remains
open if any path was skipped because its positive control did not work.

The final campaign is staged as one directory containing `campaign.json`,
`report.md`, `harness/` and `evidence/`. The campaign binding names the exact
source commit, owner configuration, effective configuration, factory release,
local patch and lab certificate digests; firmware, Secure Boot variables, disk
and TPM baselines; every update candidate and disposable clone; deviations and
required report/harness/oracle paths. Run `scripts/evidence-bundle.py seal` with
a separate evaluation key, then verify with an independently obtained
certificate. Verification recomputes every member and rejects missing, extra,
altered, linked, noncanonical or wrong-authority bundles. The signing key and
trusted certificate are not evidence supplied by the tested router.

Fresh-install recovery has additional VM runners and evidence described in
[recovery qualification](recovery-qualification.md). Run the affected recovery
cases against the release candidate. Historical tests that deliberately override
experimental gates do not qualify the supported compiled-policy path.
