# Recovery and operations

A deployment sequence belongs to the owner and increases independently of the
platform semantic version. Never reuse a sequence, including after restoring a
repository, recreating a workflow or rebuilding with different configuration.
A rollback is a new deployment of reviewed inputs with a higher sequence; the
accepted boot entry remains a fallback until the candidate is accepted.

Each device also needs a permanent `hardware.machine_id`, generated once in its
private configuration. Preserve the installed ID when migrating an existing
router. The signed root and initrd use the same ID, and repartitioning uses it
as its seed. systemd binds automatic `/var` discovery to this identity; never
derive it from a release, rotating key, hostname or changing network settings.
See [systemd's partition discovery rules](https://github.com/systemd/systemd/blob/main/man/systemd-gpt-auto-generator.xml).

Fresh TPM state enrollment binds to direct PCRs 7 and 15 and signed PCR 11.
The verified initrd unlocks state and closes the PCR 15 window before switching
root. Boot health checks the enrollment and current-boot unlock observation.
Keep the offline recovery key before changing
firmware or Secure Boot policy. Automatic pcrlock policy generation stays
disabled unless a reviewed signed-image integration supplies its profile and
`/usr/share/lanrith/enable-pcrlock-policy` marker. See the pinned
[systemd enrollment interface](https://github.com/systemd/systemd/blob/v257/man/systemd-cryptenroll.xml).

The signed manifest declares purpose, image identity, platform version,
sequence, effective configuration/integration digest, architecture and the
exact artifact names, lengths and SHA-256 digests. Unknown fields, extra files,
linked files, wrong trust, replay and incomplete sets fail admission.

On the router, an operator uploads to the unprivileged staging area and triggers
the fixed image-operation interface. Its privileged service authenticates private
copies of the manifest and signature before opening the payloads. It checks
each copied payload against the signed size and SHA-256 digest. The operator can do this with
`administration.root_access: disabled`, without root login or sudo.
The admitted files and publication directories are flushed before staging, so
the authenticated inbox survives a power cycle after admission.
The updater identifies the actual mounted dm-verity dependency graph and both
slots; it does not guess a disk from device naming. Undersized, mounted,
ambiguous or foreign targets fail. The inactive signature/hash/root are written
before the boot-counted UKI. The accepted default is retained and only a
one-shot boot is selected. Staging does not itself reboot.
The admitted pending UKI and its directory are flushed before the boot choice
is published. One-shot selection resolves the bootloader's reported entry ID
for that exact pending file and checks the resulting firmware choice. The
pending file keeps its boot counter until a successful boot is blessed.

The EFI partition is discovered from the running boot, verified as a FAT
partition on the verified-root disk, and accessed through its mounted filesystem.
Either `/boot` or `/efi` is supported, including systemd automounts. Distribution
automatic update and reboot timers are masked; the approved staging and
deployment workflow owns those actions.

The ESP is mounted `ro,nodev,nosuid,noexec` during ordinary operation. The
authenticated staging helper opens a writable mount only while
`systemd-sysupdate` copies the admitted boot entry; boot blessing does the same
only while committing a successful counted boot. Each helper flushes the ESP
and restores the read-only mount before reporting success. Update verification
and EFI one-shot/default selection occur with the ESP read-only. A failure to
restore it is a failed operation and a health fault. This protects against
ordinary services and accidental writes; unrestricted root can remount it and
remains inside the trusted boundary described in `security-model.md`.

If the operator worker stops during a transfer, its stop hook verifies the ESP,
restores its mount flags and reads back the accepted one-shot entry. A new
trigger can proceed once `lanrith-image status` reports the interrupted
operation as `failed`. An unresolved selection keeps the operation pending.

The image deliberately installs no static files in `/usr/lib/sysupdate.d`.
Invoking `systemd-sysupdate` directly is unsupported: only `lanrith-runtime`
may generate the temporary definitions after it has authenticated the release,
identified the mounted verified-root graph, and selected the inactive slots.

Staging also requires the running slot to be the explicitly accepted persistent
default. Accept a healthy candidate before staging another update, so its
previously accepted fallback cannot be overwritten prematurely.

After an independently authorized reboot, verify the boot observation,
Secure Boot, dm-verity, encrypted state, selected interfaces, required services
and recovery enrollment. Only then accept the deployment as default. A failed
candidate must return automatically to the previously accepted entry. Keep the
matching factory image, public trust, recovery key and previous configuration
offline. Exercise recovery with populated state before a production cutover.

Boot health checks the declared LAN gateway prefixes and usable address flags,
required local routes, and listeners owned by the SSH, Kea and Unbound daemons.
A disconnected optional uplink can remain offline. When it has carrier, its
declared static addresses and gateways must be installed. The gate sends local
DNS queries through the host resolver and, when Chrony has a named upstream,
through its private resolver. With BIND enabled it also checks each zone's SOA, generated service
answers and release-managed RRsets against the running authority. Failure
messages identify the requirement in the journal for `lanrith-health.service`.

Run `lanrith-status` to read the latest whole-boot health check. Its `health`
object reports `passed` or `failed` for a completed check within 60 seconds
of its start. `age_seconds` measures time since that start. A missing, stale,
interrupted or still-running check has an unavailable result. To refresh it,
run `systemctl start lanrith-health.service` as root. The separate `boot`
object records the historical boot event. Its `accepted` field stays true
after a failed refresh if promotion committed the running image.

Advisory observation timers continue to run independently. Check the monitoring
results and `systemctl --failed` to inspect failures on an accepted boot.
Staging starts a fresh health check before writing the new slot.

## Service credential provisioning

A basic Lanrith installation needs no service credentials. Supply a credential
only when an enabled integration uses it; disabled integrations and unused
directory declarations need no values. Static DNS zones also need no TSIG keys.
The optional `credentials` map connects each active service's reference to an
absolute file path on the build controller:

```yaml
credentials:
  directory_bind: {file: /run/private-build/directory-password}
  vpn_bgp: {file: /run/private-build/bgp-password}
```

Have your existing secret manager materialize these files in private temporary
storage for the build. Files must be ordinary, singly linked files owned by the
build user, with mode `0400` or `0600`. For active references, symlinks, missing
files, invalid native formats and incomplete sets fail the build. Unused
references are not opened or embedded, so disabling a feature does not require
removing its file references or keeping those files available. Values do not belong
in YAML, command arguments or logs. The local builder checks the set again
against preflight and passes it to the offline container through private tmpfs.

The factory image, update root, installer USB and build workspace contain the
embedded credentials. Anyone with raw read access can recover their values.
Local builds with credentials set the release directories to mode `0700` and
each verified artifact to `0600`. Track every copy, its readers, restore and
export operators, storage location and retirement date. Include CI artifacts,
snapshots and removable media. Keep working copies on protected storage and
exclude them from public releases and shared caches.

For offline retention, encrypt the release for a separately held restore key.
For example, on a controller using Bash and GnuPG, verify the recovery
certificate fingerprint with its custodian, then write to a new file in a
private archive directory.

```bash
set -euo pipefail
umask 077
archive=$(mktemp "$archive_directory/.lanrith.XXXXXXXX.gpg")
tar -C "$private_output" -cf - . |
  gpg --no-options --batch --recipient-file "$recovery_public_certificate" --encrypt > "$archive"
```

Record the archive location only after the pipeline succeeds. An authorized
operator can restore it with `gpg --decrypt "$archive" | tar -xf - -C "$private_restore"`
in a new mode-`0700` directory, using the same pipeline failure handling.
Verify both restored release signatures and artifact hashes with the
independently trusted boot certificate before using either image. Rehearse
restore with synthetic media and check that an unrelated user cannot open a
raw copy or decrypt the archive. Retire plaintext staging copies and snapshots
under the owner's retention policy. An installer left unattended still carries
a readable root. A deployment requiring confidentiality after loss of that
media needs separate provisioning or a device-bound design qualified for
replacement and fallback.

The image stores its selected credentials under
`/usr/lib/lanrith/credentials/`, in root-owned private directories and files.
Services receive only their declared values through systemd `LoadCredential`;
SNMP reads its private image configuration while retaining its engine identity
and boot counter in encrypted persistent state. Owner YAML and controller source
paths are not runtime inputs.

First boot checks each integration's inputs before starting its daemon or
preparation helper. A missing log password blocks Alloy. FRR can still start
with valid routing credentials. Candidate acceptance verifies the complete
bound catalog and every required extension. Offline recovery-key verification
remains a separate installation step.

Rotate credentials by building a new image. Each slot retains its own
credentials. Before cutover, generate a plan from the mounted, verified roots.

```bash
tool=scripts/qualify-credential-rotation.py
slots=(--candidate "$candidate_root" --fallback "$fallback_root")
python3 "$tool" "${slots[@]}" plan > rotation.json
```

For each slot and reference, fill its `peers` object with all endpoints using
that identity. For example, `{"log-a":"overlap","log-b":"reversal"}` describes
an ingest peer that accepts both accounts and a peer that must reverse its
single active credential. Use `unchanged` when the same identity remains valid
after retirement. Compare the secret manager's version identifiers and
peer inventory for both deployments. Two equal catalogs can bind different
secret values. For BGP listen ranges and RADIUS client prefixes, include
each deployed peer that uses the reference.

FRR starts with the selected image's routing configuration. Its systemd unit
disables live reload. For a BGP peer that accepts one TCP MD5 key, coordinate
the peer change at cutover and reverse it before testing the fallback slot.
On each slot, record the time to a fresh established session and check that
the expected prefix uses that peer as its next hop.

Supply an owner-controlled executable through `--probe`. It receives one JSON
request on standard input with the expected slot identity, phase, reference,
peer label and a new challenge. Obtain the observed identity from the booted
router, authenticate the peer and perform a fresh operation using that slot's
identity. Return a JSON object containing the observed `identity`, the
`challenge` from this request and an `outcome` of `authenticated` or `denied`.
Report `denied` only for explicit rejection of that credential by the
authenticated peer. For protocols that silently drop a bad credential,
correlate the attempt with peer-side authentication evidence obtained via an
independent management account. Exit nonzero on transport failure, timeout
or ambiguous protocol results. Keep values, peer transcripts and secrets out of the reply.

```bash
python3 "$tool" "${slots[@]}" check --plan rotation.json --phase candidate --probe "$peer_probe"
```

Repeat with `fallback` after booting the predecessor and `restored-candidate`
after returning to the candidate. Before each boot, coordinate single-identity
peer changes and verify the operator can reverse them during recovery. Record
any recovery constraint before cutover. While fallback remains supported,
keep overlap identities valid. Once the owner retires the predecessor, test
`retired-fallback` in an isolated rehearsal and `retired-candidate` against the
current identity. Keep the returned slot identities and per-peer outcomes.
Suspected compromise calls for immediate revocation and a recovery image with
trusted credentials.

## SNMP polling and fallback

The monitoring owner maintains the list of poller egress addresses. Record the
IPv6 source **as seen on the router attachment** during both a normal poll and
a failover poll. A pod address can differ from the address sent by its node.
For each entry record the poller or shared workload, attachment, CIDR and
reason for access. Give every temporary prefix a retirement condition, such
as successful polls from both reserved addresses after a workload migration.

Compare that list with `observability.snmp.clients` and the verified release.
The unit's `IPAddressAllow=` lines include the host listener and loopback.
The UDP/161 request and reply rules in `/etc/nftables.conf` show which remote
CIDRs may use each interface. Account for every admitted subnet, including
infrastructure and workload ranges, even when no dedicated poller address lies
in them. Remove a range from the declaration once its retirement condition is
met, and review the fallback image separately. It can still admit an older
scope.

On the poller, use its private Net-SNMP profile for the selected slot. Set
`clientaddr` in the profile when the host has multiple egress addresses. Get
the IF-MIB name and 64-bit receive counter for the same router interface.
Supply its current ifIndex in `index` and the image's IPv6 listener in `server`.

```bash
SNMPCONFPATH="$profile_dir" MIBS= snmpget -v3 -l authPriv -r0 -t2 \
  "udp6:[$server]:161" ".1.3.6.1.2.1.31.1.1.1.1.$index" \
  ".1.3.6.1.2.1.31.1.1.1.6.$index"
```

Require the expected interface name and a Counter64 value from each retained
poller. In a disposable rehearsal, check that a source inside the retired
range loses access on its existing UDP tuple while the retained pollers still
read the counter. Record the source, slot sequence, interface, value and poll
time. For LibreNMS, also confirm a fresh completed device poll updates that
port's counters through the normal and failover paths.

For an image with `credential_delivery` set to `image` in
`/etc/lanrith/integrations/snmp-runtime-policy.json`, build the candidate
with the new protected `credentials` input. The agent reads the image file
named by its unit's `-c` argument. Editing a retained Ansible credential cannot
rotate this image. Keep the old and new poller profiles in the monitoring
owner's secret store and list both pollers as peers with the `reversal` policy
in the [rotation plan](#service-credential-provisioning).

| Rehearsal boot | Poller action |
| --- | --- |
| Accepted predecessor | Read the interface with its profile. Record the engine ID and boot count. |
| Candidate | Select the new profile, poll from both paths and confirm the old profile receives an authentication rejection. |
| Fallback | Restore the predecessor profile, repeat the reads and confirm rejection of the candidate profile. |
| Restored candidate | Switch the pollers back, repeat the checks and record the completed poll before retiring fallback. |

Keep the same encrypted `/var/lib/snmp` throughout. Restoring an old copy can
rewind the SNMPv3 replay counter. After each agent start, read only the two
engine fields through an authorized local console or management session.
Net-SNMP's persistent file also contains localized authentication material.

```sh
sudo awk '$1 == "oldEngineID" || $1 == "engineBoots" {print $1, $2}' /var/lib/snmp/snmpd.conf
```

Require the same engine ID and a strictly increasing count. Count a wrong
profile as rejected only after an explicit USM authentication failure or
independent agent-side authentication evidence. A UDP timeout alone could
indicate a route, filter or listener failure. Keep profiles and full daemon
state out of the qualification record.

## Extension credential provisioning

An admitted extension declares its JSON credential slots and service readers in
its manifest. Supply each active slot under `EXTENSION/NAME` in the same build
configuration:

```yaml
credentials:
  example-addon/bootstrap: {file: /run/private-build/addon-bootstrap.json}
```

Lanrith validates the bounded JSON object at build time and installs it under
`/usr/lib/lanrith/credentials/extensions/EXTENSION/NAME`. The declared consumers
receive it through `$CREDENTIALS_DIRECTORY/NAME`; an unrelated service receives
no read grant. Extension credentials follow the same image rotation and fallback
rules as core credentials. Optional extension startup remains subject to normal
core boot acceptance. A required extension must pass its configured health
checks before the image is accepted.

## Credential recovery after compromise

After any suspected root compromise, do not treat a successful reboot as
credential recovery. Isolate the router, preserve external evidence, build from
independently verified inputs, set a fresh `administration.host_key_rotation`,
and rotate every reusable authority that was readable on the device: directory
bind, BGP authentication, DNS update/transfer, RADIUS client/proxy, log ingest,
SNMPv3 and private extension/console credentials. Revoke old values at their
remote systems before reconnecting the router, distribute the new SSH host
fingerprint independently, invalidate directory grants/enrollment and RADIUS
fallback data, and reauthorize devices. Treat forwarded SSH-agent use during
the compromise window as exposed session authority; remove affected keys from
the administrator allowlist if its security-key confirmation history is not
conclusive. Encryption at rest does not undo disclosure after `/var` was
unlocked.

Restore only explicitly inventoried data. Leases and DNS journals need native
parser validation; policy history and grants must retain freshness/epoch checks;
translation allocations must retain unique source mappings; credentials and
SSH identity must come from the new recovery generation. Never restore update
inboxes, executable content, service-manager overrides, old enrollment markers
or a complete `/var` snapshot from the compromised system. Private extension
state needs an owner-specific migration and withdrawal test.

The signed image places hard memory, process and descriptor ceilings on its
DNS, DHCP, NTP, directory-policy and translation services. Exhausting a ceiling
is an availability event, never an authorization fallback: firewall defaults
and directory terminal-deny behavior remain installed while the affected
service restarts or stays failed. Update subprocesses also have bounded
deadlines and report only the public tool name. Durable policy and translation
writers flush a complete temporary file before replacement, so an exhausted
filesystem retains the last complete record or no new record. These controls
do not qualify storage exhaustion by themselves. Before production, run the
candidate-specific resource, malformed-state and clock campaign in
`qualification.md` and retain its external alarms in the signed evidence
bundle.

Initial factory installation verifies media against the certificate embedded
in the booted verified root, checks matching root identities, excludes the boot
disk and mounted/in-use devices, and requires the full stable target identity
in the destructive confirmation. It reads the copied image back before
power-off. Never substitute an ordinary raw writer for those checks.

The installer displays disk choices, confirmation prompts and progress on the
connected monitor and configured serial consoles. Either keyboard can select a
disk. The console that submits the first answer owns the remaining prompts;
the other consoles display status but cannot confirm erasure. Disconnecting the
active console stops the operation instead of moving its confirmation elsewhere.
An unavailable serial port does not prevent installation through the monitor.

Paste each answer only after its prompt appears. The erase confirmation must
include `ERASE-AND-INSTALL` followed by the complete selected disk path, with
matching case. An empty or mismatched answer displays the prompt again; after
three failed attempts installation stops. Type `CANCEL` to stop immediately.
No disk write occurs until the exact confirmation and final disk checks pass.

First-boot recovery-key enrollment also offers both consoles. Press Enter on
the console where you will record the key. Recovery keys and encryption
passphrases use only that console and are never copied to the other screen or
the journal. Disable recording on the chosen console before continuing. Record
the displayed key offline, then enter that copy at the hidden prompt. Reboot
and enter the same copy if enrollment stops. The first boot of an upgraded
installation asks for its existing copy. If that copy is lost and the console
offers replacement, type `REPLACE`. Keep the new copy for any retry. The old
slot is retired only after the new copy unlocks its own slot. A bound TPM
migration requires the existing copy and cannot replace it.

Slot and encrypted state provisioning must finish before the initrd switches
to the installed root. A candidate failure attempts authenticated fallback;
if that cannot pass, the initrd holds for serial or independent media recovery.
See [boot recovery](recovery.md) for build inputs, slot selection and offline
backup and restore. Disk checks bind GPT identities to kernel partition numbers,
capacity and in-use state; cached udev partition properties do not select the
state volume or update slots.

Create a USB installer from the owner's authenticated factory release directory:

```sh
sudo python3 scripts/make-media.py /path/to/factory --certificate /independent/trust/boot.crt \
  --target /dev/disk/by-id/usb-selected-device
```

The writer requires a typed destructive confirmation and rejects mounted,
in-use, read-only, undersized and incompatible targets. It preserves and reads
back every original partition, then mounts the payload read-only and verifies
its complete signed file set. Add `--verify-only` to repeat verification without
writing. Do not run either command until a qualified factory release exists.

For boot-key rotation, first enroll and qualify the new trust while retaining
the old accepted fallback. For evidence-key rotation, review the new public
certificate separately. Revoke compromised artifact digests in the reviewed
revocation policy and publish a fresh signed assessment. Do not silently fall
back to an older vulnerable release when admission fails.

Seal a completed security campaign only after its report and evidence are
final. Prepare the strict `campaign.json` binding described in
`qualification.md`, retain the evaluation key outside the campaign workspace,
and run:

```sh
python3 scripts/evidence-bundle.py seal /absolute/path/to/campaign \
  --key /independent/evaluation.key
python3 scripts/evidence-bundle.py verify /absolute/path/to/campaign \
  --certificate /independent/evaluation.crt
```

Do not edit the bundle after sealing. A correction is a new campaign ID and
seal, not an overwritten manifest or an exception recorded outside the signed
inventory.


## WAN sensor logs

When the sensor is enabled, `lanrith-ids-rotate.timer` checks EVE size every
minute. At 16 MiB, logrotate renames the file and signals the sensor to reopen
its output. The service verifies a write to the successor within 65 seconds and
retains four archives with delayed compression. Check
`journalctl -u lanrith-ids-rotate.service` after a rotation error and check free
space on `/var`. Size checks permit overshoot between runs. Set a site retention
objective from measured EVE bytes per second and available space. A guaranteed
storage ceiling requires a dedicated quota or allocation.
