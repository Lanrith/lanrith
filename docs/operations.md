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
the fixed image-operation interface. Its privileged service copies into exclusive
root-owned files before signature verification. The operator can do this with
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

The image deliberately installs no static files in `/usr/lib/sysupdate.d`.
Invoking `systemd-sysupdate` directly is unsupported: only `lanrith-runtime`
may generate the temporary definitions after it has authenticated the release,
identified the mounted verified-root graph, and selected the inactive slots.

Staging also requires the running slot to be the explicitly accepted persistent
default. Accept a healthy candidate before staging another update, so its
previously accepted fallback cannot be overwritten prematurely.

After an independently authorized reboot, verify the fresh boot observation,
Secure Boot, dm-verity, encrypted state, selected interfaces, required services
and recovery enrollment. Only then accept the deployment as default. A failed
candidate must return automatically to the previously accepted entry. Keep the
matching factory image, public trust, recovery key and previous configuration
offline. Exercise recovery with populated state before a production cutover.

## Service credential provisioning

An image with credential-dependent integrations emits a fixed catalog at
`/usr/share/lanrith/credentials.json`. It contains references, native formats,
paths and consumer units. Credential values and owner YAML stay outside the
image. The installed metadata binds the catalog's digest; a missing or changed
catalog cannot disable the boot requirement. Minimal profiles have no catalog,
provisioning socket or credential wait.

The configured operator can inspect provisioning through the existing SSH
transport, including with `administration.root_access: disabled`:

```sh
ssh operator@router lanrith-credentials status
```

For initial installation or newly selected bindings, the owner's protected
secret-manager runner supplies a JSON object on stdin. Each key is a catalog
reference; each value is canonical Base64 of the complete native credential
file. TSIG's native file already contains Base64, so the transport encodes that
file again. Invoke `lanrith-credentials stage CONFIGURATION_SHA256` through SSH
with that object as stdin. Never put values in arguments, environment variables,
source files or temporary controller files. The server checks the socket peer's
UID and validates the complete set before stopping any consumer.

Staging returns a transaction ID and starts the selected consumers so the
owner's automation can check actual authentication and permissions. Syntax
validation alone does not establish backend agreement. After those checks pass,
the same operator confirms that exact transaction:

```sh
ssh operator@router lanrith-credentials commit TRANSACTION_ID
```

Confirmation permits the normal image-health checks to run. It cannot bypass
them. The service starts an inactive completion observer and leaves an active
observer running. It never restarts that observer or stops mandatory firewall
guards. SSH/OOB, recursive DNS and NTP have no dependency on the credential gate.

Provisioning has a 600-second window before the ordinary image-readiness
deadline; the completion service's outer deadline remains effective. A failed
candidate returns to its accepted fallback. On an initial installation, a late
successful confirmation can start completion again without reinstalling.
Keep the separate recovery-key acknowledgement and other health requirements
in the installation workflow.

Unchanged admitted bindings carry through ordinary A/B updates automatically.
Staging cannot change a value needed by an admitted fallback. Initial,
uncommitted installation values can be corrected; each replacement gets a new
transaction ID. Interrupted writes resume only for the same image and catalog.
Credential rotation needs a separately qualified transition workflow.

## Extension credential provisioning

The same installed operator can provision an admitted extension with root access
disabled. Each namespace has its own catalog, socket, lock and transaction history.
Use the extension ID from the reviewed manifest:

```sh
ssh operator@router lanrith-extension-credentials example-addon status
```

The protected secret-manager runner sends the complete set as a JSON object on
stdin: keys are slot names and values are canonical Base64 of each complete JSON
credential object. Invoke `lanrith-extension-credentials example-addon stage
CONFIGURATION_SHA256` with that input. The returned transaction ID identifies
the exact prepared bytes and compiled reader bindings. Consumers receive
systemd credentials under `$CREDENTIALS_DIRECTORY/NAME`. After the extension's
authentication and functional checks succeed, confirm that transaction:

```sh
ssh operator@router lanrith-extension-credentials example-addon commit TRANSACTION_ID
```

An optional namespace reports `needs-core-acceptance` until both the persisted
image identity and the current boot observation confirm acceptance. Its stage
and commit operations control only its declared readers and readiness gate.
An extension required by core health can provision before acceptance; boot
completion waits for its committed set alongside the core credentials.

Uncommitted extension values can be corrected after core acceptance. Invalid
input and attempted changes to admitted values are rejected before readers stop.
Changing readers requires fresh admission. To rotate an admitted value, use a
new slot name in a newly built image and qualify the transition with the retained
fallback. Each namespace retains its admitted history; exhausted history fails
before service quiescence. Interrupted writes resume only for the same image,
catalog and namespace. Extension state initialization and application-specific
checks belong to that extension.

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
