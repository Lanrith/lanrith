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

**Treat the resulting private image, build workspace, backups and installer USB
as secret media.** The verified root is read-only, not encrypted. Anyone who can
read the raw image can extract its credentials. Keep these artifacts out of
public releases and shared caches. The public platform contains no owner values.

The image stores its selected credentials under
`/usr/lib/lanrith/credentials/`, in root-owned private directories and files.
Services receive only their declared values through systemd `LoadCredential`;
SNMP reads its private image configuration while retaining its engine identity
and boot counter in encrypted persistent state. Owner YAML and controller source
paths are not runtime inputs.

First boot validates the image files immediately. There is no credential upload,
stage/commit operation, or ten-minute provisioning wait. Missing or malformed
image inputs fail the readiness check; the existing health and fallback logic
still decides whether the image can be accepted. SSH/OOB, recursive DNS and NTP
have no dependency on this credential check. Recovery-key acknowledgement
remains a separate installation step.

Rotate credentials by building and installing a new image through A/B updates.
Each slot carries its own set, so booting the previous slot selects its original
credentials without restoring shared secret files. Keep the previous credentials
valid at external services while that slot remains a supported fallback; image
rollback cannot undo a password revocation in an external directory or service.
Validate backend authentication as part of private image acceptance.

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
the journal. Disable recording on the chosen console before continuing.

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
