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

TPM state enrollment explicitly binds to PCR 7, and boot health checks every
TPM token for that policy. Keep the offline recovery key before changing
firmware or Secure Boot policy. Automatic pcrlock policy generation stays
disabled unless a reviewed signed-image integration supplies its profile and
`/usr/share/lanrith/enable-pcrlock-policy` marker. See the pinned
[systemd enrollment interface](https://github.com/systemd/systemd/blob/v257/man/systemd-cryptenroll.xml).

The signed manifest declares purpose, image identity, platform version,
sequence, effective configuration/integration digest, architecture and the
exact artifact names, lengths and SHA-256 digests. Unknown fields, extra files,
linked files, wrong trust, replay and incomplete sets fail admission.

On the router, an administrator uploads to the unprivileged staging area and
invokes the root-owned promotion helper through the approved authorization
path. It copies into exclusive root-owned files before signature verification.
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

Initial factory installation verifies media against the certificate embedded
in the booted verified root, checks matching root identities, excludes the boot
disk and mounted/in-use devices, and requires the full stable target identity
in the destructive confirmation. It reads the copied image back before
power-off. Never substitute an ordinary raw writer for those checks.

Slot and encrypted state provisioning must finish before the initrd switches
to the installed root. A provisioning failure leaves the system in initrd
emergency mode. Disk checks bind GPT identities to kernel partition numbers,
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
