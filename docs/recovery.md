# Boot recovery for fresh installations

Lanrith keeps two verified root slots and one encrypted state volume. A failed
candidate can return to the accepted image while keeping that state. Recovery
does not offer a shell, package installation or configuration editing. Normal
changes are delivered through an operator-triggered signed image update.

This implementation targets fresh installations. Existing systems that lack
the image state contract need a separate migration or a fresh installation.
Legacy TPM token migration remains disabled.

## Build inputs

Owner YAML is read by the builder. Images contain generated JSON and native
service configuration; they do not load owner YAML at boot or during recovery.
Signing keys remain on the build controller.

`build-recovery` accepts the same digest-checked `--target-facts` and
`--retained-allocations` inputs as `build`. Supply them when the selected owner
profile needs verified device ownership or retained translation identities.
They affect generated recovery artifacts and are not installed as runtime
configuration.

For TPM installations, the builder uses direct SHA-256 PCRs 7 and 15 and signed
PCR 11. It unlocks state in the verified initrd, enrolls the offline recovery
key during first installation, and extends PCR 15 before switching root. It
then verifies that the enrolled TPM token cannot unseal again in that boot.
The recovery key must be recorded outside the router during installation.

The stable PCR signing authority authorizes its signed images, including the
compatible fallback. This policy does not implement TPM NV anti-rollback or
revoke older owner-signed images. Boot-authority revocation and trust transitions
need separate qualification; a higher deployment sequence alone does not revoke
an old TPM unlock policy.

PCR signing requires an RSA-2048 key with exponent 65537. Supply its key and
certificate with `--pcr-key` and `--pcr-certificate` on every build. Keep this
authority stable across updates. If these arguments are omitted, the builder
uses the image signing authority only if it meets those requirements. It
rejects an unsuitable key rather than falling back to PCR 7 alone.

For a fixed-command serial recovery menu, select a serial port such as
`hardware.boot.recovery_console: ttyS0` and provide
`--recovery-passphrase-hash /private/recovery.hash`. The file must be owned by
the build user, mode `0600`, and contain the existing Lanrith scrypt hash format.
This credential is separate from root login and works with
`administration.root_access: disabled`.

## Firmware trust and maintenance

New factory and recovery media install owner-signed systemd-boot at both
`EFI/BOOT/BOOTX64.EFI` and `EFI/systemd/systemd-bootx64.efi`. Enroll the
image signing certificate in the target firmware's allowed image database
(`db`). PK and KEK authorize database changes. The PCR signing authority
authorizes the UKI measurements used for encrypted-state unlock. Keep the
offline state recovery key available independently.

For a target that needs vendor shim, set `hardware.boot.removable_shim_sha256`
to the SHA-256 digest of the exact approved signed shim binary. This selects
shim at the removable entry. The builder checks that pin and verifies the
owner signatures on the installed systemd-boot, shim's second stage, and UKI.
The target must authorize shim in firmware and the owner-signed second stage
through shim. If the target must also boot the canonical systemd-boot entry
directly, authorize its signer in firmware db. Test the planned db, dbx, MOK
and SBAT state on each required entry before installation or maintenance. A/B
staging writes the candidate UKI to the ESP. Changing an existing loader
chain requires a separately qualified maintenance step.

A change to the boot chain or firmware databases can change PCR 7. Rehearse
the intended firmware, boot paths, both installed UKIs and independent recovery
media on disposable retained state. Obtain the destination SHA-256 PCR 7 from
that independently approved configuration. The recovery boot and both
installed boot paths must reach that same value.

Before maintenance, collect the actual encrypted state device's LUKS2 JSON
metadata, its GPT partition UUID and LUKS UUID. Keep the full dump private.
Use `cryptsetup luksDump --dump-json-metadata "$STATE_DEVICE"` on the identified
volume. Create the exact predecessor binding on the build controller.

```sh
python3 scripts/prepare-firmware-transition.py \
  --state-partuuid "$STATE_PARTUUID" --approved-pcr7 "$APPROVED_PCR7" \
  < private-premaintenance-luks.json > firmware-transition.json
```

Build independent `build-recovery` media with the existing disk binding,
`--recovery-state-uuid`, `--recovery-passphrase-hash`, the same trusted PCR
authority, and `--firmware-transition firmware-transition.json`. The signed
initrd authorizes replacement of the named TPM token on this disk. It also
reserves the first free LUKS2 token and keyslot for an interrupted enrollment.
The current implementation handles a single strong TPM token with verified
independent recovery methods.

After applying the qualified firmware change, boot the recovery medium,
authenticate on its configured console, and run `inspect-state` with the
recorded offline key. Run `reenroll-tpm`, check the displayed PCR 7 against
the approved value, type `REENROLL`, and enter the recorded key. The operation
checks Secure Boot, verified root, the live PCR 7, state identity and bound
keyslots. It enrolls the exact approved PCR 7 with signed PCR 11 and zero
PCR 15. It tests early unlock and late denial before retiring the predecessor.
The offline recovery key remains usable across the header writes. After
interruption, cold boot the same recovery medium and repeat the command.

Remove recovery media and cold boot twice. Check the current-boot early-unlock
observation on each boot and read retained state. Include the authorized fallback
in the platform rehearsal. A physical platform whose recovery and installed
paths measure different PCR 7 values requires its own qualified procedure.
Observing a denial on a target supplies no authority to sign a new destination.

## An update with a usable fallback

Build each update against the accepted prior release:

```sh
lanrith build owner.yaml \
  --base /admitted/lanrith-base.tar.gz \
  --initrd-base /admitted/lanrith-initrd-base.tar.gz \
  --platform-lock /admitted/platform-lock.json \
  --platform-bundle /admitted/bundle \
  --workspace /build/router-12 --output /releases/router-12 \
  --version 0.1.0 --sequence 12 \
  --certificate /private/owner.crt --key /private/owner.key \
  --pcr-certificate /private/pcr.crt --pcr-key /private/pcr.key \
  --recovery-passphrase-hash /private/recovery.hash \
  --fallback-release /releases/router-11 \
  --fallback-disk-by-id /dev/disk/by-id/EXAMPLE-router-disk \
  --fallback-esp-uuid 11111111-2222-3333-4444-555555555555
```

All paths and identifiers above are synthetic. The fallback inputs bind the
prior signed UKI and partition bytes, physical disk identity and EFI partition
UUID into the candidate. Staging checks those bytes against the accepted
running slot before modifying the inactive slot.

The local preflight/signing workflow accepts `--boot-inputs /private/boot-inputs.json`
on both `scripts/build-local.py preflight` and `assemble`. This file contains
canonical paths named `pcr_key`, `pcr_certificate`, `recovery_hash` and
`fallback_release`, plus `fallback_disk_by_id` and `fallback_esp_uuid`. Optional
inputs can be omitted; each key/certificate or fallback group must be complete.
Preflight records the public authority, credential and signed fallback digests.
Signing rechecks them, copies keys into private tmpfs, and passes the admitted
inputs to the network-disabled builder.

The hosted factory workflow accepts protected secrets `LANRITH_PCR_KEY`,
`LANRITH_PCR_CERTIFICATE` and `LANRITH_RECOVERY_PASSPHRASE_HASH`. Pin the public
PCR certificate as `trust/pcr.crt` in the owner repository. Use the local
workflow or direct build command for updates that require a bound prior-release
directory; the hosted workflow does not fetch that directory automatically.

Both images must have compatible state formats and unchanged trust authorities.
New platform builds carry reviewed reader/writer declarations from
`lanrith/state_formats.py`. Compatible package updates can keep those format
identifiers; persistent-format changes require updated readers and qualification
of upgrade and rollback. Older archives without declarations are conservatively
tied to their exact base digest. Authority changes still require a separately
implemented transition; a version number alone does not establish compatibility.

The bootloader displays a five-second menu containing the installed UKIs.
Command-line editing is disabled. Select the earlier image there for manual
rollback. Firmware serial redirection determines whether this menu appears on
the physical serial port.

For a deliberate manual rollback, systemd-boot's `d` key sets the selected entry
as the persistent default. An automatic fallback preserves the existing accepted
default and needs no manual change.

On a candidate failure, the initrd checks the bound fallback bytes, verified
root metadata, state contract and TPM policy. It requests a reboot only while
the failed candidate is running, the bound previous release is the persistent
default and the loader has no pending one-shot. A conflicting choice stays in
place for the operator.

The failure service and emergency console share one automatic attempt per
boot and signed initrd identity. The default verification budget is 900
seconds. Set `hardware.boot.fallback_timeout_seconds` (1 to 86400 seconds)
for the time measured with both slots on the deployment's storage. Measure
the time to the prompt with a failed candidate. Uninterruptible device I/O
requires a separately qualified hardware watchdog.

## Serial recovery

When automatic fallback is unavailable, the configured serial menu prompts for
its recovery passphrase. Three incorrect attempts close the session. After
authentication, the menu shows the commands available for the current boot.

- `status` shows fallback eligibility or the one-shot selected this session.
- `fallback` verifies the bound previous slot while it is still the persistent
  default. Enter its exact deployment number to select it for one boot.
- `reboot` boots the fallback confirmed in this session.
- `exit` closes the session.

The menu has no arbitrary command, filesystem path or root-login action.
The persistent default survives a serial one-shot. After acceptance the new
release is the default. The serial menu then offers `status` and `exit`.
For manual recovery, use the firmware console to reach the bootloader or
boot the independently signed recovery medium.

## Independent recovery media

Prepare the medium before deployment. Select an accessible serial or
hypervisor terminal in the recovery build's `hardware.boot.recovery_console`
(for example, `ttyS0` or `hvc0`). A display-only `tty0` installation shows
the hold message on its screen. To use interactive recovery, qualify access
to the selected terminal and boot the prepared medium under the machine's
Secure Boot trust policy.

Use `lanrith build-recovery` with the same admitted platform and signing inputs
as a normal build. Provide `--recovery-passphrase-hash`,
`--recovery-disk-by-id` and, for encrypted-state inspection,
`--recovery-state-uuid`. Optional `--recovery-offline-inputs` accepts a build-time
JSON binding of the independently signed release disk for slot inspection.
Obtain the installed disk aliases, ESP/state partition UUIDs and encrypted state
UUID from the `recovery` object in `lanrith-image status`. These are observations,
not credentials or boot authority; every recovery operation rechecks them.

The dedicated recovery image removes the installer entry point. Its release
has purpose `recovery`; the updater and factory installer reject it as an
ordinary update or factory payload. Verify and write it using:

```sh
lanrith verify /releases/recovery --purpose recovery --certificate /private/owner.crt
sudo python3 scripts/make-media.py /releases/recovery --purpose recovery \
  --certificate /private/owner.crt --target /dev/disk/by-id/usb-EXAMPLE-recovery
```

The writer requires typed confirmation and verifies the signed partition bytes
after writing. Boot the medium under Secure Boot using its trusted owner key.
Firmware enrollment and physical media behavior require qualification on the
target hardware.

To admit OS slot repair, add `--allow-slot-repair` together with the offline
release binding and encrypted state UUID. After serial authentication, `repair`
asks for the offline state key, verifies the signed release and retained state
formats, and asks for confirmation of the deployment number. For TPM images it
also verifies the signed PCR policy and tests the existing TPM tokens against
the recovery boot before writing.

Repair selects the existing slot by its signed partition UUIDs and types. It
writes and reads back the root, verity and signature partitions, then publishes
the matching UKI on the ESP. It preserves the partition table, encrypted state
and other OS slot and returns the target disk to read-only mode. The source
release remains available for retry after interruption. Select the repaired
deployment in the bootloader when leaving recovery. Repair requires intact GPT
identities and a mountable EFI filesystem; it does not repartition the disk.

For offline backup and restore, `--recovery-offline-backup` accepts a JSON file
with schema `1`, `target_disk_by_id`, `backup_disk_by_id`, `state_partuuid`,
`state_uuid` and `backup_partuuid`. The backup partition must be ext4, support
fs-verity, and have label `lanrith-backup`. The recovery, target and backup disks
must be separate. The image binds these identities; the menu cannot choose
another target.

`backup` copies the offline encrypted state, authenticates and protects the copy
with fs-verity, and displays its backup ID and SHA-256 measurement. Retain that
receipt independently of the backup disk. `restore` requires the offline
recovery key, the matching receipt and typed confirmation of the backup ID.
It validates the backup before opening the target for writes and restores the
LUKS metadata last. An interrupted restore retains the independent backup for
retry. Restore does not automatically authorize a boot or prove compatibility
with another image.

Backup age is an operator decision using the separately retained receipt.
Neither a filename nor a timestamp on the backup media proves freshness.
