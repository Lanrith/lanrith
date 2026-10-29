# Recovery qualification

The fresh-install recovery implementation has synthetic VM evidence in
`recovery-qualification.json`. The record identifies the source snapshots and
test subjects. It grants no production admission and asserts no physical
hardware qualification.

The affected runners are:

| Runner | Behavior checked |
| --- | --- |
| `tests/qualify_fresh_recovery_vm.py` | Fresh measured boot, late TPM unseal denial, injected initrd failure, authenticated fallback reboot and retained state |
| `tests/qualify_offline_inputs_vm.py --root-disabled --dedicated-export` | Signed recovery export and read-back, wrong-purpose rejection, authenticated serial inspection, corrupted-slot denial and unchanged disks |
| `tests/qualify_slot_repair_vm.py` | Incorrect offline key rejection, confirmed signed OS repair, unchanged GPT/state/other slot, and repaired boot with retained identity |
| `tests/qualify_admitted_backup_vm.py` | Compiled backup/restore permission, independent receipt confirmation, wrong-receipt rejection and exact encrypted-state restoration after damage |

Run each in the pinned privileged builder with networking disabled, matching
base and initrd archives, fresh disposable work/result paths, and sufficient
bounded storage. The fresh-boot and slot-repair runners also require a
`--disk-directory` for their virtual target. The runners create their own keys
and agents; they need no operator SSH agent or physical security key.

These cases use the supported signed-policy paths without changing qualification
constants or substituting successful state checks. Older experimental runners
remain useful for isolated failure cases, but their gate overrides are recorded
and must not be presented as production authorization.

The tests retain bounded JSON diagnostics. Serial transcripts, recovery keys,
private signing keys and guest disks are not public evidence. Completed test
images can be removed after their processes stop and results are retained.

Before releasing an owner image, repeat the affected tests against its exact
admitted platform and source. Review its state reader/writer declarations,
disk/ESP capacity, fallback binding and signing authorities. Retain the existing
package, vulnerability, provenance and release-admission gates.

The operator must separately qualify the target firmware's Secure Boot and TPM
behavior, boot-menu visibility, serial port, watchdog and recovery USB boot.
Record the offline state key and backup receipt outside the router. An unusable
disk, damaged partition table, unmountable EFI filesystem or missing recovery
key needs a separate recovery procedure; OS slot repair does not claim to solve
those failures.

## Security review notes

The write boundary is a signed, verified recovery initrd with a compiled list of
operations and exact disk identities. Serial authentication alone cannot choose
another target or obtain a shell. Repair additionally requires the offline state
key, compatible retained state, the signed source release and confirmation of its
deployment number. Backup and restore require independent media; restore checks
the authenticated immutable payload and separately retained receipt before
opening the target for writes.

Unit tests cover rejected identities, signatures, unsafe paths, incompatible
state, unprivileged requests and cleanup after failures. The VM cases exercise
real Secure Boot, verity, LUKS, TPM and filesystem behavior where applicable.
Root-disabled images keep the fixed image-operation service available to the
authorized operator while removing general elevation paths.

Trust-authority transitions and legacy TPM migration remain unavailable through
this fresh-install interface. A receipt does not establish backup age. A
watchdog must cover uninterruptible kernel or device stalls; the userspace
deadlines cannot make that guarantee.
