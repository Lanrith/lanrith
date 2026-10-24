# Security model

Lanrith treats unrestricted operating-system root as a trusted administrative
boundary. Root can change live nftables rules, routes, mounts and services on a
conventional single-kernel router. The product does not claim that dm-verity, a
read-only root filesystem or a same-kernel monitor can contain an attacker who
already has that authority.

This is narrower than treating every local account as trusted. The named
administrator has no root capability merely because it can log in. It becomes
root only after a separate, authenticated `sudo` transition. Service accounts
and ordinary processes have no such transition.

## Authority boundaries

The root trusted computing base includes the kernel, PID 1, root-owned boot and
network management services, privileged Lanrith helpers, the OpenSSH privileged
monitor and an administrator after successful elevation. A compromise inside
that boundary is a root compromise even when the initial process was called a
service.

UID is not the whole boundary. `systemd-networkd`, for example, uses a non-root
UID but holds narrowly declared network-control capabilities. It can change
routes because that is its job, so it belongs to the network-control trusted
computing base. Moving the same process to UID 0 would hide rather than remove
that authority. Qualification therefore distinguishes ordinary non-root
identities from capability-bearing control services and checks each privileged
service against an explicit capability and sandbox contract.

Before elevation, the administrator is an unprivileged account. SSH permits
only the configured account and rejects direct root login, passwords and
keyboard-interactive authentication. `sudo` reauthenticates with the forwarded
administrator key on the management path or with the explicitly enabled serial
recovery passphrase on its selected terminal. It has no `NOPASSWD` fallback or
shared root password.

An owner can instead set `administration.root_access: disabled`. That choice is
compiled into the image: root has a locked password and non-login shell, the
administrator has no sudo membership, SSH agent forwarding is disabled, and
sudo, su, set-user-ID and file-capability elevation paths are absent. UID 0 and
narrow capabilities still exist inside the operating-system trusted computing
base for services that cannot perform their function without them. Recovery or
re-enabling operator root access requires independently verified signed media.

Network daemons should parse untrusted traffic as non-root identities wherever
their protocol permits it. A daemon that must retain a capability is part of a
smaller privileged service boundary for that capability; its effective and
bounding sets, namespace, writable paths and reachable sockets must be recorded
and justified. Root-running front ends need protocol-specific privilege
separation or must be counted in the root trusted computing base.

The base image gives Kea only `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW` and runs
it as `_kea`. Unbound starts with the five capabilities needed to refresh its
trust anchor, bind port 53 and drop identity; the live resolver must have empty
effective and permitted sets. Both units use `NoNewPrivileges`, seccomp,
read-only system paths and restricted address families. `cron`,
`systemd-hostnamed`, `ssh.socket` and `sshd@.service` are masked because Lanrith
has no workflow that needs them. The selected `ssh.service` remains the login
broker. In root-enabled images its privileged monitor is part of the root TCB;
in rootless images it also receives `NoNewPrivileges`, a bounded capability
set and read-only filesystem views with only the upload directory writable.

## Guarantees before root compromise

An administrator before elevation, an unprivileged service identity and any
other ordinary non-root account must be unable to:

- change firewall, routing, interface or kernel network policy;
- mount or replace filesystems, write block devices, or alter the ESP and EFI
  variables;
- control system services or privileged Lanrith runtime operations;
- write signed-root configuration, root-owned policy, boot state or protected
  persistent state;
- read unrelated credentials, host keys or authentication material;
- signal or inspect processes outside the access allowed by its identity;
- acquire root through a set-user-ID/file-capability path or an unattended
  administrative credential.

Service isolation and firewall identity checks remain security controls, not
substitutes for the kernel's user and capability boundary. An owner access rule
does not grant local process privilege.

The owner YAML and normalized compiler model are build inputs. Neither is
installed in the root filesystem or initrd, and no deployed service depends on
them. The image contains only generated runtime artifacts and the small runtime
modules needed to validate and operate those artifacts.

## Guarantees after root compromise

Lanrith promises recovery and evidence, not continued live enforcement. A root
attacker can alter the running policy and can read secrets already available to
the running system. Operators must isolate the router, preserve remote evidence,
boot or reinstall from independently verified media, and rotate reusable
credentials exposed to the device.

Secure Boot, signed UKIs, dm-verity and signed update admission still matter:
they reject untrusted base-image content and provide a known recovery point.
They do not stop root changing live policy. ESP and firmware boot-selection
changes are persistent inputs to recovery and therefore need separate tests;
the ability to reject one unsigned UKI is not proof that every allowed firmware
trust path is safe.

During normal userspace operation the ESP is mounted read-only with device,
set-ID and execution semantics disabled. The authenticated updater and boot
blessing operation each use a bounded writable window, flush their changes and
restore the read-only mount before success. Boot-entry authentication and
one-shot selection happen after that restoration. This is a least-authority
control for non-root processes and operational errors, not containment of an
attacker already inside the unrestricted-root boundary.

External telemetry can detect missing heartbeats, policy changes and unexpected
boot identities. It cannot prove live policy integrity when its only source is
the compromised router, so release qualification also uses observations made
outside the guest.

## Qualification

Every candidate runs the unprivileged control-boundary test in both native VM
profiles. It verifies direct root SSH denial, failed unattended elevation, and
failed firewall, route, sysctl, mount, service-control, block-device, protected
file and privileged-runtime operations from the administrator and every
installed account without its service-granted capabilities. It checks the
effective capabilities of live processes, enforces the declared sandbox for
the network-control identity, and verifies that failed probes left policy and
services unchanged.

Candidate-specific service qualification records effective UID, groups,
capabilities, `NoNewPrivileges`, seccomp state, namespaces, writable paths and
network reachability for each enabled daemon. Tests run from the real daemon
context where a unit grants capabilities or supplementary groups. Static unit
inspection alone is not enough. The native gate also rejects an active cron,
hostname API or alternate SSH activation path and checks the live Unbound, Kea,
Chrony and networkd process capability sets against their declared bounds.

A disposable root positive control may repeat policy-mutation attacks to show
that the oracle is capable of detecting them. That result confirms the declared
root boundary; it is not a release failure. The same externally observed change
from any non-root context is a release blocker.
