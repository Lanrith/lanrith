# Phase B configuration

Phase B provides one typed configuration contract for a small router and the
optional components used by larger installations. A configuration with two
interfaces, one LAN, a DHCP pool and an explicit Internet access rule produces
a working DHCP, DNS and NTP router. BGP, directory policy, discovery,
translation, telemetry, IDS and acceleration are optional.

The implementation is complete at the shared source and component level. A
production deployment is still a separate release decision: it needs an
admitted public base, an owner-signed image, qualified persistent-state
migration, boot and rollback results, and hardware evidence for the selected
machine. Source tests or a locally assembled image do not replace those gates.

## Build-time configuration boundary

Owner YAML is accepted only by the build compiler. It is never copied to the
root filesystem or initrd and no deployed service reads it. The normalized
source model is also build-only.

The compiler emits daemon configuration, systemd units and narrowly scoped JSON
runtime manifests. The policy baseline is an intermediate build artifact: the
finalizer converts it into the pinned policy profile and removes it. The final
tree check rejects:

- source YAML and normalized configuration files;
- the intermediate policy baseline;
- compiler modules, including dormant imports from runtime code; and
- build-only directories or tools in the root filesystem and initrd.

Generated configuration used by third-party daemons may use that daemon's
native syntax, including YAML where required. This does not expose or retain the
owner configuration.

Changing router intent therefore requires a new image. Runtime state contains
leases, DNS journals, translation allocations, policy history, identities and
credentials, but it is not a second configuration source.

## Defaults and networks

Ordinary LANs receive DNS and NTP unless either service is disabled globally or
for that network. A DHCPv4 pool starts DHCPv4 and supplies the generated gateway,
DNS and NTP options. Management networks receive no ordinary LAN services and
cannot forward in either direction.

The default managed service ranges are `10.255.254.0/24` and subnet `fe02`
inside the selected ULA `/48`. DNS uses host `10` and NTP host `40`. An owner can
replace either range to retain existing service addresses.

IPv6 router advertisements and provider GUA assignment are independent. Turning
off GUA retains ULA service. Turning off RA retains configured addresses and
neighbour discovery without advertising client configuration. Every combination
is validated for IPv4-only, IPv6-only and dual-stack networks.

## Access policy

Named groups describe sources and destinations; they grant nothing by
themselves. Rules are evaluated in order and preserve interface, address, MAC,
family, protocol, port, direction and connection-state predicates. The default
is deny.

`authorization` has three modes:

- `owner` is static owner permission;
- `directory` requires a fresh, scoped delegated grant and terminates matching
  traffic with a denial when no grant is current; and
- `inherit` follows the source network's identity policy.

Owner and directory permission both remain behind mandatory source validation,
protected-network checks, connection classification, physical ownership and
translated-tuple validation. Neither authorization mode can bypass an earlier
deny or the automatic control-plane guards. Stale grants, lost ownership epochs,
wrong interfaces and crossed source/destination scopes fail closed.

Delegation limits constrain permissions issued by a directory without removing
the owner's ability to write a narrower static rule. Directory failure removes
directory-dependent traffic while independent owner rules continue to operate.

## NAT64 and NAT46

`translation.nat64` and `translation.nat46` are independent and disabled by
default. Enabling a translator creates reachability only. An access rule with a
matching translation selector is still required.

NAT64 lets selected IPv6 clients reach IPv4 destinations. Its public and private
source pools remain distinct, and retained dynamic source identities are bound
to their source, destination, interface, protocol, port and policy epochs.

The root supervisor publishes a four-second readiness witness containing the
child PID, kernel start ticks, boot-clock timestamp, configuration digest and
executable device/inode. A bounded worker checks the executable after dropping
to the translator UID; the worker cannot be traced by that UID. The policy
helper independently checks the live process and image-owned ELF while retaining
only `CAP_NET_ADMIN`. Failed probes, stale witnesses and executable changes deny
activation. This contract uses generated runtime files and requires no owner
YAML on the router.

NAT46 lets selected IPv4 clients reach only the configured IPv6 mappings. Each
mapping has a name, one IPv4 alias and one IPv6 destination. DNS records can
reference that name and return the alias for A and the target for AAAA. An
unmapped address never becomes arbitrary IPv6 access.

The compiler rejects overlapping pools and networks, duplicate aliases or
targets, mappings outside their pool, invalid retained allocations and
references to a disabled translator. It generates interfaces, routes, return
handling and translator runtime manifests for the enabled direction only.
Native and translated enforcement share the same ordered access decision.

## Optional components

The typed compiler covers authoritative and recursive DNS, DHCPv4, NTP,
controlled discovery, bounded BGP, RADIUS MAC admission, directory policy,
NAT64, NAT46, WAN IDS, metrics, log delivery, SNMPv3 and hardware ownership.
Disabling a component removes its listeners, routes, units and generated policy.

RADIUS admits MAC-authentication requests only; EAP and the unused inner tunnel
are disabled. Directory grants use freshness and epoch checks. Discovery reflects
only the declared browse types, networks, publisher scopes and DNS views. Log,
metrics and SNMP clients are restricted to their configured source selectors.
IDS observes the uplink and does not add inline blocking or download rules.

`owner: vpp` reserves an interface for acceleration. Assembly derives the PCI
function, driver transition, IOMMU group and hugepage plan from the ownership
declaration plus build-time hardware facts. Ambiguous devices, shared groups,
identity drift and insufficient memory reject the build or boot before device
mutation. A software-only router needs no acceleration settings.

## Persistent state and migration

Migration bindings identify persistent state without copying a previous settings
tree into the image. The protected state set includes machine identity, boot
trust, disk geometry, accounts, SSH host identity, leases, DNS journals, policy
history, translation allocations, credentials and extension state. Credentials
are referenced by protected runtime paths; their secret bytes do not enter
public configuration or build evidence.

Assembly rejects an image that cannot fit both installed root slots. Upgrade,
acceptance and rollback preserve the existing state directories and deployment
sequence. Those properties must be exercised again for each owner image and
target machine.

## Qualification coverage

The source suite covers minimal and segmented routers, all RA/GUA combinations,
custom service ranges, overlap rejection, hardware without acceleration and
optional-component withdrawal. Native parsers and network fixtures exercise
Kea, Unbound, Chrony, BIND, FRR, FreeRADIUS, Suricata, SNMP, discovery and log
configuration.

The policy-agent suite exercises native, NAT64, NAT46 and combined translation
paths in disposable kernel VMs. It covers TCP, UDP, ICMP, return traffic,
fragment/error handling, owner denies, directory outages and expiry, source
spoofing, stale translated tuples, physical egress changes and all configured
static mappings. Race, vet, lint and vulnerability checks are release gates.

Private parity tests are expected to bind the approved rule count, peer count,
mapping count, retained allocations and generated DNS records without exposing
those values in the public repository.

## Examples

[simple.yaml](../examples/simple.yaml) is a commented two-port IPv4 example with
synthetic values. [minimal.yaml](../examples/minimal.yaml) and
[segmented.yaml](../examples/segmented.yaml) are qualification fixtures. Keep a
complete commented owner configuration in the private repository together with
its private migration and hardware bindings.
