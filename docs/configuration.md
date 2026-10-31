# Configuration and integrations

`schema: 1` accepts only documented fields. Duplicate fields, YAML aliases,
unknown options, overlapping subnets, conflicting DHCP pools, invalid hardware
selectors and undeclared management networks fail validation. See the
[examples](../examples) and [compiler](../lanrith/config.py).

| Field | Purpose |
| --- | --- |
| `hostname` | Router's DNS label |
| `hardware.interfaces` | Stable MAC, udev path or driver selector, name and MTU |
| `hardware.storage` | Optional `/dev/disk/by-id` install target and ESP, root and state budgets in MiB |
| `hardware.machine_id` | Permanent device identity, generated once before installation; retain it across updates and recovery |
| `hardware.boot` | Secure Boot, TPM requirement and boot/recovery consoles |
| `hardware.watchdog` | `auto` (default), `required` or `disabled`; device and timeout in seconds |
| `hardware.fancontrol` | Optional hwmon temperature sources and explicitly selected PWM fan outputs; [details](fancontrol.md) |
| `hardware.acceleration` | Explicit PCI ownership and hugepage allocation |
| `uplink` | DHCP/static IPv4, RA/static IPv6, gateways, optional IPv4 masquerading and CAKE upload rate |
| `networks` | Tagged or untagged attachments, gateways, RA, DNS, DHCP pools, optional routed source prefixes and forwarding isolation |
| `access` | An ordered list of generic routed allow/deny rules; unmatched new connections are denied |
| `administration` | Management networks, administrator public keys, account, port, root-access mode and optional serial login |
| `services` | Independent optional feature selection |
| `extensions` | IDs of separately reviewed integration manifests |
| `release` | Owner image identity and monotonic `sequence_floor` |

Use `networks.<name>.dhcp4.id` to retain a DHCPv4 subnet identity, for example
`dhcp4: {id: 1024, pools: [192.168.10.100-192.168.10.200]}`. IDs must be unique
integers from 1 to 4294967294. They are independent of VLAN numbers. Kea uses
these IDs to associate leases with subnets, so retain the existing IDs when
importing a lease file. See the [Kea subnet identifier contract](https://kea.readthedocs.io/en/kea-3.0.0/arm/dhcp4-srv.html#ipv4-subnet-identifier).

Omitting `id` assigns the first unused positive number in network order, reserving
explicit IDs first. The normalized build input records every assigned ID so
canonical snapshots and native policy admission agree with Kea. Pin IDs in the
owner file before reordering existing networks or changing a persisted layout.
Disabled scopes reserve no ID. IDs are compiled into native configuration and
bounded runtime contracts; owner YAML remains build-only.

Selecting RADIUS admission also configures Kea's private Unix control socket
and the packaged lease-command hook used by its bounded admission collector.
Before startup completes, an unprivileged post-start check verifies the main
daemon's UID/PID and service group, then removes execute/other access with mode
`0660`. The `_kea` group is reserved for the daemon and explicitly admitted
service collectors. Admission collectors retain empty capability sets; they
need no DAC override. Missing readiness is bounded; an unsafe path or different
peer fails startup. Disabling RADIUS
omits the socket, hook and post-start check. The socket remains administrative IPC owned by
Kea's service account; ordinary users and observation-only consumers must not
receive access to it. Lease observations alone grant no forwarding permission.

## Access rules

Use the same rules for every routed destination. Network names come from your
`networks` map. `uplink` selects the declared uplink interface; `any` imposes no
interface restriction. An IP address or CIDR selects that address range. A list
matches any of its entries.

```yaml
access:
  rules:
    - name: Block a specific external host
      action: deny
      from: home
      to: {network: uplink, addresses: 203.0.113.9}
    - name: Allow home and guest Internet access
      action: allow
      from: [home, guest]
      to: uplink
    - name: Allow home access to the guest web service
      action: allow
      from: home
      to: {network: guest, addresses: 172.20.20.7}
      protocol: tcp
      ports: [443]
```

`name` is an optional human-readable label. Use 1–96 printable characters,
without leading or trailing whitespace. Named rules must be unique, ignoring
case. Names are preserved in the image's resolved configuration for inspection
and future console display. They are metadata: renaming a rule does not change
its match, position or permissions, and the compiler does not insert names into
firewall code. Unnamed rules remain valid.


The first matching rule decides. A selector with both `network` and `addresses`
requires both to match; a host exception therefore stays restricted to its
declared interface. An optional source `mac` adds another requirement. Use
`interface` instead of `network` for a declared integration's tunnel, transit
or namespace interface. Selectors never create interfaces, addresses or routes.

Omitted `protocol` means any protocol. Supported names are `tcp`, `udp`, `sctp`,
`icmp`, `icmpv6`, `gre`, `esp` and `ah`. `ports` are destination ports for TCP,
UDP or SCTP. An optional `family` restricts a rule to `ipv4` or `ipv6`;
address selectors and ICMP also determine the packet family.

Rules normally match `new`, `established` and `related` connection states.
They run before the automatic established/related return permit, so an explicit
deny also applies to matching existing traffic. Denies apply in either connection
direction unless `direction: original` or `direction: reply` narrows them.
Unmatched new connections are denied; an empty rule list grants no routed access.
`default: deny` can be written explicitly; `default: allow` is rejected.
Administration networks and enabled local service listeners remain separate.

Optional `states`, `direction`, `tcp_flags`, `icmp_types` and numeric `icmp_codes`
narrow an ordinary rule. States are limited to `new`, `established` and `related`.
Asymmetric returns that need an invalid/untracked exception belong to an admitted,
qualified routing capability with exact source/interface/target bounds. Ordinary
rules cannot bypass the earlier source, isolation or invalid-packet guards.
Descriptions are optional review text and are never interpreted as firewall code.
Unknown fields, malformed selectors, incompatible families and oversized rule
expansions fail validation before assembly.

Set `uplink.masquerade: true` if internal IPv4 traffic needs source NAT on the
uplink. This changes address translation; access rules still decide which traffic
may pass. It covers connected and declared routed IPv4 source prefixes, excluding
attachments with forwarding disabled. It defaults to false for the generic rules model. Translation mappings,
service addresses, directory policy and routing peers belong to their components.
They do not add platform-specific access sections or implicit grants.

Existing `internet`/`between_networks` configurations remain accepted, preserving
their routed grants and NAT defaults. Generated security guards apply to both
models. Convert the whole access section when adopting `rules`;
mixing the two models is rejected to avoid ambiguous ordering.

## Generated security and service rules

The access list describes forwarding decisions. It does not contain DHCP port
pairs, neighbour-discovery messages, return-packet plumbing or daemon egress.
Lanrith generates those from the selected network modes and enabled services.
Router input, forwarding and output all default to deny.

Source guards admit only the declared connected and routed sources on each
internal attachment and reject their spoofed use on the uplink. A private or
CGNAT uplink remains valid; there is no blanket ban on private WAN sources.
`networks.NAME.routed_prefixes` supplies additional non-overlapping prefixes routed
behind an attachment. It does not install routes or permit forwarding. Routing
peers and their import/export constraints still need configured routing support.

Set `networks.NAME.forwarding: false` for an isolated management or service
attachment. The firewall blocks both forwarding directions before ordinary
access rules and established-flow shortcuts; masquerading excludes it. Its
explicitly selected local listeners remain available. No network name, VLAN,
interface model or external backend implies a trust role.

DHCP bootstrap is restricted to the selected interface and local/broadcast
destinations. Uplink DHCP and RA rules follow the configured modes. IPv6 link
control uses declared interfaces, required hop limits and message codes; link-local
traffic cannot become routed transit. Network source-route and redirect protections
cover global defaults and interfaces present before or after sysctl activation,
including VLAN names containing dots. IPv6 routing headers are disabled rather
than retaining the kernel's type-2 exception. See the
[kernel sysctl reference](https://docs.kernel.org/networking/ip-sysctl.html) and
[systemd interface handling](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html).
The implementation preserves
essential IPv6 control/error traffic described in
[RFC 4890](https://www.rfc-editor.org/rfc/rfc4890.html).

Management access is generated with the selected interface, source prefixes and
local addresses. DNS/NTP listeners follow service selection. Their outbound
DNS/NTP queries use their package accounts; ordinary root or unrelated daemon
traffic does not gain arbitrary egress. SSH, DNS, DHCP and NTP service units bind
to successful nftables activation. Replacing a complete firewall through an
admitted integration also requires qualification of these boundaries.

The built-in compiler covers DNS, DHCP, NTP, controlled discovery, bounded BGP,
RADIUS MAC admission, directory policy, NAT64, NAT46, IDS, metrics, log delivery,
SNMP and VPP ownership. It derives listener, peer, namespace, translation and
return rules from typed component settings while preserving ordered owner denies
through native and translated paths. Enabling a package or component grants no
trust to a cluster, directory or backend. Temporary broad permissions remain
explicit owner rules.

Directory policy generates host egress for the policy reader's UID, exact
server addresses, TCP port, interface and assigned router sources. Targets need
an unambiguous declared ordinary attachment or a route through one. Router,
management, managed-service and translator identities are excluded. This
connectivity exception supplies no client forwarding permission.

An IP-literal directory URL uses that address directly. A named URL requires
`addresses` with one to eight unique IP pins. Lanrith emits the corresponding
host entries at build time and retains the URL hostname for TLS verification.
This avoids a dependency on DNS while enforcing exact destinations. Changing a
pin requires a new image. For example, with matching declared networks:

```yaml
identity:
  directories:
    devices:
      enabled: true
      url: ldap+starttls://directory.example.test:389
      addresses: [192.0.2.30, 'fd42:1234:5678:10::30']
      base_dn: dc=example,dc=test
      bind_dn: cn=router,dc=example,dc=test
      credential: directory_bind  # Protected runtime credential reference.
      ca_file: trust/directory.pem  # Reviewed public CA in runtime.trust.
  policy:
    enabled: true
    directory: devices
    networks: [devices]
```

With metrics enabled, a separate credential-free identity observes verified
directory TLS. Its results describe transport health; authenticated collection
and fresh grants have separate requirements. See [router health metrics](metrics.md).

When authenticated log delivery is enabled, Lanrith also emits a one-minute
heartbeat containing the accepted boot ID, selected entry, release sequence and
effective configuration digest. The timer is part of boot health and the event
uses the same redacted, TLS-authenticated, bounded Alloy queue as the journal.
The remote collector must alert on a missing or stale heartbeat and retain the
event outside the router. This is a liveness signal, not remote attestation: an
attacker with unrestricted root can forge local events.

## Hardware and optional integrations

See [router health metrics](metrics.md) for collector units, metric names,
query and inventory bounds, and source-admission behavior.

Defaults allocate a 1 GiB ESP, two 4 GiB root slots and 64 GiB encrypted state.
Surplus storage stays unallocated. Factory installation requires an eligible
512-byte logical-sector disk and explicit destructive confirmation. TPM is
required by default. A profile without TPM uses an operator-entered encryption
passphrase; it is never embedded in an image. Record the separate recovery key
offline before boot acceptance. Serial login is disabled unless enabled with a
private provisioning hash and a selected console. Kernel and journal output
must not disclose secrets on that console.

`administration.root_access` defaults to `enabled` for schema-1 compatibility.
Set it to `disabled` to build an image with no human UID-0 login or elevation
path. The administrator can still use key-authenticated SSH for unprivileged
inspection, but cannot use `sudo`, `sudoedit`, `su`, agent-forwarded PAM
authentication, set-user-ID programs or file-capability executables. Serial
login is incompatible with this mode. Re-enabling root access requires a new
signed image or verified signed recovery media; no deployed setting can change
the mode. The owner YAML is consumed during compilation and is never installed
or read by the deployed image.

`administration.root_access: disabled` removes root login, sudo and su. The
unprivileged operator can still upload an image and trigger the fixed update
service. A separately provisioned fixed-command recovery menu remains available
through `--recovery-passphrase-hash`; it grants no shell access. See
[boot recovery](recovery.md) for PCR signing and recovery build inputs.

Hardware watchdog defaults are `mode: auto`, `device: /dev/watchdog0` and
`timeout_seconds: 60`. Root and initrd use the same systemd watchdog policy.
`auto` works without a watchdog; when the selected device exists, boot acceptance
requires it to be active and owned by the system manager. `required` also rejects
missing hardware. Device selection accepts `/dev/watchdog0` through
`/dev/watchdog31`; timeouts accept integers from 10 to 3600 seconds. Hardware
may round the timeout to a supported value. `disabled` stops systemd from
opening a watchdog, including during reboot. It does not disarm a watchdog
already started by firmware or another owner. Qualify watchdog handover and
recovery on the selected hardware before deployment.

The shared components above have built-in typed configuration. Private products,
including a separately admitted console, continue to use integration extensions.
Merely installing a package or admitting an extension does not enable it.

An extension has `extension.json` and a `root/` directory. Its manifest contains
`schema`, `id`, `features`, `health_units`, and an exact `files` map of SHA-256,
size and numeric mode. The private repository pins the manifest digest in
`extensions.lock`. Ordinary files only are allowed; no links, devices,
maintainer scripts or build hooks run during signing. Health units become boot
acceptance requirements.

Use `start_units` for extension-owned services, sockets, timers or targets that
should start after core boot acceptance. Each unit must be inventoried under
`usr/lib/systemd/system/`. Lanrith starts them after the accepted boot observation;
their failure does not become a core boot requirement. Units also listed in
`health_units` remain mandatory. Extension units must keep their own dependency
and resource limits; `start_units` does not add a restart policy.

An optional `network` object declares host listeners and managed-service clients.
Both refer to users in the extension's `identities.users` list. For example:

```json
{
  "listeners": [{
    "user": "example-agent", "network": "home", "address": "192.168.10.1",
    "sources": ["192.168.10.0/24"], "protocol": "tcp", "port": 8443
  }],
  "services": [{"user": "example-agent", "service": "metrics", "family": 4}]
}
```

Listeners require an exact gateway address on the named network, explicit
same-family source prefixes within that attachment, TCP or UDP, and a port from
1024 to 65535. The configured SSH port is reserved. Management-network listeners
remain reachable only through their own attachment. These declarations add no
forwarding permission and cannot bypass source validation, OOB isolation or
translation guards.

Managed-service access currently supports the selected metrics API over TCP 9100,
using family `4` or `6`. It requires metrics to be enabled. Lanrith derives the
host-link source and service destination, admits the matching namespace input,
and checks the extension UID before accepting tracked output. Other unprivileged
UIDs cannot reuse those tuples. Declared UIDs receive no other external output
permission; existing host loopback policy and privileged-root authority remain.
This contract supplies network admission, not application authentication or a
sandbox for untrusted extension code. The owner must review the extension's units,
helpers and credentials.

Typed network declarations cannot be combined with a complete firewall
replacement. The build emits native rules only; no runtime extension parser or
owner YAML is needed. Removing a declaration removes its new-connection grant.

An optional `observations` manifest list selects a read-only policy endpoint:

```json
[{"service": "policy", "user": "example-agent"}]
```

The reader and its primary group must belong to that extension's identities.
Policy must be enabled, and only one reader across the active extensions is
supported. Lanrith generates the fixed socket
`/run/lanrith-policy-observations/observations.sock` and pins the reader UID.
The component checks kernel peer credentials and accepts only bounded observation
requests. This grants no proposal, status/operator or mutation endpoint access.

The core helper launcher prepares the root-owned, group-scoped socket and then
becomes the existing helper process. It uses the helper's existing capability
set and one supplementary reader group. Endpoint setup failures leave the two
mandatory helper sockets available; they create no failed optional socket unit
and do not change the native boot failure gate. Removing the declaration removes
the optional endpoint on the next image boot. Application schemas, adapters and
private account bindings remain extension responsibilities. Qualify the actual
selected component and complete image as well as the launcher before deployment.

The generated helper unit uses `Type=notify` and a 100-second startup limit.
Its selected component must implement the bounded post-start binding handoff:
ownership and application permits stay closed until the independent producer
supplies qualified evidence, and only then can the helper report readiness.
An `unobserved` observation reply does not establish readiness. A development
candidate passing the native harness does not qualify the pinned component
release or the owner's complete image.

The selected policy helper currently requires fixed post-NAT source addresses.
Combining directory policy with client masquerade or managed-service source
translation over a DHCP IPv4 or RA IPv6 uplink is rejected by `validate` and
`render`, before native profile assembly. Select static addresses for the
translated uplink families for that combination.
An ordinary router without directory policy retains DHCP WAN support. A policy
profile with no source translation can also use a dynamic uplink; a qualified
live source-address producer is required before translated dynamic policy paths
can be supported.

An optional `replaces` list explicitly admits replacement of compiler-generated
firewall, networkd, Kea, Unbound, Chrony or routing-sysctl files. This is for
reviewed advanced policy, including service namespaces. Conflicts without that
list fail. Boot, updater, trust, PAM, SSH and sudo authority remain protected.
Place custom runtime helpers under `/usr/lib/lanrith/integrations/` or an
owner-specific directory, and integration data under `/etc/` or
`/usr/share/lanrith/integrations/`.

Namespace, translation, OOB and acceleration helpers read compiler-generated
strict JSON manifests, not owner YAML or shell settings. SNMP reads its generated
runtime policy and a separately bound protected credential. There is no default
NIC model, PCI address or Linux driver. PCI binding checks the exact function,
interface, MAC, expected driver and exclusive IOMMU group before changing
anything. Shared groups are rejected. `lanrith-vpp-device.service` and
`verify-vpp-device` retain this ownership boundary. VPP/DPDK support for a chosen
NIC still needs qualification on that hardware. Acceleration devices are
separate from Linux-owned interfaces.

Declare both `lanrith-vpp-device.service` and `vpp.service` as selected health
requirements to unmask that integration. The optional hardware readiness unit
orders after VPP when VPP is selected, without pulling it into a software-only
configuration. It waits for declared hardware within a bounded boot deadline.

`router-network-status` checks only the interfaces declared in the compiled
configuration. Hugepages use the selected `hardware.acceleration.hugepages_mib`
budget in 2 MiB pages. No OOB port, separate LAN port, NIC model or fixed
hugepage count is required. Keep the associated units disabled until
that integration's configuration and hardware have been qualified.

Extensions are executable runtime code and policy supplied by the owner. Review
all bytes and qualify the resulting network behavior, disabled combinations,
state migration and withdrawal behavior. Adding a package to an owner image
also needs pinned package and vulnerability evidence; a configuration flag is
not package approval. The public base already includes the supported core
package universe, so ordinary configuration changes do not rebuild packages.

`administration.host_key_state` selects the protected persistent SSH identity directory.
The default is `/var/lib/lanrith/ssh-host-keys`; an owner migrating existing state
can select its existing root-owned directory. Every parent must be root-owned
and protected from writes by other users. An update keeps an existing key.

`administration.host_key_rotation` defaults to `retain`. After a root-compromise
recovery, set it to a freshly generated 128-bit lowercase hexadecimal value in
the signed build input. On the first boot of that generation, Lanrith atomically
replaces the persistent Ed25519 host key before SSH starts and records the
generation only after the new key and public key are durable. Reusing a value is
not a new rotation. The generation is not a secret, but it must be unpredictable
to persistent state prepared before the recovery image is isolated and built.
Clients must receive and verify the new fingerprint through an independent
channel.

Extensions cannot overwrite base package binaries. Existing service configuration
files need an explicit admitted `replaces` entry. Selected health requirements
activate the corresponding units; unselected optional daemons remain masked,
including activation through D-Bus or sockets.

An extension can declare `identities.users` (`name`, numeric `uid`, numeric
`gid`, optional `home`) and `identities.groups` (`name`, numeric `gid`, optional
`members`). These add locked service accounts with no login shell. The compiler
preserves core accounts, rejects duplicate names/IDs and checks the final native
registry. Account and sysusers files cannot be supplied as an ordinary overlay.
Review any ownership conversion of existing state separately.

Private migration inputs may supply an optional `runtime` object. Its
`credentials` map binds declared credential names to canonical files beneath
`/var/lib` or `/var/cache`. DNS, routing, directory policy, RADIUS and logging
stage selected inputs through `LoadCredential`. SNMP uses its managed activation
helper. Assembly does not read or copy credential values. The default path is
`/var/lib/lanrith/credentials/<name>`, except the SNMP input at
`/var/lib/lanrith/snmp/snmpd.conf`.

For active consumers, `/usr/share/lanrith/credentials.json` records the selected
references, paths, native formats and service units. Disabled integrations add
no requirement. It contains metadata only. The protected first-install writer,
operator protocol and boot gate are still under implementation; this catalog
does not seed an empty state filesystem.

`runtime.service_identities` maps account names to required numeric `uid` and
`gid`, with optional `home` and `shell`. Assembly checks the admitted base and
admitted extension account registry, and rejects missing accounts, aliases or
changed values. These assertions do not create accounts, remap IDs or change
persistent ownership. `runtime.trust` maps declared `trust/<name>.pem` directory
CA references to public PEM certificate chains. Only certificates are accepted;
private keys and arbitrary files are rejected. Trust material and assertions
are included in the configuration digest. Keep private bindings out of public
examples and source releases.

Persistent `/var` is mounted `nodev,nosuid,noexec`, and boot health rejects a
weaker effective mount. State is data, never an executable overlay. Component
readers still validate ownership, permissions, size and format; the mount flags
do not make attacker-controlled leases, journals, grants or credentials safe to
restore.

`health_units` contains shared requirements. An optional
`health_units_by_feature` map declares requirements for each selected feature.
A disabled feature does not activate its units merely because its extension is
present. Extensions with an empty `features` list activate their declared health
requirements when explicitly selected; this supports separately owned components.

Namespace egress integrations explicitly choose `lanrith_wan_mode` from
`static`, `routed` or `delegated`. Static mode supplies the service address and
prefix directly; routed and delegated modes provide the reviewed prefix and
address resolver functions and require an on-link WAN with proxy NDP. Other
WAN layouts can use an owner integration without these helpers. Service IDs
are owner-selected hexadecimal IPv6 host suffixes (`lanrith_unbound_service_id`
and `lanrith_chrony_service_id`), not fixed allocations. The owner supplies
`lanrith_service_ipv6_cleanup_prefix` to scope stale address and proxy cleanup.
Keep all allocations, functions, time sources, daemon configuration and
credentials in the private integration. Serial hardening helpers likewise use
an explicit enable flag and selected TTY; core boot acceptance uses the typed
owner configuration.
