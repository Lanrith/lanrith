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
| `hardware.acceleration` | Explicit PCI ownership and hugepage allocation |
| `uplink` | DHCP/static IPv4, RA/static IPv6, gateways, optional IPv4 masquerading and CAKE upload rate |
| `networks` | Tagged or untagged attachments, gateways, RA, DNS, DHCP pools, optional routed source prefixes and forwarding isolation |
| `access` | An ordered list of generic routed allow/deny rules; unmatched new connections are denied |
| `administration` | Management networks, administrator public keys, account, port, root-access mode and optional serial login |
| `services` | Independent optional feature selection |
| `extensions` | IDs of separately reviewed integration manifests |
| `release` | Owner image identity and monotonic `sequence_floor` |

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

## Hardware and optional integrations

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
recovery is incompatible with this mode. Re-enabling root access requires a new
signed image or verified signed recovery media; no deployed setting can change
the mode. The owner YAML is consumed during compilation and is never installed
or read by the deployed image.

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
`/var/lib` or `/var/cache`. BIND and FRR use those paths with `LoadCredential`;
assembly does not read or copy their contents. Other components remain subject
to their runtime support gates. Without a binding, a credential uses
`/var/lib/lanrith/credentials/<name>`.

`runtime.service_identities` maps account names to required numeric `uid` and
`gid`, with optional `home` and `shell`. Assembly checks the admitted base and
admitted extension account registry, and rejects missing accounts, aliases or
changed values. These assertions do not create accounts, remap IDs or change
persistent ownership. `runtime.trust` maps declared `trust/<name>.pem` directory
CA references to public PEM certificate chains. Only certificates are accepted;
private keys and arbitrary files are rejected. Trust material and assertions
are included in the configuration digest. Keep private bindings out of public
examples and source releases.

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
