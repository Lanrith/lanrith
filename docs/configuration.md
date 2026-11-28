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

Selecting RADIUS directory admission also configures Kea's private Unix control socket
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

## Link readiness and IPv6 client routes

Network-online waits for the configured address families on host-managed LANs.
Set `uplink.required_for_online: true` when boot requires addresses on the WAN.
The default permits the LAN to start with the WAN unplugged. An untagged,
IPv4-only interface with `role: management` keeps its static address without
carrier. IPv6 management retains duplicate-address detection.

`uplink.ipv6: ra` selects SLAAC. The router accepts prefix information and
upstream routes and ignores DHCPv6 Managed and Other Configuration flags.

A LAN with a global gateway prefix inside a fixed, routed `uplink.downstream_prefix`
advertises a default IPv6 route. Other LANs default to `ipv6_delivery: local`.
A local LAN advertises its SLAAC prefixes, specific routes to internal networks,
and routes to its selected DNS and NTP services. Its default-router lifetime is
zero. Clients that use the advertised off-link routes need RFC 4191 support.

Set `networks.<name>.ipv6_delivery: routed` when the upstream routes that LAN's
assigned subnet to the router. With `uplink.delivery: on_link`, install a more
specific upstream route for each routed LAN before selecting this option.
Verify the upstream route lookup and return traffic for a fresh client address.
For on-link delivery, networkd installs a proxy NDP entry for each selected
service address whenever the WAN appears. These addresses belong to the router
while that link is configured, including when a local service is stopped.

Use `networks.<name>.ipv6_upstream_routes` for specific unicast destinations
reachable through a private upstream. It takes a list of IPv6 prefixes, for
example `[fd12:3456:7890::/64]`. The upstream must route the client's source
prefix back to the router. The local scope permits native IPv6 WAN forwarding
only to these destinations and declared IPv6 `uplink.private_services`.
In routed scope, sources from the LAN's provider allocation can also reach
the public Internet. The ordered access policy still applies in both cases.

On an RA-enabled LAN, set `pref64: nat64` or `pref64: nat64-internal` to
advertise the enabled translator's prefix. The compiler checks for an applicable
IPv6 access grant, including a deliberately restricted one. Every client on
that LAN can see the prefix. The access rule still controls destinations,
ports and identities. Omit `pref64` to leave the option out. Existing profiles
that relied on automatic PREF64 need this selection on each eligible LAN.
Networkd advertises a lifetime of 1,800 seconds while the translator unit is
active. When the unit stops, the router removes the option from subsequent
advertisements. Clients can retain an earlier advertisement until it expires.

## Access rules

Image builds use the TUN policy backend by default. The compiler emits immutable
access rules and selector sets; the policy helper publishes fresh bindings and
expiring directory grants into those sets. NAT64 checks the IPv6 client side of
its TUN interface, and NAT46 checks the IPv4 client side. Stock TAYGA performs
translation. Neither component adds permission merely by being enabled.

Owner YAML is consumed only during the build. The installed root and initrd contain
native daemon files and narrow runtime JSON contracts. The image finalizer removes
the intermediate policy baseline, and the final-tree check rejects configuration
sources, compiler modules and the retired NAT64 allocation supervisor. New intent
requires a new image and an operator-triggered A/B update.

Image finalization also writes `policy-program.json`, a read-only snapshot of
the compiled native firewall objects bound to the policy program digest. An
observation extension can use this independent baseline to display installed
rules without reading the private delegation model or learning a baseline from
the running kernel. A matching rule or grant is not a packet outcome.

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

Host processes reach the managed DNS endpoint over the service veth. Chrony
uses the resolver on loopback inside their shared namespace. Public DNS uses
direct recursion by default. Set `services.dns.upstreams` to numeric addresses
for plain forwarding, or select authenticated DNS over TLS under `services.dns`.

```yaml
services:
  dns:
    tls_forwarding:
      trust: system
      upstreams:
        - address: 192.0.2.53
          authentication_name: resolver.example.net
```

Supply the address of a reachable forwarder on TCP port 853. Its certificate
must cover the declared name and chain to the image's system CA bundle.
If every forwarder fails verification, the resolver returns SERVFAIL. Private
zones retain their own handlers.
For private DNS64, `services.dns.private_dns64_startup` defaults to `required`.
Choose `independent` to start public DNS after a failed private service start.
The private service still participates in boot health checks. Enabling
NAT64 with discovery also starts this resolver when BIND is disabled.
Discovery lookups use an eight-second TCP deadline at the child authority and
a thirty-second outer deadline across the DNS64 chain.

Ordinary DNS clients query Unbound. Add an attachment and source address to
`services.dns.authoritative.direct_readers` for each client that needs to query
the primary directly. Configured publishers can query from their declared sources.
Each writer needs a TSIG key and an allowed source on its declared attachment.
With `grants` omitted, that source and key can publish new names throughout
the writer’s zone, including TXT ownership records. Zone transfers require
`zone_transfer: true` and the same source and key. A transfer-only client
sets `grants: []` and `zone_transfer: true`.

```yaml
direct_readers:
  - {network: home, addresses: 192.168.10.23}
zones:
  example.test:
    persistent: true
    records:
      controller.lab: {A: 192.168.10.50}
    fixed_records: [controller.lab]
writers:
  inventory:
    zone: example.test
    sources: {network: home, addresses: 192.168.10.20}
    key_name: inventory-key
    credential: inventory_tsig
    zone_transfer: true
```

A publisher can replace or remove ordinary persistent seed records. Mark a
relative address owner in `fixed_records` to keep the declared A and AAAA
answers. Use the quoted YAML key `'@'` in `records` and `fixed_records: ['@']`
to fix the zone apex itself. Writers cannot change any record type at a fixed name or add an NS
delegation or DNAME redirection above it. BIND also protects the zone apex NS
and SOA, the built-in service addresses in the primary zone and the path to
every configured child zone. The parent reserves NS, DS, CNAME and DNAME at
a locally hosted child’s origin. Fixed names
use DNS case-insensitive matching. An explicit grant list narrows the writer’s
authority to particular names, subtrees and record types.

```yaml
grants:
  - {subtree: apps, types: [A, AAAA, CNAME, SRV, TXT]}
  - {name: status, types: [TXT]}
```

A subtree includes its root. `subtree: '@'` covers the zone. Exact grants and
static or fixed address names share the overall 1 MiB configuration file limit.

To delegate discovery views, add `discovery_delegation` to the immutable
authoritative zone matching `services.discovery.domain`. For example,
`discovery_delegation: {views: [home, devices], publish_browse: true}` creates
child NS records, addresses for the discovery nameserver, and DNS-SD browse
PTRs for those views. Readers can discover the default view when it appears
in this list. Omit `publish_browse` to publish only referrals and nameserver
addresses. To admit an independent resolver, declare its source in both
`services.dns.authoritative.direct_readers` and `services.discovery.direct_readers`,
for example `[{network: home, addresses: 192.168.10.23}]`. A child reader can
query all configured discovery views. With the lists omitted, ordinary clients
use the managed recursive resolver. Choose a forward domain outside `local.` and
`arpa.` and map each DNS view to a distinct collected link.

A persistent authoritative zone starts from its image seed. To keep a particular
RRset under release management after first boot, declare it under
`services.dns.authoritative.zones.<zone>.managed_rrsets`. This zone fragment
adds a service IPv6 address and changes an existing IPv4 address.

```yaml
persistent: true
records:
  status: {AAAA: '2001:db8::53'}
  relay: {A: 192.0.2.22}
managed_rrsets:
  status: {AAAA: {previous: []}}
  relay: {A: {previous: [192.0.2.20]}}
```

`previous` lists every value in the expected old RRset. An empty list requires
the set to be absent. To withdraw a record, remove it from the seed and keep
its old values under `managed_rrsets` with `remove: true`. A, AAAA and CNAME
are supported, including addresses that the compiler generates for services.

At startup a private BIND instance replays the zone journal and applies all
pending changes for that zone in one DNS UPDATE. If the current data matches
neither the desired set nor its prerequisite, named stays stopped and the boot
health check fails. Assign each managed set with its publisher before upgrading.
Publishers lose write access to each selected address type and to CNAME at
that name. A managed CNAME reserves the whole name. Other seed entries continue
to serve as first-boot defaults.

For an existing zone, startup replays the journal, completes the declared
`managed_rrsets` transitions and checks each fixed address and its delegation
path before public DNS starts. A matching address can become fixed in place.
For a newly fixed name missing from the stored zone, add a transition with
`previous: []`. To change an existing fixed address, set its new value in
`records` and list the actual previous RRset under `managed_rrsets`. To retire
a previously published address family, use `remove: true` for its old RRset.
A conflicting stored value or existing covering delegation stops public DNS.
Resolve an unintended NS or DNAME with the previous configuration before
adopting that name as fixed.

Both image slots share the zone and journal. Check fallback against the
post-upgrade records. An older slot with a managed declaration needs a matching
reverse transition to restore the previous value. If only the journal survives a
restore, recover the matching base zone before starting named.

The built-in compiler covers DNS, DHCP, NTP, controlled discovery, bounded BGP,
RADIUS MAC admission, directory policy, NAT64, NAT46, IDS, metrics, log delivery,
SNMP and VPP ownership. It derives listener, peer, namespace, translation and
return rules from typed component settings while preserving ordered owner denies
through native and translated paths. Enabling a package or component grants no
trust to a cluster, directory or backend. Temporary broad permissions remain
explicit owner rules.

The system journal stores logs on encrypted `/var`. At boot the flush unit
writes a marker through `/dev/log`, then reads it from the persistent machine
journal and checks journald's reported storage limits. If the unit fails,
inspect `journalctl -b -u systemd-journal-flush.service`. After repairing the
destination, restart the unit to retry the flush before rebooting.

Use `observability.journal.system_keep_free_mib: 8192` to reserve 8 GiB
against journal growth. Omit the field to use journald's filesystem-based
reserve. `system_max_use_mib` sets the journal cap in MiB and defaults to
1024. It accepts values from 128 through the configured state partition
size. Other services can consume space inside the reserve. The updater checks
its own working space when it admits an image.

For local syslog delivery, set `observability.journal.syslog_receiver_unit`
to the name of a socket-activated service installed under
`/usr/lib/systemd/system/` by the base or a selected integration. The service
must consume the datagram descriptor from
`syslog.socket`. Without a declaration journald accepts `/dev/log` input and
disables local syslog forwarding. Alloy reads the journal independently.

Set `observability.ids.enabled` to observe the WAN with two signed packet
signatures. SID 1000001 reports an incoming TCP SYN to port 22. SID 1000002
reports an incoming ICMPv6 echo request. Each signature emits up to six
observations per minute across all senders. The destination group uses declared
attached and managed service subnets, routed client prefixes and static
addresses on the router's WAN. The provider gateway counts as external. An
address learned dynamically on the WAN can fall outside these groups. WAN
observations alone cannot identify a client behind source NAT or establish an
SSH authentication outcome.

The sensor writes local EVE to `/var/log/suricata/eve.json`. To forward the
SID, event time and WAN interface to the configured log destination, set
`observability.ids.forward_alerts: true` with log delivery enabled. The
observer projects these fields before Alloy queues the message. With metrics
enabled, the host collector also receives aggregate capture-health counters.

With discovery enabled, the collector can browse Avahi records, the publisher can
create and withdraw them, and root can query the daemon state. To grant another
installed Unix account access, set `services.discovery.local_clients` to a map
from account name to `status`, `browse` or `publish`. For example,
`local_clients: {admin: status}` allows the administrator to call `GetState`.
A publish grant lets that account register records directly on Avahi's selected
links. Membership in `netdev` alone grants no Avahi methods.

Directory policy generates host egress for the policy reader's UID, exact
server addresses, TCP port, interface and assigned router sources. Targets need
an unambiguous declared ordinary attachment or a route through one. Router,
management, managed-service and translator identities are excluded. This
connectivity exception supplies no client forwarding permission.

An IP-literal directory URL uses that address directly. A named URL requires
`addresses` with one to eight unique IP pins. Lanrith emits the corresponding
host entries at build time and retains the URL hostname for TLS verification.
This avoids a dependency on DNS while enforcing exact destinations. Changing a
pin requires a new image.

The directory server normally sees a router address on its outgoing network.
If the server only admits the managed RADIUS address, set `source_service: radius`
on the directory used by RADIUS admission. The policy reader and the optional TLS
probe then use the managed IPv4 or ULA source for connections to that directory's
pinned addresses and TCP port. The server needs a return route to the service range.

For example, with matching declared networks:

```yaml
identity:
  directories:
    devices:
      enabled: true
      url: ldap+starttls://directory.example.test:389
      addresses: [192.0.2.30, 'fd42:1234:5678:10::30']
      base_dn: dc=example,dc=test
      bind_dn: cn=router,ou=users,dc=example,dc=test
      credential: directory_bind  # Protected runtime credential reference.
      ca_file: trust/directory.pem  # Reviewed public CA in runtime.trust.
  policy:
    enabled: true
    directory: devices
    networks: [devices]
```

The default mapping reads Authentik accounts under `ou=users` and groups under
`ou=groups`. For a different schema, set `mapping` on the directory. This
example uses OpenLDAP entries with a MAC address, an explicit account state,
a stable entry UUID and DN-valued direct group membership.

```yaml
mapping:
  users_base_dn: ou=devices,dc=example,dc=test
  groups_base_dn: ou=roles,dc=example,dc=test
  user_object_class: inetOrgPerson
  group_object_class: groupOfNames
  user_id: entryUUID
  group_id: entryUUID
  user_rdn: uid
  group_rdn: cn
  device_mac: macAddress
  group_name: cn
  device_active: employeeType
  active_value: enabled
  inactive_value: disabled
  group_member: member
  group_policy: description
```

Both search bases must be within `base_dn`. The reader searches the immediate
children of each base by default. Set `user_scope` or `group_scope` to
`subtree` for entries in nested organizational units. In a custom mapping, the bind account can reside
elsewhere under the same base. Map `group_policy` to an attribute that holds
one Lanrith policy JSON value on policy groups. Restrict who may write that
attribute, account state and membership. Add `member_of: memberOf` to require
agreement between both membership directions when the directory maintains
backlinks. Otherwise the group's member DNs supply direct membership. Use the
same spelling for DN values in entries and their membership references.

For a binary stable identifier such as `objectGUID`, set `user_id_encoding`
or `group_id_encoding` to `hex`. The reader preserves the underlying bytes
as hexadecimal digits. For an integer account-control attribute such as
`userAccountControl`, replace `active_value` and `inactive_value` with
`disabled_bit: 2`. A malformed or missing state on a device prevents renewal.

`search_mode` defaults to `auto`. The reader first requests complete, bounded
LDAP searches. If the server reports a size limit, the reader discards the
attempt and starts over with critical RFC 2696 paging. Set `paged` to require
paging from the first request or `unpaged` for a directory that can return
both searches in full. Referrals, incomplete reads and timeouts leave the
previous grant expiry in force.

When you declare a mapping or search mode, image assembly checks the settings
and bind DN with the reader binary inside that image. The check runs offline
and requires no directory password.

With metrics enabled, a separate credential-free identity observes verified
directory TLS. Its results describe transport health; authenticated collection
and fresh grants have separate requirements. See [router health metrics](metrics.md).

The policy helper requires a synchronized kernel clock at startup and after a
link replacement. If this image supplies clock synchronization, configure trusted
upstreams in `services.ntp`. Without a synchronized clock the helper withholds
grants. Test clock recovery alongside restoration of the policy interfaces.

Enabling log delivery installs a one-minute heartbeat timer. After promotion, a
dedicated unprivileged writer emits the accepted boot ID, selected EFI entry,
release identity, configuration digest, monotonic tick and original UTC time
in nanoseconds. Alloy sends it through the same bounded TLS queue as the
journal. Retain the receiver records outside the router and check them against
the accepted boot. A privileged router process can forge local events.
[Receiver alarm and qualification](qualification.md)

### Local time service

Omitting `services.ntp` disables chrony and the DHCP NTP option. To enable time
service, list the upstreams your site trusts. A string selects a pool with
chrony's default target of four responding members for a name. A numeric
address identifies one peer. The addresses and names below are examples.

```yaml
services:
  ntp:
    enabled: true
    upstreams:
      - {type: server, address: 192.0.2.123}
      - {type: pool, address: time.example.test, family: ipv6, maxsources: 2}
    total_sources: 3
    require_numeric_source: true
    ratelimit: {interval: 3, burst: 8, leak: 2}
```

`family` accepts `ipv4` or `ipv6`. A pool's `maxsources` target ranges from 1
to 16. Optional `total_sources` checks the sum of the targets. A pool may try
more candidates while finding responders. Distinct names can resolve to the same
peer. Check actual diversity and reachability with `chronyc -n sources`.

Use `require_numeric_source` when a cold router must acquire time even if DNSSEC
rejects upstream names because its clock is stale. Choose a maintained, reachable
address whose time you trust. Directory grants need synchronized kernel time.
Declare the local NTP service for that deployment, or explicitly set
`services.ntp.enabled: false` when another mechanism disciplines the clock.

On LANs with NTP access and DHCPv4, Kea advertises the local listener in
option 42. Client-selected destinations follow ordinary forwarding policy. **Before upgrading a LAN that
enforces local time**, set `networks.<name>.ntp_intercept: true` to retain its
UDP/123 redirection. A redirected client cannot authenticate an NTS response
for its original external server.

The optional `ratelimit` applies per apparent client IP. The example permits
a burst of eight replies with an average interval of eight seconds and a
one-in-four chance of replying beyond the limit. Clients behind a single NAT
address share that budget. Omitting the setting leaves chrony's response
limiting disabled.

## Hardware and optional integrations

See [router health metrics](metrics.md) for collector units, metric names,
query and inventory bounds, and source-admission behavior.

Defaults allocate a 1 GiB ESP, two 4 GiB root slots and 64 GiB encrypted state.
On the installed router, `hardware.storage.initialization_timeout_seconds`
bounds the host slot and encrypted-state check. The default is 120 seconds.
Set a value from 1 to 3600 seconds using cold-start measurements from the
target storage. The initrd factory and recovery enrollment have separate
deadlines. The host check journals any busy or undersized standby roles.
Root can read the most recent storage observation in
`/run/lanrith/slot-health.json`.

Surplus storage stays unallocated. Factory installation requires an eligible
512-byte logical-sector disk and explicit destructive confirmation. TPM is
required by default. A profile without TPM uses an operator-entered encryption
passphrase; it is never embedded in an image. Record the separate recovery key
offline before boot acceptance. Serial login is disabled unless enabled with a
private provisioning hash and a selected console. Kernel and journal output
must not disclose secrets on that console.

For a shared serial port, set `administration.serial.cooldown` to a mapping
with `attempts` (2–10) and `seconds` (1–300). For example, three attempts
and 30 seconds block serial passphrase checks for 30 seconds after the third
consecutive rejection. Each counted rejection starts a fresh interval. A
successful check or an interval without another counted rejection clears the
count. Attempts during the cooldown leave the deadline in place. The count
survives getty restarts and clears on reboot. The default omits this cooldown.
Authorized SSH agent elevation remains available during a serial cooldown.

Factory prompts are available on the monitor and the serial ports selected by
`hardware.boot.console`, `hardware.boot.recovery_console`, or enabled
`administration.serial`. Serial provisioning uses 115200 8N1 unless
`hardware.boot.console` supplies a baud rate for that port. A build with monitor
boot output and serial recovery therefore supports installation through either.
The builder records these devices in the signed runtime manifest; no owner YAML
is needed on the installed system. Selecting a console for initial key enrollment
does not change the configured authenticated recovery menu or enable serial login.

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

SSH binds the gateway addresses of the selected host management networks on
`administration.ssh_port` (default 22). If a link comes up late, SSH starts
on the available addresses and reloads as the others arrive. Boot readiness
requires every declared address and its listening socket. Inspect
`journalctl -u ssh.service -u lanrith-ssh-listeners.service` for pending
addresses and reloads.

To keep agent-backed sudo and close the other SSH forwarding channels, add
these mappings under `administration`.

```yaml
ssh_forwarding:
  agent: true
  tcp: false
  unix: false
  x11: false
ssh_limits:
  max_auth_tries: 3
  login_grace_seconds: 30
  client_alive_interval_seconds: 300
  client_alive_count_max: 3
```

Each forwarding choice is optional. Omitted channels follow Debian’s SSH
configuration, which enables all four. Rootless images disable agent forwarding
and reject `agent: true`. Setting `agent: false` on a root-enabled image
removes the forwarded agent needed for sudo over SSH.

Debian defaults to six authentication attempts and a 120-second login grace
period. The default probe interval is zero and the default count is three.
Specify whole seconds for the two time settings. A zero grace period removes
the authentication deadline. A zero interval disables probes, and a zero count
keeps unresponsive sessions open. The attempt limit must be at least one.
All four settings accept integers up to 2147483647.

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

An optional `credentials` list declares protected secret slots for an extension:

```json
[
  {"name": "bootstrap", "format": "json", "consumers": ["example-app.service"]}
]
```

Each consumer must be a literal `.service` file in that extension's inventory.
Template units and core service replacements are rejected. Lanrith derives the
root-only path `/usr/lib/lanrith/credentials/extensions/EXTENSION/NAME`, generates
`LoadCredential=NAME:PATH` for the declared readers, and binds the reader set into
the catalog digest. Build-time `credentials` entries supply the values. The manifest and provenance
contain no values; the private image contains root-only credential files.

The supported value format is a UTF-8 JSON object, at most 64 KiB, with unique
keys, finite numbers, at most 4,096 nodes and nesting depth 16. An extension can
declare 16 slots and 64 service readers. Its consumer must validate the
application-specific schema and authentication material before using them.
The shared runtime never executes supplied JSON or accepts caller-selected file
paths, unit names or commands.

All active extension slots require build-time sources, including optional
extensions. An extension implementing a selected core feature, or declaring
mandatory `health_units`, must pass health checks before boot acceptance.
Disabled feature providers emit no credential catalogs or reader bindings.
There are no runtime provisioning sockets or credential transaction histories
for image credentials. See [credential provisioning](operations.md#extension-credential-provisioning).


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

An optional `observations` manifest list selects fixed read-only endpoints:

```json
[{"service": "policy", "user": "example-agent"},
 {"service": "logs", "user": "example-agent"},
 {"service": "dns", "user": "example-agent"},
 {"service": "firewall", "user": "example-agent"}]
```

The reader and its primary group must belong to that extension's identities.
Each endpoint supports one reader across active extensions and requires its
corresponding component to be enabled. Each endpoint may be selected alone.
For policy, Lanrith generates the fixed socket
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

For DNS, the declaration enables Unbound's client query and response dnstap
messages. Resolver and forwarder copies, server identity and version are excluded.
The fixed ingress `/run/lanrith-dns-tap.sock` admits only Unbound's Unix UID.
A separate locked collector account is allocated during image assembly from
unused system IDs, after base and extension IDs have been reserved. It needs
no capabilities, Internet sockets, DNS credentials or persistent state. Its
confined process receives the boot ID through one read-only bind; no runtime
owner configuration or account provisioning is needed.

The admitted reader receives read access to
`/run/lanrith-dns-observations/events.jsonl` and `health.json`. It cannot write
the directory or impersonate the resolver. Metadata includes client address,
transport, question, producer time, transaction hash and bounded answer summaries.
Each record carries its boot ID, producer epoch and successful-write ordinal.
When Unbound supplies a bounded query-start timestamp, it is retained exactly
as nanoseconds alongside the response time; consumers need not reconstruct it
from floating-point latency. Old spool files retain their original producer
identity across collector restart, allowing replay detection independently of
current health counters.
The compiled collector manifest advertises `record_schema: 1`; an admitted
adapter can require that contract while building its image.
TXT and other arbitrary record payloads, raw DNS packets and server identity
are omitted. A and AAAA addresses and NS, CNAME, PTR and MX targets are retained
for up to 16 answers. Unsupported, oversized, stale or malformed messages are
rejected. Query metadata without a corresponding response does not prove a DNS
timeout or a firewall decision.

The volatile spool holds at most three 1 MiB files, with complete JSON lines
bounded to 16 KiB. Rotation discards older observations. Health reports a new
producer epoch on each collector start, same-boot monotonic freshness, emitted
and rejected records, failed writes, overwritten records and disconnects.
These are collection counters; loss inside Unbound or before the collector is
not fully measurable. Consumers must report gaps and avoid claiming complete
DNS history. A quiet file is not a resolver health signal.

The candidate `firewall` endpoint records sampled host input/forward default
drops. Assembly preserves all existing rules, then adds a bounded logging
statement immediately before an unconditional counter/drop in each default-deny
path. Typed extension listeners are resolved first, and the manifest binds the
final generated ruleset. A whole-firewall replacement cannot select this
endpoint. Earlier guards, explicit-owner rules, policy-agent, translator,
output and service-namespace decisions remain outside its observation coverage.

Its locked account is allocated at build time, independently of the DNS
collector. The service briefly needs NET_ADMIN to bind one fixed NFLOG group;
before decoding packets it clears effective, permitted, inheritable and ambient
capabilities. The bounding set remains NET_ADMIN only, and NoNewPrivileges
prevents regaining it through exec. The admitted reader receives only group
read access to `/run/lanrith-firewall-observations`, with no kernel socket or
firewall-control authority. Stopping the receiver or exhausting the log sampler
does not affect the unconditional drop.

The shared volatile spool has the same three-file and line bounds as DNS. Each
record binds original kernel time, boot, producer epoch, ordinal, ruleset hash,
hook and rule identity to a bounded IPv4/IPv6 TCP/UDP/ICMP tuple. Packet payloads,
MAC headers, marks and socket-owner details are omitted. Health separates
rejections, failed writes, overwritten records, kernel sequence gaps, netlink
overrun signals and startup gaps. These cannot establish complete packet counts
or original client identity through translation. The mandatory base/admission
gate binds the executable, shared libraries, implementation and generated service
tested in a disposable container. Complete-image and consumer integration
qualification remain required before release.

DNS starts with a bounded, optional socket dependency and has no collector
readiness dependency. The collector retries at five-second intervals without
entering the boot check's terminal failed-unit set for a rejected runtime
contract. Its resource limits and log rate limit remain in force. An absent or
stalled reader does not grant access or stop resolution. Removing the observation
declaration removes its native configuration, account, socket and collector from
the next image; DNS remains enabled independently. The private DNS64 upstream
resolver is not tapped, so translated recursive copies are not counted twice.

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

Run `/usr/lib/lanrith/router-network-status --details` as root to print a
timestamped JSON sample. It includes Linux port drivers and MTUs, the configured
hugepage size and its persistent, free and reserved page counts. For a dormant
reservation it also shows the PCI driver, IOMMU members, netdevs and any Linux
identity observed before binding during this boot. A null field means unknown.
The VFIO descriptor sample lists visible PIDs holding the selected group or
device character node. An incomplete scan is marked unknown. A descriptor
observation alone cannot establish exclusive DMA access.

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

`administration.host_key_rotation` defaults to `retain`. A new appliance
generates one Ed25519 key on empty state. If a public key or provisioning
record survives without the private key, SSH waits for recovery. Restore the
device's private key from its encrypted backup and compare the served
fingerprint with the device record held outside the router. An intact pair
starts on full state. A missing or stale public half is repaired from the
private key when space is available.

To rotate after recovery, set `host_key_rotation` in the signed build input to a
fresh, unpredictable 32-digit lowercase hexadecimal generation. First install
and accept a release with the transactional host-key reader and `retain` on the
same state directory. Image admission checks that the fallback can read the new
format. On the rotation release the helper stages one private candidate,
commits its fingerprint and generation, and removes the staged copy. If power
fails during this operation, boot the image authorizing the pending generation
to finish it. Once committed, the fallback can serve the new identity. Verify
and distribute its SHA256 fingerprint through an independent channel.

For restore verification, set `administration.host_key_pin` in the signed image
to a mapping with `generation` and `fingerprint`. Use the 32-digit generation
(or `retain` for a never-rotated key) and the OpenSSH `SHA256:...` fingerprint
from the device's independent record. The helper checks the private key before
adopting a historical generation-only marker. A wrong or missing private key
blocks SSH. An unpinned image can accept a consistent older snapshot of all
state. Keep the current generation and fingerprint outside the backup, and
use the pin when restoring. A fallback pinned to a different identity cannot
accompany a new rotation.

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

The build-time `credentials` map is optional. A basic router with DHCP, recursive
DNS, NTP and Internet forwarding needs no service credentials and no credential
readiness gate. Add entries only for authentication used by enabled integrations:

| Integration | When a credential is required |
| --- | --- |
| Authoritative DNS | Each configured signed-update writer; static zones need none |
| BGP | Each peer group configured with password authentication |
| Directory policy | The directory selected by the enabled policy; unused directories need none |
| RADIUS | Shared secrets for configured UDP NAS clients and a UDP upstream proxy; a directory bind is separate and optional |
| Remote logging | Only `authentication: basic`; `authentication: none` needs no credential |
| SNMPv3 | The enabled monitoring user |
| Extensions | Credential slots declared by an active admitted extension |

Disabled integrations require no secret values. Their entries may remain in
`credentials`: the builder does not read, validate file contents or embed unused
inputs. Disabling DNS also disables its authoritative service and writer keys.
Public SSH keys and build signing inputs are separate from this map.
Extension references use `EXTENSION/NAME`:

```yaml
credentials:
  directory_bind: {file: /run/private-build/directory-password}
  example-addon/bootstrap: {file: /run/private-build/addon-bootstrap.json}
```

An enabled HTTPS log exporter can omit both `username` and `credential` for
collectors without client authentication, or set `authentication: none`
explicitly. TLS certificate and server-name validation still apply. Supplying
both fields selects Basic authentication; `authentication: basic` can make that
choice explicit. A partial pair or credentials combined with `none` is rejected,
so a missing password cannot silently turn authentication off.

RADIUS MAC admission uses a UDP proxy. Set each NAS client and proxy to
`transport: udp`, or omit the field for its default. Give each endpoint its
shared-secret reference. These credentials authenticate the endpoints. The
backend supports proxy authentication over UDP only. With
`admission: {network: devices}`, the router accepts the upstream decision for
the declared VLAN.

For directory admission, select `directory`, `group_dn` and `network`.
The directory policy reader uses its own bind credential. FreeRADIUS uses the
provider's authenticated reply. Set `admission.provider_policy` to the logical
provider name (`provider`), the SHA-256 of the active provider policy
(`revision`), and its independently trusted export digest (`binding_sha256`).
The release checks these fields during configuration validation.

Obtain the export from the provider administrator's authenticated readback of
the effective group policy and response mapping. Export a group DN only when
membership is required on every path that can grant the VLAN. The provider
administrator should verify this with both a member and a nonmember. The
following JSON illustrates the export fields. Substitute the active revision.

```json
{
  "schema": 1,
  "provider": "inventory-admission",
  "revision": "<64 lowercase hex digits>",
  "endpoint": "10.20.10.32",
  "directory": "inventory",
  "directory_url": "ldaps://directory.site.example.test:636",
  "directory_base_dn": "dc=example,dc=test",
  "group_dn": "cn=devices,ou=groups,dc=example,dc=test",
  "vlan": 20
}
```

`endpoint` is the canonical IP of the RADIUS provider. The directory name,
URL and DNs use the strings in the release. Hash the **provider export**
using `hashlib.sha256(lanrith.release.canonical(export)).hexdigest()`. This
encoding sorts JSON keys, uses ASCII escapes and compact separators, and ends
with one newline. Pin the digest through the release owner's trusted channel.
Requalify the active provider revision and its member and nonmember decisions
when changing the group, upstream or VLAN. Keep the provider revision in sync
with every router slot that might run during rollout or rollback.

For wired fallback, `fallback.clients` selects individual wired NAS addresses
and ports. Set `provider_response_seconds` to the qualified upper bound on
ordinary RADIUS responses, rounded up to 1–26 seconds. Set `nas_retry_seconds`
to the shortest first retry or give-up interval among those clients, in whole
seconds rounded down. The deadline must allow three seconds beyond the
provider bound, up to 120 seconds total. The proxy gives the provider one
second of headroom and leaves at least two seconds for local handling and
delivery before the NAS retries. Measure these values with the actual NAS
and provider under expected load.

An unanswered request may use the last live approval for that MAC, NAS and
port. The in-memory cache holds at most 256 entries for five minutes each.
A wired fallback lookup preserves the original expiry. An authenticated reject,
a challenge, or a live approval with incompatible VLAN attributes removes the
entry.
Restarting FreeRADIUS starts with an empty cache.

Paths must be absolute and canonical. Files must have mode `0400` or `0600`
and belong to the build user. Assembly rejects missing, linked or malformed
inputs required by active consumers before creating the build workspace. The
native formats are TSIG Base64, a BGP token, a directory password, a RADIUS shared secret, a logging
password, and the bounded SNMP user configuration. Extension inputs are JSON
objects. The generated catalog records formats, paths and consumer units;
credential values are held separately in root-only image files.

The YAML and source paths are build inputs only. Images and USB installers that
contain these files are secret media: verified root storage does not encrypt
them. See [credential provisioning](operations.md#service-credential-provisioning)
for handling, A/B rotation and fallback requirements.

Legacy `runtime.credentials` paths describe older mutable-state integrations.
They cannot be combined with image credentials and cannot satisfy the complete
credential-input requirement for new builds. `runtime.credential_headers` may
still select the expected header for a retained SNMP input format.

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


The `logs` endpoint uses the selected journal exporter's existing redaction
pipeline. Its local branch replaces every message body with `journal message
withheld`; it exports the journal's producer timestamp as OTLP `timeUnixNano`,
boot/transport metadata and the bounded host/job/unit/priority attributes. The
remote branch retains its redacted message and separate persistent queue. This
adds no console-specific name, raw journal reader, listener or network grant.

The logging pre-start command reads only its systemd credential copy. It accepts
a private owner file or a root-owned file with an exact named-user read ACL for
the exporter UID. It rejects group/world grants and additional named users.
This follows [systemd's credential writer](https://github.com/systemd/systemd/blob/v257/src/core/exec-credential.c#L294-L339)
without changing access to the protected credential store.

The exporter writes JSONL to `/run/lanrith-log-observations/events.jsonl`, with
1 MiB rotation and two backups. The root staging helper prepares the fixed directory for the exporter and
the admitted reader's primary group, mode `2750`. It is separate from systemd's
`RuntimeDirectory` ownership so the reader group survives the transition to the
main command. New files inherit that group.
The selected exporter creates mode `0644` files; the protected parent directory
prevents other users from reaching them. The reader cannot modify files or the
directory and receives no membership in the exporter's credential or journal
groups. Missing or reassigned reader accounts close read access while the
exporter continues privately. Unsafe retained paths are rejected before startup.

`health.json` in that directory carries a same-boot monotonic observation and
separate `local_sent_records` and `local_failed_records` counters, plus a
`producer_epoch` that changes when the exporter supervisor restarts. Local write
failure does not stop remote export or its watchdog. The generated unit limits
its own journal emission to 50 messages per 30 seconds. This is a bounded
observation stream, not durable journal storage or proof of service health.
Rotation, filesystem faults and restart can lose records; consumers must expose
loss, reject stale health and handle epoch, counter and boot changes. The local
directory remains until reboot; only validated unpublished health files are
collected during restart. Published observations are not removed by preparation. Omitting the declaration emits no local branch or directory;
owner YAML and the extension manifest are not read at runtime. Application event
schemas and unit-to-event mappings remain extension responsibilities.
