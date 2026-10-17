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
| `uplink` | DHCP/static IPv4, RA/static IPv6, gateways and optional CAKE upload rate |
| `networks` | Tagged or untagged attachments, gateway addresses, RA, DNS and DHCP pools |
| `access` | Explicit internet access and directional TCP/UDP inter-network permits |
| `administration` | Management networks, administrator public keys, account, port and optional serial login |
| `services` | Independent optional feature selection |
| `extensions` | IDs of separately reviewed integration manifests |
| `release` | Owner image identity and monotonic `sequence_floor` |

Defaults allocate a 1 GiB ESP, two 4 GiB root slots and 64 GiB encrypted state.
Surplus storage stays unallocated. Factory installation requires an eligible
512-byte logical-sector disk and explicit destructive confirmation. TPM is
required by default. A profile without TPM uses an operator-entered encryption
passphrase; it is never embedded in an image. Record the separate recovery key
offline before boot acceptance. Serial login is disabled unless enabled with a
private provisioning hash and a selected console. Kernel and journal output
must not disclose secrets on that console.

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

DNS, DHCP and NTP have built-in configuration. Discovery, RADIUS/directory
policy, FRR, translation, IDS, metrics, logs, SNMP and VPP use integration
extensions until their typed configuration interfaces are qualified. Merely
installing their packages does not enable them.

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

Optional namespace, translation, OOB and acceleration helpers read the
owner's `/etc/lanrith/integrations/network-profile.sh`; its settings use the
`lanrith_` prefix. SNMP reads
`/etc/lanrith/integrations/snmp-runtime-policy.json`. These files are absent
from the neutral base and can be supplied by an admitted integration without
overwriting protected runtime code. PCI binding uses `lanrith_vpp_bdf`,
`lanrith_vpp_iommu_group`, `lanrith_vpp_linux_interface`,
`lanrith_vpp_mac_address` and `lanrith_vpp_linux_driver`. There is no default
NIC model, PCI address or Linux driver. Binding checks the exact function,
interface, MAC, expected driver and exclusive IOMMU group before changing
anything. Shared groups are rejected. `lanrith-vpp-device.service` and
`verify-vpp-device` retain this ownership boundary; the owner explicitly admits
the VPP dependency drop-in and its configuration. VPP/DPDK support for a chosen
NIC still needs qualification. Acceleration devices are separate from declared
Linux-owned interfaces.

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
