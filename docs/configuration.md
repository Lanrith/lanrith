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
