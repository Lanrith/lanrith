# Router health metrics

Enabling `observability.metrics` starts a host node_exporter and an HTTP proxy
on the generated service addresses. Collector selectors restrict the proxy's
network and source scopes. The proxy opens its backend connection from its
assigned IPv4 address on the service link and accepts bodyless `GET /metrics`
requests on port 9100. It requests plain Prometheus text from the exporter.
Content-length or chunk framing lets a scraper detect a lost suffix even when
the last received sample is complete. The proxy allows 32 clients, 15 seconds
per request and 16 MiB per exporter response, including framing. For HTTP/1.0 clients, it stages
chunked exporter output in private temporary files with a shared 16 MiB
limit, then sends the verified length. The proxy journal reports aggregate size,
timeout and backend failure counts in 30-second windows.

The host firewall drops local TCP connections to the generated backend on
port 9101. Scrape the proxy on port 9100 from an admitted collector.
The exporter's `--version` output and `node_exporter_build_info` identify
the Debian package version and patched source revision.

The netstat collector keeps the IPv4 protocol fields and reads IPv6 from
`/proc/net/snmp6`. Each exported name begins with `node_netstat_`.

| IPv6 prefix | Field suffixes |
| --- | --- |
| `Ip6_` | InOctets, OutOctets, InHdrErrors, InTooBigErrors, InNoRoutes, InAddrErrors, InUnknownProtos, InTruncatedPkts, OutNoRoutes |
| `Icmp6_` | InMsgs, OutMsgs, InErrors, OutErrors, InCsumErrors |
| `Udp6_`, `UdpLite6_` | InDatagrams, OutDatagrams, NoPorts, InErrors, RcvbufErrors, SndbufErrors, InCsumErrors |

The kernel supplies up to 28 IPv6 series. A missing field produces no sample.
A reported zero is a measured value.

For independent path monitoring, configure a blackbox exporter module with
`prober: tcp` and no query or response. Target the generated service address
and port as `host:9100` or `[IPv6]:9100` from an admitted collector source.
For example, this module opens a connection and sends no bytes.

```yaml
modules:
  router_metrics_tcp:
    prober: tcp
    timeout: 5s
```

Use the ServiceMonitor's `up` for HTTP scrape success and the per-target
`LanrithRouterCollectionUnavailable` rule below for missing or stale router
data. A TCP probe can succeed while either data check fails. Each additional
HTTP GET runs another exporter gather.

`lanrith-router-metrics.timer` runs a separate bounded host collector every
30 seconds. `lanrith-router-metrics.service` writes
`/var/lib/node_exporter/textfile_collector/lanrith_router.prom` atomically. The
directory is root-owned and the exporter has read access. Boot-time tmpfiles cleanup removes the previous boot’s router sample. This timer never targets
the long-running `lanrith-metrics.service` proxy.

The immutable `router-metrics.json` contract contains selected units, host
interfaces, client attachments, firewall hook declarations, selected DHCP pool IDs and enabled observation sources. It contains no source
YAML, owner groups, access rules or credentials. VPP-owned ports and interfaces
in another namespace are excluded from host observations.

All router health families use the `lanrith_router_` prefix:

| Family suffix | Observation |
| --- | --- |
| `image_info` | Image, version and deployment sequence |
| `unit_active` | Selected service/timer state, labeled by its full unit name |
| `mount_read_only`, `var_mounted_rw`, `var_free_bytes` | Root/state mounts and available state capacity |
| `firewall_hook_present` | Match of a compiled base chain’s family, table, name, type, hook, priority, policy and bound interface in the host or services namespace |
| `firewall_recovery_floor_active`, `firewall_startup_barrier_closed` | Active recovery table and the managed TUN policy’s closed startup set |
| `policy_helper_ready`, `policy_last_application`, `policy_status_query_timestamp_seconds`, `policy_directory_age_seconds`, `policy_apply_age_seconds` | Authenticated helper status, usable last application and its reported observation ages |
| `policy_reader_latest_attempt`, `policy_reader_attempt_timestamp_seconds` | Latest current-boot reader outcome and its journal reception time |
| `dhcp4_pool_assigned_addresses`, `dhcp4_pool_capacity_addresses` | Current occupancy and capacity, labeled by stable `subnet_id` and `pool` |
| `dhcp4_allocation_failures_total`, `dhcp4_declined_addresses` | Allocation failures since Kea startup and current declined addresses, labeled by `subnet_id` |
| `secure_boot_enabled`, `ab_slots_initialized`, `recovery_key_enrolled` | Observed firmware state and persistent installation markers |
| `interface_present`, `interface_admin_up`, `interface_carrier_up`, `interface_operational_up`, `interface_up` | Distinct host interface states |
| `interface_receive_*_total`, `interface_transmit_*_total` | Host interface byte, packet, error and drop counters |
| `nftables_loaded`, `chrony_synchronised` | Core table presence and Chrony’s reported external synchronisation |
| `chrony_observation_timestamp_seconds` | Original service-account NTP query time |
| `chrony_reference_timestamp_seconds`, `chrony_clock_error_bound_seconds` | Last reference update (Unix seconds) and estimated maximum clock error from that tracking row |
| `ids_stats_fresh`, `ids_stats_timestamp_seconds`, `ids_interval_valid` | Freshness of the last native AF_PACKET sample, its EVE timestamp and availability of a consecutive interval |
| `ids_capture_packets_total`, `ids_kernel_drops_total`, `ids_capture_errors_total`, `ids_tcp_reassembly_gaps_total` | Engine counters since sensor startup |
| `ids_tcp_session_memcap_drops_total`, `ids_tcp_segment_memcap_drops_total`, `ids_flow_emergencies_total` | TCP memory-limit drops and flow emergency-mode entries |
| `alloy_queue_capacity_bytes`, `alloy_queue_size_bytes` | Configured logical log queue capacity and current occupancy |
| `alloy_enqueue_failed_records_total`, `alloy_send_failed_records_total` | Rejected enqueue records and failed send attempts |
| `directory_tls_verified`, `directory_tls_endpoints_total`, `directory_tls_endpoints_verified` | Verified TLS across every pinned directory endpoint |
| `directory_tls_observation_timestamp_seconds`, `directory_tls_certificate_not_after_seconds` | Probe time and the earliest certificate expiry when all endpoints verify |
| `directory_trust_certificate_not_after_seconds` | Installed trust expiry for each distinct certificate, labeled by its SHA-256 fingerprint |
| `client_neighbor_count`, `client_neighbor_info` | Usable ARP/NDP observations on configured ordinary LANs |
| `client_inventory_complete`, `client_inventory_collection_timestamp_seconds` | Inventory completeness and time of the last complete collection |
| `metrics_query_success`, `metrics_collection_success`, `metrics_collection_timestamp_seconds`, `metrics_collection_duration_seconds` | Measurement availability and age |

Alert on failed queries and stale collection timestamps. Missing data is not an
observed empty inventory. Individual service-health metrics can be zero even
when collection succeeds. Disabled NTP has no synchronization query or metric.

When IDS and metrics are enabled, a local receiver validates the sensor UID and
projects aggregate EVE stats. Samples expire after 75 seconds. Each counter also
has a `_delta` gauge for the last consecutive interval. A restart or counter reset
starts a new interval. Set `ids="enabled"` on the target's
`lanrith_expected_router` series to use the example capture-staleness and
kernel-drop alerts. NIC driver loss needs a separate measurement.

Commands have a two-second limit, and local socket activation and response have a four-second limit within the shared 20-second budget. Neighbor
details are limited to 256 entries per interface and 1024 in total; exceeding
those bounds marks inventory incomplete. A failed or truncated inventory keeps
the last complete timestamp. The textfile is limited to 1 MiB, plus 1 MiB when DHCP statistics are
selected to accommodate up to 4,096 pools.

PID 1 passes the collector a read-only mountinfo descriptor. Each mount query
requires exactly one matching mount point. Either a read-only mount or a
read-only superblock makes the filesystem read-only. Missing or ambiguous
mounts omit the gauge and set its query success to zero.

The host collector lists nft table and chain metadata. A socket-activated worker
runs the same fixed queries inside the services network namespace and returns
one Boolean for each declared hook. A successful query can report a missing
hook. An unavailable namespace omits its hook series and sets
`metrics_query_success{collector="firewall_hooks_services"}` to zero. Hook
presence measures attachment geometry. The recovery floor and the startup set
have separate series. They can block traffic while the normal hooks exist.

When directory policy is enabled, its existing operator account runs
`router-policy-status` against the status-only socket. The worker returns
readiness, application status and the ages of directory and application data.
Unknown ages are omitted. The host timestamps the start of the status query.
The example projects the two reported ages forward to the evaluation time and
compares them with the generated 90-second policy lifetime. A fresh application with zero
grants is valid. No grant identifiers enter the exposition.

When DHCP is enabled the collector reads the root-only statistics socket and
requires exactly the subnet and pool IDs generated for this image. A missing,
partial, oversized or invalid response omits the DHCP series and sets
`metrics_query_success{collector="dhcp4"}` to zero. Out-of-pool reservations
do not consume pool capacity. The collector receives no lease-reader group.

### Consumer rules

The [example rules](../examples/monitoring/router.rules.yml) expect one
independently provisioned `lanrith_expected_router` gauge with value 1 for each
expected `(job, instance)`. Set its `directory`, `ntp` and `logs` labels to `enabled`
for the applicable routers. In a federated installation, include the cluster
identifier in each match if job and instance can repeat. The example allows
120 seconds for a 30-second collection interval, up to six seconds of timer
jitter, a 25-second activation timeout, a 30-second scrape interval and a
15-second rule evaluation interval. Adjust the window for local schedules. The
five-second future tolerance accommodates small clock differences.

Use `lanrith:directory_tls_healthy` for the enabled directory targets. Keep
the job and instance labels when displaying results. A recent collection can report a failed directory query. The stale
probe alert then identifies the missing observation. A fresh negative handshake
clears that alert and raises the TLS transport alert. A lost scrape or a failed
collector with no query results raises the collection alarm. Run the rule fixture
from the repository root with `promtool test rules tests/router_metrics_rules.yml`.

Enrollment requires a current `lanrith:inventory_current` for that router.
If it is absent, pause all reconciliation for that router, including deletion.
Before inferring disappearance, require a current `lanrith:reconcilable_attachment`
with the device’s previously assigned network, interface and placement.
The example’s `lanrith:enrollable_neighbor` keeps observations with exactly one
declared placement. Supply `lanrith_attachment_info` with value 1 and the
labels `job`, `instance`, `network`, `interface` and `placement` from your
attachment inventory. Pause reconciliation for an unmapped or ambiguous
attachment. A complete empty inventory has a fresh complete timestamp and
no neighbor details. During truncation, subtract the last complete timestamp
from the evaluation time to display how long a previous complete view has
been unavailable. A timestamp of zero means no complete view has been recorded.

When NTP and metrics are both enabled, `lanrith-ntp-health.timer` runs a
capability-empty observer as the packaged `_chrony` account in the service
network namespace. It executes only the fixed numeric CSV `tracking` query.
Chrony's control directory remains mode 0700. The observer can create the
temporary reply socket required by `chronyc` in that directory, as described
by the [upstream client implementation](https://github.com/mlichvar/chrony/blob/4.6/client.c#L199-L225).
It shares Chrony's service identity and is trusted within that service boundary.

The observer atomically publishes `/run/lanrith-ntp-health/health.json` with
mode 0640 in a mode-0750 directory. The host collector receives the `_chrony`
read group and retains only `CAP_NET_ADMIN`. This does not let it traverse
Chrony's control directory. It rejects old-boot, wrong-namespace, malformed
or more than 90-second-old observations. The exported NTP timestamp retains
the original observation time across later host collections.

A successful query with no external synchronization emits
`chrony_synchronised` zero with `metrics_query_success{collector="chrony"}` one.
A daemon/query failure emits query success zero. A missing or rejected snapshot
also omits the synchronization and NTP timestamp families. Disabling NTP removes
the observer service, timer, query and read-group membership; disabling metrics
removes the observer while NTP continues independently. No control listener or
owner configuration source is added.

For a Chrony panel, provision the expected NTP targets independently of the
scraper. Set the instant query to `lanrith:chrony_state`, label each series
`{{job}} {{instance}}`, and display one value per series. Map −1 to Unknown,
0 to Unsynchronised and 1 to Synchronised. Replace any fleet-wide
`max(homelab_router_chrony_synchronised)` selector and its two-value mapping
together. A failed Chrony query, stale observation, lost collector or missing
scrape changes the affected target to Unknown. An unrelated collector can fail
while the same router still has a measured clock state.

The example allows 180 seconds from the original Chrony query and 120 seconds
from collection. The conservative observer-to-display path allows 36 seconds
for each timer, 15 for the observer, 25 for collection, 30 before the next
scrape, 10 for that scrape and 15 before evaluation (167 seconds altogether).
The host independently enforces its 90-second monotonic limit when reading a
snapshot. Check the configured group interval and scrape deadline before
installing the rules. Keep the observer, collection and scrape chain within the
site’s maximum age, including jitter and expected clock skew.

To check a site's accuracy objective, set `chrony_accuracy="enabled"` on its
expected NTP target. Supply one `lanrith_chrony_max_reference_age_seconds`
(positive) and one `lanrith_chrony_max_clock_error_seconds` (zero or positive)
with that target's `job` and `instance`. Both limits must be finite. Display
`lanrith:chrony_accuracy_state` as −1 Unknown, 0 Outside objective or 1 Within
objective. A measured reference older than the limit or an estimate above the
limit yields 0. A failed query, local reference, missing limit, unavailable
estimate or implausibly future reference yields −1. A pre-upgrade snapshot can
still supply synchronisation while its accuracy is unknown.

The estimate adds the absolute remaining system-time correction, root
dispersion and half the root delay. It assumes a correct reference clock.
Chrony can continue reporting external synchronisation in holdover. Select
an age limit that allows the configured upstream polling interval and the time
to observe and scrape a measurement. [Chrony tracking fields](https://chrony-project.org/doc/4.6.1/chronyc.html#tracking)

When logging is enabled, the Alloy supervisor publishes a bounded observation
in `/run/lanrith-logs/health.json`. The collector reads it through a supplementary
group without network access or permission to read the exporter credential.
It requires the expected owner, safe permissions, the current boot and an
observation no more than 15 seconds old. An unavailable observation sets
`metrics_query_success{collector="alloy"}` to zero and emits no queue or failure
counters. Disabling logging removes that query and group membership.

The example Alloy rules report sustained queue growth, failed enqueues, failed
sends and missing observations per enabled router. Enqueue failures count
rejected records. Failed sends can include retries. A permanent HTTP 401 can
discard a batch while the queue is empty. Both counters reset on exporter
restart. Keep a separate receiver alarm for overdue heartbeats matching the
accepted boot and deployment. A normal queue depth can coexist with that alarm.

To qualify an outage objective, replay representative normal and peak input
against an isolated copy of the receiver. During a complete delivery outage,
measure the rise in `alloy_queue_size_bytes` over elapsed seconds before the
first enqueue failure. For each rate, divide the available logical queue bytes
(capacity minus starting occupancy) by the measured bytes per second. Compare
both durations with the owner's required outage window. Record the starting
free space on the encrypted state filesystem and peak disk use through
overflow, restart, drain and compaction. Reserve space for the journal and
other state. Verify delivery of a newly emitted heartbeat after drain.

When directory policy and metrics are both enabled, a separate
`lanrith-directory-health.timer` runs a credential-free TLS probe every
30 seconds. Its dedicated identity can reach only the selected directory
addresses and TCP port through their declared attachment. It has no policy-reader
credential, policy IPC access or capabilities. LDAPS and StartTLS both require
the supplied CA, matching server identity and TLS 1.2 or newer. Each pinned
address has a two-second deadline, within a 16-second total budget.

The probe publishes `/run/lanrith-directory-health/health.json` atomically with
mode 0640. The collector receives only its read group and rejects observations
older than 90 seconds or from a previous boot. A failed handshake produces
`directory_tls_verified` zero; an unavailable observation sets
`metrics_query_success{collector="directory"}` to zero and omits the TLS
families. Certificate expiry is zero until every selected endpoint verifies.
Directory authentication, authoritative policy data and fresh grants need their
own acceptance checks. A remote outage leaves existing policy failure behavior
in place; TLS success is not a boot-acceptance probe.

For directory policy, the collector reads the latest fixed JSON result from
the reader service’s journal stream. The reader polls every 30 seconds.
`collection_failed` covers bind and collection failures. `submission_failed`
means the reader could not confirm a submission. The helper can return
`rejected`, `shadow` or `applied`. A zero-grant apply counts as a confirmed
application. The collector checks the boot and journal reception time and
withholds malformed or older-than-90-second attempts. The exported labels
contain only the outcome. Read `lanrith:policy_reader_outcome` to exclude
replayed textfiles and unavailable scrapes.

Set `policy="enforce"` on the expected-router series for routers that
require enforced directory policy. The helper supplies the age of its last
application and of the directory observation behind it. The example rule
projects both ages forward from the time of the status query. It warns when
either reaches 60 seconds or the last confirmed application is unknown. With
a 90-second lease and 15-second evaluations this leaves at least one evaluation
before the deadline while Prometheus is running. A delayed scrape can keep the
warning active after recovery until it delivers the new confirmation. Budget
the reader poll, collection, scrape and evaluation schedules when selecting
local thresholds.

The collector reads the public trust file selected by the installed manifest
even when no endpoint verifies. The `directory_trust` query requires metadata
for the complete bundle of up to 16 certificates. Match the `sha256` label to
the installed certificate during overlapping renewal. An unavailable bundle
raises the unknown-trust alert. The example uses 180 days for trust renewal
and 14 days for a verified leaf. To compare issuance to a single endpoint,
supply one `lanrith_directory_issued_leaf_not_after_seconds` series per
`(job, instance)` from the issuer for that endpoint. The router reports only
the earliest leaf expiry across multiple endpoints.

Console inventories, private dashboard mappings and backend alert configuration
belong to the owner's setup.
