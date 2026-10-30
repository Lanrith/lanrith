# Router health metrics

Enabling `observability.metrics` starts a host node_exporter and an HTTP proxy
on the generated service addresses. Collector selectors restrict the proxy's
network and source scopes. The exporter backend remains reachable only by the
proxy identity. The proxy accepts bounded, bodyless `GET /metrics` requests.

`lanrith-router-metrics.timer` runs a separate bounded host collector every
30 seconds. `lanrith-router-metrics.service` writes
`/var/lib/node_exporter/textfile_collector/lanrith_router.prom` atomically. The
directory is root-owned; the exporter has read access. This timer never targets
the long-running `lanrith-metrics.service` proxy.

The immutable `router-metrics.json` contract contains selected units, host
interfaces, client attachments and whether NTP and logging are enabled. It contains no source
YAML, owner groups, access rules or credentials. VPP-owned ports and interfaces
in another namespace are excluded from host observations.

All router health families use the `lanrith_router_` prefix:

| Family suffix | Observation |
| --- | --- |
| `image_info` | Image, version and deployment sequence |
| `unit_active` | Selected service/timer state, labeled by its full unit name |
| `mount_read_only`, `var_mounted_rw`, `var_free_bytes` | Root/state mounts and available state capacity |
| `secure_boot_enabled`, `ab_slots_initialized`, `recovery_key_enrolled` | Observed firmware state and persistent installation markers |
| `interface_present`, `interface_admin_up`, `interface_carrier_up`, `interface_operational_up`, `interface_up` | Distinct host interface states |
| `interface_receive_*_total`, `interface_transmit_*_total` | Host interface byte, packet, error and drop counters |
| `nftables_loaded`, `chrony_synchronised` | Core table presence and upstream clock synchronization |
| `alloy_queue_capacity_bytes`, `alloy_queue_size_bytes` | Configured logical log queue capacity and current occupancy |
| `alloy_enqueue_failed_records_total`, `alloy_send_failed_records_total` | Rejected enqueue records and failed send attempts |
| `client_neighbor_count`, `client_neighbor_info` | Usable ARP/NDP observations on configured ordinary LANs |
| `client_inventory_complete`, `client_inventory_collection_timestamp_seconds` | Inventory completeness and time of the last complete collection |
| `metrics_query_success`, `metrics_collection_success`, `metrics_collection_timestamp_seconds`, `metrics_collection_duration_seconds` | Measurement availability and age |

Alert on failed queries and stale collection timestamps. Missing data is not an
observed empty inventory. Individual service-health metrics can be zero even
when collection succeeds. Disabled NTP has no synchronization query or metric.

Queries have a two-second limit within a 20-second collection budget. Neighbor
details are limited to 256 entries per interface and 1024 in total; exceeding
those bounds marks inventory incomplete. A failed or truncated inventory keeps
the last complete timestamp. Collector output is limited to 1 MiB. These bounds
also constrain metric cardinality and memory use.

When logging is enabled, the Alloy supervisor publishes a bounded observation
in `/run/lanrith-logs/health.json`. The collector reads it through a supplementary
group without network access or permission to read the exporter credential.
It requires the expected owner, safe permissions, the current boot and an
observation no more than 15 seconds old. An unavailable observation sets
`metrics_query_success{collector="alloy"}` to zero and emits no queue or failure
counters. Disabling logging removes that query and group membership.

Enqueue failures indicate records rejected by the bounded queue. Send failures
can be retried and must not be interpreted as a count of permanently lost
records. Both counters reset when the exporter process restarts. These are
observations supplied by the exporter, not evidence of policy enforcement.

Directory TLS families remain outstanding. Console inventories, private
dashboard mappings and backend alert configuration belong to the owner's setup.
