"""Compile component and boot contracts; no source intent is installed."""

import ipaddress

from . import authoritative, authoritative_migration, dns64, fancontrol_config, hardware_config, intent, journal, networkd
from . import integrations as references
from .release import canonical, require


def required_units(value, *, target_facts=None, integrations=()):
    units = ['nftables.service', 'ssh.service', 'systemd-networkd.service', journal.FLUSH, *integrations]
    receiver = journal.settings(value).get('syslog_receiver_unit')
    if receiver:
        units.append(receiver)
    if value['uplink'].get('required_for_online'):
        units.append('systemd-networkd-wait-online.service')
    units += [f'lanrith-pref64-{name}.service'
              for name in {n['pref64'] for n in value['networks'].values() if 'pref64' in n}]
    if fancontrol_config.active(value):
        units.append('lanrith-fancontrol.service')
    for feature, unit in (('dns', 'unbound.service'), ('dhcp4', 'kea-dhcp4-server.service'), ('ntp', 'chrony.service')):
        if value['services'].get(feature, {}).get('enabled'):
            units.append(unit)
    if value['administration']['serial']['enabled']:
        units.append('lanrith-serial-idle-watchdog.service')
    if (any(value['services'].get(f, {}).get('enabled') for f in ('dns', 'ntp')) or
            value.get('identity', {}).get('radius', {}).get('enabled') or
            any(value.get('observability', {}).get(f, {}).get('enabled') for f in ('metrics', 'snmp', 'logs'))):
        units.append('lanrith-services.service')
    if value.get('routing', {}).get('bgp', {}).get('enabled'):
        units.append('frr.service')
    if value.get('identity', {}).get('policy', {}).get('enabled'):
        units += ['lanrith-policy-guards.service', 'lanrith-policy-bootstrap.service', 'lanrith-policy-bindings.service',
                  'lanrith-policy-helper.service', 'lanrith-policy-reader.service']
    if value.get('identity', {}).get('radius', {}).get('enabled'):
        units.append('freeradius.service')
    if authoritative.active(value):
        units.append('named.service')
    if value.get('translation', {}).get('nat46', {}).get('enabled'):
        units.append('lanrith-nat46.service')
    if value.get('translation', {}).get('nat64', {}).get('enabled'):
        units += ['lanrith-nat64.service', 'lanrith-nat64-internal.service']
        if dns64.private_active(value):
            units.append('lanrith-dns64-private.service')
            if dns64.reverse_stubs(value):
                units.append('lanrith-dns64-reverse.service')
    if target_facts is not None:
        units.append('lanrith-hardware-ownership.service')
    if value.get('observability', {}).get('ids', {}).get('enabled'):
        units.append('lanrith-ids.service')
    if value.get('observability', {}).get('metrics', {}).get('enabled'):
        units += ['lanrith-metrics.service', 'prometheus-node-exporter.service']
    if value.get('observability', {}).get('snmp', {}).get('enabled'):
        units.append('snmpd.service')
    if value.get('observability', {}).get('logs', {}).get('enabled'):
        units.append('alloy.service')
    if value['services'].get('discovery', {}).get('enabled'):
        units += ['avahi-daemon.service', 'discovery-bridge-publisher.service',
                  'discovery-bridge-collector.service', 'discovery-bridge-dns.service']
    return sorted(set(units))


def advisory_timers(value):
    timers = []
    observability = value.get('observability', {})
    if observability.get('ids', {}).get('enabled'):
        timers.append('lanrith-ids-rotate.timer')
    if observability.get('metrics', {}).get('enabled'):
        timers.append('lanrith-router-metrics.timer')
        if value['services']['ntp']['enabled']:
            timers.append('lanrith-ntp-health.timer')
        if value.get('identity', {}).get('policy', {}).get('enabled'):
            timers.append('lanrith-directory-health.timer')
    if observability.get('logs', {}).get('enabled'):
        timers.append('lanrith-telemetry-heartbeat.timer')
    return sorted(timers)


def network_requirements(value):
    interfaces = []
    for key, lan in value['networks'].items():
        addresses = intent.gateway_addresses(lan)
        item = {'name': lan['name'], 'addresses': addresses}
        if not networkd.requires_carrier(lan):
            item['carrier_optional'] = True
        if 'namespace' in lan:
            item['namespace'] = lan['namespace']
        routes = [str(p) for route in value.get('routing', {}).get('static_routes', [])
                  if route['network'] == key for p in references.prefixes(value, route['to'])]
        if routes:
            item['routes'] = [{'to': prefix} for prefix in routes]
        interfaces.append(item)
    wan = value['uplink']
    required = wan.get('required_for_online', False)
    if required or wan.get('addresses'):
        item = {'name': value['hardware']['interfaces'][wan['interface']]['name'],
                'addresses': wan.get('addresses', [])}
        if required:
            item['routable_families'] = [int(family[-1]) for family in networkd.required_uplink_families(wan)]
        else:
            item['optional'] = True
        routes = []
        for family in (4, 6):
            destination = '0.0.0.0/0' if family == 4 else '::/0'
            gateway = next((g for g in wan.get('gateways', []) if ipaddress.ip_address(g).version == family), None)
            if gateway:
                routes.append({'to': destination, 'via': gateway})
            elif required and wan.get('ipv'+str(family), 'dhcp' if family == 4 else 'ra') in ('dhcp', 'ra'):
                routes.append({'to': destination})
        item['routes'] = routes
        interfaces.append(item)
    return interfaces


def dns_requirements(value):
    resolver = intent.service_addresses(value, 'dns')
    needs_ntp_dns = False
    if value['services']['ntp']['enabled']:
        for server in intent.ntp_upstreams(value):
            try:
                ipaddress.ip_address(server['address'])
            except ValueError:
                needs_ntp_dns = True
                break
    dns = {'listeners': resolver, 'ntp_client': needs_ntp_dns}
    if not authoritative.active(value):
        blocked = {name.lower().rstrip('.') for name in value['services']['dns'].get('blocked_domains', [])}
        dns['queries'] = [['localhost.', 'A', 'NXDOMAIN' if 'localhost' in blocked else ['127.0.0.1']]]
        return dns
    settings = authoritative.settings(value)
    records = authoritative.zone_records(value)
    # Ordinary seed records in a persistent zone belong to its operator. Limit
    # boot work to zone loading, declared service endpoints and signed transitions.
    expected = {(zone+'.', 'SOA'): 'present' for zone in settings['zones']}
    for name, rrsets in authoritative.service_records(value).items():
        for kind, answer in rrsets.items():
            expected[(name+'.'+settings['primary_zone']+'.', kind)] = [answer]
    changes = authoritative_migration.managed_rrsets(settings['zones'], records)
    for transitions in changes.values():
        for record in transitions:
            expected[(record['name'], record['type'])] = record['desired']
    queries = [[name, kind, data] for (name, kind), data in sorted(expected.items())]
    source, target = authoritative.resolver_path(value)
    dns.update(authority=target, source=source, queries=queries)
    return dns


def health(value, *, target_facts=None, integrations=(), access_backend='tun'):
    require(access_backend in ('legacy', 'tun'), 'Unknown boot health translation backend.')
    probes = []
    if value.get('translation', {}).get('nat46', {}).get('enabled'):
        probes.append('nat46')
    if value.get('translation', {}).get('nat64', {}).get('enabled'):
        probes += ['nat64', 'nat64-internal']
    if target_facts is not None:
        probes.append('ownership')
    plan = {'schema': 2, 'units': required_units(value, target_facts=target_facts, integrations=integrations),
            'interfaces': network_requirements(value), 'probes': probes}
    if access_backend == 'tun':
        plan['native_translation'] = True
    if value['services']['dns']['enabled']:
        plan['dns'] = dns_requirements(value)
    return plan


def render(value, *, target_facts=None, access_backend='tun'):
    admin = value['administration']
    return {'usr/share/lanrith/health.json': canonical(health(value, target_facts=target_facts,
                                                           access_backend=access_backend)).decode(),
            'usr/share/lanrith/administration.json': canonical(
                {'schema': 1, **{k: admin[k] for k in ('username', 'host_key_state', 'host_key_rotation',
                                                       'serial', 'root_access', 'host_key_pin') if k in admin}}).decode(),
            'usr/share/lanrith/hardware.json': canonical(hardware_config.manifest(value)).decode()}
