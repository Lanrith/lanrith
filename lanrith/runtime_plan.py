"""Compile component and boot contracts; no source intent is installed."""

import ipaddress

from . import hardware_config, intent
from .release import canonical


def required_units(value, *, target_facts=None, integrations=()):
    units = ['nftables.service', 'ssh.service', 'systemd-networkd.service', *integrations]
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
    if value['services']['dns'].get('authoritative', {}).get('enabled'):
        units.append('named.service')
    if value.get('translation', {}).get('nat46', {}).get('enabled'):
        units.append('lanrith-nat46.service')
    if value.get('translation', {}).get('nat64', {}).get('enabled'):
        units += ['lanrith-nat64.service', 'lanrith-nat64-internal.service']
        if value['services']['dns'].get('authoritative', {}).get('enabled'):
            units.append('lanrith-dns64-private.service')
    if target_facts is not None:
        units.append('lanrith-hardware-ownership.service')
    if value.get('observability', {}).get('ids', {}).get('enabled'):
        units.append('lanrith-ids.service')
    if value.get('observability', {}).get('metrics', {}).get('enabled'):
        units += ['lanrith-metrics.service', 'prometheus-node-exporter.service']
    if value.get('observability', {}).get('snmp', {}).get('enabled'):
        units.append('snmpd.service')
    if value.get('observability', {}).get('logs', {}).get('enabled'):
        units += ['alloy.service', 'lanrith-telemetry-heartbeat.timer']
    if value['services'].get('discovery', {}).get('enabled'):
        units += ['avahi-daemon.service', 'discovery-bridge-publisher.service',
                  'discovery-bridge-collector.service', 'discovery-bridge-dns.service']
    return sorted(set(units))


def health(value, *, target_facts=None, integrations=()):
    probes = []
    if value.get('translation', {}).get('nat46', {}).get('enabled'):
        probes.append('nat46')
    if value.get('translation', {}).get('nat64', {}).get('enabled'):
        probes += ['nat64', 'nat64-internal']
    if target_facts is not None:
        probes.append('ownership')
    return {'schema': 1, 'units': required_units(value, target_facts=target_facts, integrations=integrations),
            'interfaces': [{'name': item['name'],
                            'addresses': [str(ipaddress.ip_interface(a).ip) for a in intent.gateway_addresses(item)],
                            **({'namespace': item['namespace']} if 'namespace' in item else {})}
                           for item in value['networks'].values()], 'probes': probes}


def render(value, *, target_facts=None):
    admin = value['administration']
    return {'usr/share/lanrith/health.json': canonical(health(value, target_facts=target_facts)).decode(),
            'usr/share/lanrith/administration.json': canonical(
                {'schema': 1, **{k: admin[k] for k in ('username', 'host_key_state', 'host_key_rotation',
                                                       'serial', 'root_access')}}).decode(),
            'usr/share/lanrith/hardware.json': canonical(hardware_config.manifest(value)).decode()}
