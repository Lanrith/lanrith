"""Project active credential consumers into an image-owned provisioning catalog."""

from . import bindings
from .release import canonical, require
from .credential_values import FORMATS, UNITS, validate_catalog


def catalog(value):
    credentials, units = {}, set()

    def add(reference, kind, selected_units, parameters=None):
        item = {'reference': reference, 'path': bindings.credential_path(value, reference),
                'format': kind, 'parameters': parameters or {}}
        require(reference not in credentials or credentials[reference] == item,
                'One credential reference cannot have different provisioning grammars.')
        credentials[reference] = item
        units.update(selected_units)

    dns = value['services']['dns'].get('authoritative', {})
    if dns.get('enabled', False):
        for writer in dns.get('writers', {}).values():
            add(writer['credential'], 'tsig-base64', {'named.service'})
    bgp = value.get('routing', {}).get('bgp', {})
    if bgp.get('enabled', False):
        for group in bgp['peer_groups'].values():
            if 'credential' in group:
                add(group['credential'], 'bgp-token', {'frr.service', 'lanrith-routing-credentials.service'})
    identity = value.get('identity', {})
    policy = identity.get('policy', {})
    if policy.get('enabled', False):
        directory = identity['directories'][policy['directory']]
        add(directory['credential'], 'directory-password', {
            'lanrith-policy-bootstrap.service', 'lanrith-policy-bindings.service',
            'lanrith-policy-helper.service', 'lanrith-policy-reader.service'})
    radius = identity.get('radius', {})
    if radius.get('enabled', False):
        for consumer in [*radius['clients'].values(), radius['proxy']]:
            add(consumer['credential'], 'radius-secret', {'freeradius.service'})
    logs = value.get('observability', {}).get('logs', {})
    if logs.get('enabled', False):
        add(logs['credential'], 'log-password', {'alloy.service'})
    snmp = value.get('observability', {}).get('snmp', {})
    if snmp.get('enabled', False):
        add(snmp['credential'], 'snmp-user', {'snmpd.service'}, {
            'username': snmp['username'], 'header': bindings.credential_header(value, snmp['credential'])})
    return validate_catalog({'schema': 1, 'credentials': [credentials[name] for name in sorted(credentials)],
                             'units': sorted(units)})


def encoded(value):
    """No values, source YAML, inactive consumers or controller inputs are emitted."""
    return canonical(catalog(value))


def render(value):
    result = catalog(value)
    return {'usr/share/lanrith/credentials.json': canonical(result).decode()} if result['credentials'] else {}
