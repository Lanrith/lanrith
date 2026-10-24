"""Check compiled boot requirements without loading the configuration compiler."""

import ipaddress
import json
from pathlib import Path
import re

from .release import read, require
from .update import command


PROBES = {'nat46', 'nat64', 'nat64-internal', 'ownership'}
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')


def check(plan):
    require(isinstance(plan, dict) and set(plan) == {'schema', 'units', 'interfaces', 'probes'} and
            plan['schema'] == 1 and isinstance(plan['units'], list) and 3 <= len(plan['units']) <= 256 and
            isinstance(plan['interfaces'], list) and 1 <= len(plan['interfaces']) <= 256 and
            isinstance(plan['probes'], list) and len(plan['probes']) <= len(PROBES),
            'Invalid compiled boot requirements.')
    require(all(isinstance(unit, str) and re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(?:service|timer)', unit)
                for unit in plan['units']) and len(set(plan['units'])) == len(plan['units']) and
            all(isinstance(probe, str) and probe in PROBES for probe in plan['probes']) and
            len(set(plan['probes'])) == len(plan['probes']), 'Invalid compiled boot requirements.')
    for probe in plan['probes']:
        manifest = json.loads(read(Path('/usr/share/lanrith', probe+'.json'), 1024*1024))
        if probe == 'nat46':
            from .translation_runtime import status
        elif probe == 'ownership':
            from .hardware import ownership_status as status
        else:
            from .nat64_runtime import status
        status(manifest)
    for unit in plan['units']:
        require(command(['systemctl', 'is-active', unit]).strip() == 'active', 'Required service is not active.')
    for interface in plan['interfaces']:
        require(isinstance(interface, dict) and {'name', 'addresses'} <= set(interface) <=
                {'name', 'addresses', 'namespace'} and isinstance(interface['name'], str) and
                len(interface['name']) <= 15 and IDENTIFIER.fullmatch(interface['name']) and
                isinstance(interface['addresses'], list) and len(interface['addresses']) <= 256 and
                ('namespace' not in interface or isinstance(interface['namespace'], str) and
                 IDENTIFIER.fullmatch(interface['namespace'])), 'Invalid compiled gateway requirement.')
        addresses = [str(ipaddress.ip_address(a)) for a in interface['addresses']]
        arguments = ['ip'] + (['-netns', interface['namespace']] if 'namespace' in interface else [])
        rows = json.loads(command(arguments+['-j', 'address', 'show', 'dev', interface['name']]))
        require(len(rows) == 1, 'Required network interface is absent.')
        observed = {item['local'] for item in rows[0].get('addr_info', [])}
        require(set(addresses) <= observed, 'Declared gateway address is absent.')
