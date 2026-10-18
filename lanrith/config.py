"""Compile router intent without depending on a particular household or NIC."""

from __future__ import annotations

import hashlib
import base64
import ipaddress
import json
from pathlib import Path
import re
import copy

import yaml

from .release import canonical, require, ReleaseError
from . import access as access_rules
from . import firewall


FEATURES = {'dns', 'dhcp4', 'ntp', 'discovery', 'radius', 'policy', 'bgp', 'nat64',
            'nat46', 'ids', 'metrics', 'logs', 'snmp', 'vpp'}
IDENTIFIER = re.compile(r'[a-z][a-z0-9-]{0,11}\Z')
IFNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z')


class Loader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(isinstance(key, str) and key not in result, 'Duplicate or invalid YAML field.')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def fields(value, allowed, required=()):
    require(isinstance(value, dict) and not (set(value) - set(allowed)) and set(required) <= set(value),
            'Unknown, missing or invalid configuration fields.')


def load(path):
    data = path.read_bytes()
    require(0 < len(data) <= 1024 * 1024, 'Configuration exceeds its size limit.')
    require(b'\x00' not in data, 'Configuration contains invalid bytes.')
    try:
        # Anchors/aliases introduce recursive or shared objects across the approval boundary.
        for token in yaml.scan(data):
            require(not isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)),
                    'YAML anchors and aliases are not supported.')
        value = yaml.load(data, Loader=Loader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ReleaseError('Invalid YAML configuration.') from error
    return normalize(value)


def effective_digest(value, integrations, serial_provisioning_sha256=None):
    """Bind normalized intent, admitted integrations and selected serial material."""
    value = normalize(value)
    require(isinstance(integrations, dict) and set(integrations) == set(value['extensions']) and
            all(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
                for digest in integrations.values()), 'Effective integration digests differ from configuration.')
    enabled = value['administration']['serial']['enabled']
    require((serial_provisioning_sha256 is not None) == enabled and
            (serial_provisioning_sha256 is None or isinstance(serial_provisioning_sha256, str) and
             re.fullmatch(r'[0-9a-f]{64}', serial_provisioning_sha256)),
            'Effective serial provisioning differs from configuration.')
    return hashlib.sha256(canonical({'configuration': value, 'integrations': integrations,
                                    'serial_provisioning_sha256': serial_provisioning_sha256})).hexdigest()


def normalize(value):
    value = copy.deepcopy(value)
    fields(value, {'schema', 'hostname', 'hardware', 'uplink', 'networks', 'access', 'services',
                   'administration', 'release', 'extensions'},
           {'schema', 'hostname', 'hardware', 'uplink', 'networks', 'administration'})
    require(type(value['schema']) is int and value['schema'] == 1, 'Unsupported configuration schema.')
    hostname = value['hostname']
    require(isinstance(hostname, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', hostname),
            'Hostname must be a simple DNS label.')
    hardware = value['hardware']
    fields(hardware, {'architecture', 'interfaces', 'boot', 'storage', 'acceleration', 'machine_id', 'watchdog'}, {'interfaces'})
    if 'machine_id' in hardware:
        require(isinstance(hardware['machine_id'], str) and
                re.fullmatch(r'[0-9a-f]{32}', hardware['machine_id']) and hardware['machine_id'] != '0'*32,
                'Machine identity must be a nonzero 32-digit lowercase hexadecimal ID.')
    require(hardware.get('architecture', 'x86-64') == 'x86-64',
            'This release qualifies x86-64; additional architectures require a supported build profile.')
    watchdog = hardware.setdefault('watchdog', {})
    fields(watchdog, {'mode', 'device', 'timeout_seconds'})
    watchdog.setdefault('mode', 'auto')
    watchdog.setdefault('device', '/dev/watchdog0')
    watchdog.setdefault('timeout_seconds', 60)
    require(watchdog['mode'] in ('auto', 'required', 'disabled') and
            isinstance(watchdog['device'], str) and
            re.fullmatch(r'/dev/watchdog(?:[0-9]|[12][0-9]|3[01])', watchdog['device']) and
            type(watchdog['timeout_seconds']) is int and 10 <= watchdog['timeout_seconds'] <= 3600,
            'Invalid hardware watchdog policy.')
    boot = hardware.setdefault('boot', {'secure_boot': True, 'tpm': 'required'})
    fields(boot, {'secure_boot', 'tpm', 'console', 'recovery_console'})
    require(type(boot.get('secure_boot', True)) is bool and boot.get('tpm', 'required') in ('required', 'disabled'),
            'Invalid boot protection profile.')
    require(isinstance(boot.get('console', 'tty0'), str) and
            re.fullmatch(r'(tty0|ttyS[0-9]+(?:,[0-9]+n8)?|hvc[0-9]+)', boot.get('console', 'tty0')),
            'Invalid boot console.')
    recovery = boot.setdefault('recovery_console', boot.get('console', 'tty0').split(',')[0])
    require(isinstance(recovery, str) and re.fullmatch(r'(tty0|ttyS[0-9]+|ttyUSB[0-9]+|ttyAMA[0-9]+|hvc[0-9]+)', recovery),
            'Invalid recovery console.')
    storage = hardware.setdefault('storage', {})
    fields(storage, {'target', 'root_mib', 'state_mib', 'esp_mib'})
    if 'target' in storage:
        require(isinstance(storage['target'], str) and
                re.fullmatch(r'/dev/disk/by-id/[A-Za-z0-9_.:+-]+', storage['target']),
                'Factory storage must use an explicit stable device identity.')
    for key, default in (('root_mib', 4096), ('state_mib', 65536), ('esp_mib', 1024)):
        storage.setdefault(key, default)
        if key in storage:
            require(type(storage[key]) is int and 128 <= storage[key] <= 1024 * 1024,
                    'Invalid storage capacity.')
    if 'acceleration' in hardware:
        fields(hardware['acceleration'], {'pci', 'hugepages_mib'}, {'pci', 'hugepages_mib'})
        require(isinstance(hardware['acceleration']['pci'], list) and hardware['acceleration']['pci'] and
                all(isinstance(pci, str) and re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', pci)
                    for pci in hardware['acceleration']['pci']) and
                len(set(hardware['acceleration']['pci'])) == len(hardware['acceleration']['pci']),
                'Invalid or duplicate acceleration device selection.')
        require(type(hardware['acceleration']['hugepages_mib']) is int and
                2 <= hardware['acceleration']['hugepages_mib'] <= 1024 * 1024 and
                hardware['acceleration']['hugepages_mib'] % 2 == 0,
                'Invalid hugepage allocation.')
    interfaces = hardware['interfaces']
    require(isinstance(interfaces, dict) and 2 <= len(interfaces) <= 64, 'Declare the physical/virtual interfaces.')
    selectors, interface_names = set(), set()
    for key, interface in interfaces.items():
        require(IDENTIFIER.fullmatch(key), 'Invalid interface key.')
        fields(interface, {'match', 'name', 'mtu'}, {'match'})
        name = interface.setdefault('name', key)
        require(isinstance(name, str) and IFNAME.fullmatch(name) and name not in interface_names,
                'Invalid or duplicate Linux interface name.')
        interface_names.add(name)
        fields(interface['match'], {'mac', 'path', 'driver'})
        require(len(interface['match']) == 1, 'Each interface needs one stable hardware selector.')
        kind, selector = next(iter(interface['match'].items()))
        require(isinstance(selector, str) and len(selector) <= 128, 'Invalid interface selector.')
        require((kind == 'mac' and re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', selector)) or
                (kind in ('path', 'driver') and re.fullmatch(r'[A-Za-z0-9_.:*?-]+', selector)),
                'Invalid hardware selector.')
        require((kind, selector) not in selectors, 'Duplicate interface selectors.')
        selectors.add((kind, selector))
        require(type(interface.get('mtu', 1500)) is int and 1280 <= interface.get('mtu', 1500) <= 9216,
                'Unsupported interface MTU.')
    uplink = value['uplink']
    fields(uplink, {'interface', 'ipv4', 'ipv6', 'addresses', 'gateways', 'upload_shaping', 'masquerade'}, {'interface'})
    require(type(uplink.get('masquerade', False)) is bool, 'Uplink masquerading must be a boolean.')
    require(uplink['interface'] in interfaces, 'Uplink interface is not declared.')
    require(uplink.get('ipv4', 'dhcp') in ('dhcp', 'static', 'disabled') and
            uplink.get('ipv6', 'ra') in ('ra', 'static', 'disabled'), 'Unsupported uplink address mode.')
    for address in uplink.get('addresses', []):
        ipaddress.ip_interface(address)
    for gateway in uplink.get('gateways', []):
        ipaddress.ip_address(gateway)
    require(isinstance(uplink.get('addresses', []), list) and len(uplink.get('addresses', [])) <= 8 and
            isinstance(uplink.get('gateways', []), list) and len(uplink.get('gateways', [])) <= 2,
            'Invalid uplink address inventory.')
    wan_addresses = [ipaddress.ip_interface(address) for address in uplink.get('addresses', [])]
    for family in (4, 6):
        mode = uplink.get('ipv'+str(family), 'dhcp' if family == 4 else 'ra')
        addresses = [address for address in wan_addresses if address.version == family]
        gateways = [ipaddress.ip_address(g) for g in uplink.get('gateways', []) if ipaddress.ip_address(g).version == family]
        require((mode == 'static') == bool(addresses) and (not gateways or mode == 'static') and
                len(gateways) <= 1, 'Static uplink addresses and gateways must match their address modes.')
        require(all(not a.ip.is_multicast and not a.ip.is_unspecified and not a.ip.is_loopback for a in addresses),
                'Invalid uplink address.')
        require(all(g.is_link_local or any(g in a.network for a in addresses) for g in gateways),
                'Uplink gateway is not directly reachable.')
    if 'upload_shaping' in uplink:
        fields(uplink['upload_shaping'], {'mbps'}, {'mbps'})
        require(type(uplink['upload_shaping']['mbps']) is int and
                1 <= uplink['upload_shaping']['mbps'] <= 100000, 'Invalid upload shaping rate.')
    networks = value['networks']
    require(isinstance(networks, dict) and 1 <= len(networks) <= 64, 'Declare at least one internal network.')
    subnets, attachments = [], set()
    network_names = set()
    for key, network in networks.items():
        require(IDENTIFIER.fullmatch(key), 'Invalid network key.')
        fields(network, {'interface', 'vlan', 'addresses', 'dhcp4', 'ra', 'dns', 'name', 'namespace',
                         'forwarding', 'routed_prefixes'},
               {'interface', 'addresses'})
        require(network['interface'] in interfaces and network['interface'] != uplink['interface'],
                'Internal networks cannot use the uplink.')
        vlan = network.get('vlan')
        require(vlan is None or type(vlan) is int and 1 <= vlan <= 4094, 'Invalid VLAN identifier.')
        attachment = (network['interface'], vlan)
        require(attachment not in attachments, 'Duplicate network attachment.')
        attachments.add(attachment)
        parent = interfaces[network['interface']]['name']
        name = network.setdefault('name', parent if vlan is None else f'{parent}.{vlan}')
        require(isinstance(name, str) and IFNAME.fullmatch(name) and name not in network_names and
                (vlan is None or name not in interface_names), 'Invalid or duplicate network interface name.')
        network_names.add(name)
        if 'namespace' in network:
            require(isinstance(network['namespace'], str) and
                    re.fullmatch(r'[a-z][a-z0-9-]{0,47}', network['namespace']), 'Invalid network namespace.')
        require(isinstance(network['addresses'], list) and 1 <= len(network['addresses']) <= 8,
                'Declare bounded gateway addresses.')
        parsed = [ipaddress.ip_interface(address) for address in network['addresses']]
        for address in parsed:
            require(not address.ip.is_multicast and not address.ip.is_unspecified and
                    not address.ip.is_loopback and not address.ip.is_link_local, 'Invalid network gateway.')
            require(all(address.version != other.version or not address.network.overlaps(other)
                        for other in subnets), 'Internal networks overlap.')
            subnets.append(address.network)
            require(all(address.version != wan.version or not address.network.overlaps(wan.network)
                        for wan in wan_addresses), 'Internal and uplink networks overlap.')
        for option, default in (('ra', False), ('dns', False), ('forwarding', True)):
            require(type(network.get(option, default)) is bool, 'Network feature flags must be booleans.')
        require(not network.get('ra') or any(address.version == 6 and address.network.prefixlen == 64
                                           for address in parsed), 'SLAAC requires an IPv6 /64.')
        if 'dhcp4' in network:
            fields(network['dhcp4'], {'pool'}, {'pool'})
            pool = network['dhcp4']['pool']
            require(isinstance(pool, list) and len(pool) == 2, 'DHCP pool needs first and last address.')
            first, last = [ipaddress.IPv4Address(address) for address in pool]
            ranges = [address for address in parsed if address.version == 4]
            require(len(ranges) == 1 and first <= last and first in ranges[0].network and last in ranges[0].network and
                    not first <= ranges[0].ip <= last and first != ranges[0].network.network_address and
                    last != ranges[0].network.broadcast_address, 'DHCP pool conflicts with its gateway or subnet.')
    routed = []
    for network in networks.values():
        entries = network.get('routed_prefixes', [])
        require(isinstance(entries, list) and len(entries) <= 32, 'Declare bounded routed source prefixes.')
        for entry in entries:
            require(isinstance(entry, str) and '%' not in entry, 'Invalid routed source prefix.')
            try:
                prefix = ipaddress.ip_network(entry, strict=True)
            except ValueError:
                raise ReleaseError('Invalid routed source prefix.') from None
            require(prefix.prefixlen > 0 and not (prefix.is_multicast or prefix.is_loopback or
                    prefix.is_link_local or prefix.network_address.is_unspecified) and
                    not any(prefix.version == other.version and prefix.overlaps(other) for other in subnets+routed+[
                        address.network for address in wan_addresses]),
                    'Routed source prefixes must be distinct from connected and other routed networks.')
            routed.append(prefix)
    access = value.setdefault('access', {})
    require(isinstance(access, dict), 'Access configuration must be a mapping.')
    if 'rules' in access or 'default' in access:
        access_rules.render(access, networks, interfaces, uplink)
    else:
        # Admit existing owner files without mixing their implicit ordering
        # with the new explicit, first-match policy.
        fields(access, {'internet', 'between_networks'})
        require(isinstance(access.get('internet', []), list) and
                all(key in networks for key in access.get('internet', [])), 'Unknown internet-access network.')
        require(isinstance(access.get('between_networks', []), list), 'Invalid connection rules.')
        for rule in access.get('between_networks', []):
            fields(rule, {'from', 'to', 'protocol', 'ports'}, {'from', 'to', 'protocol', 'ports'})
            require(rule['from'] in networks and rule['to'] in networks and rule['from'] != rule['to'],
                    'Connection rule references invalid networks.')
            require(rule['protocol'] in ('tcp', 'udp') and isinstance(rule['ports'], list) and
                    1 <= len(rule['ports']) <= 64 and
                    all(type(port) is int and 1 <= port <= 65535 for port in rule['ports']), 'Invalid connection ports.')
    administration = value['administration']
    fields(administration, {'networks', 'authorized_keys', 'ssh_port', 'username', 'serial', 'host_key_state'},
           {'networks', 'authorized_keys'})
    host_key_state = administration.setdefault('host_key_state', '/var/lib/lanrith/ssh-host-keys')
    require(isinstance(host_key_state, str) and re.fullmatch(r'/var/lib/[A-Za-z0-9_/-]+', host_key_state) and
            all(part not in ('.', '..') for part in Path(host_key_state).parts) and
            not host_key_state.endswith('/'), 'Host keys require a protected persistent state directory.')
    username = administration.setdefault('username', 'admin')
    require(isinstance(username, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', username) and
            username not in ('root', 'nobody', 'daemon'), 'Invalid administrator account.')
    serial = administration.setdefault('serial', {'enabled': False})
    fields(serial, {'enabled', 'tty', 'timeout_seconds'}, {'enabled'})
    require(type(serial['enabled']) is bool and
            re.fullmatch(r'(ttyS[0-9]+|ttyUSB[0-9]+|ttyAMA[0-9]+|hvc[0-9]+)', serial.get('tty', 'ttyS0')) and
            type(serial.get('timeout_seconds', 300)) is int and 30 <= serial.get('timeout_seconds', 300) <= 3600,
            'Invalid serial administration policy.')
    require(isinstance(administration['networks'], list) and administration['networks'] and
            all(key in networks for key in administration['networks']), 'Declare management networks explicitly.')
    require(isinstance(administration['authorized_keys'], list) and administration['authorized_keys'],
            'At least one administrator public key is required.')
    for key in administration['authorized_keys']:
        require(isinstance(key, str) and re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) '
                                                     r'[A-Za-z0-9+/=]+(?: [^\r\n]+)?', key), 'Invalid public-key line.')
        parts = key.split(' ')
        try:
            encoded = base64.b64decode(parts[1], validate=True)
            length = int.from_bytes(encoded[:4], 'big')
            require(len(encoded) >= 4 + length and encoded[4:4+length].decode('ascii') == parts[0],
                    'Public-key encoding differs from its type.')
            if parts[0] == 'ssh-ed25519':
                require(encoded[4+length:8+length] == b'\x00\x00\x00\x20' and len(encoded) == 8+length+32,
                        'Invalid Ed25519 public-key encoding.')
        except (ValueError, UnicodeDecodeError) as error:
            raise ReleaseError('Invalid public-key encoding.') from error
    require(type(administration.get('ssh_port', 22)) is int and
            1 <= administration.get('ssh_port', 22) <= 65535, 'Invalid SSH port.')
    services = value.setdefault('services', {})
    fields(services, FEATURES)
    for feature, settings in services.items():
        fields(settings, {'enabled', 'configuration'}, {'enabled'})
        require(type(settings['enabled']) is bool, 'Service enable flags must be booleans.')
        # Native integration modules must be explicitly admitted until their typed compiler is qualified.
        if settings['enabled'] and feature not in {'dns', 'dhcp4', 'ntp'}:
            require(isinstance(settings.get('configuration'), str) and
                    re.fullmatch(r'[a-z][a-z0-9-]{0,47}', settings['configuration']),
                    'Advanced service requires a declared, admitted configuration extension.')
    extensions = value.setdefault('extensions', [])
    require(isinstance(extensions, list) and len(extensions) <= 32 and
            all(isinstance(item, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', item) for item in extensions) and
            len(extensions) == len(set(extensions)), 'Invalid or duplicate extension identity.')
    for feature, settings in services.items():
        if settings['enabled'] and feature not in {'dns', 'dhcp4', 'ntp'}:
            require(settings['configuration'] in extensions,
                    'Enabled advanced service has no admitted extension declaration.')
    if 'release' in value:
        fields(value['release'], {'image_id', 'sequence_floor'})
        require(isinstance(value['release'].get('image_id', 'lanrith'), str) and
                re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['release'].get('image_id', 'lanrith')),
                'Invalid release image identity.')
        require(type(value['release'].get('sequence_floor', 0)) is int and
                0 <= value['release'].get('sequence_floor', 0) <= 999999999,
                'Invalid release deployment sequence.')
    require(not any(network.get('dns') for network in networks.values()) or
            services.get('dns', {}).get('enabled', False), 'Network DNS requires the DNS service.')
    require(not any('dhcp4' in network for network in networks.values()) or
            services.get('dhcp4', {}).get('enabled', False), 'DHCP pools require the DHCP service.')
    return value


def render(value):
    value = normalize(value)
    user = value['administration']['username']
    files = {'etc/hostname': value['hostname'] + '\n',
             'etc/hosts': '127.0.0.1 localhost\n127.0.1.1 '+value['hostname']+'\n'
                 '::1 localhost ip6-localhost ip6-loopback\n',
             'etc/sysctl.d/90-lanrith-routing.conf': firewall.sysctls(),
             'etc/ssh/sshd_config.d/00-lanrith.conf':
                 'PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
                 f'AllowUsers {user}\nHostKey {value["administration"]["host_key_state"]}/ssh_host_ed25519_key\n'
                 f'Port {value["administration"].get("ssh_port", 22)}\n',
             f'home/{user}/.ssh/authorized_keys': '\n'.join(value['administration']['authorized_keys']) + '\n',
             'etc/security/authorized_keys': '\n'.join(value['administration']['authorized_keys']) + '\n',
             'etc/sudoers.d/60-lanrith': f'{user} ALL=(ALL:ALL) ALL\nDefaults:{user} env_keep += "SSH_AUTH_SOCK"\n'
                 f'Defaults:{user} timestamp_type=tty\nDefaults:{user} timestamp_timeout=5\n'}
    interfaces, networks = value['hardware']['interfaces'], value['networks']
    for key, interface in interfaces.items():
        kind, selector = next(iter(interface['match'].items()))
        match = {'mac': 'MACAddress', 'path': 'Path', 'driver': 'Driver'}[kind]
        files[f'etc/systemd/network/10-{key}.link'] = (
            f'[Match]\n{match}={selector}\n\n[Link]\nName={interface["name"]}\n'
            f'MTUBytes={interface.get("mtu", 1500)}\n')
    wan = interfaces[value['uplink']['interface']]['name']
    uplink = value['uplink']
    dhcp = 'ipv4' if uplink.get('ipv4', 'dhcp') == 'dhcp' else 'no'
    files['etc/systemd/network/20-uplink.network'] = (
        f'[Match]\nName={wan}\n\n[Network]\nDHCP={dhcp}\n'
        f'IPv6AcceptRA={"yes" if uplink.get("ipv6", "ra") == "ra" else "no"}\n'
        'LLMNR=no\nMulticastDNS=no\n' +
        ('LinkLocalAddressing=no\n' if uplink.get('ipv6', 'ra') == 'disabled' else 'LinkLocalAddressing=ipv6\n') +
        ''.join(f'Address={address}\n' for address in uplink.get('addresses', [])) +
        ''.join(f'Gateway={gateway}\n' for gateway in uplink.get('gateways', [])) +
        '\n[DHCPv4]\nUseDNS=no\nUseNTP=no\nUseHostname=no\n')
    if 'upload_shaping' in uplink:
        files['etc/systemd/network/20-uplink.network'] += (
            '\n[CAKE]\nParent=root\nBandwidth=' + str(uplink['upload_shaping']['mbps']) +
            'M\nFlowIsolationMode=dual-src-host\nNAT=yes\nPriorityQueueingPreset=besteffort\nSplitGSO=yes\n')
    parents = {}
    for key, network in networks.items():
        if 'vlan' in network:
            files[f'etc/systemd/network/30-{key}.netdev'] = (
                f'[NetDev]\nName={network["name"]}\nKind=vlan\n\n[VLAN]\nId={network["vlan"]}\n')
            parents.setdefault(interfaces[network['interface']]['name'], []).append(network['name'])
        text = f'[Match]\nName={network["name"]}\n\n[Network]\n'
        text += ''.join(f'Address={address}\n' for address in network['addresses'])
        text += 'IPv6AcceptRA=no\nIPv6SendRA=' + ('yes' if network.get('ra') else 'no') + '\n'
        text += 'LinkLocalAddressing=' + ('ipv6' if any(':' in a for a in network['addresses']) else 'no') + '\n'
        text += 'LLMNR=no\nMulticastDNS=no\n'
        if network.get('ra'):
            if network.get('dns'):
                resolvers = [str(ipaddress.ip_interface(a).ip) for a in network['addresses'] if ':' in a]
                text += '\n[IPv6SendRA]\nDNS=' + ' '.join(resolvers) + '\nEmitDNS=yes\n'
            for address in network['addresses']:
                parsed = ipaddress.ip_interface(address)
                if parsed.version == 6:
                    text += f'\n[IPv6Prefix]\nPrefix={parsed.network}\n'
        files[f'etc/systemd/network/40-{key}.network'] = text
    for parent, vlans in parents.items():
        require(not any(n['name'] == parent for n in networks.values()),
                'Use tagged networks on a trunk, or an explicitly separate untagged interface.')
        files[f'etc/systemd/network/25-{parent}-trunk.network'] = (
            f'[Match]\nName={parent}\n\n[Network]\nLinkLocalAddressing=no\n' +
            ''.join(f'VLAN={vlan}\n' for vlan in vlans))
    files['etc/nftables.conf'] = firewall.render(value)
    if value['services'].get('ntp', {}).get('enabled'):
        text = ('pool 2.pool.ntp.org iburst\ndriftfile /var/lib/chrony/chrony.drift\n'
                'rtcsync\nmakestep 1 3\ncmdport 0\n')
        for network in networks.values():
            for address in network['addresses']:
                text += f'allow {ipaddress.ip_interface(address).network}\n'
        files['etc/chrony/chrony.conf'] = text
    if value['services'].get('dns', {}).get('enabled'):
        # Address configuration and IPv6 DAD can finish after network.target.
        # Bind only these explicit addresses before they are ready; health
        # still requires the declared gateway addresses before acceptance.
        text = 'server:\n  ip-freebind: yes\n  interface: 127.0.0.1\n  interface: ::1\n  access-control: 0.0.0.0/0 refuse\n  access-control: ::/0 refuse\n'
        for network in networks.values():
            if network.get('dns'):
                for address in network['addresses']:
                    parsed = ipaddress.ip_interface(address)
                    text += f'  interface: {parsed.ip}\n  access-control: {parsed.network} allow\n'
        files['etc/unbound/unbound.conf.d/lanrith.conf'] = text
    if value['services'].get('dhcp4', {}).get('enabled'):
        scopes = []
        for key, network in networks.items():
            if 'dhcp4' not in network:
                continue
            address = next(ipaddress.ip_interface(a) for a in network['addresses'] if ':' not in a)
            scopes.append({'id': len(scopes) + 1, 'subnet': str(address.network), 'interface': network['name'],
                           'pools': [{'pool': ' - '.join(network['dhcp4']['pool'])}],
                           'option-data': [{'name': 'routers', 'data': str(address.ip)}] +
                                          ([{'name': 'domain-name-servers', 'data': str(address.ip)}] if network.get('dns') else [])})
        files['etc/kea/kea-dhcp4.conf'] = json.dumps({'Dhcp4': {
            'interfaces-config': {'interfaces': [scope['interface'] for scope in scopes]},
            'lease-database': {'type': 'memfile', 'persist': True, 'name': '/var/lib/kea/kea-leases4.csv'},
            'valid-lifetime': 3600, 'subnet4': scopes}}, indent=2) + '\n'
    files['usr/share/lanrith/resolved.json'] = canonical(value).decode()
    files['usr/share/lanrith/configuration.sha256'] = hashlib.sha256(canonical(value)).hexdigest() + '\n'
    return files


def write(value, directory):
    require(not directory.exists() and not directory.is_symlink(), 'Output directory must not exist.')
    files = render(value)
    directory.mkdir(mode=0o700)
    for name, text in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o440 if name.startswith('etc/sudoers.d/') else 0o644)
    return hashlib.sha256(canonical(value)).hexdigest()
