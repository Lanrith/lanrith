"""Compile a bounded RADIUS service without embedding runtime credentials."""

import ipaddress as ip

from . import bindings, intent, service_plane
from .release import canonical


def active(value):
    return value.get('identity', {}).get('radius', {}).get('enabled', False)


def directory_admission(value):
    return active(value) and 'directory' in value['identity']['radius']['admission']


def manifest(value):
    radius = value['identity']['radius']
    listeners = intent.service_addresses(value, 'radius')
    proxy = ip.ip_address(radius['proxy']['address'])
    source = next(address for address in listeners if ip.ip_address(address).version == proxy.version)
    clients = []
    for name, client in sorted(radius['clients'].items()):
        item = {'name': name, 'address': str(ip.ip_network(client['address'])),
                'kind': client['kind'], 'credential_name': client['credential']}
        if 'port' in client:
            item['port'] = client['port']
        clients.append(item)
    fallback = radius.get('fallback', {})
    return {
        'schema_version': 1,
        'listeners': listeners,
        'authentication_port': 1812,
        'accounting_port': 1813,
        'admission_vlan': value['networks'][radius['admission']['network']]['vlan'],
        'clients': clients,
        'proxy': {'address': str(proxy), 'port': 1812, 'source': source,
                  'credential_name': radius['proxy']['credential'],
                  **({'response_window': fallback['provider_response_seconds'] + 1}
                     if fallback.get('enabled', False) else {})},
        'fallback_clients': sorted(fallback.get('clients', [])) if fallback.get('enabled', False) else [],
    }


def _static_proxy():
    # The image-only configuration has no client or upstream secret. Keeping a
    # rejecting local server makes the distribution parser testable before the
    # combined client and proxy generation replaces this file.
    pool = '    home_server = lanrith_fallback\n'
    return (
        'proxy server {\n    default_fallback = no\n}\n'
        'home_server lanrith_fallback {\n    virtual_server = lanrith_mab_fallback\n}\n'
        'home_server_pool lanrith_pool {\n    type = fail-over\n'+pool+'}\n'
        'realm lanrith {\n    auth_pool = lanrith_pool\n    nostrip\n}\n'
        'realm NULL {\n    auth_pool = lanrith_pool\n}\n'
        'realm DEFAULT {\n    auth_pool = lanrith_pool\n}\n')


def _accounting():
    return (
        'linelog router_accounting {\n'
        '    filename = syslog\n    syslog_facility = authpriv\n    syslog_severity = info\n'
        '    format = "radius-policy-accounting-v1 '
        '{\\"received_at\\":%l,\\"mac\\":\\"%{control:Tmp-String-0}\\",'
        '\\"nas_source\\":\\"%{Packet-Src-IP-Address}\\",'
        '\\"nas_reported_ipv4\\":\\"%{request:NAS-IP-Address}\\",'
        '\\"nas_port\\":\\"%{request:NAS-Port}\\",'
        '\\"nas_port_type\\":\\"%{request:NAS-Port-Type}\\",'
        '\\"nas_port_id_hex\\":\\"%{hex:&request:NAS-Port-Id}\\",'
        '\\"session_id_hex\\":\\"%{hex:&request:Acct-Session-Id}\\",'
        '\\"status\\":\\"%{request:Acct-Status-Type}\\",'
        '\\"event_time\\":\\"%{request:Event-Timestamp}\\",'
        '\\"delay_seconds\\":\\"%{request:Acct-Delay-Time}\\",'
        '\\"session_seconds\\":\\"%{request:Acct-Session-Time}\\",'
        '\\"ipv4\\":\\"%{request:Framed-IP-Address}\\",'
        '\\"ipv6_addresses\\":\\"%{request:Framed-IPv6-Address[*]}\\",'
        '\\"ipv6_prefixes\\":\\"%{request:Framed-IPv6-Prefix[*]}\\",'
        '\\"interface_id\\":\\"%{request:Framed-Interface-Id}\\",'
        '\\"vlan_reported_hex\\":\\"%{hex:&request:Tunnel-Private-Group-Id}\\"}"\n}\n')


def _mab_validation(indent='        '):
    return (
        indent+'if (!&request:User-Name || &request:User-Name !~ /^[0-9A-Fa-f]{12}$/ || '
        '!&request:User-Password || !&request:Calling-Station-Id || &request:EAP-Message || '
        '&request:CHAP-Password || &request:MS-CHAP-Response || &request:MS-CHAP2-Response) {\n'
        +indent+'    reject\n'+indent+'}\n'
        +indent+'if (&request:User-Name[1] || &request:User-Password[1] || '
        '&request:Calling-Station-Id[1] || &request:Service-Type[1] || &request:NAS-Port-Type[1]) {\n'
        +indent+'    reject\n'+indent+'}\n'
        +indent+'if (&request:Service-Type && &request:Service-Type != Call-Check) {\n'
        +indent+'    reject\n'+indent+'}\n'
        +indent+'update control {\n'+indent+'    Tmp-String-0 := "%{toupper:%{request:User-Name}}"\n'+indent+'}\n'
        +indent+'if (&request:Calling-Station-Id =~ '
        '/^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]'
        '([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$/) {\n'
        +indent+'    update control {\n'+indent+'        Tmp-String-1 := '
        '"%{toupper:%{1}%{2}%{3}%{4}%{5}%{6}}"\n'+indent+'    }\n'+indent+'}\n'
        +indent+'elsif (&request:Calling-Station-Id =~ /^[0-9A-Fa-f]{12}$/) {\n'
        +indent+'    update control {\n'+indent+'        Tmp-String-1 := '
        '"%{toupper:%{request:Calling-Station-Id}}"\n'+indent+'    }\n'+indent+'}\n'
        +indent+'else {\n'+indent+'    reject\n'+indent+'}\n'
        +indent+'if (&control:Tmp-String-0 !~ /^[0-9A-F][02468ACE][0-9A-F]{10}$/ || '
        '&control:Tmp-String-0 == "000000000000" || &control:Tmp-String-0 != &control:Tmp-String-1 || '
        '&control:Tmp-String-0 != "%{toupper:%{request:User-Password}}") {\n'
        +indent+'    reject\n'+indent+'}\n')


def _site(policy, binding):
    vlan = policy['admission_vlan']
    text = [f'# Verified provider admission binding SHA-256 {binding}'] if binding else []
    text.append('server default {')
    for address in policy['listeners']:
        field = 'ipv6addr' if ':' in address else 'ipaddr'
        for kind, port in (('auth', 1812), ('acct', 1813)):
            text += ['    listen {', '        type = '+kind, '        '+field+' = '+address,
                     '        port = '+str(port), '    }']
    text += [
        '    accounting {',
        '        if (&request:Calling-Station-Id =~ /^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$/) {',
        '            update control {',
        '                Tmp-String-0 := "%{toupper:%{1}%{2}%{3}%{4}%{5}%{6}}"',
        '            }',
        '        }',
        '        elsif (&request:Calling-Station-Id =~ /^[0-9A-Fa-f]{12}$/) {',
        '            update control {',
        '                Tmp-String-0 := "%{toupper:%{request:Calling-Station-Id}}"',
        '            }',
        '        }',
        '        if (&control:Tmp-String-0 =~ /^[0-9A-F][02468ACE][0-9A-F]{10}$/ && &control:Tmp-String-0 != "000000000000" && !&request:Calling-Station-Id[1] && &request:Acct-Session-Id && !&request:Acct-Session-Id[1] && !&request:Acct-Status-Type[1] && (&request:Acct-Status-Type == Start || &request:Acct-Status-Type == Stop || &request:Acct-Status-Type == Alive || &request:Acct-Status-Type == Interim-Update) && !&request:Framed-IPv6-Address[16] && !&request:Framed-IPv6-Prefix[4]) {',
        '            router_accounting',
        '        }',
        '        ok',
        '    }',
        '    authorize {',
    ]
    for index, client in enumerate(policy['clients']):
        branch = 'if' if index == 0 else 'elsif'
        text.append('        '+branch+' ("%{client:shortname}" == "'+client['name']+'") {')
        text.extend(_mab_validation('            ').rstrip().splitlines())
        # Carry the validated wired NAS/port selection to the reply and timeout handlers.
        if client['name'] in policy['fallback_clients']:
            text += [f'            if (&request:NAS-Port == {client["port"]} && !&request:NAS-Port[1] && '
                     '(!&request:NAS-Port-Type || &request:NAS-Port-Type == Ethernet)) {',
                     '                update control {', '                    Tmp-Integer-0 := 1',
                     '                }', '            }']
        text += ['            update control {', '                Proxy-To-Realm := "lanrith"',
                 '            }', '        }']
    text += ['        else {', '            reject', '        }', '    }']
    # In 3.2.7 zero TTL deletes a hit but creates on a miss unless read-only.
    forget = [
        '            if (&control:Tmp-Integer-0) {',
        '                update control {',
        '                    Cache-Read-Only := yes',
        '                    Cache-TTL := 0',
        '                }',
        '                lanrith_mab_cache',
        '            }',
    ]
    if policy['fallback_clients']:
        text += [
            '    post-proxy {',
            '        Post-Proxy-Type Reject {',
            *forget, '        }',
            '        Post-Proxy-Type Fail-Authentication {',
            '            if (&control:Tmp-Integer-0) {',
            '                update control {', '                    Cache-Read-Only := yes', '                }',
            '                lanrith_mab_cache',
            '                if (ok && &control:Tunnel-Type == VLAN && &control:Tunnel-Medium-Type == IEEE-802 && '
            f'&control:Tunnel-Private-Group-Id == "{vlan}") {{',
            '                    update control {', '                        Response-Packet-Type := Access-Accept',
            '                    }', '                    update reply {',
            '                        Tunnel-Type := VLAN', '                        Tunnel-Medium-Type := IEEE-802',
            f'                        Tunnel-Private-Group-Id := "{vlan}"', '                    }',
            '                }', '            }', '        }', '    }']
    text += ['    post-auth {', '        Post-Auth-Type Challenge {']
    if policy['fallback_clients']:
        text.extend(forget)
    text += [
        '            reject', '        }',
        '        if (!&reply:Tunnel-Type || &reply:Tunnel-Type != VLAN || &reply:Tunnel-Type[1] || '
        '!&reply:Tunnel-Medium-Type || &reply:Tunnel-Medium-Type != IEEE-802 || &reply:Tunnel-Medium-Type[1] || '
        f'!&reply:Tunnel-Private-Group-Id || &reply:Tunnel-Private-Group-Id != "{vlan}" || '
        '&reply:Tunnel-Private-Group-Id[1]) {']
    if policy['fallback_clients']:
        text.extend(forget)
    text += ['            reject', '        }']
    if policy['fallback_clients']:
        text += ['        if (&control:Tmp-Integer-0 && !&control:Post-Proxy-Type && '
                 '"%{proxy-reply:Packet-Type}" == "Access-Accept") {', '            update control {',
                 '                Cache-TTL := -300', '            }', '            lanrith_mab_cache', '        }']
    text += ['    }', '}']
    return '\n'.join(text)+'\n'


def _cache(vlan):
    return (
        'cache lanrith_mab_cache {\n    driver = "rlm_cache_rbtree"\n'
        '    key = "%{client:shortname}:%{request:NAS-Port}:%{control:Tmp-String-0}"\n'
        '    ttl = 300\n    max_entries = 256\n    add_stats = no\n    update {\n'
        '        &control:Tunnel-Type := VLAN\n'
        '        &control:Tunnel-Medium-Type := IEEE-802\n'
        f'        &control:Tunnel-Private-Group-ID := "{vlan}"\n'
        '    }\n}\n')


def render(value):
    if not active(value):
        return {}
    policy = manifest(value)
    admission = value['identity']['radius']['admission']
    binding = admission.get('provider_policy', {}).get('binding_sha256')
    references = sorted({policy['proxy']['credential_name'],
                         *(client['credential_name'] for client in policy['clients'])})
    credentials = ''.join('LoadCredential='+name+':'+bindings.credential_path(value, name)+'\n'
                          for name in references)
    allows = sorted({client['address'] for client in policy['clients']} |
                    {str(ip.ip_network(policy['proxy']['address']))})
    unit = (
        '[Unit]\nDescription=Bounded network admission and accounting\n'
        'Requires=lanrith-services.service lanrith-radius-runtime.service\n'
        'After=lanrith-services.service lanrith-radius-runtime.service systemd-journald.service\n'
        'BindsTo=lanrith-services.service nftables.service\n'
        'Before=lanrith-policy-bindings.service\n\n[Service]\n'
        'NetworkNamespacePath=/run/netns/'+service_plane.NAMESPACE+'\n'
        'ExecStartPre=\n'
        'ExecStartPre=/usr/sbin/freeradius -Cx -lstdout\n'
        'BindReadOnlyPaths=/run/lanrith-radius/radius.conf:/etc/freeradius/3.0/proxy.conf\n'
        'ReadWritePaths=/run/freeradius\nLogsDirectory=freeradius\nLogsDirectoryMode=0750\n'
        'IPAddressDeny=any\nIPAddressAllow=localhost\n'+
        ''.join('IPAddressAllow='+prefix+'\n' for prefix in allows)+
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nNoNewPrivileges=yes\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
        'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\n'
        'Restart=on-failure\nRestartSec=2s\n')
    # Mount sources must exist before systemd constructs the daemon's sandbox.
    # A separate root helper also keeps the native fragments read-only to freerad.
    stage = (
        '[Unit]\nDescription=Prepare protected RADIUS configuration fragments\n'
        'Before=freeradius.service\n\n[Service]\nType=oneshot\nUser=root\nGroup=freerad\n'
        'ExecStart=/usr/lib/lanrith/radius-runtime stage\n'+credentials+
        'RuntimeDirectory=lanrith-radius\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n'
        'UMask=0077\nTimeoutStartSec=30s\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nPrivateNetwork=yes\n'
        'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\n'
        'ProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\n'
        'RestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n'
        'ReadWritePaths=/run/lanrith-radius\nMemoryMax=64M\nMemorySwapMax=0\nTasksMax=8\nLimitCORE=0\n')
    return {
        'usr/share/lanrith/radius.json': canonical(policy).decode(),
        'etc/freeradius/3.0/clients.conf': '# Runtime credentials are staged through systemd credentials.\n',
        'etc/freeradius/3.0/proxy.conf': _static_proxy(),
        # The generated service is MAC admission only and rejects EAP input.
        # Replace Debian's enabled EAP module so an unrelated bootstrap TLS
        # key is neither generated nor required in the deployed image.
        'etc/freeradius/3.0/mods-enabled/eap': '# EAP is intentionally disabled by the Lanrith MAB policy.\n',
        'etc/freeradius/3.0/mods-enabled/lanrith_accounting': _accounting(),
        'etc/freeradius/3.0/mods-enabled/lanrith_mab_cache': _cache(policy['admission_vlan']),
        'etc/freeradius/3.0/sites-enabled/inner-tunnel':
            '# The EAP inner tunnel is intentionally disabled by the Lanrith MAB policy.\n',
        'etc/freeradius/3.0/sites-enabled/default': _site(policy, binding),
        'etc/freeradius/3.0/sites-enabled/lanrith_mab_fallback':
            'server lanrith_mab_fallback {\n    authorize {\n        reject\n    }\n}\n',
        'etc/systemd/system/freeradius.service.d/60-lanrith.conf': unit,
        'usr/lib/systemd/system/lanrith-radius-runtime.service': stage,
    }
