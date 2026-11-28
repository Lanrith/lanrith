"""Authenticated reads and engine continuity for the disposable SNMP slot fixture."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def profile(sequence):
    assert sequence in (9, 10)
    return {'username': 'fixture-monitor', 'auth_protocol': 'SHA-256', 'priv_protocol': 'AES',
            'auth_password': f'Public-Fixture-Authentication-{sequence}',
            'priv_password': f'Public-Fixture-Encryption-{sequence}'}


def get(server, sequence, interface, *, source=None, namespace=None, expected='read'):
    index = int((Path('/sys/class/net')/interface/'ifindex').read_text())
    selected = profile(sequence)
    with tempfile.TemporaryDirectory(dir='/run') as private:
        client = Path(private)/'snmp.conf'
        client.write_text('defSecurityLevel authPriv\ndefSecurityName '+selected['username']+
                          '\ndefAuthType SHA-256\ndefPrivType AES\ndefAuthPassphrase "'+selected['auth_password']+
                          '"\ndefPrivPassphrase "'+selected['priv_password']+'"\n'+
                          ('clientaddr '+source+'\n' if source else ''))
        client.chmod(0o600)
        command = ['snmpget', '-v3', '-r0', '-t2', '-Oqv', 'udp6:['+server+']:161',
                   f'.1.3.6.1.2.1.31.1.1.1.1.{index}', f'.1.3.6.1.2.1.31.1.1.1.6.{index}']
        if namespace:
            command = ['nsenter', '--net=/run/netns/'+namespace, '--', *command]
        result = subprocess.run(command, capture_output=True, timeout=10, text=True,
                                env={**os.environ, 'LC_ALL': 'C', 'MIBS': '', 'SNMPCONFPATH': private,
                                     'SNMP_PERSISTENT_DIR': private})
    if expected == 'denied':
        assert result.returncode and 'Authentication failure' in result.stderr, \
            'Inactive profile did not receive an explicit authentication failure.'
    elif expected == 'withdrawn':
        assert result.returncode and 'timeout' in result.stderr.lower(), 'Expected withdrawn poller timeout.'
    else:
        assert expected == 'read' and result.returncode == 0, 'Active profile failed the host IF-MIB GET.'
        name, counter = result.stdout.strip().splitlines()
        assert name.strip('"') == interface and counter.isdecimal() and 0 <= int(counter) < 2**64
        return int(counter)


def qualify(sequence, interface):
    installed = json.loads(Path('/usr/share/lanrith/installed.json').read_bytes())
    policy = json.loads(Path('/etc/lanrith/integrations/snmp-runtime-policy.json').read_bytes())
    assert installed['deployment_sequence'] == sequence and installed['credential_delivery'] == 'image'
    assert policy['credential_delivery'] == 'image' and policy['username'] == profile(sequence)['username']
    for unit in ('snmpd.service', 'lanrith-credential-snmp-user.service'):
        subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True, timeout=10)
    inactive = 10 if sequence == 9 else 9
    attempt = subprocess.run(['/usr/lib/lanrith/snmp-runtime', 'apply'], input=json.dumps(profile(inactive)),
                             capture_output=True, text=True, timeout=10)
    assert attempt.returncode and 'only through a new image' in attempt.stderr
    get(policy['server'], inactive, interface, expected='denied')
    counter = get(policy['server'], sequence, interface)
    # The manager's read-only MIB excludes the SNMP-FRAMEWORK-MIB. Extract
    # just these two public values from the privileged persistent configuration.
    state = Path('/var/lib/snmp/snmpd.conf').read_text()
    engine, = re.findall(r'^oldEngineID (0x[0-9a-fA-F]+)$', state, re.M)
    boots, = re.findall(r'^engineBoots ([0-9]+)$', state, re.M)
    assert 0 < int(boots) < 2147483647
    return {'sequence': sequence, 'engine_id': engine, 'engine_boots': int(boots),
            'if_name': interface, 'if_hc_in_octets': counter, 'inactive_profile': 'authentication failure'}


if __name__ == '__main__':
    print(json.dumps(qualify(int(sys.argv[1]), sys.argv[2])))
