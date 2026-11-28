"""Offline packaged FreeRADIUS admission, provider membership and wired outage fixture."""

import argparse
from contextlib import contextmanager
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, radius, radius_runtime
from test_radius import GROUP, MEMBERS, OTHER_GROUP, declaration, provider_export


SECRETS = {'radius_wired': 'A'*32, 'radius_wireless': 'B'*32, 'radius_upstream': 'C'*32}
WIRED, WIFI = '192.168.10.40', '192.168.10.49'


def package_tree(root):
    shutil.copytree('/etc/freeradius/3.0', root, symlinks=True)
    package_group = grp.getgrnam('freerad').gr_gid
    for path in (root, *root.rglob('*')):
        if not path.is_symlink():
            os.chown(path, 0, package_group)
    settings = root/'radiusd.conf'
    settings.write_text(settings.read_text().replace('raddbdir = /etc/freeradius/3.0', 'raddbdir = '+str(root)))
    # Each instance has only the generated MAC site enabled.
    (root/'sites-enabled/inner-tunnel').write_text('# fixture\n')
    (root/'mods-enabled/eap').write_text('# fixture\n')


@contextmanager
def daemon(root):
    log = root.parent/(root.name+'.log')
    with log.open('w') as stream:
        proc = subprocess.Popen(['freeradius', '-f', '-lstdout', '-d', str(root)], stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+5
            while 'Ready to process requests' not in log.read_text():
                if proc.poll() is not None or time.monotonic() > deadline:
                    # Do not echo packet debug logs or client configuration.
                    errors = [line for line in log.read_text().splitlines()
                              if any(word in line.lower() for word in ('error', 'failed', 'permission denied',
                                                                        'cannot ', 'unknown ', 'unable ', 'invalid '))]
                    raise AssertionError(f'{root.name} startup failed: {errors[-6:]}')
                time.sleep(.05)
            yield
        except AssertionError:
            decisions = [row for row in log.read_text().splitlines() if row.startswith('(') and
                         any(token in row for token in ('cache', 'post-proxy', 'post-auth', 'if (updated',
                                                       'Tmp-Integer-0', 'Packet-Type', 'Login incorrect'))]
            print(root.name, *decisions[-70:], sep='\n', flush=True)
            raise
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def install_proxy(root, value, ttl):
    value = config.normalize(value)
    files = radius.render(value)
    for name, body in files.items():
        if name.startswith('etc/freeradius/3.0/'):
            if ttl != 300:
                body = body.replace('ttl = 300', f'ttl = {ttl}').replace('Cache-TTL := -300', f'Cache-TTL := -{ttl}')
            (root/Path(name).relative_to('etc/freeradius/3.0')).write_text(body)
    policy = radius.manifest(value)
    (root/'clients.conf').write_text(radius_runtime.clients_configuration(policy, SECRETS))
    (root/'proxy.conf').write_text(radius_runtime.proxy_configuration(policy, SECRETS))
    return policy


def install_provider(root, policy, group, vlan=22, challenge=False):
    # The same synthetic effective group relation used for the trusted export
    # drives actual PAP authentication and standard tunnel attributes here.
    address = policy['proxy']['address']
    (root/'clients.conf').write_text('client edge {\n ipaddr = '+policy['proxy']['source']+
        '\n secret = '+SECRETS['radius_upstream']+'\n require_message_authenticator = yes\n}\n')
    (root/'proxy.conf').write_text('proxy server {\n default_fallback = no\n}\n')
    pending = '  update control {\n   Response-Packet-Type := Access-Challenge\n  }\n  handled\n' if challenge else ''
    (root/'sites-enabled/default').write_text(
        'server default {\n listen {\n type = auth\n ipaddr = '+address+'\n port = 1812\n }\n'
        ' authorize {\n'+pending+'  if ("%{toupper:%{User-Name}}" != "'+MEMBERS[group]+'") {\n   reject\n  }\n'
        '  update control {\n   Cleartext-Password := &User-Name\n  }\n  pap\n }\n'
        ' authenticate {\n  Auth-Type PAP {\n   pap\n  }\n }\n post-auth {\n'
        '  update reply {\n   Tunnel-Type := VLAN\n   Tunnel-Medium-Type := IEEE-802\n'
        f'   Tunnel-Private-Group-Id := "{vlan}"\n  }}\n }}\n}}\n')


def request(policy, mac, accept, *, source=WIRED, port=5, station=None):
    station = mac if station is None else station
    nas = 'radius_wired' if source == WIRED else 'radius_wireless'
    timeout = 5
    packet = (f'User-Name = "{mac}"\nUser-Password = "{mac}"\nCalling-Station-Id = "{station}"\n'
              f'NAS-Port = {port}\nService-Type = Call-Check\nMessage-Authenticator = 0x00\n'
              f'Packet-Src-IP-Address = {source}\n')
    start = time.monotonic()
    result = subprocess.run(['radclient', '-x', '-r', '1', '-t', str(timeout),
                             policy['listeners'][0]+':1812', 'auth', SECRETS[nas]],
                            input=packet, text=True, capture_output=True, timeout=timeout+2)
    elapsed = time.monotonic()-start
    expected = 'Access-Accept' if accept else 'Access-Reject'
    observed = [row for row in result.stdout.splitlines() if row.startswith('Received ')]
    assert len(observed) == 1 and expected in observed[0], (
        nas, port, expected, observed, elapsed, result.returncode, result.stderr,
        [line for line in result.stdout.splitlines() if 'eceived' in line or 'ERROR' in line])
    assert elapsed < timeout
    if accept:
        assert 'Tunnel-Private-Group-Id:0 = "22"' in result.stdout, 'Wrong admission VLAN'
    return elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-ttl', action='store_true', help='Wait through the full 300-second outage cache lifetime.')
    args = parser.parse_args()
    links = json.loads(subprocess.check_output(['ip', '-j', 'link']))
    assert os.geteuid() == 0 and [link['ifname'] for link in links] == ['lo'] and not Path(
        '/usr/share/lanrith/installed.json').exists(), 'Requires disposable native-tools network namespace.'
    print('freeradius sha256', hashlib.sha256(Path(shutil.which('freeradius')).read_bytes()).hexdigest(), flush=True)
    print(subprocess.check_output(['freeradius', '-v'], text=True).splitlines()[0], flush=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    ttl = 300 if args.full_ttl else 12
    with tempfile.TemporaryDirectory(prefix='radius-native.') as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        proxy, peer = root/'proxy', root/'provider'
        package_tree(proxy)
        package_tree(peer)
        for entry in ('/var/log/freeradius', '/run/freeradius'):
            state = Path(entry)
            state.mkdir(parents=True, exist_ok=True)
            os.chown(state, 0, grp.getgrnam('freerad').gr_gid)
            state.chmod(0o770)
        value = declaration()
        policy = install_proxy(proxy, value, ttl)
        # The runtime consumer validates the manifest before it stages any secrets.
        manifest = root/'radius.json'
        manifest.write_text(json.dumps(policy))
        assert radius_runtime.load(manifest)[0] == policy
        for address in [*policy['listeners'], policy['proxy']['address'], WIRED, WIFI]:
            addr = ipaddress.ip_address(address)
            subprocess.run(['ip', 'address', 'add', f'{addr}/{addr.max_prefixlen}', 'dev', 'lo'], check=True)
        member, other = MEMBERS[GROUP], MEMBERS[OTHER_GROUP]
        install_provider(peer, policy, GROUP)
        with daemon(proxy):
            with daemon(peer):
                request(policy, member.lower(), True)
                request(policy, member, True, source=WIFI)
                request(policy, other, False)
            print('Warm cache after outage', round(request(policy, member, True), 3), 'seconds', flush=True)
            request(policy, member, False, port=6)
            request(policy, member, False, source=WIFI)
            request(policy, member, False, station=other)
            request(policy, other, False)
            install_provider(peer, policy, OTHER_GROUP)
            with daemon(peer):
                request(policy, member, False)
            request(policy, member.lower(), False)
        value['identity']['radius']['admission'].update(group_dn=OTHER_GROUP, provider_policy=provider_export(OTHER_GROUP))
        policy = install_proxy(proxy, value, ttl)
        with daemon(proxy):
            request(policy, other, False)
            with daemon(peer):
                request(policy, member, False)
                request(policy, other, True)
            install_provider(peer, policy, OTHER_GROUP, challenge=True)
            with daemon(peer):
                request(policy, other, False)
            request(policy, other, False)
            install_provider(peer, policy, OTHER_GROUP)
            with daemon(peer):
                request(policy, other, True)
            install_provider(peer, policy, OTHER_GROUP, vlan=21)
            with daemon(peer):
                request(policy, other, False)
            request(policy, other, False)
            install_provider(peer, policy, OTHER_GROUP)
            with daemon(peer):
                request(policy, other, True)
                created = time.monotonic()
            time.sleep(max(0, created+ttl-7-time.monotonic()))
            request(policy, other.lower(), True)
            time.sleep(max(0, created+ttl+1-time.monotonic()))
            request(policy, other, False)
            with daemon(peer):
                request(policy, other, True)
        with daemon(proxy):
            request(policy, other, False)
        print(f'Both policy revisions, provider recovery, scope, rejection, TTL {ttl}s and restart passed.')


if __name__ == '__main__':
    main()
