#!/usr/bin/env python3
"""Exercise generated bootstrap, reader, helper and binding units together.

Run only in an offline disposable systemd container. The directory is a bounded
synthetic LDAP wire server; TLS, the actual unprivileged reader, authenticated
IPC, persistent helper, journal collector and Kea are real. No operational
credentials, production directory or owner YAML are used by the services.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import policy_runtime
from lanrith.release import canonical, require
import policy_bindings_component_native as bindings_test
import policy_observer_component_native as base

PEER = 'fd42:1234:5678:10::30'
DIRECTORY = Path('/run/synthetic-directory')
READER = 'lanrith-policy-reader.service'
BOOTSTRAP = 'lanrith-policy-bootstrap.service'


def tlv(tag, value):
    if isinstance(value, str): value = value.encode()
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x82])+size.to_bytes(2, 'big')
    return bytes([tag])+length+value


def fields(data):
    result = []
    while data:
        require(len(data) >= 2, 'Truncated synthetic BER.')
        tag, size = data[:2]; offset = 2
        if size & 128:
            count = size & 127
            require(0 < count <= 3 and len(data) >= 2+count, 'Invalid synthetic BER length.')
            size = int.from_bytes(data[2:2+count], 'big'); offset += count
        require(size <= 65536 and len(data) >= offset+size, 'Oversized synthetic BER.')
        result.append((tag, data[offset:offset+size])); data = data[offset+size:]
    return result


def exact(stream, size):
    value = b''
    while len(value) < size:
        block = stream.recv(size-len(value))
        if not block: raise EOFError()
        value += block
    return value


def receive(stream):
    header = exact(stream, 2)
    size = header[1]
    if size & 128:
        count = size & 127
        require(0 < count <= 3, 'Invalid synthetic request length.')
        size = int.from_bytes(exact(stream, count), 'big')
    require(header[0] == 0x30 and size <= 65536, 'Invalid synthetic LDAP envelope.')
    return fields(exact(stream, size))


def result(message_id, tag, *, paging=False):
    body = tlv(2, message_id)+tlv(tag, tlv(10, b'\0')+tlv(4, b'')+tlv(4, b''))
    if paging:
        page = tlv(0x30, tlv(2, b'\0')+tlv(4, b''))
        body += tlv(0xa0, tlv(0x30, tlv(4, '1.2.840.113556.1.4.319')+tlv(4, page)))
    return tlv(0x30, body)


def entry(message_id, dn, attributes):
    encoded = b''
    for key, values in attributes.items():
        encoded += tlv(0x30, tlv(4, key)+tlv(0x31, b''.join(tlv(4, value) for value in values)))
    return tlv(0x30, tlv(2, message_id)+tlv(0x64, tlv(4, dn)+tlv(0x30, encoded)))


def serve():
    def event(stage):
        with (DIRECTORY/'events').open('a') as stream: stream.write(stage+'\n')
    user = 'cn='+bindings_test.MAC+',ou=users,dc=example,dc=test'
    groups = ['cn=vlan-placement,ou=groups,dc=example,dc=test',
              'cn=trusted-access,ou=groups,dc=example,dc=test']
    snapshot = bindings_test.snapshot()['directory']
    with socket.socket(socket.AF_INET6) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((PEER, 389)); listener.listen(4)
        (DIRECTORY/'ready').touch()
        while True:
            connection, _ = listener.accept()
            event('accepted')
            connection.settimeout(5)
            try:
                mode = (DIRECTORY/'mode').read_text()
                if mode == 'outage': continue
                request = receive(connection)
                require(request[1] == (0x77, tlv(0x80, '1.3.6.1.4.1.1466.20037')),
                        'Reader did not require StartTLS before bind.')
                connection.sendall(result(request[0][1], 0x78))
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                certificate = 'wrong' if mode == 'untrusted' else 'server'
                context.load_cert_chain(DIRECTORY/(certificate+'.pem'), DIRECTORY/(certificate+'.key'))
                connection = context.wrap_socket(connection, server_side=True)
                event('verified-starttls')
                request = receive(connection)
                require(request[1][0] == 0x60 and fields(request[1][1]) == [
                    (2, b'\3'), (4, b'cn=router,ou=users,dc=example,dc=test'), (0x80, b'synthetic-wire-only')],
                    'Reader bind differs from the synthetic credential.')
                connection.sendall(result(request[0][1], 0x61))
                event('bound')
                for unit in ('groups', 'users'):
                    request = receive(connection); message_id = request[0][1]
                    require(request[1][0] == 0x63 and fields(request[1][1])[0] ==
                            (4, ('ou='+unit+',dc=example,dc=test').encode()), 'Unexpected search namespace.')
                    if unit == 'groups':
                        for index, group in enumerate(snapshot['groups']):
                            name = ('vlan-placement', 'trusted-access')[index]
                            attrs = {'uid': [group['id']], 'cn': [name], 'objectClass': ['goauthentik.io/ldap/group'],
                                     'member': [user], 'network_policy_v1': [group['policy']]}
                            connection.sendall(entry(message_id, groups[index], attrs))
                    else:
                        attrs = {'uid': ['synthetic-device'], 'cn': [bindings_test.MAC],
                                 'objectClass': ['goauthentik.io/ldap/user'], 'memberOf': groups,
                                 'ak-active': ['false' if mode == 'inactive' else 'true']}
                        connection.sendall(entry(message_id, user, attrs))
                    connection.sendall(result(message_id, 0x65, paging=True))
                    event('searched-'+unit)
            except (ssl.SSLError, EOFError, OSError) as error:
                event(type(error).__name__)  # No request or credential content.
            finally:
                connection.close()


class ServiceGraph:
    def __init__(self):
        self.server = None
        self.samples = 0
        self.paused = None
        self.reader_hash = None

    def configure(self, value):
        value['identity']['directories']['directory']['url'] = 'ldap+starttls://['+PEER+']:389'
        value['identity']['directories']['directory']['bind_dn'] = 'cn=router,ou=users,dc=example,dc=test'
        value['groups'] = {}
        value['access']['rules'] = [{'action': 'allow', 'from': 'devices', 'to': 'uplink'}]
        return value

    def interfaces(self, value):
        names = base.prepare_interfaces(value)
        base.run('ip', 'netns', 'add', 'directory')
        base.run('ip', 'link', 'delete', 'lan.1')
        base.run('ip', 'link', 'add', 'lan.1', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'directory')
        base.run('ip', 'link', 'set', 'lan.1', 'up')
        for arguments in (('link', 'set', 'lo', 'up'), ('link', 'set', 'eth0', 'up'),
                          ('address', 'add', PEER+'/64', 'dev', 'eth0', 'nodad')):
            base.run('nsenter', '--net=/run/netns/directory', '--', 'ip', *arguments)
        return names

    def install(self, candidate, contract, files, metadata, units):
        # As in credentials_native: propagate systemd's credential mounts within
        # the container's isolated /run tmpfs, never into the host namespace.
        base.run('mount', '--make-shared', '/run')
        require(not DIRECTORY.exists(), 'Synthetic directory already exists.')
        DIRECTORY.mkdir(mode=0o700)
        (DIRECTORY/'mode').write_text('valid')
        for name in ('server', 'wrong'):
            base.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Synthetic-only-directory', '-addext', 'subjectAltName=IP:'+PEER,
                '-keyout', str(DIRECTORY/(name+'.key')), '-out', str(DIRECTORY/(name+'.pem')))
        trust = Path(contract['directory']['ca_file']); trust.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(DIRECTORY/'server.pem', trust); trust.chmod(0o644)
        self.reader_hash = bindings_test.sha(candidate/'router-policy-reader')
        shutil.copyfile(candidate/'router-policy-reader', '/usr/bin/router-policy-reader')
        Path('/usr/bin/router-policy-reader').chmod(0o755)
        profile = Path(contract['profile_metadata']); profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_bytes(canonical(metadata)); profile.chmod(0o644)
        credentials = Path('/var/lib/lanrith/credentials'); credentials.mkdir(mode=0o700, parents=True)
        credential = credentials/contract['directory']['credential_name']
        credential.write_text('synthetic-wire-only\n'); credential.chmod(0o600)
        policy_runtime.ENROLLMENT.parent.mkdir(mode=0o700, parents=True)
        for name in (BOOTSTRAP, READER, 'lanrith-policy-guards.service'):
            (units/name).write_text(files['usr/lib/systemd/system/'+name])
        # Finalization inspected the physical guard table. Real boot starts
        # from nftables.conf, then the guard unit installs that table once.
        # Reusing the finalizer namespace without this reset duplicates rules.
        boot_rules = Path('/run/synthetic-boot.nft')
        boot_rules.write_text(files['etc/nftables.conf'])
        base.run('nft', '-f', str(boot_rules))
        # Kernel topology and nft loading are supplied by this isolated fixture.
        # These stubs stand in only for the image boot/mount substrate.
        for name in ('nftables.service', 'systemd-networkd.service', 'systemd-sysctl.service'):
            (units/name).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
        self.server = subprocess.Popen(['nsenter', '--net=/run/netns/directory', '--', sys.executable,
                                       str(Path(__file__).resolve()), '--serve'], stdin=subprocess.DEVNULL)
        bindings_test.wait(lambda: (DIRECTORY/'ready').exists())

    def outcomes(self):
        lines = base.run('journalctl', '--no-pager', '-u', READER, '-o', 'cat').stdout.splitlines()
        result = []
        for line in lines:
            try: value = json.loads(line)
            except ValueError: continue
            if isinstance(value, dict) and value.get('schema_version') == 1 and 'outcome' in value:
                result.append(value)
        return result

    def resume(self):
        if self.paused is not None:
            os.kill(self.paused, signal.SIGCONT); self.paused = None

    def submit(self):
        self.resume()
        if self.samples:
            base.run('systemctl', 'restart', READER)
        outcomes = bindings_test.wait(lambda: (values if len(values := self.outcomes()) > self.samples else None))
        self.samples = len(outcomes)
        self.paused = int(base.run('systemctl', 'show', '--property=MainPID', '--value', READER).stdout)
        os.kill(self.paused, signal.SIGSTOP)
        value = outcomes[-1]
        return {'status': value['outcome'], 'grant_count': value['grant_count']}

    def qualify(self, checks, observed, observe, bindings):
        checks.append('generated-bootstrap-loads-systemd-credential-and-real-starttls-reader-without-controller-rules')
        require(policy_runtime.ENROLLMENT.is_file(), 'Generated bootstrap did not enroll persistent state.')
        info = Path('/proc')/str(self.paused)/'status'
        status = info.read_text()
        require('Uid:\t1701\t1701\t1701\t1701' in status and 'CapEff:\t0000000000000000' in status,
                'Reader retained unexpected privilege.')
        checks.append('actual-reader-is-unprivileged-with-zero-capabilities')
        def kernel_grants():
            elements = []
            for family in (4, 6):
                listing = json.loads(base.run('nft', '-j', '-n', 'list', 'set',
                    'inet', 'lanrith', 'tp_grants'+str(family)).stdout)
                elements.extend(element for row in listing['nftables']
                                for element in row.get('set', {}).get('elem', []))
            return elements
        require(kernel_grants(), 'Fresh directory grant was not installed in the kernel.')
        (DIRECTORY/'mode').write_text('untrusted')
        require(self.submit()['status'] == 'collection_failed', 'Untrusted TLS reached policy submission.')
        # Do not shorten or renew the production 90-second grant lifetime.
        # Observations preserve compilation provenance, including expired grants;
        # enforcement is the current kernel set, not the historical total.
        started = time.monotonic()
        bindings_test.wait(lambda: not kernel_grants(), seconds=100)
        observed['directory_outage_expiry_seconds'] = time.monotonic()-started
        checks.append('untrusted-directory-cannot-refresh-original-grant-lifetime')
        (DIRECTORY/'mode').write_text('valid')
        require(self.submit()['grant_count'] > 0, 'Recovered TLS collection did not restore a fresh grant.')
        (DIRECTORY/'mode').write_text('inactive')
        require(self.submit()['grant_count'] == 0 and not kernel_grants(),
                'Inactive directory identity retained permission.')
        checks.append('fresh-inactive-directory-entry-withdraws-permission')
        (DIRECTORY/'mode').write_text('valid')
        require(self.submit()['grant_count'] > 0, 'Reactivated identity did not get a fresh grant.')
        self.resume()
        base.run('systemctl', 'stop', base.HELPER, base.DEPENDENCIES[1], READER, BOOTSTRAP)
        self.samples = len(self.outcomes())
        require(policy_runtime.cohort(policy_runtime.load_contract()) == [bindings_test.MAC],
                'Shutdown discarded classified history.')
        # Simulate volatile /run loss while retaining the same /var state.
        for path in (policy_runtime.ROOT, policy_runtime.READER): shutil.rmtree(path)
        base.run('systemctl', 'start', base.HELPER, timeout=110)
        first = self.submit()
        require(first['status'] in ('applied', 'rejected'), 'Reader did not resume after persistent recovery.')
        bindings_test.wait(lambda: bindings()['complete'] and bindings()['records'])
        require(self.submit()['grant_count'] > 0, 'Reboot-shaped runtime recovery did not admit fresh evidence.')
        checks.append('volatile-runtime-loss-restores-durable-history-and-needs-fresh-directory-and-bindings')
        observed['reader_outcomes'] = self.outcomes()
        require(bindings_test.sha(Path('/usr/bin/router-policy-reader')) == self.reader_hash,
                'Reader changed during qualification.')

    def close(self):
        self.resume()
        if (DIRECTORY/'events').exists():
            print('Synthetic directory stages: '+(DIRECTORY/'events').read_text(), file=sys.stderr)
        else:
            for arguments in (('ip', '-6', 'route', 'get', PEER), ('ip', '-6', 'neighbour'),
                              ('nsenter', '--net=/run/netns/directory', '--', 'ip', '-6', 'address')):
                sys.stderr.buffer.write(base.run(*arguments, check=False).stdout)
        if self.server is not None:
            self.server.terminate(); self.server.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--collector-sha256')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if args.serve:
        serve()
    else:
        graph = ServiceGraph()
        try:
            bindings_test.qualify(args.candidate, args.collector_sha256, args.result,
                access_backend='tun', configure=graph.configure, prepare_interfaces=graph.interfaces, service_graph=graph)
        finally:
            base.run('ip', 'netns', 'delete', 'directory', check=False)
