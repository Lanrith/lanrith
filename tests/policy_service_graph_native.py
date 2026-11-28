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
from lanrith import policy_runtime, router_metrics_runtime
from lanrith.release import canonical, require
import policy_bindings_component_native as bindings_test
import policy_observer_component_native as base
from policy_enrollment_native import interrupt_after
from test_radius import provider_export

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


def result(message_id, tag, *, cookie=None, code=0):
    body = tlv(2, message_id)+tlv(tag, tlv(10, bytes([code]))+tlv(4, b'')+tlv(4, b''))
    if cookie is not None:
        page = tlv(0x30, tlv(2, b'\0')+tlv(4, cookie))
        body += tlv(0xa0, tlv(0x30, tlv(4, '1.2.840.113556.1.4.319')+tlv(4, page)))
    return tlv(0x30, body)


def entry(message_id, dn, attributes):
    encoded = b''
    for key, values in attributes.items():
        encoded += tlv(0x30, tlv(4, key)+tlv(0x31, b''.join(tlv(4, value) for value in values)))
    return tlv(0x30, tlv(2, message_id)+tlv(0x64, tlv(4, dn)+tlv(0x30, encoded)))


def search_page(connection, unit, expected_cookie):
    message_id, search, *rest = receive(connection)
    require(search[0] == 0x63 and fields(search[1])[:3] == [
        (4, ('ou='+unit+',dc=example,dc=test').encode()), (10, b'\1'), (10, b'\0')],
        'Unexpected search namespace or scope.')
    if not rest:
        require(not expected_cookie, 'Reader resumed a continuation without paging.')
        return message_id[1], None
    controls, = rest
    control, = fields(controls[1])
    oid, critical, value = fields(control[1])
    require(controls[0] == 0xa0 and control[0] == 0x30 and oid == (4, b'1.2.840.113556.1.4.319')
            and critical[0] == 1 and critical[1] in (b'\xff', b'\1') and value[0] == 4,
            'Reader omitted critical paging.')
    page, = fields(value[1])
    size, cookie = fields(page[1])
    require(page[0] == 0x30 and size[0] == 2 and cookie == (4, expected_cookie),
            'Reader did not return the issued paging cookie.')
    return message_id[1], int.from_bytes(size[1], 'big')


def directory_rows(mode):
    names = ('vlan-placement', 'trusted-access')
    groups = ['cn='+name+',ou=groups,dc=example,dc=test' for name in names]
    user = 'cn='+bindings_test.MAC+',ou=users,dc=example,dc=test'
    member_groups = groups[:1] if mode == 'withdrawn' else groups
    entries = {'groups': [], 'users': []}
    for index, group in enumerate(bindings_test.snapshot()['directory']['groups']):
        attrs = {'uid': [group['id']], 'cn': [names[index]], 'objectClass': ['goauthentik.io/ldap/group'],
                 'network_policy_v1': [group['policy']]}
        if groups[index] in member_groups:
            attrs['member'] = [user]
        entries['groups'].append((groups[index], attrs))
    entries['users'].append((user, {'uid': ['synthetic-device'], 'cn': [bindings_test.MAC],
        'objectClass': ['goauthentik.io/ldap/user'], 'memberOf': member_groups,
        'ak-active': ['false' if mode == 'inactive' else 'true']}))
    entries['users'].append(('cn=router,ou=users,dc=example,dc=test', {
        'uid': ['synthetic-lookup'], 'cn': ['router'], 'objectClass': ['goauthentik.io/ldap/user']}))
    return entries


def serve_searches(connection, mode, event):
    for unit, rows in directory_rows(mode.removeprefix('unpaged-')).items():
        cookie = b''
        offset = 0
        while offset < len(rows):
            message_id, size = search_page(connection, unit, cookie)
            if mode.startswith('unpaged-'):
                require(size is None, 'Unpaged fixture received a paging control.')
                for dn, attributes in rows:
                    connection.sendall(entry(message_id, dn, attributes))
                if unit == 'users' and mode == 'unpaged-interrupted':
                    return
                limited = unit == 'users' and mode == 'unpaged-limited'
                connection.sendall(result(message_id, 0x65, code=4 if limited else 0))
                break
            if size is None:
                # This directory requires paging for the full search. A standard
                # size-limit result makes the auto reader restart with paging.
                connection.sendall(result(message_id, 0x65, code=4))
                continue
            require(size in (1, 256), 'Unexpected page size.')
            if cookie and mode == 'interrupted' and unit == 'users':
                event('withheld-users-continuation')
                return
            page = rows[offset:offset+size]
            for dn, attributes in page:
                connection.sendall(entry(message_id, dn, attributes))
            offset += len(page)
            cookie = unit.encode() if offset < len(rows) else b''
            connection.sendall(result(message_id, 0x65, cookie=None if mode == 'missing-control' else cookie))
            if mode == 'missing-control':
                event('omitted-control')
                return
        event('searched-'+unit)


def serve():
    def event(stage):
        with (DIRECTORY/'events').open('a') as stream: stream.write(stage+'\n')
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
                if mode == 'bind-rejected':
                    connection.sendall(result(request[0][1], 0x61, code=49))
                    continue
                connection.sendall(result(request[0][1], 0x61))
                event('bound')
                serve_searches(connection, mode, event)
            except (ssl.SSLError, EOFError, OSError) as error:
                event(type(error).__name__)  # No request or credential content.
            finally:
                connection.close()


class ServiceGraph:
    def __init__(self, check_provider=False, check_unpaged=False):
        self.check_provider = check_provider
        self.check_unpaged = check_unpaged
        self.provider_results = []
        self.server = None
        self.samples = 0
        self.paused = None
        self.reader_hash = None

    def configure(self, value):
        value['identity']['directories']['directory']['url'] = 'ldap+starttls://['+PEER+']:389'
        value['identity']['radius']['admission']['provider_policy'] = provider_export(
            directory_url=value['identity']['directories']['directory']['url'])
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
        self.credential_gate = files[
            'etc/systemd/system/lanrith-policy-reader-setup.service.d/50-lanrith-credentials.conf']
        credential = self.credential = credentials/contract['directory']['credential_name']
        credential.write_text('synthetic-wire-only\n'); credential.chmod(0o600)
        policy_runtime.ENROLLMENT.parent.mkdir(mode=0o700, parents=True)
        for name in (BOOTSTRAP, READER, 'lanrith-policy-reader-setup.service', 'lanrith-policy-guards.service'):
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
        # Crash after the installed helper's empty history has reached /var.
        # The generated unit must resume this exact state when systemd starts.
        interrupt_after(contract, policy_runtime, 'install_record',
                        lambda directory, name, value: name == 'state.json')
        state = Path(contract['state_directory'])
        require((state/'state.json').exists() and not (state/'ownership-epoch.json').exists(),
                'Unexpected first-install interruption point.')
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
        outcome, timestamp = router_metrics_runtime.reader_attempt(time.monotonic()+2)
        require(outcome == value['outcome'] and 0 <= time.time()-timestamp <= 90,
                'Router metrics failed to observe the authenticated current-boot reader attempt.')
        return {'status': value['outcome'], 'grant_count': value['grant_count']}

    def provider_check(self, stage, expected, *, passes):
        result = base.run('setpriv', '--reuid=1701', '--regid=1701', '--clear-groups', '--',
                          '/usr/bin/router-policy-reader', '-config-directory', str(policy_runtime.READER),
                          '-check-provider', stage, check=False)
        require((result.returncode == 0) == passes, 'Unexpected provider check exit for '+stage)
        receipt = json.loads(result.stdout)
        require(set(receipt) == {'schema_version', 'outcome', 'grant_count', 'denial_count'}
                and receipt['schema_version'] == 1 and receipt['outcome'] == expected,
                'Unexpected provider check outcome for '+stage)
        self.provider_results.append({'stage': stage, 'exit_code': result.returncode, **receipt})
        return receipt

    def qualify_provider(self, checks, observe, kernel_grants):
        for stage in ('single-page', 'multi-page'):
            require(self.provider_check(stage, 'applied', passes=True)['grant_count'] > 0 and kernel_grants(),
                    'Complete synthetic directory did not install the expected grant.')
        before = observe()['snapshot']
        for mode in ('missing-control', 'interrupted'):
            (DIRECTORY/'mode').write_text(mode)
            self.provider_check('multi-page', 'collection_failed', passes=False)
            after = observe()['snapshot']
            require(before['generation'] == after['generation'] and before['grants'] == after['grants'],
                    'Incomplete collection changed the applied grant or its expiry.')
        (DIRECTORY/'mode').write_text('withdrawn')
        require(self.provider_check('withdrawn', 'applied', passes=True)['grant_count'] == 0 and not kernel_grants(),
                'Removing the direct access membership did not withdraw the grant.')
        self.provider_check('multi-page', 'applied', passes=False)
        (DIRECTORY/'mode').write_text('valid')
        require(self.provider_check('multi-page', 'applied', passes=True)['grant_count'] > 0 and kernel_grants(),
                'Membership restoration failed to issue a fresh grant.')
        checks.append('provider-single-and-multi-page-receipts-withdrawal-and-interrupted-continuation-expiry')

        if self.check_unpaged:
            (DIRECTORY/'mode').write_text('unpaged-valid')
            require(self.provider_check('unpaged', 'applied', passes=True)['grant_count'] > 0 and kernel_grants(),
                    'Complete ordinary searches did not grant access.')
            before = observe()['snapshot']
            for mode in ('unpaged-limited', 'unpaged-interrupted'):
                (DIRECTORY/'mode').write_text(mode)
                self.provider_check('unpaged', 'collection_failed', passes=False)
                after = observe()['snapshot']
                require(after['generation'] == before['generation'] and after['grants'] == before['grants'],
                        'An incomplete ordinary search changed the applied grant or expiry.')
            (DIRECTORY/'mode').write_text('unpaged-withdrawn')
            require(self.provider_check('unpaged-withdrawn', 'applied', passes=True)['grant_count'] == 0 and not kernel_grants(),
                    'An ordinary search failed to withdraw the direct grant.')
            (DIRECTORY/'mode').write_text('valid')
            require(self.provider_check('multi-page', 'applied', passes=True)['grant_count'] > 0 and kernel_grants(),
                    'Fresh directory data did not restore the grant.')
            checks.append('unpaged-provider-application-withdrawal-and-incomplete-search-expiry')

    def qualify(self, checks, observed, observe, bindings):
        checks.append('generated-reader-setup-loads-systemd-credential-and-real-starttls-reader-without-controller-rules')
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
        if self.check_provider:
            self.qualify_provider(checks, observe, kernel_grants)
        def application_ages():
            status = base.run('setpriv', '--reuid=1702', '--regid=1702', '--clear-groups', '--',
                              '/usr/bin/router-policy-status', '-socket', str(base.STATUS), '-server-uid', '0',
                              '-timeout', '1500ms').stdout
            summary = router_metrics_runtime.policy_summary(status)
            require(summary['ready'] and summary['applied'], 'Confirmed helper application is missing.')
            return summary['directory_age_ms'], summary['apply_age_ms']
        confirmed = observe()['snapshot']
        prior_ages = application_ages()
        for mode in ('bind-rejected', 'missing-control'):
            (DIRECTORY/'mode').write_text(mode)
            require(self.submit()['status'] == 'collection_failed', 'Failed directory poll looked complete.')
            after = observe()['snapshot']
            require(after['generation'] == confirmed['generation'] and after['grants'] == confirmed['grants'],
                    'A failed poll or metrics read changed the last confirmed application.')
            ages = application_ages()
            require(all(new > old for new, old in zip(ages, prior_ages)), 'A failed poll reset an application age.')
            prior_ages = ages
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
        # The collector can withdraw a window that spans an accounting update.
        # Require both fresh sources when the directory comes back.
        bindings_test.wait(lambda: bindings()['complete'] and bindings()['records'])
        require(self.submit()['grant_count'] > 0, 'Recovered TLS collection did not restore a fresh grant.')
        (DIRECTORY/'mode').write_text('inactive')
        withdrawn = self.submit()
        require(withdrawn == {'status': 'applied', 'grant_count': 0} and not kernel_grants()
                and max(application_ages()) < 30000, 'Fresh zero-grant withdrawal was not confirmed.')
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
        # The preceding clean shutdown already restored denies. Clear the
        # historical sets so this start has to reconstruct them from /var.
        for name in ('tp_history_mac', 'tp_history4'):
            base.run('nft', 'flush', 'set', 'inet', 'lanrith', name)
        self.credential.unlink()
        setup = 'lanrith-policy-reader-setup.service'
        units = Path('/run/systemd/system')
        gate = 'lanrith-credential-ready.service'
        dropin = units/(setup+'.d')/'50-lanrith-credentials.conf'
        dropin.parent.mkdir(exist_ok=True)
        dropin.write_text(self.credential_gate)
        (units/gate).write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/false\n')
        base.run('systemctl', 'daemon-reload')
        require(base.run('systemctl','start',gate,check=False).returncode != 0, 'Fixture gate unexpectedly passed.')
        base.run('systemctl', 'start', BOOTSTRAP)
        for name, value in (('tp_history_mac', bindings_test.MAC), ('tp_history4', bindings_test.IP)):
            result = base.run('nft', '-j', '-n', 'list', 'set', 'inet', 'lanrith', name)
            require(value.encode() in result.stdout, 'Recovery did not restore '+name)
        require(not kernel_grants(), 'Recovery installed a historical grant.')
        (units/gate).write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
        base.run('systemctl', 'daemon-reload')
        base.run('systemctl', 'reset-failed', gate)
        require(base.run('systemctl', 'start', setup, check=False).returncode != 0,
                'Reader setup accepted a missing credential.')
        self.credential.write_text('synthetic-wire-only\n')
        self.credential.chmod(0o600)
        base.run('systemctl', 'reset-failed', setup)
        base.run('systemctl', 'start', setup)
        require(not kernel_grants(), 'Credential repair alone renewed an old grant.')
        checks.append('missing-reader-secret-allows-local-history-restoration-and-repair-alone-issues-no-grant')
        base.run('systemctl', 'start', base.HELPER, timeout=110)
        first = self.submit()
        require(first['status'] in ('applied', 'rejected'), 'Reader did not resume after persistent recovery.')
        bindings_test.wait(lambda: bindings()['complete'] and bindings()['records'])
        require(self.submit()['grant_count'] > 0, 'Reboot-shaped runtime recovery did not admit fresh evidence.')
        checks.append('volatile-runtime-loss-restores-durable-history-and-needs-fresh-directory-and-bindings')
        if self.check_provider:
            observed.pop('binding')
            observed.pop('grant_snapshot')
            observed['provider_checks'] = self.provider_results
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
    parser.add_argument('--check-provider', action='store_true', help='exercise a reader candidate with provider qualification support')
    parser.add_argument('--check-unpaged', action='store_true', help='also qualify ordinary LDAP searches with a generic reader candidate')
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--collector-sha256')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if args.serve:
        serve()
    else:
        graph = ServiceGraph(check_provider=args.check_provider or args.check_unpaged, check_unpaged=args.check_unpaged)
        try:
            bindings_test.qualify(args.candidate, args.collector_sha256, args.result,
                access_backend='tun', configure=graph.configure, prepare_interfaces=graph.interfaces, service_graph=graph)
        finally:
            base.run('ip', 'netns', 'delete', 'directory', check=False)
