"""Reconcile signed-image RRset transitions in the private pre-start primary."""

import base64
import json
import os
from pathlib import Path
import subprocess
import time


class MigrationError(ValueError):
    pass


def prerequisite(record, values):
    name, kind = record['name'], record['type']
    if not values:
        return [f'prereq nxrrset {name} {kind}']
    return [f'prereq yxrrset {name} {kind} {value}' for value in values]


def transaction(zone, commands, key):
    request = '\n'.join(['server 127.0.0.1 1053', 'zone '+zone+'.', *commands, 'send', ''])
    result = subprocess.run(['/usr/bin/nsupdate', '-v', '-t', '3', '-k', str(key)], input=request,
                            capture_output=True, text=True, timeout=5, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode == 0:
        return True
    # Only a failed prerequisite means "different data". Authentication,
    # refusal, transport failures and malformed requests must stop migration.
    if result.stderr.strip() in ('update failed: NXRRSET', 'update failed: YXRRSET',
                                 'update failed: NXDOMAIN', 'update failed: YXDOMAIN'):
        return False
    raise MigrationError(f'Unable to check or update release-managed DNS zone {zone}.')


def reconcile(zone, records, key):
    expected = [line for r in records for line in prerequisite(r, r['desired'])]
    if transaction(zone, expected, key):
        return
    checks, edits = [], []
    for record in records:
        desired = prerequisite(record, record['desired'])
        if transaction(zone, desired, key):
            checks.extend(desired)
            continue
        name, kind = record['name'], record['type']
        checks.extend(prerequisite(record, record['previous']))
        if record['desired']:
            if kind in ('A', 'AAAA'):
                checks.append(f'prereq nxrrset {name} CNAME')
            elif not record['previous']:
                # A CNAME cannot share its owner with a publisher's other data.
                checks.append(f'prereq nxdomain {name}')
        edits.append(f'update delete {name} {kind}')
        edits.extend(f'update add {name} 300 {kind} {value}' for value in record['desired'])
    if not transaction(zone, checks+edits, key):
        raise MigrationError(f'Release-managed DNS prerequisite conflict in zone {zone}.')
    if not transaction(zone, expected, key):
        raise MigrationError(f'Release-managed DNS result mismatch in zone {zone}.')


def check_fixed(zone, records, key):
    # The private primary has no concurrent publishers. Multiple read-only
    # RFC 2136 requests can check a large inventory without a DNS size limit.
    def verify(batch):
        commands = [line for r in batch for line in prerequisite(r, r['desired'])]
        return transaction(zone, commands, key)

    def check(batch):
        if verify(batch):
            return
        # Report a specific failed prerequisite, even for a large zone. Each
        # batch is a conjunction over the same read-only state.
        while len(batch) > 1:
            middle = len(batch)//2
            batch = batch[middle:] if verify(batch[:middle]) else batch[:middle]
        record = batch[0]
        raise MigrationError(f'Fixed DNS addresses or delegation conflict in zone {zone} '
                             f'for {record["name"]} {record["type"]}.')

    batch = []
    size = 0
    for record in records:
        cost = sum(len(line)+32 for line in prerequisite(record, record['desired']))
        if batch and size+cost > 32768:
            check(batch)
            batch = []
            size = 0
        batch.append(record)
        size += cost
    if batch:
        check(batch)


def migrate(plan, config, key, fixed=None):
    fixed = fixed or {}
    # The image supplies both the plan and matching exact-name/type grants.
    # Only this service sees the auxiliary listener and volatile key directory.
    secret = base64.b64encode(os.urandom(32)).decode('ascii')
    # The service owns a fresh private runtime directory on each activation.
    fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(f'key "lanrith-migration" {{ algorithm hmac-sha256; secret "{secret}"; }};\n')
        with subprocess.Popen(['/usr/sbin/named', '-g', '-n', '1', '-c', str(config)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as named:
            try:
                deadline = time.monotonic()+12
                for zone in sorted(plan.keys() | fixed.keys()):
                    while True:
                        if named.poll() is not None:
                            raise MigrationError('Private migration DNS primary exited during startup.')
                        try:
                            if transaction(zone, ['prereq yxrrset '+zone+'. SOA'], key):
                                break
                        except MigrationError:
                            pass
                        if time.monotonic() >= deadline:
                            raise MigrationError(f'Private migration DNS primary could not load zone {zone}.')
                        time.sleep(0.1)
                    changes = plan.get(zone, [])
                    managed = {(r['name'], r['type']) for r in changes}
                    # Check everything outside this atomic migration before writing.
                    # reconcile verifies the desired values of the managed RRsets.
                    check_fixed(zone, [r for r in fixed.get(zone, []) if (r['name'], r['type']) not in managed], key)
                    if changes:
                        reconcile(zone, changes, key)
            finally:
                named.terminate()
                try:
                    named.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    named.kill()
                    named.wait()
                    raise MigrationError('Private migration DNS primary failed to stop.') from None
            if named.returncode != 0:
                raise MigrationError('Private migration DNS primary stopped abnormally.')
    finally:
        key.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        migrate(json.loads(Path('/usr/share/lanrith/dns-migration.json').read_text()),
                Path('/etc/bind/lanrith-migration.conf'), Path('/var/lib/bind/migration.key'),
                json.loads(Path('/usr/share/lanrith/dns-fixed.json').read_text()))
    except MigrationError as error:
        raise SystemExit(str(error)) from None
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('Unable to reconcile release-managed DNS records.') from None
