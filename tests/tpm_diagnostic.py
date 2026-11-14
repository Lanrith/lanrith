"""Fixed-category TPM setup diagnostics for disposable signed qualification images."""
import re
import json
import shutil
import subprocess
from pathlib import Path

UNIT = 'systemd-tpm2-setup.service'
CATEGORIES = {
    'read-only': ('read-only file system',),
    'permission': ('permission denied', 'operation not permitted'),
    'missing-file': ('no such file or directory',),
    'no-space': ('no space left on device',),
    'timeout': ('timed out', 'timeout',),
    'srk': ('srk', 'storage root key'),
    'write-key': ('failed to write', 'failed to save', 'failed to serialize'),
    'initialize': ('failed to initialize',),
    'tpm-memory': ('out of memory for object contexts', 'object memory'),
    'authorization': ('authorization failure', 'authorization failed'),
}
RESULTS = frozenset(('success', 'exit-code', 'signal', 'core-dump', 'timeout',
                     'watchdog', 'start-limit-hit', 'resources', 'protocol', 'oom-kill'))


def status(raw):
    """Select only known service results and bounded integer exit properties."""
    result = {}
    if len(raw) > 65536:
        return result
    for line in raw.decode(errors='replace').splitlines():
        key, separator, value = line.partition('=')
        if not separator:
            continue
        if key == 'Result' and value in RESULTS:
            result[key] = value
        elif key in ('ExecMainCode', 'ExecMainStatus', 'StatusErrno') and re.fullmatch(r'[0-9]{1,10}', value):
            result[key] = int(value)
    return result


def categories(raw):
    if len(raw) > 65536:
        return ['oversized-journal']
    text = raw.decode(errors='replace').lower()
    return sorted(name for name, phrases in CATEGORIES.items() if any(p in text for p in phrases))


def journal_categories(raw):
    if len(raw) > 65536:
        return ['oversized-journal']
    names = set()
    errnos = {'1':'permission', '2':'missing-file', '5':'io-error', '13':'permission',
              '28':'no-space', '30':'read-only', '110':'timeout'}
    try:
        for line in raw.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict):
                continue
            message = row.get('MESSAGE')
            if isinstance(message, str):
                names.update(categories(message.encode()))
            value = row.get('ERRNO')
            if type(value) in (str, int) and str(value) in errnos:
                names.add(errnos[str(value)])
    except (ValueError, UnicodeError):
        names.add('malformed-journal')
    return sorted(names)


def prepare(tree):
    """Add diagnostics before signing; this never changes a production image."""
    helper = tree/'usr/lib/lanrith/qualification-tpm-diagnostic.py'
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__), helper)
    units = tree/'etc/systemd/system'
    dropin = units/(UNIT+'.d/99-qualification-diagnostic.conf')
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text('[Unit]\nOnFailure=lanrith-qualification-tpm-diagnostic.service\n')
    (units/'lanrith-qualification-tpm-diagnostic.service').write_text(
        '[Unit]\nDescription=Disposable TPM failure categories\nDefaultDependencies=no\nAfter='+UNIT+'\n'
        '[Service]\nType=oneshot\nStandardOutput=journal+console\nStandardError=null\n'
        'ExecStart=/usr/bin/python3 -I /usr/lib/lanrith/qualification-tpm-diagnostic.py\n'
        'NoNewPrivileges=yes\nMemoryMax=32M\nTasksMax=8\nTimeoutStartSec=30\n')


def main():
    try:
        result = subprocess.run(['journalctl', '--no-pager', '--boot', '--unit='+UNIT,
                                 '--output=json', '--output-fields=MESSAGE,ERRNO', '--lines=40'], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10)
        names = journal_categories(result.stdout) if result.returncode == 0 else ['journal-unavailable']
    except (OSError, subprocess.TimeoutExpired):
        names = ['journal-unavailable']
    for name in names:
        print('LANRITH_QA_TPM_'+name, flush=True)
    print('LANRITH_QA_TPM_failure', flush=True)


if __name__ == '__main__':
    main()
