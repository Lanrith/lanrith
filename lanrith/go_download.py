"""Retry only transient transport failures while downloading selected Go modules."""

import json
import re
import subprocess
import sys
import time


def transport_failure(result):
    if result.returncode != 1:
        return False
    errors = []
    # With -json, Go writes module failures to stdout, possibly alongside
    # successful module records. Every reported error must be retryable.
    remaining = result.stdout.strip()
    while remaining:
        try:
            record, end = json.JSONDecoder().raw_decode(remaining)
        except ValueError:
            return False
        if not isinstance(record, dict):
            return False
        if record.get('Error'):
            if not isinstance(record['Error'], str):
                return False
            errors.extend(record['Error'].splitlines())
        remaining = remaining[end:].lstrip()
    errors.extend(line for line in result.stderr.splitlines() if line.strip())
    transient = re.compile(
        r'https://[^\s]+.*(?:'
        r'stream error: stream ID [0-9]+; (?:INTERNAL_ERROR|CANCEL); received from peer|'
        r'connection reset by peer|unexpected EOF|'
        r'(?:429 Too Many Requests|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout)'
        r')$')
    return bool(errors) and all(transient.search(error) for error in errors)


def download(*arguments, cwd=None, env=None, capture_output=True, text=True):
    if capture_output is not True or text is not True:
        raise ValueError('Module download output must remain captured text.')
    command = ('go', 'mod', 'download', *arguments)
    for attempt in range(3):
        result = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            return result
        # Keep the original diagnostics in the job log, including errors that
        # go mod download -json reports on stdout instead of stderr.
        print(result.stdout + result.stderr, file=sys.stderr, end='', flush=True)
        if attempt == 2 or not transport_failure(result):
            result.check_returncode()
        delay = (2, 5)[attempt]
        print(f'Go module transport failed; retry {attempt+2}/3 in {delay}s.', file=sys.stderr, flush=True)
        time.sleep(delay)


if __name__ == '__main__':
    result = download(*sys.argv[1:])
    print(result.stdout, end='')
    print(result.stderr, file=sys.stderr, end='')
