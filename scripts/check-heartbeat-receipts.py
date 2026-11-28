#!/usr/bin/env python3
"""Check a receiver's Loki range response against an independently accepted router boot."""

import argparse
import json
from pathlib import Path
import re
import sys
import time
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.image_operation import identity
from lanrith.release import VERSION, require, unique
from lanrith.update import UUID


UNIT = 'lanrith-telemetry-heartbeat.service'
SECOND = 10**9


class Sample(NamedTuple):
    journal_ns: int
    emitted_ns: int
    monotonic_ns: int


def expected_event(installed, status):
    release = identity(installed)
    version = installed['platform_version']
    require(isinstance(version, str) and VERSION.fullmatch(version), 'Invalid platform version.')
    boot = status['boot']
    require(isinstance(boot, dict) and boot.get('accepted') is True and boot.get('boot_complete') is True and
            type(boot.get('schema')) is int and boot['schema'] == 1 and isinstance(boot.get('boot_id'), str) and
            re.fullmatch(UUID, boot['boot_id']), 'A committed boot observation is required.')
    shared = {'image_id': release['image_id'], 'platform_version': version,
              'deployment_sequence': release['deployment_sequence']}
    for actual in (boot, status):
        require(type(actual.get('deployment_sequence')) is int and shared.items() <= actual.items(),
                'Observed release differs from the image.')
    require(status.get('configuration_sha256') == release['configuration_sha256'] and
            boot.get('selected_entry') == release['uki_name'], 'Observed configuration or EFI entry differs.')
    return {**shared, 'schema': 1, 'event': 'lanrith-heartbeat', 'boot_id': boot['boot_id'],
            'selected_entry': release['uki_name'], 'configuration_sha256': release['configuration_sha256']}


def check(host, installed, status, response, *, now_ns, max_age_seconds=90, clock_skew_seconds=5):
    require(0 <= clock_skew_seconds < max_age_seconds, 'Invalid freshness or clock uncertainty budget.')
    expected = expected_event(installed, status)
    labels = {'host': host, 'job': 'router-journal', 'unit': UNIT}
    require(response.get('status') == 'success' and response['data']['resultType'] == 'streams' and
            isinstance(response['data']['result'], list), 'Receiver query did not return Loki streams.')
    samples = []
    unexpected_at = 0
    missing_time = False
    for stream in response['data']['result']:
        if not labels.items() <= stream['stream'].items():
            continue
        for stamp, line in stream['values']:
            if not isinstance(line, str) or not isinstance(stamp, str) or not re.fullmatch(r'[0-9]{1,19}', stamp):
                continue
            try:
                event = json.loads(line, object_pairs_hook=unique)
            except (ValueError, RecursionError):
                continue
            if not isinstance(event, dict) or event.get('event') != 'lanrith-heartbeat':
                continue
            matches = (stream['stream'].get('journal_boot') == expected['boot_id'].replace('-', '') and
                       stream['stream'].get('journal_transport') == 'stdout' and
                       type(event.get('schema')) is int and type(event.get('deployment_sequence')) is int and
                       expected.items() <= event.items())
            emitted, tick = event.get('emitted_unix_ns'), event.get('monotonic_ns')
            if type(tick) is not int or tick <= 0:
                continue
            if type(emitted) is not int or emitted <= 0:
                missing_time |= matches
                continue
            journal = int(stamp)
            # The journal records stdout shortly after emission. Its wall clock
            # and the producer's clock are on the same host. Allow rounding
            # down to microseconds and local delay up to the writer deadline.
            if not (emitted-1000 <= journal <= emitted+20*SECOND and
                    max(emitted, journal) <= now_ns+clock_skew_seconds*SECOND):
                continue
            if matches:
                samples.append(Sample(journal, emitted, tick))
            else:
                unexpected_at = max(unexpected_at, journal)

    previous = pair = None
    for sample in sorted(samples):
        if previous is not None:
            if sample.journal_ns == previous.journal_ns or sample.monotonic_ns <= previous.monotonic_ns:
                continue
            pair = (previous, sample)
        previous = sample
    if pair is None and missing_time:
        raise ValueError('Heartbeat freshness unknown: original source time is missing.')
    require(pair is not None, 'Two increasing heartbeats from the accepted boot are required.')
    earlier, latest = pair
    require(latest.journal_ns > unexpected_at, 'The newest heartbeat identifies an unexpected boot or release.')
    require(min(latest.journal_ns, latest.emitted_ns) >= now_ns-max_age_seconds*SECOND,
            'Accepted heartbeat is overdue.')
    require(min(earlier.journal_ns, earlier.emitted_ns) >= now_ns-2*max_age_seconds*SECOND,
            'A second recent matching heartbeat is required.')
    return latest.monotonic_ns


def load(path, limit):
    with path.open('rb') as stream:
        data = stream.read(limit+1)
    require(len(data) <= limit, 'Receiver input exceeds size limit.')
    return json.loads(data, object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', required=True, type=Path, help='verified, extracted running image')
    parser.add_argument('--status', required=True, type=Path, help='independent lanrith-status JSON')
    parser.add_argument('--max-age-seconds', type=int, default=90)
    parser.add_argument('--clock-skew-seconds', type=int, default=5)
    parser.add_argument('response', type=Path, help='unparsed Loki query_range JSON')
    args = parser.parse_args()
    try:
        metadata = args.image_root/'usr/share/lanrith/installed.json'
        host = (args.image_root/'etc/hostname').read_text().strip()
        tick = check(host, load(metadata, 65536), load(args.status, 65536), load(args.response, 2*1024*1024),
                     now_ns=time.time_ns(), max_age_seconds=args.max_age_seconds, clock_skew_seconds=args.clock_skew_seconds)
    except (OSError, AttributeError, KeyError, TypeError, ValueError, RecursionError) as error:
        parser.exit(1, f'Heartbeat alarm: {error}\n')
    print(f'Fresh heartbeat pair for {host}. Latest monotonic_ns={tick}.')


if __name__ == '__main__':
    main()
