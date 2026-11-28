#!/usr/bin/env python3
"""Check the projected EVE message at a local TLS OTLP receiver."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.ids_observer import alert
from logs_native import SECRET, unauthenticated_delivery


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alloy', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    event = {'event_type': 'alert', 'timestamp': '2026-11-20T12:34:56.123456+0000', 'in_iface': 'wan',
             'alert': {'signature_id': 1000001, 'signature': SECRET.decode()}, 'src_ip': '192.0.2.2'}
    projected = alert(event, 'wan')
    assert projected == {'sid': 1000001, 'event_time': '2026-11-20T12:34:56.123456+00:00', 'interface': 'wan'}
    unauthenticated_delivery(args.alloy, message=json.dumps(projected, separators=(',', ':')),
                             unit='lanrith-ids-observer.service', redaction_probe=False)
    print('Projected WAN interface, SID, and event timestamp arrived through the real local TLS OTLP queue.')
