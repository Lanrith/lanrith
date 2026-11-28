"""Check rendered exporter and both filters on a dedicated Cilium receiver."""

import copy
import ipaddress
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

from lanrith import config
from test_logs import declaration

REPO = Path(__file__).resolve().parents[1]
check = runpy.run_path(REPO/'scripts/check-log-receiver.py')['check']


def manifests(root, endpoint):
    value = declaration()
    value['observability']['logs']['endpoint'] = endpoint
    rendered = config.render(config.normalize(value))
    folder = root/'usr/share/lanrith'
    folder.mkdir(parents=True)
    for name in ('logs.json', 'service-plane.json'):
        (folder/name).write_text(rendered['usr/share/lanrith/'+name])
    log = json.loads((folder/'logs.json').read_text())
    source = str(ipaddress.ip_network(log['source']))
    labels = {'app': 'ingest'}
    metadata = {'name': 'ingest', 'namespace': 'monitor'}
    service = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {**metadata,
        'annotations': {'lbipam.cilium.io/ips': log['target']}}, 'spec': {'type': 'LoadBalancer',
        'externalTrafficPolicy': 'Local', 'selector': labels.copy(), 'loadBalancerSourceRanges': [source],
        'ports': [{'port': 443, 'targetPort': 'tls'}]}}
    workload = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata,
                'spec': {'template': {'metadata': {'labels': {**labels, 'role': 'logs'}},
                         'spec': {'containers': [{'ports': [{'name': 'tls', 'containerPort': 8443}]}]}}}}
    policy = {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': metadata,
              'spec': {'endpointSelector': {'matchLabels': labels.copy()}, 'ingress': [{'fromCIDR': [source],
                       'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}]}}
    return [service, workload, policy]


class LogReceiverTests(unittest.TestCase):
    def test_ipv4_and_ipv6_sources_must_match_both_rendered_boundaries(self):
        for endpoint in ('https://192.168.10.31/otlp', 'https://[fd42:1234:5678:10::31]/otlp'):
            with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                service, deployment, policy = manifests(root, endpoint)
                check(root, [service, deployment, policy], 'monitor/ingest')
                source = ipaddress.ip_network(service['spec']['loadBalancerSourceRanges'][0])
                other = str(ipaddress.ip_network(source.network_address+1))
                for ranges in ([other], [str(source), other], [str(source.supernet())], []):
                    for boundary in ('service', 'pod'):
                        with self.subTest(ranges=ranges, boundary=boundary):
                            lb, pod = copy.deepcopy(service), copy.deepcopy(policy)
                            if boundary == 'service':
                                lb['spec']['loadBalancerSourceRanges'] = ranges
                            else:
                                pod['spec']['ingress'][0]['fromCIDR'] = ranges
                            with self.assertRaises(ValueError):
                                check(root, [lb, deployment, pod], 'monitor/ingest')

    def test_rendered_yaml_entrypoint_and_disabled_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = manifests(root, 'https://[fd42:1234:5678:10::31]/otlp')
            render = root/'receiver.yaml'
            render.write_text('\n---\n'.join(json.dumps(doc) for doc in docs))
            command = [sys.executable, str(REPO/'scripts/check-log-receiver.py'), '--image-root', str(root),
                       '--service', 'monitor/ingest', str(render)]
            subprocess.run(command, check=True, capture_output=True)
            (root/'usr/share/lanrith/logs.json').unlink()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_decoys_different_ports_and_unsupported_policy_cannot_satisfy_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = manifests(root, 'https://[fd42:1234:5678:10::31]/otlp')
            for path, value in (
                    ((0, 'metadata', 'annotations', 'lbipam.cilium.io/ips'), '2001:db8::1'),
                    ((0, 'metadata', 'annotations', 'service.cilium.io/src-ranges-policy'), 'deny'),
                    ((0, 'metadata', 'annotations', 'service.cilium.io/type'), 'NodePort'),
                    ((0, 'spec', 'externalTrafficPolicy'), 'Cluster'),
                    ((0, 'spec', 'loadBalancerIP'), '2001:db8::1'),
                    ((0, 'spec', 'selector'), {'wrong': 'app'}),
                    ((1, 'metadata', 'namespace'), 'elsewhere'),
                    ((1, 'spec', 'template', 'spec', 'hostNetwork'), True),
                    ((1, 'spec', 'template', 'spec', 'containers', 0, 'ports', 0, 'containerPort'), 9443),
                    ((2, 'metadata', 'namespace'), 'elsewhere'),
                    ((2, 'spec', 'endpointSelector'), {}),
                    ((2, 'spec', 'ingress', 0, 'fromEntities'), ['world']),
                    ((2, 'spec', 'ingress'), docs[2]['spec']['ingress']+[{}]),
                    ((2, 'spec', 'ingress', 0, 'toPorts', 0, 'ports', 0, 'protocol'), 'UDP')):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    changed = copy.deepcopy(docs)
                    element = changed
                    for key in path[:-1]:
                        element = element[key]
                    element[path[-1]] = value
                    check(root, changed, 'monitor/ingest')
            plane = root/'usr/share/lanrith/service-plane.json'
            modified = json.loads(plane.read_text())
            for route in modified['dependency_routes']:
                route['source'] = '2001:db8::1'
            plane.write_text(json.dumps(modified))
            with self.assertRaisesRegex(ValueError, 'compiled route'):
                check(root, docs, 'monitor/ingest')
