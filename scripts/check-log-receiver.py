#!/usr/bin/env python3
"""Compare an image's compiled log source with a dedicated Cilium receiver render."""

import argparse
import ipaddress as ip
import json
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.config import Loader
from lanrith.logs_runtime import validate_manifest
from lanrith.release import require, unique


def one(items, message):
    require(len(items) == 1, message)
    return items[0]


def exact_source(cidrs, source, boundary):
    require(isinstance(cidrs, list) and len(cidrs) == 1 and isinstance(cidrs[0], str)
            and '/' in cidrs[0] and ip.ip_network(cidrs[0]) == ip.ip_network(source),
            boundary+' must allow only the compiled exporter host.')


def check(image, resources, receiver):
    manifests = image/'usr/share/lanrith'
    log = validate_manifest(json.loads((manifests/'logs.json').read_bytes(), object_pairs_hook=unique))
    plane = json.loads((manifests/'service-plane.json').read_bytes(), object_pairs_hook=unique)
    source = ip.ip_address(log['source'])
    target = ip.ip_address(log['target'])
    routes = [route for route in plane['dependency_routes'] if ip.ip_network(route['to']) == ip.ip_network(target)]
    route = one(routes, 'Expected one compiled host route to the receiver.')
    require(ip.ip_address(route['source']) == source and str(source) in plane['endpoints']['logs'],
            'The compiled route and log source differ.')

    namespace, name = receiver.split('/')
    require(namespace and name, 'Supply the receiver as namespace/service.')
    require(all(doc.get('kind') != 'List' and doc.get('kind') != 'CiliumClusterwideNetworkPolicy'
                for doc in resources), 'Supply individual resources for the namespaced receiver.')
    documents = [doc for doc in resources if doc.get('metadata', {}).get('namespace', 'default') == namespace]
    service = one([doc for doc in documents if doc['kind'] == 'Service' and doc['metadata']['name'] == name],
                  'Expected one named receiver Service.')
    spec = service['spec']
    annotations = service['metadata'].get('annotations', {})
    require(service['apiVersion'] == 'v1' and spec['type'] == 'LoadBalancer' and
            spec['externalTrafficPolicy'] == 'Local' and
            annotations.get('service.cilium.io/type', 'LoadBalancer') == 'LoadBalancer' and
            annotations.get('service.cilium.io/src-ranges-policy', 'allow') == 'allow',
            'The receiver requires a source-preserving LoadBalancer with source allowlisting.')
    require(ip.ip_address(annotations['lbipam.cilium.io/ips']) == target and
            ip.ip_address(spec.get('loadBalancerIP', str(target))) == target,
            'The receiver Service VIP differs from the compiled log target.')
    exact_source(spec.get('loadBalancerSourceRanges'), source, 'LoadBalancer')
    selector = spec.get('selector')
    require(isinstance(selector, dict) and selector, 'The Service needs a pod selector.')
    port = one([p for p in spec['ports'] if p['port'] == 443 and p.get('protocol', 'TCP') == 'TCP'],
               'Expected one HTTPS Service port.')
    target_port = port.get('targetPort', port['port'])

    deployments = [doc for doc in documents if doc['kind'] == 'Deployment' and
                   selector.items() <= doc['spec']['template']['metadata']['labels'].items()]
    deployment = one(deployments, 'Expected one Deployment selected by the receiver Service.')
    require(deployment['apiVersion'] == 'apps/v1', 'Unexpected receiver Deployment API.')
    template = deployment['spec']['template']
    require(template['spec'].get('hostNetwork', False) is False, 'The receiver requires pod networking.')
    ports = [p['containerPort'] for c in template['spec']['containers'] for p in c.get('ports', [])
             if p.get('protocol', 'TCP') == 'TCP' and target_port in (p['containerPort'], p.get('name'))]
    backend = one(ports, 'The Service target port must resolve to one TCP container port.')
    require(type(backend) is int and 1 <= backend <= 65535, 'Invalid container port.')

    # Accept the dedicated source-CIDR policy shape. Additional ingress grants
    # and alternate selector forms need their own evaluation.
    policies = [doc for doc in documents if doc['kind'] in ('NetworkPolicy', 'CiliumNetworkPolicy')]
    policy = one(policies, 'Supply exactly one namespaced ingress policy in the dedicated receiver render.')
    require(policy['kind'] == 'CiliumNetworkPolicy' and policy['apiVersion'] == 'cilium.io/v2' and
            'specs' not in policy, 'Expected a single Cilium policy spec.')
    spec = policy['spec']
    require(spec.keys() <= {'endpointSelector', 'ingress', 'egress', 'description'} and
            spec['endpointSelector'] == {'matchLabels': selector},
            'The Cilium policy must select the same pods as the Service.')
    ingress = one(spec['ingress'], 'Expected one source-specific Cilium ingress rule.')
    require(set(ingress) == {'fromCIDR', 'toPorts'}, 'Unsupported Cilium ingress conditions.')
    exact_source(ingress['fromCIDR'], source, 'Pod ingress')
    require(ingress['toPorts'] == [{'ports': [{'port': str(backend), 'protocol': 'TCP'}]}],
            'The Cilium rule must admit the selected TCP container port.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--service', required=True, metavar='NAMESPACE/SERVICE')
    parser.add_argument('render', type=Path, nargs='+', help='dedicated, rendered multi-document YAML')
    args = parser.parse_args()
    try:
        documents = []
        for path in args.render:
            with path.open() as stream:
                documents.extend(doc for doc in yaml.load_all(stream, Loader=Loader) if doc is not None)
        check(args.image_root, documents, args.service)
    except yaml.YAMLError:
        parser.exit(1, 'Invalid YAML in receiver render.\n')
    except (OSError, AttributeError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, f'Receiver contract check failed ({error}).\n')
    print('The compiled route and both receiver source allowlists match.')


if __name__ == '__main__':
    main()
