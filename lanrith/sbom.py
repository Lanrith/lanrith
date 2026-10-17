"""Describe installed packages and the locked dependencies of custom components."""

import hashlib
from urllib.parse import quote

from .release import canonical, require


def go_modules(metadata):
    require(isinstance(metadata, dict) and metadata.get('GoVersion', '').startswith('go') and
            isinstance(metadata.get('Deps'), list), 'Go binary dependency metadata is incomplete.')
    result = [{'module': 'stdlib', 'version': metadata['GoVersion'].removeprefix('go')}]
    for dependency in metadata['Deps']:
        actual = dependency.get('Replace', dependency)
        require(isinstance(actual.get('Path'), str) and actual['Path'] and
                isinstance(actual.get('Version'), str) and actual['Version'] and
                not actual['Version'].startswith('('), 'Go dependency has no immutable version.')
        result.append({'module': actual['Path'], 'version': actual['Version']})
    return result


def document(inventory, custom, version, digest, stamp):
    packages, relationships, identities = {}, set(), {}

    def add(ecosystem, name, selected, *, license_name='NOASSERTION', description=None):
        require(all(isinstance(item, str) and item for item in (ecosystem, name, selected)),
                'SBOM dependency identity is incomplete.')
        identity = (ecosystem, name, selected)
        identifier = 'SPDXRef-'+hashlib.sha256(canonical(identity)).hexdigest()[:32]
        if identity not in packages:
            purl = {'Go': 'golang', 'npm': 'npm', 'crates.io': 'cargo', 'Maven': 'maven', 'Debian': 'deb/debian'}.get(ecosystem)
            record = {'SPDXID': identifier, 'name': name, 'versionInfo': selected,
                      'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
                      'licenseConcluded': 'NOASSERTION', 'licenseDeclared': license_name or 'NOASSERTION',
                      'copyrightText': 'NOASSERTION'}
            if description:
                record['comment'] = description
            if purl:
                path = name.replace(':', '/') if ecosystem == 'Maven' else name
                record['externalRefs'] = [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
                    'referenceLocator': 'pkg:'+purl+'/'+quote(path, safe='/')+'@'+quote(selected, safe='')}]
            packages[identity] = record
        return identifier

    def depends(parent, ecosystem, name, selected, **options):
        child = add(ecosystem, name, selected, **options)
        if parent != child:
            relationships.add((parent, 'DEPENDS_ON', child))
        return child

    for package in inventory['packages']:
        identities[package['name']] = add('Debian', package['name'], package['version'])
    components = custom['components']
    required = {'alloy', 'node-exporter', 'pam-rssh', 'discovery-bridge',
                'router-policy-reader', 'router-policy-helper', 'router-policy-collector'}
    require(required <= components.keys(), 'Custom dependency SBOM coverage is incomplete.')
    for component, report in sorted(components.items()):
        package_name = 'prometheus-node-exporter' if component == 'node-exporter' else component
        parent = identities.get(package_name)
        if parent is None:
            # PAM is installed as a reviewed file rather than a Debian package.
            if component != 'pam-rssh':
                continue
            parent = add('Git', 'https://github.com/z4yx/pam_rssh', report['source_commit'])
        graphs = report.get('go_modules', {})
        if component in required - {'alloy', 'pam-rssh'}:
            require(graphs, 'A required custom component has no Go dependency inventory.')
        for modules in graphs.values():
            require(modules, 'A custom binary has no dependency inventory.')
            for module in modules:
                depends(parent, 'Go', module['module'], module['version'])
        if component == 'alloy':
            for module in report['modules']:
                depends(parent, 'Go', module['module'], module['version'])
            depends(parent, 'Go', 'stdlib', report['toolchains']['go'])
            depends(parent, 'Build tool', 'Node.js', report['toolchains']['node'])
            beyla = depends(parent, 'Git', 'https://github.com/grafana/beyla', report['beyla']['commit'])
            depends(beyla, 'Git', 'https://github.com/grafana/opentelemetry-ebpf-instrumentation',
                    report['beyla']['obi_commit'])
            for module in report['beyla']['modules']:
                depends(beyla, 'Go', module['module'], module['version'])
            for module in report['npm_modules']:
                depends(parent, 'npm', module['name'], module['version'], license_name=module.get('license'),
                        description='UI build dependency' if module['development'] else 'UI dependency')
            for query in report['java_agent']['queries']:
                depends(beyla, 'Maven', query['package']['name'], query['version'])
        if component == 'pam-rssh':
            for query in report['queries']:
                if 'package' in query:
                    depends(parent, query['package']['ecosystem'], query['package']['name'], query['version'])
                else:
                    depends(parent, 'Git', 'Locked Cargo Git source', query['commit'])
    for identifier in identities.values():
        relationships.add(('SPDXRef-DOCUMENT', 'DESCRIBES', identifier))
    identity = hashlib.sha256(canonical({'inventory': digest, 'custom': custom,
                                        'version': version, 'created': stamp})).hexdigest()
    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'Lanrith '+version, 'documentNamespace': 'https://github.com/Lanrith/lanrith/sbom/'+identity,
            'creationInfo': {'creators': ['Tool: Lanrith'], 'created': stamp.replace('+00:00', 'Z')},
            'packages': sorted(packages.values(), key=lambda item: item['SPDXID']),
            'relationships': [{'spdxElementId': parent, 'relationshipType': relation,
                               'relatedSpdxElement': child} for parent, relation, child in sorted(relationships)]}
