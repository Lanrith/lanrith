"""Validate the reviewed platform before preflight and native qualification."""

import json

from .release import HEX, file_record, read, require, unique


REQUIREMENTS = frozenset({
    'appropriate-platform', 'consistent-process', 'distributed-provenance',
    'provenance-exists', 'provenance-authentic', 'provenance-unforgeable',
    'hosted', 'isolated-signing', 'isolated-concurrent-builds',
    'isolated-subsequent-builds', 'isolated-caches', 'isolated-remote-influence',
    'external-parameters', 'security-practices',
})
REVIEWED_WORKFLOWS = frozenset({
    '.github/workflows/build-base.yml', '.github/workflows/release.yml',
    '.github/workflows/check.yml', '.github/workflows/restore-cache.yml',
    '.github/workflows/publish-release.yml', '.github/workflows/archive-evidence.yml',
    '.github/workflows/security-review.yml', '.github/workflows/security-proposal.yml',
    '.github/workflows/retry-runner-capacity.yml',
})


def validate_platform(project):
    assessment = json.loads(read(project/'security/slsa-assessment.json', 4*1024*1024),
                            object_pairs_hook=unique)
    require(isinstance(assessment, dict), 'The build platform assessment must be an object.')
    requirements = assessment.get('requirements')
    require(assessment.get('schema') == 1 and assessment.get('specification') == 'SLSA v1.2' and
            assessment.get('target') == 'Build L3' and assessment.get('result') == 'design-assessed' and
            isinstance(requirements, dict) and set(requirements) == REQUIREMENTS and
            all(isinstance(item, dict) and item.get('result') == 'satisfied-by-design' and
                item.get('evidence') for item in requirements.values()),
            'The build platform lacks a complete requirement assessment.')
    workflows = assessment.get('reviewed_workflows')
    require(isinstance(workflows, dict) and set(workflows) == REVIEWED_WORKFLOWS,
            'The reviewed workflow set is incomplete; review the platform assessment before building.')
    for name, expected in sorted(workflows.items()):
        require(isinstance(expected, str) and HEX.fullmatch(expected) and
                file_record(project/name)['sha256'] == expected,
                'Assessed workflow hash differs: '+name+'. Review the workflow and update '
                'security/slsa-assessment.json before the package build.')
    return assessment
