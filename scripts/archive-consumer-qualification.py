#!/usr/bin/env python3
"""Retain operational canary evidence without private-repository attestations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import release

REPOSITORY = 'Lanrith/config-template-qualification'
NAME = 'consumer-qualification.json'
FIELDS = {'schema', 'kind', 'result', 'repository', 'source_commit', 'workflow_commit',
          'platform_version', 'platform_lock_sha256', 'configuration_sha256',
          'deployment_record_sha256', 'deployable', 'signing_authority', 'run_url'}


def validate_report(raw, context):
    release.require(context['GITHUB_REPOSITORY'] == REPOSITORY and context['GITHUB_REF'] == 'refs/heads/main',
                    'Canary evidence publication requires its isolated main branch.')
    release.require(0 < len(raw) <= 65536, 'Canary report exceeds its bounded envelope.')
    report = json.loads(raw, object_pairs_hook=release.unique)
    release.require(isinstance(report, dict) and set(report) == FIELDS,
                    'Canary report contains an unexpected evidence field.')
    release.require(report['schema'] == 1 and report['kind'] == 'isolated-consumer-qualification' and
                    report['result'] == 'pass' and report['deployable'] is False and
                    report['signing_authority'] == 'disposable-per-run', 'Canary report is not disposable qualification evidence.')
    release.require(report['repository'] == REPOSITORY and report['source_commit'] == context['GITHUB_SHA'] and
                    report['workflow_commit'] == context['LANRITH_WORKFLOW_COMMIT'] and
                    report['run_url'] == 'https://github.com/'+REPOSITORY+'/actions/runs/'+context['GITHUB_RUN_ID'],
                    'Canary report identifies another source, workflow or run.')
    for field in ('source_commit', 'workflow_commit'):
        release.require(isinstance(report[field], str) and re.fullmatch(r'[0-9a-f]{40}', report[field]),
                        'Invalid canary source digest.')
    for field in ('platform_lock_sha256', 'configuration_sha256', 'deployment_record_sha256'):
        release.require(isinstance(report[field], str) and re.fullmatch(r'[0-9a-f]{64}', report[field]),
                        'Invalid canary evidence digest.')
    release.require(isinstance(report['platform_version'], str) and
                    re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', report['platform_version']), 'Invalid qualified platform version.')
    return report


def verify_archive(published, raw, tag, source):
    release.require(published.get('immutable') is True and published.get('draft') is False and
                    published.get('prerelease') is True and published['tag_name'] == tag and
                    published['target_commitish'] == source, 'Canary archive is mutable or identifies another source.')
    assets = published['assets']
    release.require(len(assets) == 1 and assets[0]['name'] == NAME and
                    assets[0]['digest'] == 'sha256:'+hashlib.sha256(raw).hexdigest(), 'Published canary report differs from its validated bytes.')


def publish(path):
    release.require(path.name == NAME, 'Unexpected canary report filename.')
    raw = release.read(path, 65536)
    report = validate_report(raw, os.environ)
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    release.require(re.fullmatch(r'[1-9][0-9]*', run) and re.fullmatch(r'[1-9][0-9]*', attempt), 'Invalid canary run identity.')
    tag = 'audit-consumer-qualification-'+run+'-'+attempt
    def gh(*args):
        return subprocess.run(['gh', *args], check=True, capture_output=True, text=True).stdout
    gh('release', 'create', tag, '--repo', REPOSITORY, '--target', report['source_commit'],
       '--draft', '--prerelease', '--latest=false', '--title', 'Isolated consumer qualification',
       '--notes', 'Operational canary evidence for '+report['run_url']+', attempt '+attempt+
       '. This report has no hosted attestation and grants no production release authorization.', str(path))
    gh('release', 'edit', tag, '--repo', REPOSITORY, '--draft=false')
    published = json.loads(gh('api', 'repos/'+REPOSITORY+'/releases/tags/'+tag))
    verify_archive(published, raw, tag, report['source_commit'])
    print('Verified immutable canary report: https://github.com/'+REPOSITORY+'/releases/tag/'+tag)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    publish(parser.parse_args().report)
