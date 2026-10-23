#!/usr/bin/env python3
"""Configure the owner-authorized Apps without putting private keys in arguments or logs."""

import argparse
import re
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request


REPOSITORIES = ('Lanrith/lanrith', 'Lanrith/discovery-bridge', 'Lanrith/router-policy-agent')


def gh(endpoint, *, method='GET', value=None):
    command = ['gh', 'api', '--method', method, endpoint]
    if value is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(value).encode() if value is not None else None,
                            check=True, capture_output=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def key_file(value):
    path = Path(value).expanduser()
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ValueError('An App key must be a regular file owned by the current user.')
    data = path.read_bytes()
    if not 100 < len(data) < 16384:
        raise ValueError('App key size is invalid.')
    return data


def app_request(endpoint, key, app_id, *, value=None):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
    clock = int(time.time())
    unsigned = encode({'alg': 'RS256', 'typ': 'JWT'})+b'.'+encode({'iat': clock-60, 'exp': clock+480, 'iss': app_id})
    with tempfile.TemporaryDirectory(prefix='lanrith-app-auth.') as temporary:
        path = Path(temporary)/'app.pem'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(key)
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(path)], input=unsigned,
                                   check=True, capture_output=True).stdout
    token = unsigned+b'.'+base64.urlsafe_b64encode(signature).rstrip(b'=')
    request = urllib.request.Request('https://api.github.com/'+endpoint,
        data=json.dumps(value).encode() if value is not None else None,
        headers={'Authorization': 'Bearer '+token.decode(), 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reviewer-id', required=True, type=int)
    parser.add_argument('--reviewer-key', required=True, type=key_file)
    parser.add_argument('--updater-key', type=key_file)
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--create-bootstrap-prs', action='store_true')
    parser.add_argument('--branch', default='security/verified-update-automation')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_./-]{1,180}', args.branch) or '..' in args.branch:
        raise ValueError('Invalid bootstrap branch.')
    if args.activate and (args.configure or args.create_bootstrap_prs):
        raise ValueError('Activation is a separate step after the reviewed pilot.')
    if args.reviewer_id <= 0 or args.reviewer_id == 5355607:
        raise ValueError('The reviewer must be a distinct GitHub App.')
    app = app_request('app', args.reviewer_key, args.reviewer_id)
    expected = {'actions': 'read', 'checks': 'write', 'contents': 'read', 'metadata': 'read', 'pull_requests': 'write'}
    if app['id'] != args.reviewer_id or app['permissions'] != expected:
        raise ValueError('Reviewer App permissions differ from the reviewed manifest.')
    for repo in REPOSITORIES:
        install = app_request('repos/'+repo+'/installation', args.reviewer_key, args.reviewer_id)
        if install['account']['login'] != 'Lanrith' or install['repository_selection'] != 'selected':
            raise ValueError('Install the reviewer only on the three selected Lanrith repositories.')
        if args.configure:
            for environment in ('lanrith-updates', 'lanrith-review'):
                gh('repos/'+repo+'/environments/'+environment, method='PUT', value={
                    'deployment_branch_policy': {'protected_branches': True, 'custom_branch_policies': False}})
            values = [('lanrith-review', 'LANRITH_REVIEW_APP_ID', str(args.reviewer_id)),
                      ('lanrith-updates', 'LANRITH_UPDATE_APP_ID', '5355607')]
            for environment, name, value in values:
                subprocess.run(['gh', 'variable', 'set', name, '--repo', repo, '--env', environment, '--body', value], check=True, capture_output=True)
            keys = [('lanrith-review', 'LANRITH_REVIEW_APP_PRIVATE_KEY', args.reviewer_key)]
            if args.updater_key:
                # Authenticate the existing author key before writing it into any environment.
                if app_request('app', args.updater_key, 5355607)['id'] != 5355607:
                    raise ValueError('Updater key does not belong to the configured author App.')
                updater_install = app_request('repos/'+repo+'/installation', args.updater_key, 5355607)
                if updater_install['account']['login'] != 'Lanrith' or updater_install['repository_selection'] != 'selected':
                    raise ValueError('Updater must use a selected-repository Lanrith installation.')
                expected_updater = {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}
                if updater_install['permissions'] != expected_updater:
                    raise ValueError('Updater permissions differ from the restricted author policy.')
                keys.append(('lanrith-updates', 'LANRITH_UPDATE_APP_PRIVATE_KEY', args.updater_key))
            for environment, name, key in keys:
                subprocess.run(['gh', 'secret', 'set', name, '--repo', repo, '--env', environment], input=key,
                               check=True, capture_output=True)
            subprocess.run(['gh', 'variable', 'set', 'LANRITH_SECURITY_APPROVALS_ENABLED', '--repo', repo, '--body', 'false'], check=True, capture_output=True)
            subprocess.run(['gh', 'variable', 'set', 'LANRITH_REVIEW_APP_ID', '--repo', repo, '--body', str(args.reviewer_id)], check=True, capture_output=True)
            subprocess.run(['gh', 'variable', 'set', 'LANRITH_REVIEW_CONFIGURED', '--repo', repo, '--body', 'true'], check=True, capture_output=True)
            gh('repos/'+repo, method='PATCH', value={'allow_auto_merge': True})
        if args.activate:
            value = gh('repos/'+repo+'/contents/security/update-policy.json?ref=main')
            policy = json.loads(base64.b64decode(value['content']))
            if policy['mode'] != 'enforce' or policy['repository'] != repo or policy['paid_ai'] is not False or policy['reviewer_app_id'] != args.reviewer_id:
                raise ValueError('Merge the independently reviewed enforcement policy before activation: '+repo)
            endpoint = 'repos/'+repo+'/branches/main/protection/required_status_checks'
            current = gh(endpoint)
            checks = [{'context': c['context'], 'app_id': c['app_id'] if c['app_id'] is not None else -1} for c in current['checks']]
            checks = [c for c in checks if c['context'] != 'Security update admission']
            checks.append({'context': 'Security update admission', 'app_id': args.reviewer_id})
            gh(endpoint, method='PATCH', value={'strict': True, 'checks': checks})
            gh('repos/'+repo+'/branches/main/protection/enforce_admins', method='POST')
            gh('repos/'+repo+'/actions/permissions/workflow', method='PUT', value={'default_workflow_permissions': 'read', 'can_approve_pull_request_reviews': False})
            subprocess.run(['gh', 'variable', 'set', 'LANRITH_SECURITY_APPROVALS_ENABLED', '--repo', repo, '--body', 'true'], check=True, capture_output=True)
            print(repo+': independent App check required; protected enforcement activated.')
            continue
        if args.create_bootstrap_prs:
            # App-authored bootstrap PRs let the owner provide a real independent GitHub review.
            token = app_request('app/installations/'+str(install['id'])+'/access_tokens', args.reviewer_key,
                                args.reviewer_id, value={'repositories': [repo.split('/')[1]],
                                    'permissions': {'contents': 'read', 'pull_requests': 'write'}})['token']
            reasons = {
                'Lanrith/lanrith': (
                    'Security checks were failing without an updater for embedded UI dependencies or native source locks. '
                    'Large PR filesystem uploads and duplicate release handoffs also exhausted Actions storage.\n\n'
                    'Patch Go to 1.27.3/1.26.10 (GO-2026-6809), Node to 24.22.1, Vite to 7.3.7 and Vitest to 4.1.12. '
                    'Refresh authenticated Debian snapshots for BIND 9.20.30 and verify both signatures for Unbound 1.26.2. '
                    'Add advisory-bound PR generation, an independent restricted review App, exact validation/approval records, '
                    'immutable publication verification and guarded artifact cleanup.\n\n'
                    'Validation: 208 local Python tests pass (eight environment-dependent skips), workflow/source checks pass, '
                    'the UI graph has no current npm findings, and signed Unbound inputs were independently resolved and matched. '
                    'Full platform package and boot qualification must pass after pinning the newly released components. '
                    'Merge and qualify the component compiler fixes first, then update their platform pins and requalify this PR.'),
                'Lanrith/discovery-bridge': (
                    'Published binaries used Go 1.27.2, affected by GO-2026-6809. Pin Go 1.27.3 and the reviewed vulnerability scanner. '
                    'Adopt the exact shared maintenance workflow commit for advisory-bound updates, independent review, '
                    'immutable release verification and durable change history. Permit public security policy/candidate metadata '
                    'through the existing source boundary.\n\n'
                    'Validation: local race/shuffled Go tests, vet, lint, source checks and reachable-vulnerability scans pass. '
                    'Hosted qualification: https://github.com/Lanrith/discovery-bridge/actions/runs/39973757086 . '
                    'The hosted result must be successful before merge.'),
                'Lanrith/router-policy-agent': (
                    'Build and compatibility toolchains included Go 1.27.2 and 1.26.9, affected by GO-2026-6809. '
                    'Pin Go 1.27.3 for releases and 1.26.10 for compatibility. Move toolchain/image selections into validated data '
                    'and adopt the exact reviewed maintenance workflow commit for updates, independent review, immutable '
                    'release verification and durable change history.\n\n'
                    'Validation: local race/shuffled Go tests, vet, lint and reachable-vulnerability scans pass. '
                    'Hosted current/previous compiler, UID boundary, nftables, fuzz and security gates pass: '
                    'https://github.com/Lanrith/router-policy-agent/actions/runs/39973762243 . '
                    'The module inventory includes the unmaintained OpenPGP advisory GO-2026-5932; that package is neither '
                    'imported nor called, and no fixed version exists. Actual source and binary vulnerability scans remain required.')}
            description = (reasons[repo]+'\n\n'
                'This bootstrap changes workflows and approval/security controls and requires an independent human GitHub review. '
                'Automatic approval remains disabled during the report-only pilot. Neither App has a protection bypass; paid AI services are unused. '
                'See `docs/security-maintenance.md` for the owner setup, evidence verification and activation procedure.')
            body = {'title': 'Patch verified security inputs and automate audited immutable releases', 'head': args.branch,
                    'base': 'main', 'body': description}
            existing = gh('repos/'+repo+'/pulls?state=open&head=Lanrith:'+args.branch)
            if existing:
                if len(existing) != 1 or existing[0]['user']['login'] != app['slug']+'[bot]':
                    raise ValueError('Bootstrap branch already has a PR from another author; preserve independent human approval.')
                print(existing[0]['html_url'])
                continue
            request = urllib.request.Request('https://api.github.com/repos/'+repo+'/pulls', data=json.dumps(body).encode(),
                headers={'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=40) as response:
                result = json.load(response)
            print(result['html_url'])
        print(repo+': reviewer installation verified; approval pilot remains report-only.')


if __name__ == '__main__':
    main()
