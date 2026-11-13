"""Explicit maintainer authorization for installations with one human maintainer."""

import re

from .common import digest, document, require, sha, timestamp


def maintainers(policy):
    """Default to independent review; never infer permission from a merge alone."""
    if 'release_authorization' not in policy:
        return []
    value = policy['release_authorization']
    require(isinstance(value, dict) and set(value) == {'mode', 'maintainers'} and
            value['mode'] == 'maintainer-merge', 'Invalid release authorization mode.')
    actors = value['maintainers']
    require(isinstance(actors, list) and 0 < len(actors) <= 16, 'Release maintainers must be explicit.')
    for actor in actors:
        require(isinstance(actor, dict) and set(actor) == {'login', 'id'} and
                type(actor['id']) is int and actor['id'] > 0 and
                isinstance(actor['login'], str) and
                re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', actor['login']),
                'Release maintainer must identify a human GitHub account.')
    require(len({a['id'] for a in actors}) == len(actors) and
            len({a['login'].lower() for a in actors}) == len(actors), 'Duplicate release maintainer.')
    return actors


def authorize_merge(repo, source, pr, policy_raw, latest_reviews):
    """Bind a server-observed merge to the policy at the exact release source."""
    policy = document(policy_raw)
    actors = maintainers(policy)
    require(policy['repository'] == repo and actors,
            'A merged release change lacks a commit-bound approval.')
    require(pr['head']['ref'] != policy['proposal_branch'],
            'Automated proposals still require independent review.')
    actor = pr.get('merged_by') or {}
    require(actor.get('type') == 'User' and
            {'login': actor.get('login'), 'id': actor.get('id')} in actors,
            'Merge actor is not an authorized release maintainer.')
    require(pr.get('merged') is True and pr.get('merge_commit_sha') == source and
            pr.get('base', {}).get('ref') == 'main' and
            pr.get('base', {}).get('repo', {}).get('full_name') == repo and
            type(pr.get('number')) is int and pr['number'] > 0 and
            pr.get('html_url') == f'https://github.com/{repo}/pull/{pr["number"]}',
            'Maintainer authorization does not identify this merged main change.')
    require(not any(r['state'] == 'CHANGES_REQUESTED' for r in latest_reviews),
            'Maintainer merge cannot override an outstanding change request.')
    sha(source)
    sha(pr['head']['sha'])
    timestamp(pr['merged_at'])
    return {'kind': 'maintainer-merge', 'repository': repo, 'pull_request': pr['number'],
            'head_sha': pr['head']['sha'], 'merge_commit_sha': source,
            'merged_at': pr['merged_at'], 'url': pr['html_url'],
            'actor': actor['login'], 'actor_id': actor['id'], 'policy_sha256': digest(policy_raw)}


def validate_record(repo, source, pull, policy_raw):
    """Validate the separate authorization in an already attested release record."""
    authorization = pull.get('maintainer_authorization')
    require(isinstance(authorization, dict) and set(authorization) == {
        'kind', 'repository', 'pull_request', 'head_sha', 'merge_commit_sha',
        'merged_at', 'url', 'actor', 'actor_id', 'policy_sha256'},
        'Component lacks explicit maintainer authorization.')
    policy = document(policy_raw)
    require(policy['repository'] == repo and
            {'login': authorization['actor'], 'id': authorization['actor_id']} in maintainers(policy) and
            type(authorization['actor_id']) is int and
            authorization['policy_sha256'] == digest(policy_raw),
            'Component maintainer authorization differs from its source policy.')
    require(authorization['kind'] == 'maintainer-merge' and authorization['repository'] == repo and
            authorization['merge_commit_sha'] == pull['merge_commit_sha'] == source and
            authorization['pull_request'] == pull['number'] and
            authorization['head_sha'] == pull['head_sha'] and
            authorization['merged_at'] == pull['merged_at'] and
            authorization['url'] == pull['url'] == f'https://github.com/{repo}/pull/{pull["number"]}',
            'Component maintainer authorization differs from the released change.')
    sha(source)
    sha(pull['head_sha'])
    timestamp(pull['merged_at'])


def verify_publication(repo, source, pull, current, policy_raw, latest_reviews, permission):
    """Recheck live merge evidence and administrator access before any publication."""
    validate_record(repo, source, pull, policy_raw)
    observed = authorize_merge(repo, source, current, policy_raw, latest_reviews)
    require(observed == pull['maintainer_authorization'], 'Maintainer merge evidence changed before publication.')
    user = permission.get('user') or {}
    require(permission.get('permission') == 'admin' and user.get('id') == observed['actor_id'] and
            user.get('login') == observed['actor'], 'Release maintainer no longer has administrator access.')
