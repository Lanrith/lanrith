"""Content-bound maintenance records, shared by proposal, review and release."""

from .common import canonical, digest, document, now, require, safe_path, sha, timestamp


CANDIDATE = 'security/update-candidate.json'


def candidate(repo, base, policy, before, after, reasons, producer, *, requires_human=False):
    require(reasons and isinstance(reasons, list), 'An automated change needs a recorded reason.')
    changes = {}
    for path in sorted(set(before) | set(after)):
        safe_path(path)
        require(path != CANDIDATE and path in before and path in after,
                'Automatic updates cannot add, remove or rename source files.')
        if before[path] != after[path]:
            changes[path] = {'before_sha256': digest(before[path]), 'after_sha256': digest(after[path])}
    require(changes, 'There are no changed security inputs to propose.')
    subject = {'repository': repo, 'base_sha': sha(base), 'changes': changes, 'reasons': reasons,
               'policy_sha256': digest(policy), 'producer_sha': sha(producer), 'requires_human': requires_human}
    return {'schema': 1, 'kind': 'security-update-candidate', 'created_at': now(),
            'candidate_id': digest(canonical(subject)),
            'remediation_id': 'security-'+digest(canonical(sorted({r['id'] for r in reasons})))[:20],
            **subject}


def validate_candidate(record):
    require(isinstance(record, dict) and set(record) == {
        'schema', 'kind', 'created_at', 'candidate_id', 'remediation_id', 'repository',
        'base_sha', 'changes', 'reasons', 'policy_sha256', 'producer_sha', 'requires_human'}, 'Candidate record schema differs.')
    require(record['schema'] == 1 and record['kind'] == 'security-update-candidate', 'Unknown candidate record.')
    sha(record['base_sha'])
    sha(record['producer_sha'])
    timestamp(record['created_at'])
    require(type(record['requires_human']) is bool, 'Candidate review requirement must be explicit.')
    require(isinstance(record['changes'], dict) and 0 < len(record['changes']) <= 30 and
            isinstance(record['reasons'], list) and 0 < len(record['reasons']) <= 100,
            'Candidate change or reason coverage is invalid.')
    for path, change in record['changes'].items():
        safe_path(path)
        require(set(change) == {'before_sha256', 'after_sha256'} and
                all(isinstance(x, str) and len(x) == 64 and set(x) <= set('0123456789abcdef')
                    for x in change.values()), 'Candidate file digest is malformed.')
    for reason in record['reasons']:
        require(isinstance(reason, dict) and set(reason) == {
            'id', 'type', 'package', 'ecosystem', 'installed', 'fixed', 'source', 'evidence_sha256'},
            'Candidate reason schema differs.')
        require(all(isinstance(value, str) and value for value in reason.values()), 'Incomplete candidate reason.')
    subject = {k: record[k] for k in ('repository', 'base_sha', 'changes', 'reasons',
                                     'policy_sha256', 'producer_sha', 'requires_human')}
    require(record['candidate_id'] == digest(canonical(subject)) and
            record['remediation_id'] == 'security-'+digest(canonical(sorted({r['id'] for r in record['reasons']})))[:20],
            'Candidate identity does not cover its recorded inputs.')
    return record


def decision(record, *, head, base, policy, checks, eligible, findings, reviewer_source):
    return {'schema': 1, 'kind': 'security-update-decision', 'created_at': now(),
            'candidate_id': record.get('candidate_id'), 'remediation_id': record.get('remediation_id'),
            'repository': record.get('repository'), 'candidate': record,
            'head_sha': sha(head), 'base_sha': sha(base), 'policy_sha256': digest(policy),
            'reviewer_source_sha': sha(reviewer_source), 'validation': checks,
            'eligible': eligible, 'findings': findings, 'approval': None}


def write(path, value):
    require(not path.is_symlink(), 'Evidence destination cannot be a symlink.')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def read(path):
    require(path.is_file() and not path.is_symlink(), 'Evidence must be a regular file.')
    return document(path.read_bytes())
