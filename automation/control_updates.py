"""Prepare complete workflow changes for human review, never automatic approval."""
import datetime
import importlib.util
from pathlib import Path
import re
import tempfile

from .common import api, canonical, contents, digest, document, pages, require, run, sha, timestamp, version

REPO = 'Lanrith/lanrith'
PIN = re.compile(r'(?m)^(\s+(?:- )?uses: )([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})( # v([0-9]+\.[0-9]+\.[0-9]+))$')


def action_changes(before, after):
    old, new = list(PIN.finditer(before)), list(PIN.finditer(after))
    require(len(old) == len(new) and old, 'Action update changed its pin inventory.')
    mask = lambda text: PIN.sub(lambda m: m[1]+m[2]+'@PIN', text)
    require(mask(before) == mask(after), 'Action update contains changes outside SHA pins and version annotations.')
    changes = []
    for a, b in zip(old, new):
        require(a[2] == b[2] and a[1] == b[1], 'Action update changed its repository or execution context.')
        if a.groups()[2:] == b.groups()[2:]:
            continue
        require(version(a[5]) < version(b[5]) and version(a[5])[0] == version(b[5])[0],
                'Action migration needs a separately prepared human change.')
        upstream = '/'.join(b[2].split('/')[:2])
        require(upstream != REPO, 'Shared controller updates require the complete authenticated bundle.')
        release = api('repos/'+upstream+'/releases/tags/v'+b[5])
        require(not release['draft'] and not release['prerelease'], 'Action version is not a published stable release.')
        target = api('repos/'+upstream+'/git/ref/tags/v'+b[5])['object']
        if target['type'] == 'tag':
            target = api('repos/'+upstream+'/git/tags/'+sha(target['sha']))['object']
        require(target['type'] == 'commit' and target['sha'] == b[3], 'Action pin differs from its upstream version.')
        comparison = api('repos/'+upstream+'/compare/'+a[3]+'...'+b[3])
        require(comparison['status'] == 'ahead' and comparison['merge_base_commit']['sha'] == a[3],
                'Action update is not a forward change on its published source history.')
        changes.append({'repository': upstream, 'from': a[3], 'to': b[3], 'version': 'v'+b[5],
                        'review_diff': 'https://github.com/'+upstream+'/compare/'+a[3]+'...'+b[3]})
    require(changes, 'Action update contains no advancement.')
    return changes


def controller_source(tools, chosen, releases):
    require(chosen.get('immutable') is True, 'Controller release must be immutable.')
    spec = importlib.util.spec_from_file_location('controller_publication', tools/'scripts/watchdog.py')
    watchdog = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(watchdog)
    publication = watchdog.verified_publication(REPO, releases, chosen)
    require(publication is not None, 'Controller lacks authenticated publication verification.')
    with tempfile.TemporaryDirectory(prefix='lanrith-controller.') as temporary:
        root = Path(temporary)
        def download(tag, names):
            for name in names:
                run('gh', 'release', 'download', tag, '--repo', REPO, '--dir', temporary,
                    '--pattern', name, capture_output=True)
        download(chosen['tag_name'], ['selection.json', 'selection.json.intoto.jsonl', 'update-record.json'])
        selection = document((root/'selection.json').read_bytes())
        commit = sha(selection['source_commit'])
        require(selection['version'] == chosen['tag_name'] and selection['repository'] == REPO and
                selection['signer_commit'] == commit, 'Controller release source and workflow identities differ.')
        run('gh', 'attestation', 'verify', str(root/'selection.json'), '--bundle', str(root/'selection.json.intoto.jsonl'),
            '--repo', REPO, '--signer-workflow', REPO+'/.github/workflows/build-base.yml',
            '--source-digest', commit, '--signer-digest', commit, '--source-ref', 'refs/heads/main',
            '--deny-self-hosted-runners', capture_output=True)
        download(publication['tag_name'], ['publication-verification.json'])
        verification_raw = (root/'publication-verification.json').read_bytes()
        require(any(a['name'] == 'publication-verification.json' and a['digest'] == 'sha256:'+digest(verification_raw)
                    for a in publication['assets']), 'Downloaded controller verification changed after authentication.')
        verification = document(verification_raw)
        require(verification['source_commit'] == commit and verification['tag'] == chosen['tag_name'],
                'Controller publication and selection identify different source.')
        history_raw = (root/'update-record.json').read_bytes()
        require(digest(history_raw) == verification['update_record_sha256'], 'Controller authorization record differs from verified publication.')
        history = document(history_raw)
        require(history['repository'] == REPO and history['source_commit'] == commit and history['pull_requests'] and
                all(p['validation'] for p in history['pull_requests']), 'Controller has incomplete qualification history.')
        from .release_authorization import validate_record
        for pull in history['pull_requests']:
            if not pull['approvals']:
                validate_record(REPO, commit, pull, contents(REPO, 'security/update-policy.json', commit))
        suffix = '-'+selection['files']['inventory.json'][:12]
        assessments = [r for r in releases if not r['draft'] and r['tag_name'].startswith('assessment-') and r['tag_name'].endswith(suffix)]
        require(assessments, 'Controller needs a fresh retained security assessment.')
        assessment = max(assessments, key=lambda r: r['tag_name'])
        require(assessment.get('immutable') is True, 'Controller assessment is mutable.')
        download(assessment['tag_name'], ['security-assessment.json', 'security-assessment.json.intoto.jsonl'])
        report = document((root/'security-assessment.json').read_bytes())
        signer = sha(report['source_commit'])
        run('gh', 'attestation', 'verify', str(root/'security-assessment.json'),
            '--bundle', str(root/'security-assessment.json.intoto.jsonl'), '--repo', REPO,
            '--signer-workflow', REPO+'/.github/workflows/security-audit.yml', '--source-digest', signer,
            '--signer-digest', signer, '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners', capture_output=True)
        require(report['result'] == 'pass' and not report['failures'] and not report['scanner_errors'] and
                report['platform_version'] == selection['version'] and
                report['inventory_sha256'] == selection['files']['inventory.json'] and
                not set(selection['files'].values()) & set(report['revoked_sha256']) and
                datetime.timedelta(0) <= datetime.datetime.now(datetime.timezone.utc)-timestamp(report['assessed_at']) <= datetime.timedelta(hours=18),
                'Controller retained security assessment is stale, incomplete or failed.')
        return {'schema': 2, 'repository': REPO, 'version': chosen['tag_name'], 'source_commit': commit,
                'publication_audit': publication['html_url'], 'retained_assessment': assessment['html_url'],
                'verification_record_sha256': digest((root/'publication-verification.json').read_bytes()),
                'authorization_record_sha256': digest(history_raw),
                'release_authorization': 'independent-review' if all(p['approvals'] for p in history['pull_requests']) else 'maintainer-merge'}


def update_controller(root, selected):
    path = root/'security/maintenance-source.json'
    old = document(path.read_bytes())
    require(version(selected['version']) > version(old['version']), 'Controller update is not a stable advancement.')
    changes, references, collectors = {}, 0, 0
    for workflow in sorted((root/'.github/workflows').glob('*.yml')):
        text = workflow.read_text()
        updated, count = re.subn(r'(Lanrith/lanrith/\.github/workflows/[a-z-]+\.yml@)'+re.escape(old['source_commit'])+r'\b',
                                lambda m: m[1]+selected['source_commit'], text)
        references += count
        updated, count = re.subn(r'(repository: Lanrith/lanrith\s+ref: )'+re.escape(old['source_commit'])+r'\b',
                                lambda m: m[1]+selected['source_commit'], updated)
        collectors += count
        if text != updated:
            changes[workflow] = updated
    require(references >= 5 and collectors == 1, 'Controller reference inventory is incomplete.')
    require(not any(old['source_commit'] in value for value in changes.values()), 'Controller update left an obsolete reference.')
    for workflow, text in changes.items():
        workflow.write_text(text)
    path.write_bytes(canonical(selected))
    # Bootstrap the complete updater and recovery callers in the same reviewed
    # transaction as their qualified implementation, then keep them pinned too.
    for filename, title, cron in (
            ('maintenance-reconcile.yml', 'Reconcile security automation', '47 * * * *'),
            ('prepare-workflow-updates.yml', 'Prepare complete workflow updates', '37 */6 * * *')):
        permissions = ('      contents: read\n      actions: write\n      pull-requests: read\n'
                       '      checks: read\n      issues: write\n') if filename.startswith('maintenance-') else (
                       '      contents: read\n      actions: read\n      pull-requests: read\n')
        (root/'.github/workflows'/filename).write_text('name: '+title+'\non:\n  schedule:\n'
            "    - cron: '"+cron+"'\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  maintain:\n"
            "    if: github.ref == 'refs/heads/main'\n    permissions:\n"+permissions+
            '    uses: Lanrith/lanrith/.github/workflows/'+filename+'@'+selected['source_commit']+'\n    secrets: inherit\n')


def prepare(root, tools, repo):
    require(not run('git', 'status', '--porcelain', cwd=root, capture_output=True).stdout, 'Control updates require a clean main checkout.')
    base = run('git', 'rev-parse', 'HEAD', cwd=root, capture_output=True, text=True).stdout.strip()
    reasons = []
    if repo != REPO:
        releases = pages('repos/'+REPO+'/releases?per_page=100')
        stable = [r for r in releases if not r['draft'] and not r['prerelease'] and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name'])]
        require(stable, 'No qualified controller release is available.')
        chosen = max(stable, key=lambda r: version(r['tag_name']))
        old = document((root/'security/maintenance-source.json').read_bytes())
        if version(chosen['tag_name']) > version(old['version']):
            selected = controller_source(tools, chosen, releases)
            for filename in ('maintenance-reconcile.yml', 'prepare-workflow-updates.yml'):
                require(contents(REPO, '.github/workflows/'+filename, selected['source_commit']),
                        'Qualified controller does not yet support complete update and recovery callers.')
            update_controller(root, selected)
            reasons.append({'kind': 'complete-controller-update', 'previous': old, 'selected': selected})
    # Dependabot remains a discovery source for third-party Actions. Copy only
    # validated pin changes, pairing all affected design-assessment bytes in this PR.
    for pr in pages('repos/'+repo+'/pulls?state=open&per_page=100'):
        if pr['user']['login'] != 'dependabot[bot]' or pr['user']['type'] != 'Bot' or pr['head']['repo']['full_name'] != repo:
            continue
        files = pages('repos/'+repo+'/pulls/'+str(pr['number'])+'/files?per_page=100')
        if not files or not all(f['status'] == 'modified' and re.fullmatch(r'\.github/workflows/[a-z-]+\.yml', f['filename']) for f in files):
            continue
        if api('repos/'+repo+'/compare/'+base+'...'+pr['head']['sha'])['merge_base_commit']['sha'] != base:
            continue
        updates, changes = {}, []
        for file in files:
            path = file['filename']
            old = (root/path).read_text()
            new = contents(repo, path, pr['head']['sha']).decode()
            if 'Lanrith/lanrith/.github/workflows/' in new:
                # Controller pins are handled by authenticated release selection.
                continue
            changes.extend(action_changes(old, new))
            updates[root/path] = new
        if updates:
            for path, text in updates.items():
                path.write_text(text)
            reasons.append({'kind': 'action-pin-update', 'source_pr': pr['html_url'], 'source_head': pr['head']['sha'], 'changes': changes})
    if not reasons:
        return None
    assessment = root/'security/slsa-assessment.json'
    if assessment.exists():
        value = document(assessment.read_bytes())
        value['reviewed_workflows'] = {name: digest((root/name).read_bytes()) for name in value['reviewed_workflows']}
        assessment.write_bytes(canonical(value))
    record = {'schema': 1, 'repository': repo, 'base_sha': base, 'requires_human': True,
              'reason': 'Prepare workflow pins and their complete provenance/assessment companions together.', 'updates': reasons}
    (root/'security/automation-update.json').write_bytes(canonical(record))
    return record
