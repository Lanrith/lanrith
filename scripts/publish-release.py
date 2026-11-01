#!/usr/bin/env python3
"""Verify review and qualification, resume matching drafts, then seal immutable bytes."""

import base64,datetime,hashlib,json,os,pathlib,re,subprocess,time
def run(*args): return subprocess.run(args,check=True,capture_output=True,text=True).stdout
def authorized_human(review,head,author):
    user=review['user']
    if review['state']!='APPROVED' or review['commit_id']!=head or user['type']!='User' or user['login']==author:
        return False
    assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}',user['login'])
    permission=json.loads(run('gh','api',f"repos/{repo}/collaborators/{user['login']}/permission"))
    assert permission['user']['id']==user['id'] and permission['user']['login']==user['login']
    return permission['permission'] in ('admin','write')
repo=os.environ['GITHUB_REPOSITORY']
source=os.environ['GITHUB_SHA']
version=os.environ['RELEASE_VERSION'].removeprefix('v')
assert repo in ('Lanrith/lanrith','Lanrith/discovery-bridge','Lanrith/router-policy-agent')
assert re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version)
assert re.fullmatch('[0-9a-f]{40}',source)
root=pathlib.Path('release')
files=sorted(root.iterdir())
assert files and len(files)<=200 and all(p.is_file() and not p.is_symlink() and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,191}',p.name) and 0<p.stat().st_size<2*1024**3 for p in files)
update=json.loads((root/'update-record.json').read_text())
assert update['repository']==repo and update['source_commit']==source and update['pull_requests']
assert update['version'].removeprefix('v')==version
policy_file=json.loads(run('gh','api',f'repos/{repo}/contents/security/update-policy.json?ref={source}'))
policy=json.loads(base64.b64decode(policy_file['content']))
# Independently confirm the claimed review identities before publishing their record.
for pr in update['pull_requests']:
    current=json.loads(run('gh','api',f"repos/{repo}/pulls/{pr['number']}"))
    assert current['merged'] and current['merge_commit_sha']==source and current['head']['sha']==pr['head_sha']
    review_pages=json.loads(run('gh','api',f"repos/{repo}/pulls/{pr['number']}/reviews?per_page=100",'--paginate','--slurp'))
    assert isinstance(review_pages,list) and all(isinstance(p,list) for p in review_pages)
    actual=[r for page in review_pages for r in page]
    latest={r['user']['id']:r for r in sorted(actual,key=lambda r:r['id']) if r['state'] in ('APPROVED','CHANGES_REQUESTED','DISMISSED')}
    assert pr['approvals'] and all(any(r['id']==a['id'] and r['state']=='APPROVED' and r['commit_id']==pr['head_sha'] and r['user']['id']==a['actor_id'] for r in latest.values()) for a in pr['approvals'])
    assert {v['workflow'] for v in pr['validation']}==set(policy['required_workflows'])
    for validation in pr['validation']:
        current_runs=json.loads(run('gh','api',f"repos/{repo}/actions/workflows/{validation['workflow'].rsplit('/',1)[-1]}/runs?event=pull_request&head_sha={pr['head_sha']}&per_page=100"))['workflow_runs']
        assert current_runs and max(current_runs,key=lambda r:r['id'])['id']==validation['id']
        observed=json.loads(run('gh','api',f"repos/{repo}/actions/runs/{validation['id']}"))
        assert observed['event']=='pull_request' and observed['head_sha']==pr['head_sha'] and observed['path']==validation['workflow'] and observed['status']=='completed' and observed['conclusion']=='success' and observed['run_attempt']==validation['attempt']
    automated_branch=current['head']['ref']==policy['proposal_branch'] and current['head']['repo']['full_name']==repo
    if automated_branch:
        assert pr['candidate']
        candidate_file=json.loads(run('gh','api',f"repos/{repo}/contents/security/update-candidate.json?ref={pr['head_sha']}"))
        assert pr['candidate']==json.loads(base64.b64decode(candidate_file['content']))
    if automated_branch and not pr['candidate']['requires_human'] and policy['mode']=='enforce':
        checks=json.loads(run('gh','api',f"repos/{repo}/commits/{pr['head_sha']}/check-runs?check_name=Security%20update%20admission&filter=latest"))['check_runs']
        admitted=[c for c in checks if c['name']=='Security update admission' and c['app']['id']==policy['reviewer_app_id'] and c['status']=='completed' and c['conclusion']=='success']
        assert admitted
        reviewer=admitted[-1]['app']['slug']+'[bot]'
        assert any(r['state']=='APPROVED' and r['commit_id']==pr['head_sha'] and r['user']['login']==reviewer for r in latest.values())
    else:
        # Private organisation membership can appear as CONTRIBUTOR to
        # installation tokens. Verify effective write access directly.
        assert any(authorized_human(r,pr['head_sha'],current['user']['login']) for r in latest.values())
if repo=='Lanrith/lanrith':
    security=json.loads((root/'security.json').read_text())
    assert security.get('production_qualified') is True and security.get('slsa_spec')=='1.2' and security.get('slsa_build_level')==3 and security.get('qualification',{}).get('result')=='pass'
expected={}
for p in files:
    with p.open('rb') as stream: expected[p.name]='sha256:'+hashlib.file_digest(stream,'sha256').hexdigest()
tag='v'+version
# No overwrite or --clobber path is available, including on retries.
def release():
    # A draft has no published Git tag. The tag REST endpoint returns
    # 404 for it; the CLI resolves drafts and exposes their stable API ID.
    lookup=subprocess.run(['gh','release','view',tag,'--repo',repo,'--json','apiUrl'],capture_output=True,text=True)
    if lookup.returncode:
        assert 'release not found' in lookup.stderr.lower() or 'HTTP 404' in lookup.stderr
        return None
    url=json.loads(lookup.stdout)['apiUrl']
    assert re.fullmatch(r'https://api[.]github[.]com/repos/'+re.escape(repo)+r'/releases/[0-9]+',url)
    return json.loads(run('gh','api',url.removeprefix('https://api.github.com/')))
def tag_source():
    lookup=subprocess.run(['gh','api',f'repos/{repo}/git/ref/tags/{tag}'],capture_output=True,text=True)
    if lookup.returncode:
        assert 'HTTP 404' in lookup.stderr
        return None
    ref=json.loads(lookup.stdout)['object']
    for _ in range(4):
        if ref['type']=='commit': break
        assert ref['type']=='tag'
        ref=json.loads(run('gh','api',f"repos/{repo}/git/tags/{ref['sha']}"))['object']
    assert ref['type']=='commit' and ref['sha']==source, 'The existing tag names another source.'
    return ref['sha']

def validate_assets(value, *, complete=False):
    assert value['tag_name']==tag and value['target_commitish']==source, 'Release source differs.'
    assets=value['assets']
    assert len({a['name'] for a in assets})==len(assets), 'Duplicate release asset names.'
    assert all(a['name'] in expected and a['digest']==expected[a['name']] for a in assets), 'Unexpected or conflicting release asset.'
    if complete:
        assert len(assets)==len(expected), 'The release asset set is incomplete.'
    return {a['name'] for a in assets}

def transient_upload(error):
    return bool(re.search(r'HTTP 5[0-9]{2}|timed? out|timeout|unexpected EOF|connection reset|broken pipe|context deadline exceeded|TLS handshake timeout',error,re.I))

# Reject a conflicting pre-existing tag before creating or sealing anything.
tag_source()
draft=release()
if draft is None:
    # Create the draft without bulk uploads. Each missing asset is independently
    # resumable, and an existing asset is never overwritten or deleted.
    run('gh','release','create',tag,'--repo',repo,'--target',source,'--draft','--prerelease','--latest=false','--title','Lanrith '+version,'--generate-notes')
    draft=release()
assert draft is not None
present=validate_assets(draft,complete=not draft['draft'])
if draft['draft']:
    assert draft['prerelease'] and not draft.get('immutable')
    for path in files:
        if path.name in present:
            continue
        for attempt in range(1,4):
            uploaded=subprocess.run(['gh','release','upload',tag,str(path),'--repo',repo],capture_output=True,text=True)
            observed=release()
            assert observed is not None and observed['id']==draft['id'] and observed['draft'] and observed['prerelease']
            present=validate_assets(observed)
            if path.name in present:
                break  # A disconnected response can follow a successful upload.
            assert uploaded.returncode, 'Upload reported success without the expected asset.'
            if attempt==3 or not transient_upload(uploaded.stderr):
                raise RuntimeError(f'Upload of {path.name} failed after {attempt} attempt(s); the matching draft is preserved for retry.')
            print(f'Transient upload failure for {path.name}; retry {attempt+1}/3.')
            time.sleep(attempt)
    draft=release()
    assert draft is not None
    assert draft['draft'] and draft['prerelease']
    validate_assets(draft,complete=True)
    tag_source()
    run('gh','release','edit',tag,'--repo',repo,'--draft=false')
published=release()
assert published is not None and published['id']==draft['id']
assert published.get('immutable') is True and not published['draft']
validate_assets(published,complete=True)
assert tag_source()==source
# Stable/latest is promoted only after immutable bytes and tag have passed verification.
if published['prerelease']:
    run('gh','release','edit',tag,'--repo',repo,'--prerelease=false','--latest')
promoted=release()
assert promoted['id']==published['id'] and promoted['immutable'] and not promoted['draft'] and not promoted['prerelease']
validate_assets(promoted,complete=True)
assert tag_source()==source
record={'schema':1,'kind':'publication-verification','result':'pass','repository':repo,'source_commit':source,'tag':tag,'release_id':published['id'],'release_url':published['html_url'],'immutable':True,'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'assets':expected,'update_record_sha256':expected['update-record.json'][7:],'run_id':os.environ['GITHUB_RUN_ID'],'run_attempt':os.environ['GITHUB_RUN_ATTEMPT']}
pathlib.Path('verification').mkdir()
pathlib.Path('verification/publication-verification.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(published['html_url'])
