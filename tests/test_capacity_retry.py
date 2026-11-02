"""Capacity recovery must never mask tests, change source or outrun its audit/budget."""
import copy
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from automation import capacity, cleanup
from automation.common import MaintenanceError, canonical, digest

REPO=capacity.REPO
SOURCE,HEAD='a'*40,'b'*40
GIB=1024**3


class CapacityFixture:
    def setUp(self):
        self.run={'id':10,'head_sha':SOURCE,'run_attempt':1,'path':'.github/workflows/release.yml',
            'event':'push','name':'Release','head_branch':'main','head_repository':{'full_name':REPO},
            'status':'completed','conclusion':'failure','updated_at':'2026-11-01T16:00:00Z','pull_requests':[]}
        self.event={'action':'completed','repository':{'full_name':REPO},'workflow_run':self.run.copy()}
        self.pr={'number':48,'state':'open','draft':False,'head':{'sha':HEAD,'repo':{'full_name':REPO}},'base':{'sha':SOURCE,'ref':'main'}}
        self.jobs={'total_count':1,'jobs':[{'id':20,'name':'build / packages','status':'completed','conclusion':'failure',
            'steps':[{'name':'Prepare hosted runner disk','conclusion':'failure'},
                     {'name':'Compile and assess packages without privileged containers','conclusion':'skipped'}]}]}
        self.artifacts={'total_count':1,'artifacts':[{'id':30,'name':'runner-disk-packages-1','expired':False,
            'size_in_bytes':721,'workflow_run':{'id':10}}]}
        self.report={'schema':1,'kind':'hosted-runner-disk-preparation','result':'fail','minimum_free_bytes':60*GIB,
            'error':'Insufficient runner disk: 37.52 GiB free',
            'before':{'total_bytes':72*GIB,'used_bytes':59*GIB,'free_bytes':12*GIB},
            'after':{'total_bytes':72*GIB,'used_bytes':34*GIB,'free_bytes':37*GIB},
            'runner':{'GITHUB_RUN_ID':'10','GITHUB_RUN_ATTEMPT':'1','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'}}
        self.main=SOURCE;self.changed_preparation=False;self.mutations=[];self.advance=False
        self.archive={'immutable':True,'draft':False,'target_commitish':SOURCE,'assets':[],'html_url':'https://github.com/'+REPO+'/releases/tag/audit-capacity-plan-100-1'}

    def get(self,endpoint,**kwargs):
        if kwargs.get('method'):
            self.mutations.append((endpoint,kwargs))
            if endpoint.endswith('/rerun') and self.advance:
                self.run.update(run_attempt=2,status='queued',conclusion=None)
            return None
        if endpoint.endswith('/actions/runs/10'):return copy.deepcopy(self.run)
        if endpoint.endswith('/git/ref/heads/main'):return {'object':{'sha':self.main}}
        if endpoint.endswith('/pulls/48'):return copy.deepcopy(self.pr)
        if '/jobs?' in endpoint:return copy.deepcopy(self.jobs)
        if '/artifacts?' in endpoint:return copy.deepcopy(self.artifacts)
        if '/releases/tags/' in endpoint:return copy.deepcopy(self.archive)
        raise AssertionError('Unexpected endpoint: '+endpoint)

    def source(self,repo,path,ref):
        return b'changed' if self.changed_preparation and ref==HEAD else b'reviewed fixed preparation'

    def inspect(self):
        return capacity.inspect(REPO,self.event,SOURCE,get=self.get,read_source=self.source,load_report=lambda *a:copy.deepcopy(self.report))

    def pull_request(self):
        self.run.update(head_sha=HEAD,path='.github/workflows/package-check.yml',event='pull_request',name='Package qualification',head_branch='fix/example',
            pull_requests=[{'number':48,'head':{'sha':HEAD},'base':{'sha':SOURCE}}])
        self.event['workflow_run']=self.run.copy()
        self.jobs['jobs'][0]['name']='Unsigned package compilation'

    def execute(self,plan,verify=None,progress=None):
        return capacity.execute(plan,SOURCE,'audit-capacity-plan-100-1',get=self.get,read_source=self.source,
            load_report=lambda *a:copy.deepcopy(self.report),verify=verify or (lambda *a,**k:'https://example.invalid/immutable-intent'),
            progress=progress,pause=lambda _:None)

class CapacityTests(CapacityFixture, unittest.TestCase):
    def test_exact_capacity_failure_is_eligible_for_one_job_retry(self):
        plan=self.inspect()
        self.assertTrue(plan['eligible']);self.assertTrue(plan['archive'])
        self.assertEqual(plan['failed_job']['id'],20)
        self.assertEqual(plan['maximum_attempts'],3)
        self.advance=True
        result=self.execute(plan)
        self.assertEqual(result['state'],'retry-requested')
        self.assertTrue(result['retry_accepted'])
        self.assertEqual(self.mutations,[('repos/'+REPO+'/actions/jobs/20/rerun',{'method':'POST'})])

    def test_retry_budget_is_exactly_two_retries_after_initial_attempt(self):
        for attempt in (1,2,3,4):
            with self.subTest(attempt=attempt):
                self.run['run_attempt']=attempt;self.event['workflow_run']=self.run.copy()
                self.report['runner']['GITHUB_RUN_ATTEMPT']=str(attempt)
                self.artifacts['artifacts'][0]['name']=f'runner-disk-packages-{attempt}'
                plan=self.inspect()
                self.assertEqual(plan['eligible'],attempt<3)
                self.assertEqual(plan['state'],'ready' if attempt<3 else 'budget-exhausted')
                if attempt>=3:
                    with self.assertRaises(MaintenanceError):self.execute(plan)
        self.assertEqual(self.mutations,[])

    def test_each_real_build_or_scanner_failure_is_left_blocked(self):
        for step in ('Compile and assess packages without privileged containers','Native tests','govulncheck','Install the reviewed scanner'):
            with self.subTest(step=step):
                self.jobs['jobs'][0]['steps'][0]['name']=step
                self.assertFalse(self.inspect()['eligible'])
        self.assertEqual(self.mutations,[])

    def test_compile_execution_or_another_failed_job_prevents_retry(self):
        self.jobs['jobs'][0]['steps'][1]['conclusion']='success'
        self.assertFalse(self.inspect()['eligible'])
        self.jobs['jobs'][0]['steps'][1]['conclusion']='skipped'
        self.jobs['jobs'].append({'id':21,'name':'Required checks','conclusion':'failure'})
        self.jobs['total_count']=2
        self.assertFalse(self.inspect()['eligible'])

    def test_old_events_wrong_repo_forks_and_nonfailed_runs_are_ignored(self):
        mutations=(lambda:self.event.update(action='in_progress'),
            lambda:self.event['repository'].update(full_name='other/repo'),
            lambda:self.run.update(run_attempt=2),lambda:self.run.update(head_sha='f'*40),
            lambda:self.run.update(status='in_progress'),lambda:self.run.update(conclusion='success'),
            lambda:self.run.update(head_repository={'full_name':'other/fork'}),lambda:self.run.update(head_branch='feature'),
            lambda:self.run.update(path='.github/workflows/evil.yml'),lambda:setattr(self,'main','f'*40))
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.setUp();mutate();self.assertFalse(self.inspect()['eligible']);self.assertEqual(self.mutations,[])

    def test_pull_request_must_bind_current_same_repo_head_and_base(self):
        self.pull_request();self.assertTrue(self.inspect()['eligible'])
        for field in ('head','base','fork','draft','closed','association','script'):
            with self.subTest(field=field):
                self.setUp();self.pull_request()
                if field=='head':self.pr['head']['sha']='f'*40
                elif field=='base':self.pr['base']['sha']='f'*40
                elif field=='fork':self.pr['head']['repo']['full_name']='other/fork'
                elif field=='draft':self.pr['draft']=True
                elif field=='closed':self.pr['state']='closed'
                elif field=='association':self.run['pull_requests'][0]['base']['sha']='f'*40
                else:self.changed_preparation=True
                self.assertFalse(self.inspect()['eligible'])

    def test_native_recovery_requires_successful_package_handoff(self):
        self.jobs['jobs'][0]['name']='build / build'
        self.artifacts['artifacts'][0]['name']='runner-disk-native-1'
        self.assertFalse(self.inspect()['eligible'])
        self.artifacts['artifacts'].append({'id':31,'name':'package-stage-1','expired':False,'workflow_run':{'id':10},'digest':'sha256:'+'d'*64})
        self.artifacts['total_count']=2
        self.assertTrue(self.inspect()['eligible'])
        self.artifacts['artifacts'][1]['expired']=True
        self.assertFalse(self.inspect()['eligible'])

    def test_unknown_cleanup_errors_or_wrong_attempt_never_become_capacity_failures(self):
        for field in ('error','minimum','run','attempt','runner','space','result','missing_after'):
            with self.subTest(field=field):
                self.setUp()
                if field=='error':self.report['error']='Permission denied while removing SDKs'
                elif field=='minimum':self.report['minimum_free_bytes']=30*GIB
                elif field=='run':self.report['runner']['GITHUB_RUN_ID']='11'
                elif field=='attempt':self.report['runner']['GITHUB_RUN_ATTEMPT']='2'
                elif field=='runner':self.report['runner']['RUNNER_ENVIRONMENT']='self-hosted'
                elif field=='space':self.report['after']['free_bytes']=60*GIB;self.report['after']['used_bytes']=10*GIB
                elif field=='result':self.report['result']='pass'
                else:del self.report['after'];self.assertRaises(MaintenanceError,self.inspect);continue
                self.assertFalse(self.inspect()['eligible'])

    def test_incomplete_or_cross_run_report_data_fails_closed(self):
        for field in ('jobs','artifacts','report_run','oversize','measurements'):
            with self.subTest(field=field):
                self.setUp()
                if field=='jobs':self.jobs['total_count']=101
                elif field=='artifacts':self.artifacts['total_count']=101
                elif field=='report_run':self.artifacts['artifacts'][0]['workflow_run']['id']=11
                elif field=='oversize':self.artifacts['artifacts'][0]['size_in_bytes']=16385
                else:self.report['after']['free_bytes']=-1
                with self.assertRaises(MaintenanceError):self.inspect()
                self.assertEqual(self.mutations,[])

    def test_untrusted_strings_and_extra_fields_are_not_republished(self):
        self.report['unexpected']='PRIVATE-CANARY'
        self.report['after']['path']='PRIVATE-CANARY'
        self.report['runner']['ImageVersion']='PRIVATE-CANARY'
        self.report['error']+=' PRIVATE-CANARY'
        plan=self.inspect()
        self.assertTrue(plan['eligible'])
        self.assertNotIn('PRIVATE-CANARY',json.dumps(plan))
        self.assertEqual(plan['report_sha256'],digest(canonical(self.report)))

    def test_mutated_or_failed_archive_cannot_reach_the_actions_write(self):
        plan=self.inspect()
        with self.assertRaises(MaintenanceError):
            self.execute(plan,verify=lambda *a,**k:(_ for _ in ()).throw(MaintenanceError('No immutable intent')))
        self.assertEqual(self.mutations,[])
        self.report['after']['free_bytes']-=1
        with self.assertRaises(MaintenanceError):self.execute(plan)
        self.assertEqual(self.mutations,[])

    def test_changed_source_or_concurrent_retry_prevents_another_mutation(self):
        for field in ('main','attempt'):
            with self.subTest(field=field):
                self.setUp();plan=self.inspect()
                if field=='main':self.main='f'*40
                else:self.run['run_attempt']=2
                with self.assertRaises(MaintenanceError):self.execute(plan)
                self.assertEqual(self.mutations,[])

    def test_one_ambiguous_transport_error_is_recorded_and_never_retried(self):
        plan=self.inspect();snapshots=[];original=self.get
        def broken(endpoint,**kwargs):
            if kwargs.get('method'):
                self.mutations.append((endpoint,kwargs));raise OSError('connection reset after POST')
            return original(endpoint,**kwargs)
        with self.assertRaises(OSError):
            capacity.execute(plan,SOURCE,'audit-capacity-plan-100-1',get=broken,read_source=self.source,load_report=lambda *a:self.report,
                verify=lambda *a,**k:'https://example.invalid/immutable',progress=lambda r:snapshots.append(copy.deepcopy(r)),pause=lambda _:None)
        self.assertEqual(len(self.mutations),1)
        self.assertEqual(snapshots[-1]['state'],'retry-outcome-unknown')
        self.assertFalse(snapshots[-1]['retry_accepted'])

    def test_pull_request_refresh_uses_only_the_normal_trusted_reviewer(self):
        self.pull_request();plan=self.inspect();self.advance=True
        result=self.execute(plan)
        self.assertEqual(len(self.mutations),2)
        endpoint,args=self.mutations[1]
        self.assertTrue(endpoint.endswith('/security-review.yml/dispatches'))
        self.assertEqual(args['payload'],{'ref':'main','inputs':{'pr':'48'}})
        self.assertNotIn('/reviews',json.dumps(self.mutations))
        self.assertFalse(result['security_validation_bypassed'])


class CapacityArchiveTests(CapacityFixture, unittest.TestCase):
    def test_immutable_exact_source_and_digest_are_required_for_intent(self):
        plan=self.inspect()
        for attack in ('mutable','draft','source','digest','tag'):
            with self.subTest(attack=attack):
                self.archive.update(immutable=True,draft=False,target_commitish=SOURCE,assets=[{'name':'capacity-record.json','digest':'sha256:'+digest(canonical(plan))}])
                tag='audit-capacity-plan-100-1'
                if attack=='mutable':self.archive['immutable']=False
                elif attack=='draft':self.archive['draft']=True
                elif attack=='source':self.archive['target_commitish']='f'*40
                elif attack=='digest':self.archive['assets'][0]['digest']='sha256:'+'f'*64
                else:tag='audit-capacity-plan-101-1'
                with patch.dict(os.environ,{'GITHUB_RUN_ID':'100'}), self.assertRaises(MaintenanceError):
                    capacity.verify_archive(plan,tag,SOURCE,get=self.get)
                self.assertEqual(self.mutations,[])

    def test_exact_intent_uses_offline_bundle_and_pinned_hosted_signer(self):
        plan=self.inspect();self.archive['assets']=[{'name':'capacity-record.json','digest':'sha256:'+digest(canonical(plan))}]
        commands=[]
        def command(*args,**kwargs):
            commands.append(args)
            if args[:3]==('gh','release','download'):
                folder=Path(args[args.index('--dir')+1]);(folder/'capacity-record.json').write_bytes(canonical(plan));(folder/'evidence.intoto.jsonl').write_text('bundle fixture')
            return SimpleNamespace(stdout=b'')
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'100'}),patch.object(capacity,'run',side_effect=command):
            self.assertEqual(capacity.verify_archive(plan,'audit-capacity-plan-100-1',SOURCE,get=self.get),self.archive['html_url'])
        verify=commands[-1]
        self.assertEqual(verify[:3],('gh','attestation','verify'))
        self.assertEqual(verify[verify.index('--signer-digest')+1],SOURCE)
        self.assertIn('--deny-self-hosted-runners',verify)


class CapacityEnvelopeTests(unittest.TestCase):
    def test_only_one_small_regular_json_report_can_be_read(self):
        for name,extra,mode,size in [('runner-disk.json',False,0,10),('../runner-disk.json',False,0,10),
                                  ('runner-disk.json',True,0,10),('runner-disk.json',False,0o120777,10),('runner-disk.json',False,0,20000)]:
            with self.subTest(name=name,extra=extra,mode=mode,size=size):
                data=io.BytesIO()
                with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as packed:
                    info=zipfile.ZipInfo(name);info.external_attr=mode<<16
                    packed.writestr(info,canonical({'schema':1,'padding':'x'*size}))
                    if extra:packed.writestr('extra.json','{}')
                with patch.object(capacity,'run',return_value=SimpleNamespace(stdout=data.getvalue())):
                    if name=='runner-disk.json' and not extra and not mode and size==10:
                        self.assertEqual(capacity.artifact_report(REPO,30)['schema'],1)
                    else:
                        with self.assertRaises(MaintenanceError):capacity.artifact_report(REPO,30)


class CapacityCleanupTests(unittest.TestCase):
    def test_retry_handoffs_are_small_temporary_data_and_active_consumers_survive(self):
        clock=datetime.datetime(2026,11,1,17,tzinfo=datetime.timezone.utc)
        names=['runner-capacity-plan','runner-capacity-result','attested-maintenance-capacity-plan-1','attested-maintenance-capacity-result-1','runner-capacity-plan','private-authority']
        artifacts=[{'id':i,'name':name,'size_in_bytes':1024,'expired':False,'workflow_run':{'id':i}} for i,name in enumerate(names,1)]
        def get(endpoint,**kwargs):
            if kwargs.get('paginate'):return [{'artifacts':artifacts}]
            return {'name':'Recover insufficient runner capacity','status':'in_progress' if endpoint.endswith('/5') else 'completed',
                    'updated_at':(clock-datetime.timedelta(hours=3)).isoformat()}
        result=cleanup.plan(REPO,get=get,clock=clock)
        self.assertEqual([a['id'] for a in result['artifacts']],[1,2,3,4])
        self.assertEqual(result['bytes'],4096)
