import gzip
import json

import pytest

from toolkit.investigator import (
    Investigator, normalized_call, validate_case, evidence_packet, CasePlan,
)
from toolkit.service import Investigator as LiveInvestigator
from toolkit.tools import ToolExecutor
from toolkit.replay import load_evidence_archive, analyze_archive
from support import API, config, incident, client, tool, say, submit, plan, case, records

def test_controller_selection():
    assert LiveInvestigator is Investigator


def test_case_generation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    fake,calls=client([
        submit('submit_investigation_plan',plan()), say(None),
        tool('run_kql',{'query':'Event | take 3'}),
        submit('submit_evidence_grounded_case',case())])
    result, receipts=Investigator(config(tmp_path), API(config(tmp_path)), fake).investigate(incident(), [], {})
    assert result['verdict']=='suspicious'
    assert result['validation']['field_checks_passed']==1
    assert result['validation']['semantic_claims_independently_verified'] is False
    assert result['needs_human'] is True
    assert len(calls)==4
    assert calls[-1]['tools'][0]['function']['name']=='submit_evidence_grounded_case'
    assert 'ev-0001' in receipts
    stages=[x['stage'] for x in records(tmp_path) if x['kind']=='stage']
    assert stages==['DISCOVER','COLLECT','ANALYZE','VALIDATE','COMPLETE']
    assert (tmp_path/'audit'/'plans').exists()
    assert list((tmp_path/'audit'/'evidence').glob('*.jsonl.gz'))


def test_receipt_repair(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    wrong=case(ref='missing-receipt')
    fake,calls=client([submit('submit_investigation_plan',plan()),say(None),
        tool('run_kql',{'query':'Event | take 3'}),
        submit('submit_evidence_grounded_case',wrong),
        submit('submit_evidence_grounded_case',case())])
    result,_=Investigator(config(tmp_path),API(config(tmp_path)),fake).investigate(incident(),[],{})
    assert result['verdict']=='suspicious'
    assert len([x for x in records(tmp_path) if x['kind']=='analysis_rejected'])==1
    assert len(calls)==5


def test_analysis_failure(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    fake,calls=client([submit('submit_investigation_plan',plan()),say(None),
        tool('run_kql',{'query':'Event | take 3'}),say(None),say(None)])
    result,_=Investigator(config(tmp_path),API(config(tmp_path)),fake).investigate(incident(),[],{})
    assert result['verdict']=='inconclusive' and result['retryable_failure']
    assert any('ev-0001' in s for s in result['limitations'])
    assert len(calls)==5
    assert [x for x in records(tmp_path) if x['kind']=='analysis_failed'][0]['raw_rows']==1


def test_field_validation(tmp_path):
    ex=ToolExecutor(API(config(tmp_path)),incident=incident(),alerts=[])
    ex.seed_context(incident(),[],{})
    data,ref=ex.execute('run_kql',{'query':'Event | take 3'})
    valid=validate_case(json.dumps(case(ref)), ex)
    assert valid['validation']['field_checks_passed']==1
    wrong=case(ref)
    wrong['findings'][0]['verified_fields'][0]['value']='1111'
    with pytest.raises(ValueError, match='do not co-occur'):
        validate_case(json.dumps(wrong),ex)
    wrong=case(ref)
    wrong['findings'][0]['row_indices']=[999]
    with pytest.raises(ValueError, match='outside'):
        validate_case(json.dumps(wrong),ex)
    malicious=case(ref,verdict='malicious')
    malicious['findings'][0]['verified_fields']=[]
    with pytest.raises(ValueError, match='Strong benign/malicious'):
        validate_case(json.dumps(malicious),ex)


def test_reject_metadata(tmp_path):
    ex=ToolExecutor(API(config(tmp_path)),incident=incident(),alerts=[])
    ex.seed_context(incident(),[],{})
    case_doc=case('ctx-incident')
    with pytest.raises(ValueError,match='metadata or documentation'):
        validate_case(json.dumps(case_doc),ex)


def test_duplicate_queries():
    a=normalized_call('inspect_evidence',{'receipt':'ev-0001','limit':20})
    b=normalized_call('inspect_evidence',{'receipt':'ev-0001','limit':20,'offset':0})
    assert a==b
    assert normalized_call('run_kql',{'query':'Event | take 1','docs_used':['kql:a']})==normalized_call(
        'run_kql',{'query':'Event | take 1','docs_used':['kql:b']})


def test_row_sampling(tmp_path):
    ex=ToolExecutor(API(config(tmp_path)),incident=incident(),alerts=[])
    ex.seed_context(incident(),[],{})
    _,ref=ex.execute('run_kql',{'query':'Event | take 3'})
    pkt=evidence_packet(ex,incident(),CasePlan())
    assert pkt['sampled_rows_with_0_based_indices'][0]['source_ref']==ref
    assert pkt['sampled_rows_with_0_based_indices'][0]['row_index']==0
    assert 'infrastructure_notes_unverified' not in json.dumps(pkt)


def test_offline_replay(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    fake,_=client([submit('submit_investigation_plan',plan()),say(None),
        tool('run_kql',{'query':'Event | take 3'}),
        submit('submit_evidence_grounded_case',case())])
    settings=config(tmp_path)
    result, _=Investigator(settings,API(settings),fake).investigate(incident(),[],{})
    archive=list((tmp_path/'audit'/'evidence').glob('*.jsonl.gz'))[0]
    original,alerts,entities,ex=load_evidence_archive(archive,settings)
    assert original['name']==incident()['name']
    assert ex.primary_telemetry_coverage()['rows_returned']==1
    replay_fake, calls=client([submit('submit_evidence_grounded_case',case())])
    replay=analyze_archive(archive,settings,client=replay_fake)
    assert replay['verdict']=='suspicious' and replay['offline_replay']
    assert len(calls)==1 and calls[0]['tool_choice']=='required'


def test_archive_integrity(tmp_path):
    p=tmp_path/'fake.jsonl.gz'
    item={'receipt':'ctx-incident','tool':'get_incident','arguments':{},
          'sha256':'deadbeef','full_payload':True,'data':incident()}
    with gzip.open(p,'wt') as f: f.write(json.dumps(item)+'\n')
    with pytest.raises(ValueError,match='hash mismatch'):
        load_evidence_archive(p,config(tmp_path))


def test_multirow_analysis(tmp_path,monkeypatch):

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    finding=case()
    finding['findings'][0]['verified_fields']=[{'name':'EventID','value':'4662'},
                                              {'name':'Computer','value':'DC'}]
    finding['summary']='21 records returned; specific replication abuse remains unproven'
    fake, calls=client([submit('submit_investigation_plan',plan()), say(None),
                        tool('run_kql',{'query':'SecurityEvent | take 21'}),
                        submit('submit_evidence_grounded_case',finding)])
    settings=config(tmp_path)
    result,_=Investigator(settings,SampleEventsAPI(settings),fake).investigate(incident(),[],{})
    assert result['verdict']=='suspicious'
    assert result['validation']['field_checks_passed']==2
    assert len(calls)==4
    audit=records(tmp_path)
    assert any(e['kind']=='validation_pass' for e in audit)
    assert not any(e['kind']=='analysis_failed' for e in audit)


def test_fields_same_row(tmp_path):
    class Split(API):
        def query_logs(self, query, **kwargs):
            return {'rows':[{'A':'yes','B':'no'},{'A':'no','B':'yes'}],
                    'rows_returned':2,'partial':False}
    settings=config(tmp_path)
    ex=ToolExecutor(Split(settings),incident=incident(),alerts=[])
    ex.seed_context(incident(),[],{})
    _, ref=ex.execute('run_kql',{'query':'Event | take 2'})
    test=case(ref)
    test['findings'][0]['row_indices']=[0,1]
    test['findings'][0]['verified_fields']=[{'name':'A','value':'yes'},{'name':'B','value':'yes'}]
    with pytest.raises(ValueError,match='do not co-occur'):
        validate_case(json.dumps(test),ex)


def test_kql_recovery(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{'kql':1236})
    monkeypatch.setattr('toolkit.evidence.source_reference_excerpts',lambda *a,**kw:[
        {'id':'kql:between','content_verbatim':'## Syntax\nbetween (start .. end)',
         'source_url':'https://github.com/MicrosoftDocs'}])
    monkeypatch.setattr('toolkit.tools.read_doc',lambda **kw:{
        'id':'kql:between','content_verbatim':'## Syntax\nbetween (start .. end)',
        'source_url':'https://github.com/MicrosoftDocs','offset':0,'has_more':False})
    bad='Event | where TimeGenerated between (datetime(2026-10-19T15:00:00Z) and datetime(2026-10-19T16:00:00Z))'
    good='Event | where TimeGenerated >= datetime(2026-10-19T15:00:00Z) | take 3'
    fake,calls=client([submit('submit_investigation_plan',plan()),say(None),
        tool('run_kql',{'query':bad,'docs_used':['kql:between']}),
        tool('read_official_doc',{'doc_id':'kql:between','focus':'Syntax'}),
        tool('run_kql',{'query':good,'docs_used':['kql:between']}),
        submit('submit_evidence_grounded_case',case(ref='ev-0002'))])
    settings=config(tmp_path)
    api=API(settings)
    result,receipts=Investigator(settings,api,fake).investigate(incident(),[],{})
    assert result['verdict']=='suspicious'
    assert api.queries[0][0]==bad and api.queries[1][0]==good
    assert receipts['ev-0001']['tool']=='read_official_doc'
    assert receipts['ev-0002']['tool']=='run_kql'
    assert {a['function']['name'] for a in calls[3]['tools']}=={'read_official_doc'}
    assert {a['function']['name'] for a in calls[4]['tools']}=={'run_kql','get_table_schema'}


def test_azure_timeout(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    class Unavailable(API):
        def query_logs(self, query, **kw):
            raise TimeoutError('Azure not reachable')
    fake,_=client([submit('submit_investigation_plan',plan()),say(None),
        tool('run_kql',{'query':'Event | take 1'}),say(None)])
    settings=config(tmp_path)
    with pytest.raises(RuntimeError, match='Azure source unavailable'):
        Investigator(settings,Unavailable(settings),fake).investigate(incident(),[],{})
    assert any(x['kind']=='source_unavailable' for x in records(tmp_path))


class SampleEventsAPI(API):
    def query_logs(self, query, **kwargs):
        return {'rows': [{'EventID': 4662, 'Computer': 'DC',
                          'SubjectUserName': f'user{i}', 'TimeGenerated': f'2026-10-19T19:{i:02d}:20Z'}
                         for i in range(21)],
                'rows_returned': 21, 'partial': False}


def sample_receipts(tmp_path):
    settings = config(tmp_path)
    ex = ToolExecutor(SampleEventsAPI(settings), incident=incident(), alerts=[])
    ex.seed_context(incident(), [], {})
    _, ref = ex.execute('run_kql', {'query': 'SecurityEvent | take 21'})
    assert ex.receipts[ref]['rows'] == 21
    return ex, ref


def event_report(ref, **finding_overrides):
    x = case(ref)
    x['findings'][0]['observation'] = 'Event 4662 exists in cited record. This does not alone establish DCSync.'
    x['findings'][0]['verified_fields'] = [{'name':'EventID','value':'4662'}]
    x['findings'][0].update(finding_overrides)
    return x


def test_row_ids(tmp_path):
    ex, ref = sample_receipts(tmp_path)
    packet = evidence_packet(ex, incident(), CasePlan())
    key = packet['allowed_row_keys'][0]
    x = event_report(ref, row_ids=[key])
    x['findings'][0].pop('row_indices', None)
    result = validate_case(json.dumps(x), ex, allowed_row_keys=set(packet['allowed_row_keys']))
    assert result['findings'][0]['row_indices'] == [0]
    assert result['findings'][0]['row_ids'] == [key]
    assert result['validation']['field_checks_passed'] == 1


def test_all_row_indices(tmp_path):
    ex, ref = sample_receipts(tmp_path)
    x = event_report(ref, row_indices=list(range(21)))
    result = validate_case(json.dumps(x), ex)
    assert len(result['findings'][0]['row_indices']) == 21


def test_hidden_rows(tmp_path):
    ex, ref = sample_receipts(tmp_path)
    packet = evidence_packet(ex, incident(), CasePlan())
    x = event_report(ref, row_ids=[f'{ref}#20'])
    x['findings'][0].pop('row_indices',None)
    with pytest.raises(ValueError, match='not shown'):
        validate_case(json.dumps(x), ex, allowed_row_keys=set(packet['allowed_row_keys']))


@pytest.mark.parametrize('invalid', [[], [0,0], [999], ['0'], 0, [True], list(range(33))])
def test_invalid_row_indices(tmp_path, invalid):
    ex, ref = sample_receipts(tmp_path)
    x = event_report(ref, row_indices=invalid)
    with pytest.raises(ValueError, match='row_indices|empty row citation'):
        validate_case(json.dumps(x), ex)


def test_conflicting_citations(tmp_path):
    ex, ref = sample_receipts(tmp_path)
    x = event_report(ref, row_ids=[f'{ref}#0'], row_indices=[1])
    with pytest.raises(ValueError, match='conflicting'):
        validate_case(json.dumps(x), ex)


def test_citation_repair(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    wrong = event_report('ev-0001', row_indices=[])
    good = event_report('ev-0001', row_ids=['ev-0001#0'])
    good['findings'][0].pop('row_indices', None)
    fake, calls = client([submit('submit_investigation_plan',plan()),say(None),
                          tool('run_kql', {'query':'SecurityEvent | take 21'}),
                          submit('submit_evidence_grounded_case',wrong),
                          submit('submit_evidence_grounded_case',good)])
    settings=config(tmp_path)
    result, receipts=Investigator(settings, SampleEventsAPI(settings), fake).investigate(incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert result['findings'][0]['row_ids'] == ['ev-0001#0']
    events = records(tmp_path)
    rejected=[r for r in events if r['kind']=='analysis_rejected']
    assert len(rejected)==1
    assert 'empty row citation' in rejected[0]['error']
    assert rejected[0]['citation_diagnostics'][0]['row_indices'] == []
    assert len([r for r in events if r['kind']=='validation_pass'])==1
    assert len(calls)==5
    assert 'row_ids' in calls[3]['tools'][0]['function']['parameters']['properties']['findings']['items']['properties']
    assert 'row_ids' in calls[4]['messages'][-1]['content']


def test_citation_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability',lambda:{})
    wrong = event_report('ev-0001', row_indices=[])
    fake,_ = client([submit('submit_investigation_plan',plan()),say(None),
                     tool('run_kql', {'query':'SecurityEvent | take 21'}),
                     submit('submit_evidence_grounded_case',wrong),
                     submit('submit_evidence_grounded_case',wrong)])
    settings=config(tmp_path)
    result, _ = Investigator(settings,SampleEventsAPI(settings),fake).investigate(incident(),[],{})
    assert result['verdict'] == 'inconclusive'
    assert result['needs_human'] is True
    assert result['retryable_failure'] is False
    assert any('21 rows' in v for v in result['limitations'])
    assert not result['findings']


def test_inconclusive_case(tmp_path):
    ex, ref = sample_receipts(tmp_path)
    x = event_report(ref)
    x.update(verdict='inconclusive',confidence=0.0, findings=[])
    parsed = validate_case(json.dumps(x), ex)
    assert parsed['verdict']=='inconclusive'
    assert parsed['validation']['citation_count']==0
    assert parsed['validation']['human_validation_required']
