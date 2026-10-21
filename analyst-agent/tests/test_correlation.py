"""Follow-up investigation on related events, not only the alert trigger."""
import pytest

from toolkit.investigator import Investigator, evidence_packet, CasePlan
from toolkit.tools import ToolExecutor
from support import API, config, incident, client, tool, say, submit, plan, case, records


class RelatedAPI(API):
    def query_logs(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if 'BROKEN' in query:
            raise ValueError('SYN0002 syntax error in KQL')
        event_id = 4625 if '4625' in query else 4624 if '4624' in query else 4672
        return {'rows': [{'Computer': 'DC.onze.internal', 'EventID': event_id,
                          'TimeGenerated': '2026-10-21T12:01:00Z',
                          'parsed_event_data': {'TargetUserName': 'Administrator',
                                                'IpAddress': '10.10.10.22'}}],
                'rows_returned': 1, 'partial': False}


def report(follow_ref='ev-0002'):
    x = case('ev-0001')
    x['summary'] = 'Failed and successful logon records observed on the same host and source IP.'
    x['findings'][0]['verified_fields'] = [
        {'name': 'EventID', 'value': '4625'},
        {'name': 'IpAddress', 'value': '10.10.10.22'}]
    x['findings'].append({
        'source_ref': follow_ref, 'observation': 'Successful logon also observed.',
        'row_ids': [follow_ref + '#0'],
        'verified_fields': [{'name': 'EventID', 'value': '4624'},
                            {'name': 'IpAddress', 'value': '10.10.10.22'}]})
    return x


def test_collects_related_events(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    q1 = "Event | where EventID == 4625 | take 10"
    q2 = "Event | where EventID == 4624 and Computer == 'DC.onze.internal' | take 10"
    q3 = "Event | where EventID == 4672 and Computer == 'DC.onze.internal' | take 10"
    fake, calls = client([submit('submit_investigation_plan', plan()), say(None),
                          tool('run_kql', {'query': q1}),
                          tool('run_kql', {'query': q2}),
                          tool('run_kql', {'query': q3}),
                          submit('submit_evidence_grounded_case', report())])
    settings = config(tmp_path, correlation_queries=2)
    api = RelatedAPI(settings)
    result, receipts = Investigator(settings, api, fake).investigate(incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert result['validation']['field_checks_passed'] == 4
    assert len(api.queries) == 3
    assert len([r for r in receipts if receipts[r]['tool'] == 'run_kql']) == 3
    assert 'initial_event_sample' in calls[3]['messages'][-1]['content']
    assert '4625' in calls[3]['messages'][-1]['content']
    assert [x['stage'] for x in records(tmp_path) if x['kind'] == 'stage'] == [
        'DISCOVER', 'COLLECT', 'CORRELATE', 'ANALYZE', 'VALIDATE', 'COMPLETE']
    assert any(x['kind'] == 'correlation_done' and x['queries'] == 2 for x in records(tmp_path))


def test_original_receipt_stays_in_report_packet(tmp_path):
    settings = config(tmp_path)
    ex = ToolExecutor(RelatedAPI(settings))
    for event_id in (4625, 4624, 4672, 4698, 4699):
        ex.execute('run_kql', {'query': f'Event | where EventID == {event_id} | take 1'})
    pkt = evidence_packet(ex, incident(), CasePlan())
    keys = pkt['allowed_row_keys']
    assert 'ev-0001#0' in keys
    assert 'ev-0005#0' in keys
    assert 'ev-0001' in pkt['allowed_event_receipts']


def test_correlation_stops_when_model_has_no_query(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    fake, _ = client([submit('submit_investigation_plan', plan()), say(None),
                     tool('run_kql', {'query': 'Event | where EventID == 4625 | take 1'}),
                     say('DONE'), say('DONE'), submit('submit_evidence_grounded_case', single())])
    settings = config(tmp_path, correlation_queries=2)
    result, _ = Investigator(settings, RelatedAPI(settings), fake).investigate(incident(), [], {})
    assert any('No additional raw event rows' in x for x in result['limitations'])
    assert any(e['kind'] == 'correlation_stopped' for e in records(tmp_path))


def test_correlation_recovers_kql_syntax(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    monkeypatch.setattr('toolkit.evidence.source_reference_excerpts', lambda *a, **kw: [
        {'id': 'kql:where', 'content_verbatim': 'KQL where filter',
         'source_url': 'https://github.com/MicrosoftDocs'}])
    monkeypatch.setattr('toolkit.tools.read_doc', lambda **kw: {
        'id': 'kql:where', 'content_verbatim': 'KQL where syntax',
        'source_url': 'https://github.com/MicrosoftDocs'})
    fake, calls = client([
        submit('submit_investigation_plan', plan()), say(None),
        tool('run_kql', {'query': 'Event | where EventID == 4625 | take 1'}),
        tool('run_kql', {'query': 'Event | BROKEN'}),
        tool('read_official_doc', {'doc_id': 'kql:where', 'focus': 'syntax'}),
        tool('run_kql', {'query': 'Event | where EventID == 4624 | take 1'}),
        submit('submit_evidence_grounded_case', report('ev-0003'))])
    settings = config(tmp_path, correlation_queries=1)
    result, _ = Investigator(settings, RelatedAPI(settings), fake).investigate(incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert {t['function']['name'] for t in calls[4]['tools']} == {'read_official_doc'}
    assert {t['function']['name'] for t in calls[5]['tools']} == {'run_kql', 'get_table_schema'}


def test_correlation_timeout_does_not_loop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    class Slow(RelatedAPI):
        def query_logs(self, query, **kwargs):
            if '4624' in query:
                raise TimeoutError('Azure unreachable')
            return super().query_logs(query, **kwargs)
    fake, calls = client([submit('submit_investigation_plan', plan()), say(None),
                          tool('run_kql', {'query': 'Event | where EventID == 4625 | take 1'}),
                          tool('run_kql', {'query': 'Event | where EventID == 4624 | take 1'})])
    settings = config(tmp_path, correlation_queries=2)
    with pytest.raises(RuntimeError, match='Azure source unavailable'):
        Investigator(settings, Slow(settings), fake).investigate(incident(), [], {})
    assert len(calls) == 4
    assert any(x['kind'] == 'source_unavailable' for x in records(tmp_path))


def single():
    x = case()
    x['findings'][0]['verified_fields'][0]['value'] = '4625'
    return x


def test_correlate_tool_budget(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    fake, calls = client([submit('submit_investigation_plan', plan()), say(None),
                          tool('run_kql', {'query': 'Event | where EventID == 4625 | take 1'}),
                          submit('submit_evidence_grounded_case', single())])
    settings = config(tmp_path, correlation_queries=2, max_tool_calls=1)
    result, _ = Investigator(settings, RelatedAPI(settings), fake).investigate(incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert len(calls) == 4


def test_large_windows_xml_keeps_pivots_visible(tmp_path):
    class Large(RelatedAPI):
        def query_logs(self, query, **kwargs):
            row = {'EventData': 'x' * 35000,
                   'TimeGenerated': '2026-10-21T12:01:00Z',
                   'Computer': 'DC', 'EventID': 4625,
                   'parsed_event_data': {'IpAddress': '10.10.10.22',
                                         'TargetUserName': 'Administrator'}}
            return {'rows': [row], 'partial': False, 'rows_returned': 1}
    ex = ToolExecutor(Large(config(tmp_path)))
    ex.execute('run_kql', {'query': 'Event | take 1'})
    pkt = evidence_packet(ex, incident(), CasePlan())
    row = pkt['sampled_rows_with_0_based_indices'][0]['row']
    assert row['parsed_event_data']['IpAddress'] == '10.10.10.22'
    assert row['EventID'] == 4625
    assert 'EventData' not in row
