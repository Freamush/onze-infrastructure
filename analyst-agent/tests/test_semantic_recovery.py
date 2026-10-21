"""An Azure SEM0100 column error must not strand collection in schema loops."""
from toolkit.investigator import Investigator
from support import config, incident, client, tool, say, submit, plan, case, records


class API:
    def __init__(self, settings):
        self.settings = settings
        self.queries = []

    def get_table_schema(self, table):
        assert table == 'Event'
        return {'table': table, 'columns': [
            {'name': 'TimeGenerated'}, {'name': 'Computer'},
            {'name': 'EventID'}, {'name': 'EventData'}]}

    def query_logs(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if 'project TargetUserName' in query:
            raise ValueError("SEM0100 'project' operator: Failed to resolve scalar expression named 'TargetUserName'")
        eid = 4624 if '4624' in query else 4698
        return {'rows': [{'EventID': eid, 'Computer': 'DC',
                          'TimeGenerated': '2026-10-19T15:15:16Z',
                          'EventData': '<Data Name="TargetUserName">Admin</Data>',
                          'parsed_event_data': {'TargetUserName': 'Admin'}}],
                'rows_returned': 1, 'partial': False}


BAD = 'Event | project TargetUserName | take 25'


def test_bad_project_repaired_using_existing_schema(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    fake, calls = client([
        submit('submit_investigation_plan', plan()),
        tool('get_table_schema', {'table': 'Event'}),
        say('DONE'),
        tool('run_kql', {'query': BAD}),
        tool('run_kql', {'query': 'Event | take 10'}),
        submit('submit_evidence_grounded_case', case('ev-0002')),
    ])
    settings = config(tmp_path)
    result, _ = Investigator(settings, API(settings), fake).investigate(incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert {t['function']['name'] for t in calls[4]['tools']} == {'run_kql'}
    assert calls[4]['tool_choice'] == 'required'
    audit = records(tmp_path)
    assert not any(e['kind'] == 'collection_incomplete' for e in audit)
    assert not any(e['kind'] == 'broad_probe' for e in audit)


def test_stuck_schema_calls_use_bounded_probe_then_correlate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    report = case('ev-0002')
    report['findings'].append({
        'source_ref': 'ev-0003', 'row_ids': ['ev-0003#0'],
        'observation': 'Successful logon event also observed on DC.',
        'verified_fields': [{'name': 'EventID', 'value': '4624'}]})
    fake, calls = client([
        submit('submit_investigation_plan', plan()),
        tool('get_table_schema', {'table': 'Event'}),
        say('DONE'),
        tool('run_kql', {'query': BAD}),
        tool('get_table_schema', {'table': 'Event'}),
        tool('get_table_schema', {'table': 'Event'}),
        tool('run_kql', {'query': 'Event | where EventID == 4624 | take 10'}),
        submit('submit_evidence_grounded_case', report),
    ])
    settings = config(tmp_path, correlation_queries=1)
    api = API(settings)
    result, receipts = Investigator(settings, api, fake).investigate(incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert receipts['ev-0002']['broad_probe'] is True
    assert api.queries[1][0] == 'Event | take 25'
    assert api.queries[2][0] == 'Event | where EventID == 4624 | take 10'
    assert any(e['kind'] == 'broad_probe' and e['rows'] == 1 for e in records(tmp_path))
    assert any(e['stage'] == 'CORRELATE' for e in records(tmp_path) if e['kind'] == 'stage')
    assert all(calls[i]['tool_choice'] == 'required' for i in [4, 5])


def test_broad_probe_alone_cannot_confirm_alert(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    fake, _ = client([
        submit('submit_investigation_plan', plan()),
        tool('get_table_schema', {'table': 'Event'}),
        say('DONE'),
        tool('run_kql', {'query': BAD}),
        tool('get_table_schema', {'table': 'Event'}),
        tool('get_table_schema', {'table': 'Event'}),
        submit('submit_evidence_grounded_case', case('ev-0002')),
    ])
    settings = config(tmp_path, correlation_queries=0)
    result, _ = Investigator(settings, API(settings), fake).investigate(incident(), [], {})
    assert result['verdict'] == 'inconclusive'
    assert result['confidence'] <= 0.3
    assert any('unlinked diagnostic' in x for x in result['limitations'])
