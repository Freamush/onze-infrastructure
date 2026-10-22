"""Regression tests for historical incidents and empty first queries."""
from types import SimpleNamespace

from toolkit.tools import ToolExecutor
from toolkit.investigator import Investigator
from support import config, incident, client, tool, say, submit, plan, case, records


class LogSource:
    def __init__(self):
        self.settings = SimpleNamespace(query_max_hours=720)
        self.calls = []

    def query_logs(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return {'rows': [{'EventID': 4720, 'Computer': 'DC.onze.internal',
                          'TimeGenerated': '2026-10-20T21:42:21Z'}],
                'partial': False, 'rows_returned': 1}


def old_incident():
    return {'name': incident()['name'],
            'properties': {'title': 'AD Account Lifecycle Changes',
                           'firstActivityTimeUtc': '2026-10-20T21:42:21Z'}}


def test_relative_hours_do_not_hide_historical_incident():
    api = LogSource()
    ex = ToolExecutor(api, incident=old_incident(), alerts=[])
    query = ('Event | where TimeGenerated between '
             '(datetime(2026-10-20T19:42:21Z) .. datetime(2026-10-20T23:42:21Z)) '
             '| where EventID == 4720 | take 50')
    _, ref = ex.execute('run_kql', {'query': query, 'hours': 4, 'max_rows': 50})
    assert ref
    assert api.calls[0][1] == {
        'start_utc': '2026-10-20T19:42:21Z',
        'end_utc': '2026-10-20T23:42:21Z',
        'max_rows': 50
    }
    assert 'hours' not in ex.receipts[ref]['arguments']


def test_explicit_utc_range_is_respected():
    api = LogSource()
    ex = ToolExecutor(api, incident=old_incident(), alerts=[])
    args = {'query': 'Event | take 5', 'start_utc': '2026-10-19T18:00:00Z',
            'end_utc': '2026-10-19T20:00:00Z'}
    ex.execute('run_kql', args)
    assert api.calls[0][1] == {key: args[key] for key in ('start_utc', 'end_utc')}


def test_no_anchor_keeps_relative_hours():
    api = LogSource()
    ex = ToolExecutor(api)
    ex.execute('run_kql', {'query': 'Event | take 5', 'hours': 4})
    assert api.calls[0][1] == {'hours': 4}


class EmptyFirst(LogSource):
    def query_logs(self, query, **kwargs):
        self.calls.append((query, kwargs))
        rows = [] if 'EventID == 4720' in query else [
            {'EventID': 4720, 'Computer': 'DC.onze.internal',
             'TimeGenerated': '2026-10-20T21:42:21Z'}]
        return {'rows': rows, 'partial': False, 'rows_returned': len(rows)}


def test_broaden_after_empty_query(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    report = case('ev-0002')
    report['findings'][0]['verified_fields'][0]['value'] = '4720'
    fake, calls = client([
        submit('submit_investigation_plan', plan()),
        say(None),
        tool('run_kql', {'query': 'Event | where EventID == 4720 | take 5'}),
        tool('run_kql', {'query': 'Event | take 5'}),
        submit('submit_evidence_grounded_case', report),
    ])
    settings = config(tmp_path, correlation_queries=0)
    api = EmptyFirst()
    result, receipts = Investigator(settings, api, fake).investigate(old_incident(), [], {})
    assert result['verdict'] == 'suspicious'
    assert receipts['ev-0001']['rows'] == 0
    assert receipts['ev-0002']['rows'] == 1
    assert len(api.calls) == 2
    assert {t['function']['name'] for t in calls[3]['tools']} == {'run_kql'}
    assert calls[3]['tool_choice'] == 'required'


def test_three_empty_queries_stop_with_inconclusive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    fake, calls = client([
        submit('submit_investigation_plan', plan()),
        say(None),
        tool('run_kql', {'query': 'Event | where EventID == 4720 | take 5'}),
        tool('run_kql', {'query': 'Event | where EventID == 4722 | take 5'}),
        tool('run_kql', {'query': 'Event | where EventID == 4726 | take 5'}),
        submit('submit_evidence_grounded_case', {
            'verdict': 'inconclusive', 'confidence': 0.0,
            'summary': 'No events found in the checked sources.',
            'findings': [], 'limitations': ['Limited query scope'],
            'recommended_actions': ['Check source configuration'], 'needs_human': True,
        }),
    ])
    settings = config(tmp_path, correlation_queries=0)

    class AllEmpty(LogSource):
        def query_logs(self, query, **kwargs):
            self.calls.append((query, kwargs))
            return {'rows': [], 'partial': False, 'rows_returned': 0}

    api = AllEmpty()
    result, _ = Investigator(settings, api, fake).investigate(old_incident(), [], {})
    assert result['verdict'] == 'inconclusive'
    assert len(api.calls) == 3
    assert any(e.get('kind') == 'collection_empty' for e in records(tmp_path))
    assert any('no rows' in note for note in result['limitations'])
