"""Regression tests for crashes and for correlation that was silently discarded."""
import types

from toolkit.evidence import EvidenceBoard, digest_rows
from toolkit.investigator import Investigator
from toolkit.tools import ToolExecutor
from support import API, config, incident, client, tool, say, submit, plan, case, records


class AggregateAPI(API):
    def query_logs(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if 'summarize' in query:
            return {'rows': [{'IpAddress': '10.10.10.22', 'Attempts': 37}],
                    'rows_returned': 1, 'partial': False}
        return {'rows': [{'Computer': 'DC', 'EventID': 4625, 'TimeGenerated': '2026-10-19T15:15:16Z',
                          'parsed_event_data': {'IpAddress': '10.10.10.22'}}],
                'rows_returned': 1, 'partial': False}


def test_summarize_followup_counts_as_correlation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('toolkit.investigator.docs_availability', lambda: {})
    report = case('ev-0001')
    report['findings'][0]['verified_fields'] = [{'name': 'EventID', 'value': '4625'}]
    fake, calls = client([
        submit('submit_investigation_plan', plan()), say(None),
        tool('run_kql', {'query': 'Event | where EventID == 4625 | take 10'}),
        tool('run_kql', {'query': 'Event | where EventID == 4625 | summarize n=count() by IpAddress'}),
        tool('run_kql', {'query': 'Event | where EventID == 4625 | summarize n=count() by Computer'}),
        submit('submit_evidence_grounded_case', report)])
    settings = config(tmp_path, correlation_queries=2)
    result, _ = Investigator(settings, AggregateAPI(settings), fake).investigate(incident(), [], {})
    assert result['correlation']['completed'] is True
    assert result['correlation']['aggregate_receipts'] == ['ev-0002', 'ev-0003']
    assert result['verdict'] == 'suspicious'          # not forced down to inconclusive
    assert any(e['kind'] == 'correlation_done' for e in records(tmp_path))
    # the model is told the truth, and gets real pivot values from the origin rows
    state = calls[4]['messages'][-1]['content']
    assert 'was not executed' not in state and 'pivot_values_from_origin_rows' in state
    assert '10.10.10.22' in state


def test_kql_args_are_normalised_not_rejected(tmp_path):
    seen = []
    class Src:
        settings = types.SimpleNamespace(query_max_hours=720, query_max_rows=150)
        def query_logs(self, query, **kw):
            seen.append(kw); return {'rows': [], 'rows_returned': 0, 'partial': False}
    ex = ToolExecutor(Src())
    ex.execute('run_kql', {'query': 'Event | take 5', 'max_rows': 900, 'hours': 8000})
    assert seen[-1] == {'max_rows': 150, 'hours': 720}
    ex.execute('run_kql', {'query': 'Event | take 6', 'start_utc': '2026-10-20T10:00:00Z'})
    assert set(seen[-1]) == {'start_utc', 'end_utc'}
    ex.execute('run_kql', {'query': 'Event | take 7', 'start_utc': '2026-10-20T10:00:00Z',
                           'end_utc': '2999-01-01T00:00:00Z'})
    assert seen[-1]['end_utc'] < '2999'


def test_known_query_table_follows_schema_receipts(tmp_path):
    ex = ToolExecutor(API(config(tmp_path)))
    board = EvidenceBoard({}, ex)
    assert board.known_query_table() is False
    ex.receipts['ev-0001'] = {'tool': 'get_table_schema', 'arguments': {'table': 'Event'},
                              'rows': 1, 'partial': False}
    board.actions.append({'tool': 'run_kql', 'arguments': {'query': 'Event | project X'}, 'error': 'SEM0100'})
    assert board.known_query_table() is True
    board.actions.append({'tool': 'run_kql', 'arguments': {'query': 'Syslog | take 1'}, 'error': 'x'})
    assert board.known_query_table() is False


def test_large_result_is_digested_not_cut_mid_row():
    rows = [{'TimeGenerated': f'2026-10-19T15:{i % 60:02d}:00Z', 'EventID': 4625,
             'EventData': 'x' * 3000, 'parsed_event_data': {'TargetUserName': f'user{i % 3}'}}
            for i in range(150)]
    digest = digest_rows({'rows': rows, 'rows_returned': 150})
    assert digest['row_count_in_result'] == 150
    assert digest['value_frequencies']['TargetUserName'][0][1] == 50
    assert 'EventData' not in digest['sample_rows'][0]
