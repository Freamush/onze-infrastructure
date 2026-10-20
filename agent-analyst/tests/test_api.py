import hashlib
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

import pytest
from toolkit.azure_client import SentinelAPI
from toolkit.config import Settings
from toolkit.official_docs import DOCS, build_index, availability, search_docs, read_doc
from toolkit.tools import ToolExecutor


def config():
    return Settings(subscription_id='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
                    resource_group='rg', workspace_name='workspace', workspace_id='wid')


class Logs:
    def __init__(self):
        self.calls = []
    def query_workspace(self, wid, query, **kwargs):
        self.calls.append((wid, query, kwargs))
        return SimpleNamespace(status='success', tables=[SimpleNamespace(columns=['n'], rows=[[1]])])


class Credentials:
    def get_token(self, scope):
        return SimpleNamespace(token='test')


def client(logs):
    return SentinelAPI(config(), credential=Credentials(), logs_client=logs)


@pytest.mark.parametrize('q', [
    'Event | where TimeGenerated between (datetime(2026-10-19T15:00:00Z) .. datetime(2026-10-19T16:00:00Z))',
    'Event | where TimeGenerated > datetime(2026-10-19T15:00:00Z)',
    'Event | where TimeGenerated <= ago(1h)',
    'Event | where TimeGenerated in (datetime(2026-10-19T15:00:00Z))',
])
def test_kql_time_filter(q):
    logs = Logs()
    client(logs).query_logs(q, hours=1)
    assert logs.calls[0][2]['timespan'] is None
    assert q in logs.calls[0][1]


def test_absolute_timespan():
    logs = Logs()
    query = 'Event | where TimeGenerated >= datetime(2026-10-19T15:00:00Z)'
    client(logs).query_logs(query, hours=1, start_utc='2026-10-19T14:00:00Z',
                            end_utc='2026-10-19T17:00:00Z')
    assert logs.calls[0][2]['timespan'] == (
        datetime(2026, 10, 19, 14, tzinfo=timezone.utc),
        datetime(2026, 10, 19, 17, tzinfo=timezone.utc))


def test_relative_timespan():
    logs = Logs()
    client(logs).query_logs('Event | summarize n=count()', hours=4)
    assert logs.calls[0][2]['timespan'] == timedelta(hours=4)


def test_kql_error_passthrough():
    class ExplainingAPI:
        settings = SimpleNamespace(query_max_hours=720)
        def __init__(self):
            self.requests = []
        def query_logs(self, query, **kwargs):
            self.requests.append((query, kwargs))
            raise ValueError("'project' operator: Failed to resolve scalar expression named 'TaskName'")
    api = ExplainingAPI()
    worker = ToolExecutor(api)
    malformed = ('Event | where TimeGenerated between '
                 '(datetime(2026-10-19T15:00:00Z) and datetime(2026-10-19T16:00:00Z)) '
                 '| project TaskName')
    output, ref = worker.execute('run_kql', {'query': malformed, 'hours': 1})
    assert ref is None
    assert api.requests[0][0] == malformed
    assert 'TaskName' in output['error']
    assert worker.execute('run_kql', {'query': malformed, 'hours': 1})[1] is None
    assert len(api.requests) == 1


def test_incident_timespan():
    class Endpoint:
        settings = SimpleNamespace(query_max_hours=720)
        def __init__(self):
            self.kwargs = None
        def query_logs(self, query, **kwargs):
            self.kwargs = kwargs
            return {'rows': [], 'partial': False}
    api = Endpoint()
    incident = {'name': '11111111-2222-4333-8444-555555555555',
                'properties': {'firstActivityTimeUtc': '2026-10-19T17:00:00Z'}}
    w = ToolExecutor(api, incident=incident, alerts=[])
    q = 'Event | where TimeGenerated between (datetime(2026-10-19T15:00:00Z) .. datetime(2026-10-19T16:00:00Z))'
    _, ref = w.execute('run_kql', {'query': q})
    assert ref
    assert api.kwargs == {}
    assert w.receipts[ref]['arguments'] == {'query': q}


def make_test_sources(folder):
    source = folder / 'sources'
    expected_text = {}
    for key, (_, _, paths) in DOCS.items():
        root = source / key
        (root / '.git').mkdir(parents=True)
        for path_part in paths:
            (root / path_part).mkdir(parents=True, exist_ok=True)
        directory = root / paths[0]
        for i in range(12):
            text = (f'# Original page {i} for {key}\r\n\r\n'
                    f'Official definition TimeGenerated datetime offset testing {i}.\r\n'
                    f'Kusto reference operator: {"join" if i % 2 else "where"}.\r\n')
            path = directory / f'page-{i}.md'
            path.write_bytes(text.encode())
            expected_text[f'{key}:{path.relative_to(root).as_posix()}'] = text
    return expected_text


def test_document_index(tmp_path):
    originals = make_test_sources(tmp_path)
    counts = build_index(tmp_path)
    assert counts == {key: 12 for key in DOCS}
    assert availability(tmp_path) == counts
    results = search_docs('TimeGenerated datetime', limit=15, folder=tmp_path)
    assert results['results']
    assert len(results['results']) <= 15
    docid = next(iter(originals))
    item = read_doc(docid, max_chars=500, folder=tmp_path)
    assert item['content_verbatim'] == originals[docid]
    assert item['has_more'] is False
    assert item['original_file_sha256'] == hashlib.sha256(originals[docid].encode()).hexdigest()
    assert item['source_url'].startswith('https://github.com/MicrosoftDocs/')
    assert search_docs('TimeGenerated', collection='sentinel', folder=tmp_path)['results']
    assert all(x['collection'] == 'sentinel' for x in search_docs('TimeGenerated', collection='sentinel', folder=tmp_path)['results'])


def test_document_pagination(tmp_path):
    originals = make_test_sources(tmp_path)
    build_index(tmp_path)
    docid = next(iter(originals))
    first = read_doc(docid, offset=0, max_chars=500, folder=tmp_path)
    second = read_doc(docid, offset=20, max_chars=500, folder=tmp_path)
    assert first['content_verbatim'][20:] == second['content_verbatim']
    with pytest.raises(ValueError, match='identifier'):
        read_doc('../escape', folder=tmp_path)
    with pytest.raises(ValueError, match='Query contains no searchable words'):
        search_docs('_', folder=tmp_path)


def test_document_tools(tmp_path, monkeypatch):
    make_test_sources(tmp_path)
    build_index(tmp_path)
    monkeypatch.setenv('SOC_DOCS_DIR', str(tmp_path))
    class API:
        settings = SimpleNamespace(query_max_hours=720)
    executor = ToolExecutor(API())
    res, ref = executor.execute('search_official_docs',
                                {'query': 'TimeGenerated datetime', 'collection': 'kql', 'limit': 5})
    assert ref and res['results']
    chosen = res['results'][0]['id']
    doc, doc_ref = executor.execute('read_official_doc', {'doc_id': chosen, 'max_chars': 500})
    assert doc_ref
    assert 'Official definition' in doc['content_verbatim']
    assert 'original_file_sha256' in doc
    assert all(x['tool'] != 'run_kql' for x in executor.receipts.values())


def test_telemetry_tables():
    for table in ('AzureDiagnostics', 'AppServiceHTTPLogs', 'CommonSecurityLog',
                  'Syslog', 'WindowsEvent', 'AnyCustom_CL'):
        assert ToolExecutor.primary_telemetry_query(table + ' | take 10')
    for table in ('SecurityAlert', 'Heartbeat', 'SentinelHealth'):
        assert not ToolExecutor.primary_telemetry_query(table + ' | take 10')
