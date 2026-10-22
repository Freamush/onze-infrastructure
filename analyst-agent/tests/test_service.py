import hashlib
import sqlite3
from datetime import datetime, timezone, timedelta

import pytest
from toolkit.config import Settings
from toolkit.official_docs import read_doc, source_reference_excerpts
from toolkit.service import IncidentService, Store, fingerprint
from toolkit.tools import ToolExecutor

INCIDENT_ID = '11111111-2222-4333-8444-555555555555'
DOC_ID = 'kql:data-explorer/kusto/query/between-operator.md'

def conf(tmp, **opts):
    base = dict(subscription_id='s', resource_group='g', workspace_name='w', workspace_id='id',
                audit_dir=str(tmp/'audit'), max_inconclusive_rechecks=2,
                inconclusive_recheck_seconds=300, max_cases_per_poll=2)
    base.update(opts)
    return Settings(**base)


def inc(i=INCIDENT_ID, severity='Medium'):
    return {'name': i, 'properties': {'title': 'Test', 'status': 'New', 'severity': severity,
                                     'createdTimeUtc': '2026-10-19T00:00:00Z',
                                     'firstActivityTimeUtc': '2026-10-19T15:15:57Z'}}


class API:
    def __init__(self, settings):
        self.settings = settings
        self.queries = []
        self.mode = 'good'
        self.sent = []
        self.batch = []
    def query_logs(self, **kwargs):
        self.queries.append(kwargs)
        if self.mode == 'timeout':
            raise TimeoutError('Azure temporary outage')
        if self.mode == 'partial':
            return {'partial': True, 'rows': [{'EventID': 4698}], 'error': 'partial'}
        return {'rows': [{'EventID': 4698, 'Computer': 'win-workstation'}],
                'partial': False, 'rows_returned': 1}
    def get_incident_alerts(self, iid): return []
    def get_incident_entities(self, iid): return {'entities': []}
    def list_incidents(self, **kwargs): return {'items': self.batch, 'truncated': False}
    def add_incident_comment(self, *a): self.sent.append(a)


def fake_docs(tmp):
    folder = tmp / 'knowledge'
    folder.mkdir()
    db = sqlite3.connect(folder/'official_docs.sqlite3')
    db.execute('CREATE TABLE docs(id TEXT PRIMARY KEY, collection TEXT, title TEXT, body TEXT, sha256 TEXT, source_url TEXT)')
    db.execute('CREATE VIRTUAL TABLE docs_fts USING fts5(id UNINDEXED,title,body)')
    body = '# example\n' + 'noise filler\n'*220 + '## Syntax\nT | where x between (1 .. 10)\n## Examples\n'
    db.execute('INSERT INTO docs VALUES (?,?,?,?,?,?)',
               (DOC_ID, 'kql', 'between operator', body, hashlib.sha256(body.encode()).hexdigest(),
                'https://github.com/MicrosoftDocs/dataexplorer-docs/blob/REV/query/between-operator.md'))
    db.execute('INSERT INTO docs_fts VALUES (?,?,?)', (DOC_ID, 'between operator', body))
    db.commit(); db.close()
    return folder,body


def result():
    return {'verdict': 'inconclusive', 'confidence': 0.3,
            'summary': 'Not enough evidence', 'findings': [], 'limitations': ['no link'],
            'recommended_actions': ['review'], 'needs_human': True}


class Investigate:
    def __init__(self): self.called=[]
    def investigate(self, incident, *args):
        self.called.append(incident['name'])
        return result(), {}


def age_rows(store):
    store.connection.execute('UPDATE cases SET created_utc=?',
        ((datetime.now(timezone.utc)-timedelta(hours=2)).isoformat(),))
    store.connection.commit()


def test_focused_document(tmp_path):
    folder,body = fake_docs(tmp_path)
    text = read_doc(DOC_ID, max_chars=600, focus='## Syntax', folder=folder)
    assert text['offset'] > 0
    assert text['content_verbatim'] == body[text['offset']:text['next_offset']]
    assert '## Syntax' in text['content_verbatim']
    excerpts = source_reference_excerpts(['between'], folder=folder, chars_per_doc=500)
    e = excerpts[0]
    assert '## Syntax' in e['content_verbatim']
    assert e['content_verbatim'] == body[e['excerpt_offset']:e['excerpt_offset']+len(e['content_verbatim'])]


def test_kql_cache(tmp_path):
    api = API(conf(tmp_path))
    tool = ToolExecutor(api, incident=inc(), alerts=[])
    a,r1 = tool.execute('run_kql', {'query': 'Event | take 1', 'docs_used': ['kql:a']})
    b,r2 = tool.execute('run_kql', {'query': 'Event | take 1', 'docs_used': ['kql:b']})
    assert r1 == r2 and tool.last_cached and len(api.queries) == 1


def test_api_error_retry(tmp_path):
    api = API(conf(tmp_path)); api.mode='timeout'
    tool = ToolExecutor(api, incident=inc(), alerts=[])
    x,r = tool.execute('run_kql', {'query': 'Event | take 1'})
    assert r is None and x['retryable'] and len(tool.retryable_tool_failures) == 1
    api.mode = 'good'
    y,r = tool.execute('run_kql', {'query': 'Event | take 1'})
    assert r == 'ev-0001' and len(api.queries) == 2 and tool.successful_log_queries == 1


def test_partial_results(tmp_path):
    api = API(conf(tmp_path)); api.mode='partial'
    tool = ToolExecutor(api, incident=inc(), alerts=[])
    x,r = tool.execute('run_kql', {'query': 'Event | take 1'})
    assert r is None and x['retryable'] is True
    assert tool.primary_telemetry_coverage()['query_count'] == 0


def test_recheck_limit(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    store=Store(str(tmp_path/'state.db'))
    api=API(conf(tmp_path)); model=Investigate()
    service=IncidentService(api.settings,api,model,store)
    service.process(inc())
    for _ in range(2):
        age_rows(store)
        service.process(inc())
    age_rows(store)
    x=service.process(inc())
    assert x['skipped']=='already_processed'
    assert len(model.called)==3
    assert x['rechecks_done']==2


def test_delivery_pending(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings=conf(tmp_path)
    store=Store(str(tmp_path/'state.db'))
    api=API(settings)
    service=IncidentService(settings,api,Investigate(),store)
    result=service.process(inc())
    assert result['delivery_status']=='pending_configuration'
    sig=fingerprint(inc(),[])
    assert store.find(sig)['notified']==0 and store.delivery_status(sig)=='pending_configuration'


def test_delivery_priority(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings=conf(tmp_path)
    store=Store(str(tmp_path/'state.db'))
    api=API(settings); model=Investigate()
    service=IncidentService(settings,api,model,store)
    service.process(inc()); age_rows(store)
  
    service.settings=conf(tmp_path,escalation_webhook='https://example.invalid/hook')
    class Response:
        def raise_for_status(self): pass
    sent=[]
    def post(*args,**kwargs): sent.append(kwargs); return Response()
    monkeypatch.setattr('toolkit.service.requests.post',post)
    x=service.process(inc())
    assert x['skipped']=='delivery_retried'
    assert x['delivery_status']=='delivered'
    assert len(model.called)==1 and len(sent)==1


def test_incident_priority(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings=conf(tmp_path,max_cases_per_poll=2)
    api=API(settings); api.batch=[inc('low','Low'),inc('med','Medium'),inc('high','High')]
    model=Investigate()
    service=IncidentService(settings,api,model,Store(str(tmp_path/'state.db')))
    assert service.poll_once()==2
    assert model.called==['high','med']


def test_truncated_incidents(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    api=API(conf(tmp_path))
    api.list_incidents=lambda **kw: {'items':[], 'truncated':True}
    service=IncidentService(api.settings,api,Investigate(),Store(str(tmp_path/'state.db')))
    with pytest.raises(RuntimeError,match='truncated'):
        service.poll_once()
