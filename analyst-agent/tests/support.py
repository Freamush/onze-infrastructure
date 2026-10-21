import json
from types import SimpleNamespace
from toolkit.config import Settings

INCIDENT_ID = '11111111-2222-4333-8444-555555555555'

def config(tmp_path, **opts):
    values = dict(subscription_id='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
                  resource_group='r', workspace_name='w', workspace_id='wid',
                  audit_dir=str(tmp_path / 'audit'), max_rounds=10,
                  max_investigation_seconds=900, correlation_queries=0)
    values.update(opts)
    return Settings(**values)


class API:
    def __init__(self, settings):
        self.settings = settings
        self.queries = []

    def query_logs(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if 'between (' in query and ' and datetime' in query:
            raise ValueError("SYN0002 Query could not be parsed at ')' on line [4,97]")
        return {'rows': [{'Computer': 'win-workstation', 'EventID': 4698,
                         'TimeGenerated': '2026-10-19T15:15:16Z',
                         'EventData': '<Data Name="TaskName">TaskOne</Data>'}],
                'rows_returned': 1, 'partial': False}


def tool(name, args, call_id='x'):
    return SimpleNamespace(tool_calls=[SimpleNamespace(id=call_id, function=SimpleNamespace(
        name=name, arguments=json.dumps(args)))], content=None)


def say(report=None):
    return SimpleNamespace(tool_calls=None, content=json.dumps(report) if isinstance(report, dict) else report)


def client(responses):
    responses = iter(responses)
    calls = []
    def call(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=next(responses))])
    obj = SimpleNamespace(models=SimpleNamespace(list=lambda: SimpleNamespace(
        data=[SimpleNamespace(id='test-model')])), chat=SimpleNamespace(
        completions=SimpleNamespace(create=call)))
    return obj, calls


def incident():
    return {'name': INCIDENT_ID, 'properties': {'title': 'New or Updated Windows Scheduled Task',
             'severity': 'Medium', 'firstActivityTimeUtc': '2026-10-19T15:15:57Z'}}


def submit(name, data):
    return SimpleNamespace(content=None, tool_calls=[SimpleNamespace(
        id='structured', function=SimpleNamespace(name=name, arguments=json.dumps(data)))])


def plan():
    return {'hypothesis': 'Did an alert correspond to Windows event records?',
            'questions': ['Which raw records correlate by time and account?',
                          'Do we have enough evidence to infer intent?'],
            'useful_sources': ['Event', 'SecurityEvent']}


def case(ref='ev-0001', verdict='suspicious'):
    return {'verdict': verdict, 'confidence': 0.55,
            'summary': 'An event was returned; causal linkage to alert is unverified.',
            'findings': [{'source_ref': ref, 'observation': 'EventID 4698 exists in returned row.',
                          'row_indices': [0], 'verified_fields': [{'name':'EventID','value':'4698'}]}],
            'limitations': ['Exact originating rule match was not established'],
            'recommended_actions': ['Human correlate underlying event and rule'],
            'needs_human': True}


def records(tmp_path):
    files = list((tmp_path/'audit').glob('*.jsonl'))
    assert len(files) == 1
    return [json.loads(line) for line in files[0].read_text().splitlines()]

