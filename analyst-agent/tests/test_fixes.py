"""Regression tests for the small safety and reliability changes."""
from datetime import timedelta
from types import SimpleNamespace

from toolkit.config import Settings
from toolkit.event_enrichment import extract_windows_eventdata
from toolkit.service import IncidentService, Store
from toolkit.tools import ToolExecutor
from toolkit.azure_client import SentinelAPI


def settings():
    return Settings(subscription_id='sub', resource_group='rg', workspace_name='ws', workspace_id='id')


def incident(modified='2026-10-21T12:00:00Z'):
    return {'name': '11111111-2222-4333-8444-555555555555',
            'properties': {'status': 'New', 'title': 'Test', 'severity': 'Medium',
                           'lastModifiedTimeUtc': modified}}


class API:
    def __init__(self):
        self.alert_calls = 0
    def get_incident_alerts(self, iid):
        self.alert_calls += 1
        return []
    def get_incident_entities(self, iid):
        return {'entities': []}


class Model:
    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = 0
    def investigate(self, *args):
        self.calls += 1
        return {'verdict': self.verdict, 'confidence': 0.95,
                'summary': 'Test case', 'findings': [], 'limitations': [],
                'recommended_actions': [], 'needs_human': True}, {}


def test_benign_not_escalated(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    api, model = API(), Model('benign')
    service = IncidentService(settings(), api, model, Store(str(tmp_path/'state.db')))
    result = service.process(incident())
    assert result['needs_human'] is True
    assert result['escalate'] is False
    assert result['delivery_status'] == 'not_required'
    assert service.process(incident())['skipped'] == 'unchanged'
    assert api.alert_calls == 1
    assert model.calls == 1
    # An updated Sentinel incident is checked again; an unchanged alert fingerprint isn't reinvestigated.
    assert service.process(incident('2026-10-21T13:00:00Z'))['skipped'] == 'already_processed'
    assert api.alert_calls == 2


def test_suspicious_still_escalates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    service = IncidentService(settings(), API(), Model('suspicious'), Store(str(tmp_path/'state.db')))
    result = service.process(incident())
    assert result['escalate'] is True
    assert result['delivery_status'] == 'pending_configuration'
    # Pending escalation is not discarded as already delivered.
    assert service.process(incident())['skipped'] == 'already_processed'


def test_generic_windows_event_data():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <EventData><Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">10.10.10.22</Data>
      <Data Name="LogonType">3</Data><Data Name="FailureReason">%%2313</Data></EventData></Event>'''
    data = extract_windows_eventdata(xml)
    assert data == {'TargetUserName': 'Administrator', 'IpAddress': '10.10.10.22',
                    'LogonType': '3', 'FailureReason': '%%2313'}
    assert extract_windows_eventdata('<EventData><Data Name="a">hi</Data></EventData>') == {'a': 'hi'}
    assert extract_windows_eventdata('nonsense') == {}


def test_stats_are_not_raw_telemetry():
    for query in ('Event | summarize Count=count()',
                  'SecurityEvent | summarize count() by Computer',
                  'Event | count',
                  'Syslog | distinct Computer'):
        assert not ToolExecutor.primary_telemetry_query(query), query
    for query in ('Event | take 5',
                  'SecurityEvent | where EventID == 4625 | project TimeGenerated, Computer, EventID'):
        assert ToolExecutor.primary_telemetry_query(query), query


def test_api_timespan_always_bounded():
    class Logs:
        def __init__(self):
            self.kwargs = None
        def query_workspace(self, *args, **kwargs):
            self.kwargs = kwargs
            return SimpleNamespace(status='success', tables=[])
    class Credential:
        def get_token(self, scope):
            return SimpleNamespace(token='dummy')
    logs = Logs()
    api = SentinelAPI(settings(), credential=Credential(), logs_client=logs)
    api.query_logs('Event | where TimeGenerated > datetime(2020-01-01)')
    assert logs.kwargs['timespan'] == timedelta(hours=24)


def test_server_side_incident_filter():
    class Credential:
        def get_token(self, scope):
            return SimpleNamespace(token='dummy')
    api = SentinelAPI(settings(), credential=Credential(), logs_client=object())
    called = {}
    def fake_page(relative, **kwargs):
        called.update(kwargs)
        return {'items': [], 'truncated': False}
    api._page = fake_page
    api.list_incidents(status='New', severity='High')
    assert called['params']['$filter'] == "properties/status eq 'New' and properties/severity eq 'High'"
    assert called['params']['$orderby'] == 'properties/lastModifiedTimeUtc desc'


def test_nested_windows_fields_can_be_verified(tmp_path):
    import json
    from toolkit.investigator import validate_case

    class LogsAPI:
        settings = settings()
        def query_logs(self, *args, **kwargs):
            return {'rows': [{'EventID': 4625, 'Computer': 'DC',
                              'parsed_event_data': {'TargetUserName': 'Administrator',
                                                    'IpAddress': '10.10.10.22'}}],
                    'partial': False}

    worker = ToolExecutor(LogsAPI())
    _, ref = worker.execute('run_kql', {'query': 'Event | where EventID == 4625 | take 10'})
    finding = {'source_ref': ref, 'observation': 'A failed logon was recorded.',
               'row_indices': [0], 'verified_fields': [
                   {'name': 'EventID', 'value': '4625'},
                   {'name': 'IpAddress', 'value': '10.10.10.22'},
                   {'name': 'TargetUserName', 'value': 'Administrator'}]}
    report = {'verdict': 'suspicious', 'confidence': 0.4, 'summary': 'One failed logon',
              'findings': [finding], 'limitations': ['One event is not brute force'],
              'recommended_actions': [], 'needs_human': True}
    assert validate_case(json.dumps(report), worker)['validation']['field_checks_passed'] == 3
    finding['verified_fields'][1]['value'] = '9.9.9.9'
    import pytest
    with pytest.raises(ValueError, match='co-occur'):
        validate_case(json.dumps(report), worker)
