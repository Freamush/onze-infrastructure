from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from .evidence import AuditTrail, EvidenceBoard, dump_json
from .config import Settings
from .tools import ToolExecutor
from .investigator import Investigator, CasePlan, PlanJournal


def load_evidence_archive(path, settings):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    records = []
    seen = set()
    with gzip.open(path, 'rt', encoding='utf-8') as inp:
        for line in inp:
            record = json.loads(line)
            if not isinstance(record, dict) or 'receipt' not in record or 'data' not in record:
                raise ValueError('Invalid evidence archive record')
            ref = record['receipt']
            if not isinstance(ref, str) or ref in seen:
                raise ValueError(f'Duplicate or invalid evidence receipt: {ref!r}')
            seen.add(ref)
            canonical = json.dumps(record['data'], sort_keys=True,
                                   ensure_ascii=False, default=str)
            digest = hashlib.sha256(canonical.encode()).hexdigest()
            if digest != record.get('sha256'):
                raise ValueError(f'Original evidence hash mismatch: {ref}')
            if not record.get('full_payload'):
                raise ValueError(f'{ref}: an evidence preview is not sufficient for replay')
            records.append(record)
    indexed = {r['receipt']: r for r in records}
    if not all(k in indexed for k in ('ctx-incident', 'ctx-alerts', 'ctx-entities')):
        raise ValueError('Archive must contain original incident, alerts, entities')
    incident = indexed['ctx-incident']['data']
    alerts = indexed['ctx-alerts']['data']
    entities = indexed['ctx-entities']['data']
    if not isinstance(incident, dict) or 'name' not in incident:
        raise ValueError('Original incident record absent')
    api_stub = SimpleNamespace(settings=settings)
    executor = ToolExecutor(api_stub, incident=incident, alerts=alerts)
    executor.seed_context(incident, alerts, entities)
    for item in records:
        ref = item['receipt']
        if ref.startswith('ctx-'):
            if dump_json(executor.results.get(ref)) != dump_json(item['data']):
                raise ValueError(f'Initial context is inconsistent: {ref}')
            continue
        rows = item['data'].get('rows', []) if isinstance(item['data'], dict) else []
        if isinstance(item['data'], list):
            rows = item['data']
        if not isinstance(rows, list):
            rows = []
        executor.receipts[ref] = {
            'tool': item['tool'], 'arguments': item.get('arguments') or {},
            'sha256': item['sha256'], 'rows': len(rows),
            'partial': bool(item['data'].get('partial')) if isinstance(item['data'], dict) else False,
            'origin': 'offline_evidence_replay'}
        executor.results[ref] = item['data']
        if item['tool'] == 'run_kql':
            executor.successful_log_queries += 1
    return incident, alerts, entities, executor


def analyze_archive(path, settings, client=None):
    incident, alerts, entities, executor = load_evidence_archive(path, settings)
    audit = AuditTrail(settings.audit_dir, incident['name'])
    audit.append({'kind':'replay_start', 'source_archive': str(path),
                  'original_receipts': len(executor.receipts),
                  'cloud_access': False, 'writes_to_sentinel': False})
    journal = PlanJournal(audit.path)
    plan = CasePlan(phase='ANALYZE')
    journal.save(plan)
    board = EvidenceBoard({'incident':incident, 'alerts': alerts, 'entities':entities}, executor)
    model = Investigator(settings, api=SimpleNamespace(settings=settings), client=client)
    result = model._analyze(board, plan, audit, incident)
    result['incident_id']=incident['name']
    result['offline_replay']=True
    audit.append({'kind':'replay_complete', 'verdict': result['verdict'],
                  'retryable_failure': bool(result.get('retryable_failure'))})
    return result


def main():
    from dotenv import load_dotenv
    load_dotenv()
    parser=argparse.ArgumentParser(description='Analyze archived incident evidence using a local model')
    parser.add_argument('--archive', required=True, type=Path, help='Path to a complete .jsonl.gz evidence archive')
    opts=parser.parse_args()
    result=analyze_archive(opts.archive, Settings.from_env())
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

if __name__ == '__main__':
    main()
