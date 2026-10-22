from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import gzip
import hashlib
import json
import logging
import re
import uuid
from collections import Counter

from .official_docs import (
    source_reference_excerpts,
    kql_reference_topics,
)

LOG = logging.getLogger(__name__)

def dump_json(value):
    return json.dumps(value, ensure_ascii=False, default=str)


def preview(value, limit):

    text = dump_json(value)
    if len(text) <= limit:
        return value
    return {"preview_only": True, "original_chars": len(text),
            "preview_json_prefix": text[:limit], "warning": "Result preview; full data is in the evidence archive."}


def digest_rows(data, sample=5, cell=160, top=6):
    """Readable summary of a large KQL result: counts, time span, value frequencies, clean samples.

    Replaces a JSON string cut in the middle of a row, which a small model cannot use.
    Returns None when `data` is not a list of row dicts.
    """
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows or not all(isinstance(r, dict) for r in rows[:50]):
        return None

    def flat(row):
        parsed = row.get("parsed_event_data") if isinstance(row.get("parsed_event_data"), dict) else {}
        out = {k: v for k, v in row.items()
               if k != "parsed_event_data" and not (k == "EventData" and parsed)}
        for k, v in parsed.items():
            out.setdefault(k, v)
        return out

    flat_rows = [flat(r) for r in rows if isinstance(r, dict)]
    counters = {}
    for row in flat_rows:
        for key, value in row.items():
            if isinstance(value, (dict, list)) or value in (None, ""):
                continue
            counters.setdefault(key, Counter())[str(value)[:80]] += 1
    frequencies = {k: [[v, n] for v, n in c.most_common(top)] for k, c in counters.items()
                   if 1 < len(c) <= 40 and k not in ("TimeGenerated", "EventData")}
    times = [str(r["TimeGenerated"]) for r in flat_rows if r.get("TimeGenerated")]
    digest = {"digest_of_full_result": True,
              "row_count_in_result": len(rows),
              "rows_returned": data.get("rows_returned"), "truncated": data.get("truncated"),
              "value_frequencies": dict(list(frequencies.items())[:10]),
              "sample_rows": [{k: (v[:cell] if isinstance(v, str) else v) for k, v in list(r.items())[:14]}
                              for r in flat_rows[:sample]],
              "note": "Digest of the full result; every row remains in the evidence archive."}
    if times:
        digest["time_range_utc"] = {"first": min(times), "last": max(times)}
    return digest


def parse_verdict(text, valid_receipts, successful_kql):
    if not isinstance(text, str):
        raise ValueError("Missing final JSON")
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I)
    report = json.loads(raw)
    if not isinstance(report, dict):
        raise ValueError("Final report is not an object")
    if report.get("verdict") not in {"malicious", "suspicious", "benign", "inconclusive"}:
        raise ValueError("Invalid verdict")
    conf = report.get("confidence")
    if type(conf) not in (float, int) or not 0 <= conf <= 1:
        raise ValueError("confidence must be 0..1")
    if not isinstance(report.get("summary"), str) or len(report["summary"]) > 6000:
        raise ValueError("Invalid summary")
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > 15:
        raise ValueError("Invalid findings")
    cited = set()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("observation"), str):
            raise ValueError("Invalid finding")
        ref = finding.get("source_ref")
        if ref not in valid_receipts:
            raise ValueError(f"Unknown evidence receipt: {ref!r}")
        indices = finding.get("row_indices")
        if indices is not None and (
            not isinstance(indices, list) or not 1 <= len(indices) <= 8 or
            not all(type(i) is int and 0 <= i <= 999 for i in indices) or
            len(set(indices)) != len(indices)):
            raise ValueError(f"Invalid row_indices for {ref}")
        cited.add(ref)
    if report["verdict"] != "inconclusive" and not findings:
        raise ValueError("Non-inconclusive report needs findings")
    if report["verdict"] == "benign" and not (successful_kql & cited):
        raise ValueError("Benign requires at least one cited nonempty raw-event receipt")
    for key in ("limitations", "recommended_actions"):
        if not isinstance(report.get(key), list) or not all(isinstance(x, str) for x in report[key]):
            raise ValueError("Invalid " + key)
    if type(report.get("needs_human")) is not bool:
        raise ValueError("needs_human must be boolean")
    return {key: report[key] for key in (
        "verdict", "confidence", "summary", "findings", "limitations",
        "recommended_actions", "needs_human")}


def inconclusive(reason):
    return {"verdict": "inconclusive", "confidence": 0.0,
            "summary": str(reason)[:500], "findings": [],
            "limitations": ["Automated evidence verification did not complete reliably."],
            "recommended_actions": ["Have a human analyst review the original incident and raw events."],
            "needs_human": True}


class AuditTrail:
    def __init__(self, folder, incident_id):
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / f"{incident_id}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}.jsonl"

    def append(self, event):
        record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(dump_json(record) + "\n")


class EvidenceArchive:

    def __init__(self, audit_file):
        path = Path(audit_file)
        folder = path.parent / "evidence"
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / (path.stem + ".jsonl.gz")

        try:
            folder.chmod(0o700)
        except OSError:
            pass

    def append(self, receipt, metadata, data):
        canonical = json.dumps(data, ensure_ascii=False, default=str, sort_keys=True)
        sha = hashlib.sha256(canonical.encode()).hexdigest()

        record = {"receipt": receipt, "tool": metadata.get("tool"),
                  "arguments": metadata.get("arguments"), "sha256": sha,
                  "full_payload": True, "data": data}
        with gzip.open(self.path, "at", encoding="utf-8") as f:
            f.write(dump_json(record) + "\n")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


class EvidenceBoard:


    def __init__(self, context, executor):
        self.context = context
        self.executor = executor
        self.actions = []
        self.failures = []
        self.last_results = []
        self.docs_read = False
        self.source_excerpts = []
        self.consulted_doc_ids = set()
        self.model_declared_doc_ids = set()
        self.kql_errors = 0
        self.docs_required = False
        self.docs_assists = 0
        self.recovery_candidates = []
        self.recovery_searches = 0
        self.recovery_query_pending = False
        self.failed_kql = None
        self.failed_kql_signatures = set()
        self.no_progress = 0
        self.seen_inspection_payloads = set()

    @staticmethod
    def query_signature(query):


        return str(query or "").strip()

    @staticmethod
    def _query_tables(query):
        """Table names a KQL query reads from (best effort, ignores let-variables)."""
        clean = re.sub(r"/\*.*?\*/|//[^\n]*", " ", str(query or ""), flags=re.S)
        clean = re.sub(r"'(?:''|[^'])*'|\"(?:\\.|[^\"])*\"", "''", clean)
        local = {n.lower() for n in re.findall(r"\blet\s+([A-Za-z][A-Za-z0-9_]*)\s*=", clean, re.I)}
        names = re.findall(r"(?:^|[;(=])\s*([A-Za-z][A-Za-z0-9_]*)\s*\|", clean, re.M)
        for union in re.findall(r"\bunion\s+([^|;]+)", clean, re.I):
            names += [p.strip() for p in union.split(",") if re.fullmatch(r"\s*[A-Za-z][A-Za-z0-9_]*\s*", p)]
        return list(dict.fromkeys(n for n in names if n.lower() not in local and n.lower() != "let"))

    def known_query_table(self):
        """True when a schema receipt already exists for every table of the last failed/recent KQL.

        The orchestrator uses it to decide whether another get_table_schema call could
        still help the model, or whether it should go straight back to writing KQL.
        """
        known = {str(m.get("arguments", {}).get("table", "")).lower()
                 for m in self.executor.receipts.values() if m.get("tool") == "get_table_schema"}
        if not known:
            return False
        query = (self.failed_kql or {}).get("query")
        if not query:
            for action in reversed(self.actions):
                if action.get("tool") == "run_kql":
                    arguments = action.get("arguments")
                    query = arguments.get("query") if isinstance(arguments, dict) else None
                    break
        tables = self._query_tables(query)
        return bool(tables) and all(t.lower() in known for t in tables)

    def add(self, name, args, data, ref, *, cached=False):
        descriptor = {"tool": name, "arguments": preview(args, 1000),
                      "receipt": ref, "cached": cached,
                      "error": data.get("error") if isinstance(data, dict) else None}
        self.actions.append(descriptor)
        self.actions = self.actions[-50:]
        if name == "run_kql":
            self.recovery_query_pending = False
        if descriptor["error"]:
            self.failures.append(descriptor)
            self.failures = self.failures[-12:]
            if self.docs_required and name in {"search_official_docs", "read_official_doc"}:
                self.recovery_searches += 1
                if name == "read_official_doc":
                    rejected = args.get("doc_id")
                    self.recovery_candidates = [doc for doc in self.recovery_candidates
                                                if doc != rejected]
                if self.recovery_searches >= 2 and not self.recovery_candidates:
                    self.docs_required = False
                    self.recovery_query_pending = True
            if name == "run_kql":
                self.kql_errors += 1
                syntax_failure = re.search(
                    r"\b(?:SYN\d{4}|SEM\d{4}|SyntaxError|SemanticError)\b|"
                    r"Failed to resolve|could not be parsed|syntax error",
                    str(descriptor["error"]), flags=re.I)
                if syntax_failure:
                    query = str(args.get("query", ""))
                    signature = self.query_signature(query)
                    self.failed_kql_signatures.add(signature)
                    self.failed_kql = {"query": query[:12000],
                                       "error": str(descriptor["error"])[:1800],
                                       "signature": signature,
                                       "next_step": "read_original_documentation_then_new_kql"}

                    self.docs_required = True
                    self.recovery_candidates = []
                    self.recovery_searches = 0
        elif name == "search_official_docs":
            matches = data.get("results", []) if isinstance(data, dict) else []
            ids = [item["id"] for item in matches if isinstance(item, dict) and item.get("id")]
            self.consulted_doc_ids.update(ids)
            if matches:
                self.docs_read = True
            if self.docs_required:
                self.recovery_searches += 1
                self.recovery_candidates = list(dict.fromkeys(self.recovery_candidates + ids))[:12]
                if self.recovery_searches >= 2 and not self.recovery_candidates:

                    self.docs_required = False
                    self.recovery_query_pending = True
        elif name == "read_official_doc":
            full_text = (isinstance(data, dict) and
                         isinstance(data.get("content_verbatim"), str) and
                         bool(data.get("content_verbatim").strip()))
            if full_text:
                self.docs_read = True
                self.docs_assists += 1
                self.consulted_doc_ids.add(data["id"])
                if self.docs_required:
                    self.docs_required = False
                    self.recovery_query_pending = True
            elif self.docs_required:

                self.recovery_searches += 1
                if self.recovery_searches >= 2:
                    self.docs_required = False
                    self.recovery_query_pending = True
        if ref:
            self.last_results.append(ref)
            self.last_results = self.last_results[-6:]


        novel = bool(ref and not cached)
        if novel and name == "inspect_evidence":
            payload_hash = hashlib.sha256(dump_json(data).encode()).hexdigest()
            novel = payload_hash not in self.seen_inspection_payloads
            self.seen_inspection_payloads.add(payload_hash)
        self.no_progress = 0 if novel else self.no_progress + 1

    def supply_original_docs(self, query, *, error="", limit=3,
                             collection="kql"):


        try:
            topics = (kql_reference_topics(query, error) if collection == "kql"
                      else [str(query).lower()])
            passages = source_reference_excerpts(
                topics, collection=collection, limit=limit, chars_per_doc=3000)
        except Exception as exc:
            LOG.warning("Original documentation retrieval failed: %s", exc)
            return []
        if passages:
            current = {entry["id"] for entry in self.source_excerpts}
            self.source_excerpts = (self.source_excerpts + [entry for entry in passages
                                    if entry["id"] not in current])[-6:]
            self.docs_read = True


            if error and self.docs_required:
                self.recovery_candidates = list(dict.fromkeys(
                    [entry["id"] for entry in passages] + self.recovery_candidates))[:12]
            self.consulted_doc_ids.update(entry["id"] for entry in passages)
        return passages

    def _evidence_priority(self, ref, meta):
        name = meta["tool"]
        rows = meta.get("rows", 0)
        priority = {
            "get_analytics_rule": 12, "get_incident_alerts": 11,
            "get_incident_entities": 10, "get_incident": 10,
            "get_security_alert": 11, "run_kql": 18 if rows else 5,
            "read_official_doc": 7, "search_official_docs": 5, "inspect_evidence": 12,
            "get_table_schema": 6, "list_analytics_rules": 3,
        }.get(name, 1)
        return priority + (3 if ref in self.last_results else 0)

    def evidence(self, limit=23000, selected_refs=None):
        ex = self.executor
        receipts = list(ex.receipts.items())
        entries = []
        for pos, (ref, meta) in enumerate(receipts):
            priority = self._evidence_priority(ref, meta)
            if selected_refs and ref in selected_refs:
                priority += 30
            entries.append((priority, pos, ref, meta))
        entries.sort(key=lambda entry: (-entry[0], -entry[1]))
        details = []
        for priority, pos, ref, meta in entries[:20]:
            data = ex.results.get(ref)
            if isinstance(data, dict) and isinstance(data.get("rows"), list):
                payload = {"rows_returned": data.get("rows_returned"),
                           "partial": data.get("partial"), "rows": data["rows"][:4]}
            elif isinstance(data, list):
                payload = data[:3]
            else:
                payload = data
            sample_limit = 6500 if selected_refs and ref in selected_refs else 2600
            shown = preview(payload, sample_limit)
            if isinstance(shown, dict) and shown.get("preview_only") and meta["tool"] == "run_kql":
                shown = digest_rows(data, sample=3, top=4) or shown
            details.append({"ref": ref, "tool": meta["tool"],
                            "arguments": preview(meta["arguments"], 1000),
                            "rows": meta.get("rows"), "data": shown})
        ctx = self.context
        view = {
            "incident": preview(ctx.get("incident"), 2700),
            "alerts": preview(ctx.get("alerts"), 3600),
            "entities": preview(ctx.get("entities"), 1700),
            "alert_anchor_default_utc": ex.anchor,
            "evidence_inventory": [{"ref": ref, "tool": m["tool"], "rows": m["rows"],
                                    "partial": m["partial"]} for ref, m in receipts],
            "primary_telemetry_coverage": ex.primary_telemetry_coverage(),
            "large_evidence_requires_narrow_query": [
                ref for ref, meta in list(ex.receipts.items())[-3:]
                if meta.get("tool") == "run_kql" and
                len(dump_json(ex.results.get(ref))) > 14000],
            "official_reference_excerpts": self.source_excerpts[-4:],
            "official_reference_ids_provided": sorted(self.consulted_doc_ids),
            "official_reference_ids_declared_in_kql": sorted(self.model_declared_doc_ids),
            "transient_source_failures": preview(self.executor.retryable_tool_failures[-3:], 800),
            "selected_evidence": details,
            "tool_errors": preview(self.failures[-4:], 3800),
            "kql_recovery": {
                "failed_query_and_azure_error": self.failed_kql,
                "requires_reference_read": self.docs_required,
                "candidate_original_document_ids": self.recovery_candidates[:8],
                "search_attempts": self.recovery_searches,
                "revised_kql_next": self.recovery_query_pending,
            } if (self.failed_kql and (self.docs_required or self.recovery_query_pending)) else None,
        }

        while len(dump_json(view)) > limit and view["selected_evidence"]:
            view["selected_evidence"].pop()
        if len(dump_json(view)) > limit:
            view["official_reference_excerpts"] = view["official_reference_excerpts"][-2:]
        if len(dump_json(view)) > limit:
            view["evidence_inventory"] = view["evidence_inventory"][-40:]
            view["tool_errors"] = preview(self.failures[-2:], 1300)
        return view

    def decision_context(self, round_no, max_rounds, max_chars=23000):
        view = self.evidence(limit=min(16600, max(2500, max_chars * 2 // 3)))


        recent_ref = self.last_results[-1] if self.last_results else None
        digest = None
        if recent_ref:
            latest = self.executor.results[recent_ref]
            shown = preview(latest, min(7600, max(1000, max_chars // 3)))
            if isinstance(shown, dict) and shown.get("preview_only"):
                digest = digest_rows(latest)
                shown = digest or shown
            view["last_result"] = {"ref": recent_ref, "data": shown}
        view["decision"] = {"round": round_no, "max_rounds": max_rounds,
                            "case_status": {
                                "raw_queries_succeeded": self.executor.primary_telemetry_coverage()["query_count"],
                                "raw_rows_observed": self.executor.primary_telemetry_coverage()["rows_returned"],
                                "analytics_rule_read": any(m["tool"] == "get_analytics_rule" for m in self.executor.receipts.values()),
                                "documentation_passages_provided": self.docs_read,
                                "model_declared_documentation_usage": bool(self.model_declared_doc_ids),
                                "open_questions": [
                                    "Which raw record(s) actually satisfied the originating rule?",
                                    "What host/account/source identities are independently linked?",
                                    "What evidence supports or contradicts malicious intent?"
                                ],
                            },
                            "no_progress_calls": self.no_progress,
                            "kql_errors": self.kql_errors,
                            "docs_required_after_kql_error": self.docs_required,
                            "revised_kql_next": self.recovery_query_pending,
                            "recent_actions": self.actions[-10:],
                            "recent_failures": self.failures[-3:]}


        while len(dump_json(view)) > max_chars and view["selected_evidence"]:
            view["selected_evidence"].pop()
        if len(dump_json(view)) > max_chars and "last_result" in view:
            view["last_result"]["data"] = preview(digest or self.executor.results[recent_ref], 950)
        if len(dump_json(view)) > max_chars:


            view["incident"] = preview(self.context.get("incident"), 400)
            view["alerts"] = preview(self.context.get("alerts"), 600)
            view["entities"] = preview(self.context.get("entities"), 200)
            view["evidence_inventory"] = view["evidence_inventory"][-12:]
            view["tool_errors"] = preview(self.failures[-1:], 450)
            if view.get("kql_recovery") and view["kql_recovery"].get("failed_query_and_azure_error"):
                failure = view["kql_recovery"]["failed_query_and_azure_error"]
                failure["query"] = failure["query"][:3500]
            view["official_reference_excerpts"] = view["official_reference_excerpts"][-1:]
            view["decision"]["recent_actions"] = view["decision"]["recent_actions"][-3:]
            view["decision"]["recent_failures"] = view["decision"]["recent_failures"][-1:]
            view["emergency_compaction"] = True
        return view

