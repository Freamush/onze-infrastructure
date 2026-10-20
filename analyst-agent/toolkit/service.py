from datetime import datetime, timezone, timedelta
from pathlib import Path
import hashlib
import json
import logging
import sqlite3
import time
import uuid

import requests
from .investigator import Investigator
from .evidence import dump_json
from .config import Settings

LOG = logging.getLogger(__name__)


def fingerprint(incident, alerts):

    summary = []
    for alert in alerts:
        props = alert.get("properties", {})
        summary.append({"id": alert.get("name") or props.get("systemAlertId"),
                        "time": props.get("startTimeUtc"), "title": props.get("alertDisplayName")})
    payload = {"id": incident.get("name"),
               "severity": incident.get("properties", {}).get("severity"),
               "alerts": sorted(summary, key=lambda a: (a.get("id") or "", a.get("time") or ""))}
    return hashlib.sha256(dump_json(payload).encode()).hexdigest()


class Store:
    def __init__(self, path="agent_state.sqlite3"):
        self.connection = sqlite3.connect(path)
        self.connection.execute("""CREATE TABLE IF NOT EXISTS cases (
          signature TEXT PRIMARY KEY,
          incident_id TEXT NOT NULL,
          verdict TEXT NOT NULL,
          payload TEXT NOT NULL,
          case_written INTEGER NOT NULL DEFAULT 0,
          notified INTEGER NOT NULL DEFAULT 0,
          done INTEGER NOT NULL DEFAULT 0,
          created_utc TEXT NOT NULL)""")

        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(cases)")}
        if "source_signature" not in columns:
            self.connection.execute("ALTER TABLE cases ADD COLUMN source_signature TEXT")
        if "delivery_status" not in columns:
            self.connection.execute("ALTER TABLE cases ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'unknown'")
        self.connection.execute("CREATE INDEX IF NOT EXISTS cases_source_idx ON cases(source_signature,created_utc)")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS investigation_failures (
            incident_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL,
            retry_after_utc TEXT NOT NULL, error TEXT NOT NULL)""")
        self.connection.commit()

    def most_recent(self, source_signature):
        row = self.connection.execute(
            "SELECT signature,incident_id,verdict,payload,case_written,notified,done,created_utc "
            "FROM cases WHERE signature=? OR source_signature=? ORDER BY created_utc DESC LIMIT 1",
            (source_signature, source_signature)).fetchone()
        if row is None:
            return None
        return dict(zip(("signature", "incident_id", "verdict", "payload",
                         "case_written", "notified", "done", "created_utc"), row))

    def rechecks_done(self, source_signature):


        return self.connection.execute(
            "SELECT count(*) FROM cases WHERE source_signature=? AND signature<>? "
            "AND verdict='inconclusive'", (source_signature, source_signature)).fetchone()[0]

    def delivery_status(self, signature):
        row = self.connection.execute(
            "SELECT delivery_status FROM cases WHERE signature=?", (signature,)).fetchone()
        return row[0] if row else "unknown"

    def mark_delivery(self, signature, status):
        if status not in {"not_required", "delivered", "pending_configuration", "pending_retry"}:
            raise ValueError("Invalid delivery status")
        self.connection.execute("UPDATE cases SET delivery_status=? WHERE signature=?", (status, signature))
        self.connection.commit()

    def can_retry(self, incident_id):
        row = self.connection.execute(
            "SELECT retry_after_utc FROM investigation_failures WHERE incident_id=?",
            (incident_id,)).fetchone()
        return row is None or datetime.fromisoformat(row[0]) <= datetime.now(timezone.utc)

    def record_failure(self, incident_id, error, base_seconds=180):
        row = self.connection.execute(
            "SELECT attempts FROM investigation_failures WHERE incident_id=?",
            (incident_id,)).fetchone()
        attempts = (row[0] + 1) if row else 1
        seconds = min(3600, base_seconds * 2 ** min(attempts - 1, 5))
        retry_at = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
        self.connection.execute("""INSERT INTO investigation_failures
            (incident_id, attempts, retry_after_utc, error) VALUES (?,?,?,?)
            ON CONFLICT(incident_id) DO UPDATE SET attempts=excluded.attempts,
            retry_after_utc=excluded.retry_after_utc, error=excluded.error""",
            (incident_id, attempts, retry_at, str(error)[:500]))
        self.connection.commit()
        return retry_at

    def clear_failure(self, incident_id):
        self.connection.execute("DELETE FROM investigation_failures WHERE incident_id=?", (incident_id,))
        self.connection.commit()

    def find(self, signature):
        r = self.connection.execute("SELECT signature,incident_id,verdict,payload,case_written,notified,done FROM cases WHERE signature=?", (signature,)).fetchone()
        if r is None:
            return None
        return dict(zip(("signature", "incident_id", "verdict", "payload", "case_written", "notified", "done"), r))

    def put(self, signature, incident_id, result, source_signature=None):
        self.connection.execute("INSERT OR IGNORE INTO cases(signature,incident_id,verdict,payload,created_utc,source_signature) VALUES (?,?,?,?,?,?)",
                                (signature, incident_id, result["verdict"], dump_json(result),
                                 datetime.now(timezone.utc).isoformat(), source_signature))
        self.connection.commit()

    def flag(self, signature, key):
        if key not in {"case_written", "notified", "done"}:
            raise ValueError("Invalid state flag")
        self.connection.execute(f"UPDATE cases SET {key}=1 WHERE signature=?", (signature,))
        self.connection.commit()


class IncidentService:
    def __init__(self, settings: Settings, api, investigator=None, store=None):
        self.settings = settings
        self.api = api
        self.investigator = investigator
        self.store = store or Store()
        Path("reports").mkdir(parents=True, exist_ok=True)

    def _get_model(self):
        if self.investigator is None:
            self.investigator = Investigator(self.settings, self.api)
        return self.investigator

    def context(self, incident):
        iid = incident["name"]
        return self.api.get_incident_alerts(iid), self.api.get_incident_entities(iid)

    def process(self, incident, *, force=False):
        props = incident.get("properties", {})
        if props.get("status") == "Closed":
            return {"skipped": "closed"}
        iid = incident["name"]
        if not force and not self.store.can_retry(iid):
            return {"skipped": "retry_backoff", "incident": iid}
        try:
            alerts, entities = self.context(incident)
            original_sig = fingerprint(incident, alerts)
            last_case = self.store.most_recent(original_sig)
            if force:
                sig = hashlib.sha256((original_sig + ":force:" + str(uuid.uuid4())).encode()).hexdigest()
            elif last_case and not last_case["done"]:


                sig = last_case["signature"]
            elif last_case and last_case["done"]:


                if ((self.settings.escalation_webhook and not last_case["notified"]) or
                        (self.settings.case_writes and not last_case["case_written"])):
                    self._deliver(last_case["signature"], incident,
                                  json.loads(last_case["payload"]))
                    return {"skipped": "delivery_retried", "incident": iid,
                            "delivery_status": self.store.delivery_status(last_case["signature"])}
                if (last_case["verdict"] == "inconclusive" and
                        self.store.rechecks_done(original_sig) < self.settings.max_inconclusive_rechecks and
                        (datetime.now(timezone.utc) -
                         datetime.fromisoformat(last_case["created_utc"])).total_seconds()
                        >= self.settings.inconclusive_recheck_seconds):


                    sig = hashlib.sha256((original_sig + ":recheck:" +
                           str(uuid.uuid4())).encode()).hexdigest()
                    LOG.info("Rechecking inconclusive incident %s for late telemetry", iid)
                else:

                    if ((self.settings.case_writes and not last_case["case_written"]) or
                            (self.settings.escalation_webhook and not last_case["notified"])):
                        self._deliver(last_case["signature"], incident,
                                      json.loads(last_case["payload"]))
                    return {"skipped": "already_processed", "incident": iid,
                            "delivery_status": self.store.delivery_status(last_case["signature"]),
                            "rechecks_done": self.store.rechecks_done(original_sig)}
            else:
                sig = original_sig
            existing = self.store.find(sig)
            if not existing:
                LOG.info("Investigating %s: %s", iid, props.get("title", ""))
                result, receipts = self._get_model().investigate(incident, alerts, entities)
                if result.get("retryable_failure"):
                    raise RuntimeError("Investigation incomplete due to a retryable model/review failure")
                severity = props.get("severity", "Medium")
                result["escalate"] = (result["verdict"] in {"malicious", "suspicious"} or
                        (result["verdict"] == "inconclusive" and severity in {"Medium", "High"}) or
                        (bool(result["needs_human"]) and severity != "Informational"))
                result["incident_id"] = iid
                result["severity"] = severity
                result["evidence_receipts"] = receipts
                self.store.put(sig, iid, result, source_signature=original_sig)
                output_path = Path("reports") / f"{iid}-{sig[:12]}.json"
                output_path.write_text(dump_json(result), encoding="utf-8")
            else:
                result = json.loads(existing["payload"])
            self.store.clear_failure(iid)
            self._deliver(sig, incident, result)


            return {**result, "delivery_status": self.store.delivery_status(sig)}
        except Exception as exc:


            retry_at = self.store.record_failure(iid, exc, self.settings.failure_retry_seconds)
            LOG.exception("Incident %s failed; retry after %s", iid, retry_at)
            raise

    def _deliver(self, sig, incident, result):
        iid = incident["name"]
        row = self.store.find(sig)
        if not row["case_written"]:
            if self.settings.case_writes:
                clean = {k: result[k] for k in ("verdict", "confidence", "summary", "findings",
                                                    "limitations", "recommended_actions", "escalate")}
                message = "Investigation report (analyst review required)\n" + dump_json(clean)
                comment_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel-soc:comment:{iid}:{sig}"))
                self.api.add_incident_comment(iid, comment_id, message[:8000])
                if result["escalate"]:
                    if self.settings.create_review_task:
                        task_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel-soc:task:{iid}:{sig}"))
                        self.api.create_incident_task(iid, task_id,
                            "Review AI investigation and decide response", result["summary"][:3000])
                    if self.settings.mark_active_on_escalation:
                        self.api.update_incident(iid, set_status="Active")
                self.store.flag(sig, "case_written")
        if not row["notified"]:
            if result["escalate"]:
                if self.settings.escalation_webhook:
                    alert = {k: result[k] for k in ("incident_id", "severity", "verdict", "confidence",
                                                   "summary", "findings", "limitations", "recommended_actions")}
                    response = requests.post(self.settings.escalation_webhook, json=alert,
                        headers={"Idempotency-Key": sig}, timeout=20)
                    response.raise_for_status()
                    LOG.warning("Escalation delivered incident=%s verdict=%s", iid, result["verdict"])
                    self.store.flag(sig, "notified")
                    self.store.mark_delivery(sig, "delivered")
                else:
                    self.store.mark_delivery(sig, "pending_configuration")
                    LOG.warning("Review required for %s: notification endpoint is not configured", iid)
            else:
                self.store.flag(sig, "notified")
                self.store.mark_delivery(sig, "not_required")
        self.store.flag(sig, "done")

    def baseline(self):

        items = self.api.list_incidents(status="All", limit=1000)
        if items["truncated"]:
            raise RuntimeError("Cannot baseline a truncated incident inventory")
        count = 0
        for incident in items["items"]:
            if incident.get("properties", {}).get("status") == "Closed":
                continue
            alerts, _ = self.context(incident)
            sig = fingerprint(incident, alerts)
            if not self.store.find(sig):
                self.store.put(sig, incident["name"], {"verdict": "skipped_baseline"})
                for flag in ("case_written", "notified", "done"):
                    self.store.flag(sig, flag)
                count += 1
        return {"baselined": count, "truncated": items["truncated"]}

    def poll_once(self):
        batch = self.api.list_incidents(status="All", limit=5000)
        if batch["truncated"]:


            raise RuntimeError("Incident inventory is truncated. Increase paging coverage before watch mode.")
        priority = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
        incidents = sorted(batch["items"], key=lambda x: (
            priority.get(x.get("properties", {}).get("severity"), 4),
            x.get("properties", {}).get("createdTimeUtc", ""),
            x.get("name", "")))
        processed = 0
        for incident in incidents:
            if processed >= self.settings.max_cases_per_poll:
                break
            if incident.get("properties", {}).get("status") == "Closed":
                continue
            try:
                result = self.process(incident)
                if "skipped" not in result:
                    processed += 1
            except Exception:
                LOG.exception("Incident %s failed; will retry", incident.get("name"))
        return processed

    def watch(self):
        LOG.info("Starting incident watch (poll every %ss)", self.settings.polling_seconds)
        while True:
            try:
                self.poll_once()
            except Exception:
                LOG.exception("Incident polling failed; retrying")
            time.sleep(self.settings.polling_seconds)
