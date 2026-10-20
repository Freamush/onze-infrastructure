from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import re
import uuid

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from azure.identity import AzureCliCredential, DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from .config import Settings
from .event_enrichment import extract_windows_eventdata

SENTINEL_API = "2025-09-01"
TABLES_API = "2025-07-01"
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}$")


def guid(value: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Expected a valid GUID") from exc


def utc_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("UTC timestamp must be an ISO-8601 string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Timestamp must have UTC offset or Z")
    return dt.astimezone(timezone.utc)


def has_kql_time_filter(query: str) -> bool:

    return bool(re.search(r"\bTimeGenerated\b\s*(?:between\b|in\b|>=|<=|>|<|==|!=)",
                          query, re.IGNORECASE))


def trim(value, max_len=1800):
    if isinstance(value, str) and len(value) > max_len:
        return value[:max_len] + f" … [field shortened, original {len(value)} characters]"
    if isinstance(value, dict):
        return {str(k): trim(v, max_len) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [trim(v, max_len) for v in value]
    return value


class SentinelAPI:
    def __init__(self, settings: Settings, credential=None, logs_client=None, session=None):
        self.settings = settings
        self.credential = credential or (
            AzureCliCredential(tenant_id=settings.tenant_id or None)
            if settings.auth_mode == "cli" else
            DefaultAzureCredential(exclude_interactive_browser_credential=True)
        )
        self.logs = logs_client or LogsQueryClient(self.credential)
        self.http = session or requests.Session()
        if session is None:
            retries = Retry(total=3, backoff_factor=0.8, status_forcelist=[429, 502, 503, 504],
                            allowed_methods=["GET"], respect_retry_after_header=True)
            self.http.mount("https://", HTTPAdapter(max_retries=retries))
        s = settings
        self.workspace = (f"/subscriptions/{s.subscription_id}/resourceGroups/{s.resource_group}"
                          f"/providers/Microsoft.OperationalInsights/workspaces/{s.workspace_name}")
        self.base = self.workspace + "/providers/Microsoft.SecurityInsights"

    def _arm(self, method: str, relative: str, *, root="sentinel", params=None, payload=None, headers=None):
        prefix = self.base if root == "sentinel" else self.workspace
        url = f"https://management.azure.com{prefix}/{relative.lstrip('/')}"
        version = SENTINEL_API if root == "sentinel" else TABLES_API
        return self._http(method, url, params={"api-version": version, **(params or {})},
                          payload=payload, headers=headers)

    def _http(self, method, url, *, params=None, payload=None, headers=None):
        parsed = urlparse(url)

        if parsed.scheme != "https" or parsed.hostname != "management.azure.com" or parsed.port is not None:
            raise ValueError("Refusing off-Azure ARM URL")
        if not any(parsed.path.lower().startswith(p.lower() + "/") for p in (self.base, self.workspace)):
            raise ValueError("Refusing ARM URL outside configured workspace")
        token = self.credential.get_token("https://management.azure.com/.default").token
        head = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if payload is not None:
            head["Content-Type"] = "application/json"
        head.update(headers or {})
        response = self.http.request(method, url, params=params, json=payload, headers=head, timeout=(10, 65))
        response.raise_for_status()
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()

    def _page(self, relative, *, root="sentinel", params=None, max_items=300):
        prefix = self.base if root == "sentinel" else self.workspace
        ver = SENTINEL_API if root == "sentinel" else TABLES_API
        url = f"https://management.azure.com{prefix}/{relative.lstrip('/')}"
        query = {"api-version": ver, **(params or {})}
        collected = []
        for _ in range(40):
            body = self._http("GET", url, params=query)
            collected.extend(body.get("value", []))
            url = body.get("nextLink")
            if not url or len(collected) >= max_items:
                return {"items": collected[:max_items], "truncated": bool(url) or len(collected) > max_items}
            query = None
        return {"items": collected[:max_items], "truncated": True}


    def list_incidents(self, status="All", severity="All", limit=100):
        if status not in {"All", "New", "Active", "Closed"}:
            raise ValueError("Invalid incident status")
        if severity not in {"All", "Informational", "Low", "Medium", "High"}:
            raise ValueError("Invalid incident severity")
        if not 1 <= limit <= 5000:
            raise ValueError("limit must be 1..5000")
        params = {"$top": 250}
        out = self._page("incidents", params=params, max_items=limit + 1)
        hits = [x for x in out["items"] if
                (status == "All" or x.get("properties", {}).get("status") == status) and
                (severity == "All" or x.get("properties", {}).get("severity") == severity)]
        hits.sort(key=lambda x: x.get("properties", {}).get("createdTimeUtc", ""), reverse=True)
        return {"items": hits[:limit], "truncated": out["truncated"] or len(hits) > limit}

    def get_incident(self, incident_id):
        return self._arm("GET", f"incidents/{guid(incident_id)}")

    def get_incident_alerts(self, incident_id):
        return self._arm("POST", f"incidents/{guid(incident_id)}/alerts").get("value", [])

    def get_incident_entities(self, incident_id):
        return self._arm("POST", f"incidents/{guid(incident_id)}/entities")

    def get_incident_bookmarks(self, incident_id):
        return self._arm("POST", f"incidents/{guid(incident_id)}/bookmarks")

    def get_incident_comments(self, incident_id):
        return self._page(f"incidents/{guid(incident_id)}/comments", max_items=100)

    def get_incident_tasks(self, incident_id):
        return self._page(f"incidents/{guid(incident_id)}/tasks", max_items=100)

    def get_analytics_rule(self, rule_id):
        return self._arm("GET", f"alertRules/{guid(rule_id)}")

    def list_analytics_rules(self, limit=100):
        if not 1 <= limit <= 250:
            raise ValueError("limit must be 1..250")
        return self._page("alertRules", max_items=limit)


    def list_tables(self, limit=350):
        if not 1 <= limit <= 500:
            raise ValueError("limit must be 1..500")
        r = self._page("tables", root="workspace", max_items=limit)
        return {"items": [{"name": t.get("name"), "plan": t.get("properties", {}).get("plan")}
                          for t in r["items"]], "truncated": r["truncated"]}

    def get_table_schema(self, table):
        if not isinstance(table, str) or not NAME.fullmatch(table):
            raise ValueError("Invalid table name")
        try:
            r = self._arm("GET", f"tables/{table}", root="workspace")
            p = r.get("properties") or {}
            columns = (p.get("schema") or {}).get("columns") or []
            if columns:
                return {"table": table, "columns": columns, "plan": p.get("plan")}
        except requests.HTTPError as exc:
            if exc.response is None or exc.response.status_code not in (404,):
                raise

        schema = self.query_logs(f"{table} | getschema", hours=24,
                                 max_rows=min(500, self.settings.query_max_rows))
        return {"table": table, "columns": schema.get("rows", []), "source": "KQL getschema"}

    def _timespan(self, hours=24, start_utc=None, end_utc=None):
        if start_utc is not None or end_utc is not None:
            if start_utc is None or end_utc is None:
                raise ValueError("Specify both start_utc and end_utc")
            start, end = utc_time(start_utc), utc_time(end_utc)
            if start >= end or end - start > timedelta(hours=self.settings.query_max_hours):
                raise ValueError("Invalid absolute time range")
            if end > datetime.now(timezone.utc) + timedelta(minutes=5):
                raise ValueError("End time cannot be in the future")
            return start, end
        if type(hours) is not int or not 1 <= hours <= self.settings.query_max_hours:
            raise ValueError("Invalid hours range")
        return timedelta(hours=hours)

    def query_logs(self, query: str, hours=24, start_utc=None, end_utc=None, max_rows=100):
        if not isinstance(query, str) or not query.strip() or len(query) > 12000:
            raise ValueError("KQL query must be 1..12000 characters")
        if type(max_rows) is not int or not 1 <= max_rows <= self.settings.query_max_rows:
            raise ValueError(f"max_rows must be 1..{self.settings.query_max_rows}")


        restricted = r"\b(externaldata|external_table|cluster\s*\(|workspace\s*\(|app\s*\(|adx\s*\(|arg\s*\(|resource\s*\(|evaluate\s+(python|r)\b)"
        if re.search(restricted, query, re.IGNORECASE):
            raise ValueError("External/cross-resource KQL functions are not enabled")


        bounded_query = (f"set truncationmaxrecords={max_rows + 1};\n"
                         f"set truncationmaxsize=4194304;\n{query}")


        if start_utc is not None or end_utc is not None:

            sdk_timespan = self._timespan(hours, start_utc, end_utc)
        elif has_kql_time_filter(query):


            self._timespan(hours)
            sdk_timespan = None
        else:
            sdk_timespan = self._timespan(hours)
        result = self.logs.query_workspace(
            self.settings.workspace_id, bounded_query,
            timespan=sdk_timespan,
            server_timeout=self.settings.query_server_timeout,
            connection_timeout=10,
            read_timeout=self.settings.query_server_timeout + 20,
        )
        partial = result.status != LogsQueryStatus.SUCCESS
        tables = getattr(result, "tables", None) if not partial else getattr(result, "partial_data", None)
        out, n = [], 0
        for table in tables or []:


            columns = [
                c if isinstance(c, str)
                else c.get("name") if isinstance(c, dict)
                else c.name
                for c in table.columns
            ]
            for row in table.rows:
                n += 1
                if len(out) < max_rows:
                    raw = dict(zip(columns, row))


                    parsed = extract_windows_eventdata(raw.get("EventData"))


                    sample = raw
                    if parsed:
                        sample["parsed_event_data"] = parsed
                    out.append(sample)
        return {"rows": out, "rows_returned": len(out),
                "result_rows_seen": n, "truncated": n > max_rows,
                "partial": partial,
                "error": str(getattr(result, "partial_error", "")) if partial else None}

    def table_activity(self, table: str, hours=24):
        if not isinstance(table, str) or not NAME.fullmatch(table):
            raise ValueError("Invalid table name")
        return self.query_logs(f"{table} | summarize Events=count(), LastSeen=max(TimeGenerated)",
                               hours=hours, max_rows=5)

    def get_security_alert(self, system_alert_id):
        alert_id = guid(system_alert_id)
        return self.query_logs(f'SecurityAlert | where SystemAlertId == "{alert_id}" | take 5',
                               hours=self.settings.query_max_hours, max_rows=5)


    def query_threat_intelligence(self, keyword: str, limit=15):
        if not isinstance(keyword, str) or not 2 <= len(keyword) <= 256 or "\n" in keyword:
            raise ValueError("Invalid IOC keyword")
        if not 1 <= limit <= 50:
            raise ValueError("limit must be 1..50")
        return self._arm("POST", "threatIntelligence/main/queryIndicators",
                         payload={"keywords": [keyword], "pageSize": limit, "includeDisabled": False})


    def add_incident_comment(self, incident_id, comment_id, message):
        if not isinstance(message, str) or not 1 <= len(message) <= 8000:
            raise ValueError("Invalid comment length")
        return self._arm("PUT", f"incidents/{guid(incident_id)}/comments/{guid(comment_id)}",
                         payload={"properties": {"message": message}})

    def create_incident_task(self, incident_id, task_id, title, description):
        if not title or len(title) > 180 or len(description) > 4000:
            raise ValueError("Invalid task text")
        return self._arm("PUT", f"incidents/{guid(incident_id)}/tasks/{guid(task_id)}",
                         payload={"properties": {"title": title, "description": description, "status": "New"}})

    def update_incident(self, incident_id, *, add_label=None, set_status=None, set_severity=None):
        if not any(x is not None for x in (add_label, set_status, set_severity)):
            raise ValueError("No update supplied")
        if set_status is not None and set_status not in ("New", "Active"):
            raise ValueError("Automatic closure is intentionally unsupported")
        if set_severity is not None and set_severity not in ("Informational", "Low", "Medium", "High"):
            raise ValueError("Invalid severity")
        if add_label is not None and (not re.fullmatch(r"[\w .:-]{1,70}", add_label)):
            raise ValueError("Invalid label")
        current = self.get_incident(incident_id)
        old = current["properties"]
        keys = ("title", "severity", "status", "description", "owner", "labels",
                "firstActivityTimeUtc", "lastActivityTimeUtc", "classification",
                "classificationReason", "classificationComment")
        props = {k: old[k] for k in keys if k in old}
        if set_status is not None:
            props["status"] = set_status
        if set_severity is not None:
            props["severity"] = set_severity
        if add_label is not None:
            labels = list(props.get("labels") or [])
            if not any(x.get("labelName") == add_label for x in labels):
                labels.append({"labelName": add_label, "labelType": "User"})
            props["labels"] = labels
        return self._arm("PUT", f"incidents/{guid(incident_id)}",
                         payload={"etag": current.get("etag"), "properties": props},
                         headers={"If-Match": current.get("etag", "*")})

    def run_incident_playbook(self, incident_id, *, playbook_resource_id, tenant_id):

        if not playbook_resource_id.startswith("/subscriptions/") or "/providers/Microsoft.Logic/workflows/" not in playbook_resource_id:
            raise ValueError("Expected a Logic App ARM resource ID")
        return self._arm("POST", f"incidents/{guid(incident_id)}/runPlaybook",
                         payload={"logicAppsResourceId": playbook_resource_id,
                                  "tenantId": guid(tenant_id)})
