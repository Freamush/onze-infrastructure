from dataclasses import dataclass
import os


def enabled(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    subscription_id: str
    resource_group: str
    workspace_name: str
    workspace_id: str
    tenant_id: str = ""
    auth_mode: str = "cli"
    llm_url: str = "http://127.0.0.1:8081/v1"
    llm_model: str = ""
    llm_context_tokens: int = 32768
    llm_output_tokens: int = 2048
    query_max_hours: int = 720
    query_max_rows: int = 150
    query_server_timeout: int = 50
    polling_seconds: int = 60
    max_rounds: int = 20
    max_tool_calls: int = 50
    correlation_queries: int = 2
    max_investigation_seconds: int = 900
    case_writes: bool = False
    create_review_task: bool = False
    mark_active_on_escalation: bool = False
    escalation_webhook: str = ""
    audit_dir: str = "audit"
    persist_evidence: bool = True
    inconclusive_recheck_seconds: int = 21600
    max_inconclusive_rechecks: int = 2
    max_cases_per_poll: int = 5
    failure_retry_seconds: int = 180

    @classmethod
    def from_env(cls) -> "Settings":
        keys = ["AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "AZURE_WORKSPACE_NAME", "AZURE_WORKSPACE_ID"]
        missing = [k for k in keys if not os.environ.get(k)]
        if missing:
            raise ValueError("Missing Azure settings: " + ", ".join(missing))
        s = cls(
            subscription_id=os.environ[keys[0]],
            resource_group=os.environ[keys[1]],
            workspace_name=os.environ[keys[2]],
            workspace_id=os.environ[keys[3]],
            tenant_id=os.getenv("AZURE_TENANT_ID", ""),
            auth_mode=os.getenv("AZURE_AUTH_MODE", "cli"),
            llm_url=os.getenv("LLM_URL", "http://127.0.0.1:8081/v1"),
            llm_model=os.getenv("LLM_MODEL", ""),
            llm_context_tokens=int(os.getenv("LLM_CONTEXT_TOKENS", "32768")),
            llm_output_tokens=int(os.getenv("LLM_OUTPUT_TOKENS", "2048")),
            query_max_hours=int(os.getenv("QUERY_MAX_HOURS", "720")),
            query_max_rows=int(os.getenv("QUERY_MAX_ROWS", "150")),
            query_server_timeout=int(os.getenv("QUERY_TIMEOUT_SECONDS", "50")),
            polling_seconds=int(os.getenv("POLL_SECONDS", "60")),
            max_rounds=int(os.getenv("MAX_ROUNDS", "20")),
            max_tool_calls=int(os.getenv("MAX_TOOL_CALLS", "50")),
            correlation_queries=int(os.getenv("CORRELATION_QUERIES", "2")),
            max_investigation_seconds=int(os.getenv("MAX_INVESTIGATION_SECONDS", "900")),
            case_writes=enabled("ENABLE_CASE_WRITES"),
            create_review_task=enabled("CREATE_REVIEW_TASK"),
            mark_active_on_escalation=enabled("MARK_ACTIVE_ON_ESCALATION"),
            escalation_webhook=os.getenv("ESCALATION_WEBHOOK_URL", ""),
            audit_dir=os.getenv("AUDIT_DIR", "audit"),
            persist_evidence=enabled("PERSIST_EVIDENCE", True),
            inconclusive_recheck_seconds=int(os.getenv("RECHECK_INCONCLUSIVE_SECONDS", "21600")),
            max_inconclusive_rechecks=int(os.getenv("MAX_INCONCLUSIVE_RECHECKS", "2")),
            max_cases_per_poll=int(os.getenv("MAX_CASES_PER_POLL", "5")),
            failure_retry_seconds=int(os.getenv("FAILURE_RETRY_SECONDS", "180")),
        )
        if not 4096 <= s.llm_context_tokens <= 1048576:
            raise ValueError("LLM_CONTEXT_TOKENS must be 4096..1048576")
        if not 128 <= s.llm_output_tokens <= s.llm_context_tokens // 2:
            raise ValueError("LLM_OUTPUT_TOKENS must be 128..half context")
        if not 1 <= s.max_rounds <= 100:
            raise ValueError("MAX_ROUNDS must be 1..100")
        if not 1 <= s.max_tool_calls <= 500:
            raise ValueError("MAX_TOOL_CALLS must be 1..500")
        if not 0 <= s.correlation_queries <= 4:
            raise ValueError("CORRELATION_QUERIES must be 0..4")
        if not 60 <= s.max_investigation_seconds <= 14400:
            raise ValueError("MAX_INVESTIGATION_SECONDS must be 60..14400")
        if not 5 <= s.query_server_timeout <= 300:
            raise ValueError("QUERY_TIMEOUT_SECONDS must be 5..300")
        if s.auth_mode not in {"cli", "default"}:
            raise ValueError("AZURE_AUTH_MODE must be cli or default")
        if s.query_max_rows < 1 or s.query_max_rows > 1000:
            raise ValueError("QUERY_MAX_ROWS must be 1..1000")
        if s.query_max_hours < 1 or s.query_max_hours > 24 * 365:
            raise ValueError("QUERY_MAX_HOURS must be 1..8760")
        if not 300 <= s.inconclusive_recheck_seconds <= 604800:
            raise ValueError("RECHECK_INCONCLUSIVE_SECONDS must be 300..604800")
        if not 0 <= s.max_inconclusive_rechecks <= 100:
            raise ValueError("MAX_INCONCLUSIVE_RECHECKS must be 0..100")
        if not 1 <= s.max_cases_per_poll <= 100:
            raise ValueError("MAX_CASES_PER_POLL must be 1..100")
        if not 30 <= s.failure_retry_seconds <= 3600:
            raise ValueError("FAILURE_RETRY_SECONDS must be 30..3600")
        if s.polling_seconds < 15:
            raise ValueError("POLL_SECONDS must be >= 15")
        if s.create_review_task and not s.case_writes:
            raise ValueError("CREATE_REVIEW_TASK requires ENABLE_CASE_WRITES=true")
        if s.mark_active_on_escalation and not s.case_writes:
            raise ValueError("MARK_ACTIVE_ON_ESCALATION requires ENABLE_CASE_WRITES=true")
        if s.escalation_webhook and not s.escalation_webhook.startswith("https://"):
            raise ValueError("ESCALATION_WEBHOOK_URL must begin with https://")
        return s
