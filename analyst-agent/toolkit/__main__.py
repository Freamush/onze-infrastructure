import argparse
import json
import logging

from dotenv import load_dotenv
from .config import Settings
from .tools import TOOL_SPECS


def model_smoke(settings):
    from openai import OpenAI
    client = OpenAI(base_url=settings.llm_url, api_key="local", timeout=120)
    model = settings.llm_model or client.models.list().data[0].id
    from .model import ModelClient
    ModelClient(settings, api=None, client=client)
    reply = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Call probe with message ready; do not respond with prose."}],
        tools=[{"type": "function", "function": {"name": "probe", "description": "Verify structured tool calling",
            "parameters": {"type": "object", "properties": {"message": {"type": "string"}},
                           "required": ["message"], "additionalProperties": False}}}],
        tool_choice="required", temperature=0, max_tokens=160,
    )
    calls = reply.choices[0].message.tool_calls or []
    if not calls or calls[0].function.name != "probe":
        raise RuntimeError("Local model did not produce a structured function call")
    args = json.loads(calls[0].function.arguments)
    print("MODEL TOOL CALL OK:", model, args)


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Microsoft Sentinel incident investigator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list-tools", action="store_true", help="Print available LLM-facing read tools")
    group.add_argument("--test-model", action="store_true", help="Verify local function calling, no Azure connection")
    group.add_argument("--test-docs", action="store_true", help="Verify locally indexed Microsoft documentation")
    group.add_argument("--test-api", action="store_true", help="Smoke-test Azure Sentinel + Log Analytics")
    group.add_argument("--incident", type=str, help="Investigate exactly one Sentinel incident GUID")
    group.add_argument("--once", action="store_true", help="Process currently open incidents once")
    group.add_argument("--watch", action="store_true", help="Continuously process new or updated incidents")
    group.add_argument("--baseline", action="store_true", help="Explicitly mark existing incidents processed without investigation")
    parser.add_argument("--force", action="store_true", help="Force a new run with --incident")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


    for logger_name in ("azure", "httpx", "urllib3"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    if args.list_tools:
        print(json.dumps([{"name": t["function"]["name"], "description": t["function"]["description"]}
                           for t in TOOL_SPECS], indent=2, ensure_ascii=False))
        return
    if args.test_docs:
        from .official_docs import DOCS, availability, search_docs
        counts = availability()
        if set(counts) != set(DOCS):
            raise RuntimeError(f"Missing original documentation collections: {set(DOCS)-set(counts)}. Run sync-official-docs.ps1")
        print("Indexed Microsoft documentation:", counts)
        print("Example retrieval:", search_docs("TimeGenerated datetime", limit=2))
        return
    settings = Settings.from_env()
    if args.test_model:
        model_smoke(settings)
        return
    from .azure_client import SentinelAPI
    api = SentinelAPI(settings)
    if args.test_api:
        incidents = api.list_incidents(limit=5)
        print("Incidents:", [(i.get("name"), i.get("properties", {}).get("title"))
                             for i in incidents["items"]])
        print("Tables:", api.list_tables(limit=30))


        print("KQL connectivity:", api.query_logs("print ConnectionOK=1", hours=1, max_rows=1))
        for table in ("SecurityAlert", "Event"):
            try:
                print(table + ":", api.query_logs(
                    f"{table} | summarize Total=count(), LastEvent=max(TimeGenerated)",
                    hours=168, max_rows=5))
            except Exception as exc:
                print(table + ": unavailable/not ingested:", type(exc).__name__, str(exc)[:250])
        return
    from .service import IncidentService
    service = IncidentService(settings, api)
    if args.incident:
        item = api.get_incident(args.incident)
        print(json.dumps(service.process(item, force=args.force), indent=2, ensure_ascii=False, default=str))
    elif args.baseline:
        print(service.baseline())
    elif args.once:
        print("Investigated:", service.poll_once())
    elif args.watch:
        try:
            service.watch()
        except KeyboardInterrupt:
            print("Stopped")


if __name__ == "__main__":
    main()
