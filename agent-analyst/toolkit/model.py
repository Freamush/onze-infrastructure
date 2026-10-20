from __future__ import annotations

import logging

from .config import Settings

LOG = logging.getLogger(__name__)

class ModelClient:
    def __init__(self, settings: Settings, api, client=None):
        self.settings = settings
        self.api = api
        if client is None:
            from openai import OpenAI
            client = OpenAI(base_url=settings.llm_url, api_key="local", timeout=120, max_retries=0)
        self.client = client
        self.model = settings.llm_model or self.client.models.list().data[0].id
        self._verify_server_context()


    def _verify_server_context(self):
        import requests
        base = self.settings.llm_url.rstrip("/")
        if not base.endswith("/v1"):
            return
        try:
            response = requests.get(base[:-3] + "/props", timeout=4)
            if response.status_code != 200:
                return
            n_ctx = (response.json().get("default_generation_settings") or {}).get("n_ctx")
            if isinstance(n_ctx, int) and n_ctx > 0:
                LOG.info("llama.cpp per-slot context: %s tokens (agent configured %s)",
                         n_ctx, self.settings.llm_context_tokens)
                if n_ctx < self.settings.llm_context_tokens:
                    raise RuntimeError(f"Restart llama-server with -c {self.settings.llm_context_tokens} "
                                       f"and -np 1; server has {n_ctx} tokens per slot")
        except (requests.RequestException, ValueError, TypeError):
            pass


    def _complete(self, messages, *, tools=None, max_tokens=None):
        opts = {"model": self.model, "messages": messages, "temperature": 0,
                "max_tokens": max_tokens or self.settings.llm_output_tokens}
        if tools:
            opts.update(tools=tools, tool_choice="auto")
        else:
            opts.update(tool_choice="none")
        return self.client.chat.completions.create(**opts).choices[0].message


    def _submit_structured(self, messages, spec, *, max_tokens):


        response = self.client.chat.completions.create(
            model=self.model, messages=messages, temperature=0,
            max_tokens=max_tokens, tools=[spec], tool_choice="required")
        choice = response.choices[0]
        msg = choice.message
        calls = getattr(msg, "tool_calls", None) or []
        expected_name = spec["function"]["name"]
        matching = [call for call in calls if getattr(getattr(call, "function", None), "name", None) == expected_name]
        raw = str(matching[0].function.arguments or "") if matching else str(getattr(msg, "content", None) or "")
        info = {"finish_reason": getattr(choice, "finish_reason", None),
                "response_content_chars": len(str(getattr(msg, "content", None) or "")),
                "tool_call_count": len(calls), "matching_submission": bool(matching),
                "submission_chars": len(raw),
                "reasoning_chars": len(str(getattr(msg, "reasoning_content", None) or ""))}

        return raw, info


    @staticmethod
    def _schema_subset(all_tools, names):
        return [spec for spec in all_tools if spec["function"]["name"] in names]

