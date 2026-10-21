# AI Analyst Agent

For me, one of the more interesting questions about Onze was what happens after Sentinel detects something. We had the logs coming in and KQL rules producing incidents, but an alert by itself doesn't explain much. Some of us still has to open it, browse the events and often run a few more queries to understand what happened. I wanted to try giving that first part of the investigation to a locally hosted model. It takes an incident from Sentinel, then searches for evidence and after a while writes a report.

### Environment

The agent leverages our existing hybrid Onze environment. Events from the on-premises machines and Azure resources go to Log Analytics, while Sentinel handles the detection rules. The Python toolkit makes API-calls to Azure, but the LLM runs locally. To be clear, it mostly looks like this:

`On-premises --> Log Analytics --> Microsoft Sentinel --> Python toolkit --> local LLM`

More on the environment itself is in the [on-premises architecture](ad-infrastructure.md) and [Azure infrastructure](azure-infrastructure.md) documents.

### How it works

The toolkit is written in Python and uses the Microsoft Security Insights API, together with the Log Analytics Query API. It provides tools to the model to get incident details, alerts and entities, check analytics rules or table schemas, and execute KQL. The model basically decides which tool it should call and what to search for. Python handles the actual requests and stores the responses.

I used **Qwen3.5-9B** in GGUF format, running with `llama.cpp`. The investigation has next stages: `DISCOVER`, `COLLECT`, `CORRELATE`, `ANALYZE` and `VALIDATE`. During those phases it can take a look at the events attached to the original alert, search for related activity and then prepare a JSON report with its findings, verdict, confidence and suggested actions.

There is also some local reference material available to the model: Microsoft Kusto documentation for operators like `where`, `project` and `between`, datetime types, and Sysinternals documentation. On top of that, it can request schemas from the actual Log Analytics tables. Every query result gets an evidence receipt, which makes it possible to trace a finding back to returned rows. The toolkit checks those field references before the report is saved.

Reports and audit logs stay on disk, while a small state database keeps track of processed incidents. The agent can pick up new cases or investigate a specific one; `--force` allows me to repeat an investigation when testing changes. I also limited tool calls and query sizes to keep the process manageable.

### Investigation examples

I simulated several scenarios in the environment, from failed domain logons and AD account changes to scheduled tasks and an EICAR test. You can check all of the information regarding it in [Incident Examples](incident-examples.md).

### Conclusions

At the moment, it investigates and reports, but does not close incidents, nor does it update their status or perform remediation. Email or Teams notifications were not connected either. Even if a report marks a case for escalation, that part still has to be handled by a person.

The main technical issue I ran into was KQL generation. The model has documentation and can inspect table schemas, yet it sometimes asks for columns that are not available in the selected table or builds an invalid query. A query returning zero rows is not always a failure, though; there may simply be no matching events. Better handling of failed queries and another attempt with corrected fields would help quite a bit.

For now, the agent is useful for getting an initial investigation done without manually starting every search. It can work through a simpler incident and leave the evidence and report for review, while the analyst deals with something else. Adding notifications and carefully controlled actions would be a reasonable next step once the query handling is more consistent.
