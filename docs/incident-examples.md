# Analyst Agent

Four tests in the environment to show performance of the agent. Service metadata and repetitive JSON fields have been omitted.


### Example 1 - Brute-force attempts against Administrator

On `PC02`, logged in as `m.janssens`, we made several failed authentication attempts against `ONZE\Administrator` on `DC`, just enough to trigger the Sentinel rule:

![Brute-force test](image.png)

Sentinel generated a **Windows Brute Force** incident:

![Windows Brute Force alert](image-1.png)

The agent investigated the incident and returned the following result:

```text
2026-10-21 00:25:41,279 INFO Investigating d18974c9-8d8a-470e-ad52-74080c3a94af: Windows Brute Force
2026-10-21 00:25:43,144 INFO llama.cpp per-slot context: 32768 tokens (agent configured 32768)
2026-10-21 00:25:57,885 INFO Investigation stage DISCOVER: investigation questions prepared
2026-10-21 00:26:29,680 INFO Investigation stage COLLECT: bounded discovery completed
2026-10-21 00:28:19,145 INFO Investigation stage ANALYZE: read-only acquisition concluded
2026-10-21 00:28:19,146 INFO Analyzing 1 query receipts (17 rows)
2026-10-21 00:28:52,596 INFO Investigation stage VALIDATE: deterministic citation validation
2026-10-21 00:28:52,597 INFO Investigation stage COMPLETE: report prepared; analyst review required
2026-10-21 00:28:52,604 WARNING Review required for d18974c9-8d8a-470e-ad52-74080c3a94af: notification endpoint is not configured
```

```json
{
  "verdict": "malicious",
  "confidence": 0.85,
  "summary": "Windows Event ID 4625 (Account Logon Failure) events indicate repeated failed authentication attempts against the Administrator account on domain controller DC.onze.internal from source IP 10.10.10.22. All sampled events show LogonType 3 (Network) authentication with FailureReason %%2313 (The password provided was incorrect).",
  "findings": [
    {
      "source_ref": "ev-0004",
      "observation": "Multiple failed authentication attempts against Administrator account with LogonType 3 (Network) authentication",
      "verified_fields": [
        {
          "name": "TargetUserName",
          "value": "Administrator"
        },
        {
          "name": "LogonType",
          "value": "3"
        },
        {
          "name": "FailureReason",
          "value": "%%2313"
        }
      ]
    },
    {
      "source_ref": "ev-0004",
      "observation": "All authentication attempts failed with password incorrect error",
      "verified_fields": [
        {
          "name": "FailureReason",
          "value": "%%2313"
        },
        {
          "name": "EventID",
          "value": "4625"
        }
      ]
    },
    {
      "source_ref": "ev-0004",
      "observation": "Attack originated from IP 10.10.10.22 targeting domain controller DC.onze.internal",
      "verified_fields": [
        {
          "name": "IpAddress",
          "value": "10.10.10.22"
        },
        {
          "name": "Computer",
          "value": "DC.onze.internal"
        }
      ]
    }
  ],
  "limitations": [
    "Only 16 of 17 total rows were sampled for review",
    "No successful authentication events observed in the sample",
    "No correlation with other security events or alerts available",
    "Time range of sampled events does not capture full attack timeline",
    "Cannot confirm if 10.10.10.22 is internal or external network"
  ],
  "needs_human": true,
  "validation": {
    "field_checks_passed": 7,
    "citation_count": 3,
    "semantic_claims_independently_verified": false
  },
  "escalate": true,
  "incident_id": "d18974c9-8d8a-470e-ad52-74080c3a94af",
  "severity": "Medium",
  "evidence_receipts": {
    "...": "context, schemas and other metadata omitted",
    "ev-0004": {
      "tool": "run_kql",
      "rows": 17
    }
  },
  "delivery_status": "pending_configuration"
}
```

### Example 2 - Unexpected AD account creation

On `DC`, we created a new account, `test.user`, with the intention of adding it to an admin group later:

![AD account creation](image-2.png)

Sentinel generated an **AD Account Lifecycle Changes** incident:

![AD Account Lifecycle Changes alert](image-4.png)

The agent looked into the account activity:

```text
2026-10-21 22:05:17,078 INFO Investigating 238417cf-a6ca-4e7c-8cc0-f7e58757bb2c: AD Account Lifecycle Changes
2026-10-21 22:05:19,506 INFO llama.cpp per-slot context: 32768 tokens (agent configured 32768)
2026-10-21 22:05:36,202 INFO Investigation stage DISCOVER: investigation questions prepared
2026-10-21 22:06:18,643 INFO Investigation stage COLLECT: search for primary telemetry
2026-10-21 22:07:38,674 INFO Investigation stage CORRELATE: search related activity
2026-10-21 22:14:05,862 INFO Investigation stage ANALYZE: read-only acquisition concluded
2026-10-21 22:14:05,865 INFO Analyzing 4 query receipts (24 rows)
2026-10-21 22:17:16,057 INFO Investigation stage VALIDATE: deterministic citation checks
2026-10-21 22:17:21,532 INFO Investigation stage COMPLETE: report prepared; analyst review required
2026-10-21 22:17:21,538 WARNING Review required for 238417cf-a6ca-4e7c-8cc0-f7e58757bb2c: notification endpoint is not configured
```

```json
{
  "verdict": "suspicious",
  "confidence": 0.65,
  "summary": "AD account test.user was created, modified, password set, enabled, and logged on within a 2-minute window on 2026-10-20. All events occurred on DC.onze.internal by Administrator. The rapid lifecycle (create→modify→password→enable→logon) within 2 minutes is atypical for normal account provisioning.",
  "findings": [
    {
      "source_ref": "ev-0004",
      "observation": "Account test.user created by Administrator at 2026-10-20 21:40:50. PrimaryGroupId 513 indicates membership in Users group. PasswordLastSet shows %%1794 placeholder."
    },
    {
      "source_ref": "ev-0004",
      "observation": "Account test.user modified by Administrator at 2026-10-20 21:40:50 (EventID 4724)."
    },
    {
      "source_ref": "ev-0004",
      "observation": "Password for test.user changed by Administrator at 2026-10-20 21:42:01 (EventID 4726)."
    },
    {
      "source_ref": "ev-0004",
      "observation": "Account test.user enabled by Administrator at 2026-10-20 21:42:21 (EventID 4738). PasswordLastSet shows 10/20/2026 11:42:21 PM."
    },
    {
      "source_ref": "ev-0005",
      "observation": "Account test.user logged on by Administrator at 2026-10-20 21:42:21 (EventID 4722)."
    }
  ],
  "limitations": [
    "Only 6 of 24 total rows sampled; full event timeline may be incomplete",
    "Correlation queries for related activity may have failed or returned no results",
    "Correlation incomplete: 2 of 4 requested queries succeeded."
  ],
  "needs_human": true,
  "correlation": {
    "queries": 2,
    "aggregate_receipts": [],
    "rows": 8,
    "completed": false
  },
  "validation": {
    "field_checks_passed": 0,
    "citation_count": 5,
    "semantic_claims_independently_verified": false
  },
  "escalate": true,
  "incident_id": "238417cf-a6ca-4e7c-8cc0-f7e58757bb2c",
  "severity": "Medium",
  "evidence_receipts": {
    "...": "context, schemas and other metadata omitted",
    "ev-0004": {
      "tool": "run_kql",
      "rows": 8
    },
    "ev-0005": {
      "tool": "run_kql",
      "rows": 8
    },
    "ev-0006": {
      "tool": "run_kql",
      "rows": 8
    },
    "ev-0007": {
      "tool": "run_kql",
      "rows": 0
    }
  },
  "delivery_status": "pending_configuration"
}
```

### Example 3 - Scheduled task creation

On `PC02`, we used an elevated shell to create a scheduled task, then executed a process that creates a `.txt` file:

![Scheduled task test](image-5.png)

This triggered the **New or Updated Windows Scheduled Task** alert:

![Scheduled task alert](image-6.png)

The agent completed its investigation, although most of the activity it focused on was not directly related to our test task:

```text
2026-10-21 22:42:00,480 INFO Investigating 9af05837-fcc6-408a-abfd-c4c91d2be77d: New or Updated Windows Scheduled Task
2026-10-21 22:42:03,087 INFO llama.cpp per-slot context: 32768 tokens (agent configured 32768)
2026-10-21 22:42:18,719 INFO Investigation stage DISCOVER: investigation questions prepared
2026-10-21 22:42:59,823 INFO Investigation stage COLLECT: search for primary telemetry
2026-10-21 22:44:02,792 INFO Investigation stage CORRELATE: search related activity
2026-10-21 22:45:20,774 INFO Investigation stage ANALYZE: read-only acquisition concluded
2026-10-21 22:45:20,776 INFO Analyzing 2 query receipts (150 rows)
2026-10-21 22:46:22,693 INFO Investigation stage VALIDATE: deterministic citation checks
2026-10-21 22:48:01,016 INFO Investigation stage COMPLETE: report prepared; analyst review required
2026-10-21 22:48:01,027 WARNING Review required for 9af05837-fcc6-408a-abfd-c4c91d2be77d: notification endpoint is not configured
```

```json
{
  "verdict": "suspicious",
  "confidence": 0.7,
  "summary": "Analysis of PC02.onze.internal reveals suspicious credential-based network activity from user m.janssens targeting external IP 10.10.10.10 with weak credentials (ONZE\\\\Administrator WrongPass123!). Multiple scheduled task modifications were detected on the same host within the investigation timeframe. The scheduled tasks appear to be legitimate Windows system tasks (Windows Defender, Software Protection Platform), but the credential-based connection attempt warrants investigation for potential lateral movement or unauthorized access attempts.",
  "findings": [
    {
      "source_ref": "ev-0005",
      "observation": "User m.janssens executed net.exe with suspicious command-line arguments attempting to connect to external IP 10.10.10.10 using credentials ONZE\\Administrator WrongPass123!",
      "verified_fields": [
        {
          "name": "SubjectUserName",
          "value": "m.janssens"
        },
        {
          "name": "CommandLine",
          "value": "\"C:\\WINDOWS\\system32\\net.exe\" use \\\\10.10.10.10\\IPC$ /user:ONZE\\Administrator WrongPass123!"
        }
      ]
    },
    {
      "source_ref": "ev-0005",
      "observation": "Logon activity detected targeting Administrator account on DC.onze.internal from IP 10.10.10.10, potentially related to the credential-based connection attempt.",
      "verified_fields": [
        {
          "name": "TargetUserName",
          "value": "Administrator"
        },
        {
          "name": "TargetDomainName",
          "value": "ONZE"
        },
        {
          "name": "IpAddress",
          "value": "10.10.10.10"
        }
      ]
    },
    {
      "source_ref": "ev-0004",
      "observation": "Multiple scheduled task modifications detected on PC02.onze.internal, all appearing to be legitimate Windows system tasks (Windows Defender verification, cache maintenance, cleanup, and Software Protection Platform restart tasks).",
      "verified_fields": [
        {
          "name": "SubjectUserName",
          "value": "PC02$"
        },
        {
          "name": "EventID",
          "value": "4702"
        }
      ]
    }
  ],
  "limitations": [
    "Only 7 rows sampled from ev-0004 (50 total rows returned) and 6 rows sampled from ev-0005 (100 total rows returned); full scope of activity not reviewed.",
    "No direct evidence linking the credential-based connection attempt to the scheduled task modifications; temporal correlation only.",
    "Related activity on other hosts or accounts not investigated; presence or absence unknown.",
    "Correlation incomplete: 1 of 4 requested queries succeeded."
  ],
  "needs_human": true,
  "correlation": {
    "queries": 1,
    "aggregate_receipts": [],
    "rows": 100,
    "completed": false
  },
  "validation": {
    "field_checks_passed": 7,
    "citation_count": 3,
    "semantic_claims_independently_verified": false
  },
  "escalate": true,
  "incident_id": "9af05837-fcc6-408a-abfd-c4c91d2be77d",
  "severity": "Medium",
  "evidence_receipts": {
    "...": "context, schemas and other metadata omitted",
    "ev-0004": {
      "tool": "run_kql",
      "rows": 50
    },
    "ev-0005": {
      "tool": "run_kql",
      "rows": 100
    }
  },
  "delivery_status": "pending_configuration"
}
```

### Example 4 — EICAR test file

On `PC01`, logged in as `j.vermeulen`, we downloaded a `.txt` file containing the EICAR antivirus test string. Windows Defender detected it:

![EICAR test file](image-7.png)
![Windows Defender detection](image-8.png)

Sentinel generated a **Defender Threat or Configuration Change** incident:

![Defender alert](image-9.png)

The agent picked up the related events and returned its report:

```text
2026-10-21 23:28:33,232 INFO Investigating 5b12c77e-0fca-44da-8ca8-131acd43ee62: Defender Threat or Configuration Change
2026-10-21 23:28:35,716 INFO llama.cpp per-slot context: 32768 tokens (agent configured 32768)
2026-10-21 23:28:48,650 INFO Investigation stage DISCOVER: investigation questions prepared
2026-10-21 23:29:33,295 INFO Investigation stage COLLECT: search for primary telemetry
2026-10-21 23:31:04,781 INFO Investigation stage CORRELATE: search related activity
2026-10-21 23:34:37,970 INFO Investigation stage ANALYZE: read-only acquisition concluded
2026-10-21 23:34:37,973 INFO Analyzing 4 query receipts (21 rows)
2026-10-21 23:35:39,235 INFO Investigation stage VALIDATE: deterministic citation checks
2026-10-21 23:40:22,756 INFO Investigation stage COMPLETE: report prepared; analyst review required
2026-10-21 23:40:22,765 WARNING Review required for 5b12c77e-0fca-44da-8ca8-131acd43ee62: notification endpoint is not configured
```

```json
{
  "verdict": "suspicious",
  "confidence": 0.65,
  "summary": "Windows Defender on PC01.onze.internal generated multiple detection events (EventID 1116, 1117) for EICAR test file (DOS/EICAR_Test_File) and configuration change events (EventID 5007) modifying Defender settings. The EICAR test file is a known safe test file used for antivirus validation. Configuration changes include disabling Controls (409 = 0x1) and modifying EcsConfigs settings. Activity occurred between 2026-10-21T21:06:20Z and 2026-10-21T21:26:16Z.",
  "findings": [
    {
      "source_ref": "ev-0004",
      "observation": "Windows Defender detected DOS/EICAR_Test_File malware on PC01.onze.internal at 2026-10-21T21:06:20.668802Z. The file path is C:\\Users\\j.vermeulen\\Downloads\\test.txt.txt. EventID 1116 indicates a malware detection."
    },
    {
      "source_ref": "ev-0004",
      "observation": "Windows Defender detected DOS/EICAR_Test_File malware on PC01.onze.internal at 2026-10-21T21:06:36.671934Z. EventID 1117 indicates a second detection of the same test file."
    },
    {
      "source_ref": "ev-0004",
      "observation": "Windows Defender detected DOS/EICAR_Test_File malware on PC01.onze.internal at 2026-10-21T21:08:11.267148Z. EventID 1116 indicates a third detection of the test file."
    },
    {
      "source_ref": "ev-0004",
      "observation": "Windows Defender detected DOS/EICAR_Test_File malware on PC01.onze.internal at 2026-10-21T21:08:26.637273Z. EventID 1117 indicates a fourth detection of the test file."
    },
    {
      "source_ref": "ev-0003",
      "observation": "Windows Defender configuration changed at 2026-10-21T21:26:16.468958Z. Control 409 was set to 0x1 (disabled). Product Version 4.18.26090.9."
    },
    {
      "source_ref": "ev-0003",
      "observation": "Windows Defender EcsConfigs ETag configuration changed at 2026-10-21T21:26:15.942655Z. Product Version 4.18.26090.9."
    },
    {
      "source_ref": "ev-0003",
      "observation": "Windows Defender configuration changed at 2026-10-21T21:26:15.942333Z. MpFC_Dlp_Explorer_MultiCopy_Supress_FalseAlarmEvents was set to 0x1. Product Version 4.18.26090.9."
    },
    "..."
  ],
  "limitations": [
    "Related activity on other hosts (PC02.onze.internal, DC.onze.internal, DC-ENTRA.onze.internal, win-workstation) was not successfully investigated; their presence or absence is unknown.",
    "The EICAR test file is a known safe test file used for antivirus validation - this may indicate security testing rather than malicious activity.",
    "Configuration changes to Defender settings may be legitimate administrative actions or could indicate attempted evasion.",
    "Correlation incomplete: 3 of 4 requested queries succeeded."
  ],
  "needs_human": true,
  "correlation": {
    "queries": 3,
    "aggregate_receipts": [],
    "rows": 14,
    "completed": false
  },
  "validation": {
    "field_checks_passed": 0,
    "citation_count": 10,
    "semantic_claims_independently_verified": false
  },
  "escalate": true,
  "incident_id": "5b12c77e-0fca-44da-8ca8-131acd43ee62",
  "severity": "High",
  "evidence_receipts": {
    "...": "context, schemas and other metadata omitted",
    "ev-0003": {
      "tool": "run_kql",
      "rows": 7
    },
    "ev-0004": {
      "tool": "run_kql",
      "rows": 7
    },
    "ev-0005": {
      "tool": "run_kql",
      "rows": 0
    },
    "ev-0006": {
      "tool": "run_kql",
      "rows": 7
    }
  },
  "delivery_status": "pending_configuration"
}
```

All four investigations produced reports requiring analyst review. The notification endpoint was not configured, so escalation notifications were not delivered.
