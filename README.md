# ONZE – Secure Hybrid Azure Infrastructure

Secure hybrid cloud infrastructure for a fictional company **ONZE**, built entirely with **Terraform**. It follows the Microsoft Cloud Adoption Framework hub-and-spoke model, connects on-premises **Active Directory** to Microsoft **Entra ID**, ships all logs to **Microsoft Sentinel** and uses self-hosted **AI analyst agent** powered by **Qwen 3.5 9B**.

<img width="4282" height="2040" alt="onze" src="https://github.com/user-attachments/assets/aa24fd66-8dc4-4c9f-8ddc-b1eb92a7ef11" />

## Repository structure
```
.
├── bicep/       #Sentinel rules in policy as code with bicep
├── analyst-agent/      # Self-hosted AI analyst for Sentinel incidents (Python)
├── infra/          # Terraform files with modules (spoke, dcr...)
├── docs/       # Detailed architecture documentation
└── .github/workflows # CI pipelines
```
## Highlights

### Cloud infrastructure
- **Hub-and-spoke network** following the Microsoft Cloud Adoption Framework, with Azure Firewall as a default-deny egress gateway, threat intelligence in deny mode and FQDN-based allowlisting per VM
- **Private-only PaaS access**: Blob Storage and the Recovery Services vault are reachable only through private endpoints, with shared key access disabled
- **No exposed VMs**: administrative access only through Azure Bastion; VM credentials stored in Azure Key Vault and SSH-key-only login on Linux
- **Governance with Azure Policy**: custom policies deny untagged resources and public IPs on network interfaces
- **Azure Arc**: on-premises servers and workstations onboarded for centralized log collection

### On-premises and hybrid identity
- **Hardened Active Directory**: domain controller and workstations managed with GPOs for audit policy, PowerShell script block logging and Defender ASR rules
- **Segmented perimeter**: OPNsense firewall and router controlling LAN access and outbound traffic
- **Hybrid identity**: AD users and groups synced to Microsoft Entra ID via Entra Connect, with Entra ID login to cloud VMs through RBAC

### Security operations
- **Centralized SIEM**: Azure VMs, Arc-enabled on-premises machines, firewall and storage logs land in a single Log Analytics workspace with Microsoft Sentinel
- **Detection as code**: 40 Sentinel analytics rules in Bicep covering Active Directory attacks (Kerberoasting, DCSync, AS-REP roasting, password spraying), Sysmon endpoint telemetry, network, cloud and web activity

### CI/CD
- **Secretless deployments**: GitHub Actions authenticates to Azure with OIDC federated credentials bound to immutable repository IDs, with no client secrets
- **Least privilege pipeline**: a read-only identity for pull request plans and a separate write identity for apply, available only to the approval-gated `production` environment
- **Shift-left checks**: Gitleaks, Terraform validation, Checkov and Infracost on every pull request, with the Terraform plan posted for review
- **Remote state** in Azure Storage with Entra ID authentication and state locking
- **Deployment notifications**: every apply sends an email with the result, commit and run link through Azure Communication Services from a custom domain with SPF and DKIM

### AI Analyst Agent
- **Autonomous investigation**: polls Sentinel for new or updated incidents, builds an investigation plan, and iteratively queries logs until it reaches a conclusion
- **Read-only tool calling**: the model works through a fixed set of tools: running KQL, reading incidents, alerts, entities and analytics rules, discovering table schemas and searching threat intelligence indicators
- **Grounded in documentation**: a locally indexed copy of Microsoft KQL, Azure Monitor and Windows Server documentation lets the model check query syntax and event semantics instead of guessing
- **Evidence-based findings**: every query result is saved as an evidence receipt, and the final verdict is validated against the evidence it cites
- **Safe by design**: incident changes are disabled by default; investigations are bounded by limits on tool calls, rounds, query size and runtime, and every step is written to an audit log
- **Tested**: unit tests cover the API client, the investigation loop and the incident service

## Documentation
- [On-Prem Architecture](docs/ad-infrastructure.md): Active Directory, Sentinel, Qwen 3.5 9B
- [Cloud Architecture](docs/azure-infrastructure.md): machines, network, firewall, backups, identity
- [CI/CD](docs/gitactions-pipeline.md): pull request workflow and pipeline checks, deployment with OIDC
- [AI Analyst Agent](docs/agent-analyst.md) how the agent investigates Sentinel incidents
- [Incident Examples](docs/incident-examples.md) attack cases in the lab and how they were detected and investigated

## Contributors
  - **[Tymur](https://github.com/ttysiachnyi)**: on-premises infrastructure, Microsoft Sentinel, AI analyst agent
  - **[George](https://github.com/Freamush)**: cloud infrastructure, hybrid identity sync, CI/CD

## Related
- [Freamush/azure-terraform](https://github.com/Freamush/azure-terraform): the base landing zone this cloud infrastructure builds on.
