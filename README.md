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
- **Hub-and-spoke network** (Microsoft CAF) with Azure Firewall: default-deny egress, threat intelligence in deny mode, FQDN allowlisting per VM
- **Private-only PaaS**: Blob Storage and Recovery Services vault reachable only through private endpoints, shared key access disabled
- **No exposed VMs**: access only through Azure Bastion, credentials in Key Vault, SSH-key-only login on Linux
- **Azure Policy**: denies untagged resources and public IPs on network interfaces
- **Azure Arc**: on-premises servers and workstations onboarded for centralized logging

### On-premises
- **Hardened Active Directory**: GPOs for audit policy, PowerShell script block logging and Defender ASR rules
- **OPNsense perimeter**: firewall and router controlling LAN access and outbound traffic
- **Hybrid identity**: AD users and groups synced to Entra ID with Entra Connect; RBAC on synced groups gives `GG-IT` sign-in to cloud VMs and `SOC-TEAM` access to Sentinel

### Security operations
- **Centralized SIEM**: Azure VMs, Arc machines, firewall and storage logs in one Log Analytics workspace with Microsoft Sentinel
- **Detection as code**: 40+ Sentinel rules in Bicep covering AD attacks (Kerberoasting, DCSync, AS-REP roasting, password spraying), Sysmon, network, cloud and web activity

### AI analyst agent
- **Self-hosted**: local Qwen 3.5 9B model, so no security data leaves the environment
- **Autonomous investigation**: picks up new Sentinel incidents and investigates them with read-only KQL and Sentinel tools
- **Evidence-backed**: every finding cites collected evidence and is checked against locally indexed Microsoft documentation
- **Safe by default**: no incident changes, bounded tool calls and runtime, full audit log

### CI/CD
- **Secretless deployments**: OIDC federated credentials bound to immutable repository IDs, no client secrets
- **Least privilege**: read-only identity for plans, separate write identity available only to the approval-gated `production` environment
- **Shift-left checks**: Gitleaks, Terraform validation, Checkov and Infracost on every pull request, plan posted for review
- **Remote state** in Azure Storage with Entra ID authentication and locking
- **Deployment notifications** by email through Azure Communication Services from a custom domain

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
