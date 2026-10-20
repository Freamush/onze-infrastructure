# ONZE – Secure Hybrid Azure Infrastructure

Secure hybrid cloud infrastructure for a fictional company **ONZE**, built entirely with **Terraform**. It follows the Microsoft Cloud Adoption Framework hub-and-spoke model, connects on-premises **Active Directory** to Microsoft **Entra ID**, ships all logs to **Microsoft Sentinel** and uses self-hosted **AI analyst agent** powered by **Qwen 3.5 9B**.

<img width="4282" height="2040" alt="onze" src="https://github.com/user-attachments/assets/aa24fd66-8dc4-4c9f-8ddc-b1eb92a7ef11" />

## Repository structure
```
.
├── bicep/       #Sentinel rules in policy as code with bicep
├── infra/          # Terraform files with modules (spoke, dcr...)
├── docs/       # Detailed architecture documentation
└── .github/workflows # CI pipelines
```

## Highlights
- **Secured on-premises perimeter**: OPNsense firewall protecting the Active Directory environment
- **Private-only PaaS access**: Blob Storage and the Recovery Services vault are reachable only through private endpoints, with shared key access disabled
- **Governance with Azure Policy**: custom policies deny untagged resources and public IPs on network interfaces
- **Hybrid identity**: AD users and groups synced via Microsoft Entra Connect, with Entra ID login to cloud VMs through RBAC
- **Centralized monitoring**: Azure VMs, Arc-enabled on-premises machines and storage logs land in a single Log Analytics workspace with Microsoft Sentinel
- **Detection as code**: 42 Sentinel analytics rules defined and deployed with Bicep
- **Self-hosted AI analyst**: on-premises Qwen 3.5 9B agent that assists with incident investigation
- **Shift-left CI**: Gitleaks, Terraform validation, Checkov and Infracost on every pull request

## Documentation
- [On-Prem Architecture](docs/ad-infrastructure.md): Active Directory, OPNsense, Qwen 3.5 9B
- [Cloud Architecture](docs/azure-infrastructure.md): machines, network, firewall, backups, identity, Sentinel
- [CI/CD](docs/gitactions-pipeline.md): pull request workflow and pipeline checks

## Contributors
## Contributors
  - **[Tymur](https://github.com/ttysiachnyi)**: on-premises infrastructure, Microsoft Sentinel, AI analyst agent
  - **[George](https://github.com/Freamush)**: cloud infrastructure, hybrid identity sync, CI/CD

## Related
- [Freamush/azure-terraform](https://github.com/Freamush/azure-terraform): the base landing zone this cloud infrastructure builds on.
