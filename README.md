# ONZE – Secure Hybrid Azure Infrastructure

Secure hybrid cloud infrastructure for a fictional company **ONZE**, built entirely with **Terraform**. It follows the Microsoft Cloud Adoption Framework hub-and-spoke model, connects on-premises **Active Directory** to Microsoft **Entra ID**, ships all logs to **Microsoft Sentinel** and uses self-hosted Analyst Agent **Qwen 3.5 9B**.

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
- **Hub-and-spoke network** with Azure Firewall as a default-deny egress gateway and FQDN-based allowlisting per VM
- **Private-only PaaS access**: Blob Storage and the Recovery Services vault are reachable only through private endpoints
- **Hybrid identity**: AD users and groups synced via Microsoft Entra Connect, with Entra ID login to cloud VMs through RBAC
- **Centralized monitoring**: Azure VMs, Arc-enabled on-premises machines and storage logs land in a single Log Analytics workspace with Microsoft Sentinel (42 analytics rules)
- **Backup** with a tiered daily/weekly/monthly/yearly retention policy
- **Shift-left CI**: Gitleaks, Terraform validation, Checkov and Infracost on every pull request

## Documentation
- [On-Prem Architecture](docs/ad-infrastructure.md): active directory, OPNSense, Qwen 3.5 9B
- [Cloud Architecture](docs/azure-infrastructure.md): machines, network, firewall, backups, identity, Sentinel
- [CI/CD](docs/gitactions-pipeline.md): pull request workflow and pipeline checks

## Related
- [Freamush/azure-terraform](https://github.com/Freamush/azure-terraform): base landing zone cloud infrastructure builds on.
