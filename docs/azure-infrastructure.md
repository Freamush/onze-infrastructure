# ONZE – Cloud Architecture

This infrastructure is deployed with Terraform and builds on the landing zone described in [Freamush/azure-terraform](https://github.com/Freamush/azure-terraform).

## Cloud-only Machines
- **Linux-VM-Spoke1** - Debian VM with a system-assigned managed identity; the only machine allowed to access the `slzstorage` storage account.
- **WIN-VM-Spoke3** - Windows 11 workstation with a system-assigned managed identity, used by members of the `GG-IT` group synchronized from AD.

## Azure Arc Machines (on-premises)
- **DC** – Windows Server 2025 domain controller running Active Directory.
- **ENTRA-CONNECTOR** - Windows Server 2025 running Microsoft Entra Connect.
- **PC01** - Windows 11 employee workstation.
- **PC02** - Windows 11 IT administration workstation.
- **DEV01** - Ubuntu developer workstation.

The on-premises machines are onboarded to Azure Arc so that the Azure Monitor Agent can be deployed to them. Their logs are sent to the Log Analytics workspace, which is connected to Microsoft Sentinel.

## Network
The network follows the hub-and-spoke topology recommended by the Microsoft Cloud Adoption Framework (CAF) for Azure landing zones.
Each spoke is peered with the hub. Route tables on the spoke subnets send all outbound traffic (`0.0.0.0/0`) to the private IP of Azure Firewall in the hub, so every connection leaving a spoke is inspected.
**HUB:** 192.168.0.0/16
**SPOKE1:** 10.0.0.0/16
**SPOKE2:** 172.16.0.0/16
**SPOKE3:** 10.1.0.0/16
**SPOKE4:** 172.17.0.0/16

Spoke2 and Spoke4 host the private endpoints for Blob Storage and the Recovery Services vault respectively, so both services are reachable only over the private network.


## Backups
The Recovery Services vault backs up `Linux-VM-Spoke1` and `WIN-VM-Spoke3`.

**Backup policy:**
- Backups run daily at 23:00 UTC and are retained for 10 days.
- Sunday backups are retained for 4 weeks.
- The backup from the last Sunday of each month is retained for 3 months.
- The backup from the last Sunday of January is retained for 1 year.

## Entra ID & Active Directory
The ONZE infrastructure is a hybrid environment, so on-premises users must be synchronized to the cloud. For this purpose, the `ENTRA-CONNECTOR` machine runs Microsoft Entra Connect, which syncs AD users and groups to Microsoft Entra ID.

As a result, members of the `GG-IT` group in AD can sign in to the cloud-only `WIN-VM-Spoke3` with their domain accounts, since the **Virtual Machine User Login** role is assigned to `GG-IT`.

<img width="1590" height="280" alt="Entra ID role assignment" src="https://github.com/user-attachments/assets/26ddd94b-af60-4504-9459-61c478b89b61" />

## Microsoft Sentinel & Log Analytics
The `azure-log-analytics` Log Analytics workspace is the central log store for the whole infrastructure. It collects logs from the Azure VMs, the storage account (blob read/write/delete operations) and the Arc-enabled machines, which ship their logs via the Azure Monitor Agent.

Microsoft Sentinel is enabled on this workspace and serves as the SIEM. Its analytics rules are deployed with Bicep.

## Firewall
Azure Firewall is deployed in the hub VNet and filters outbound traffic with a default-deny policy. Each VM is allowed to reach only a specific set of FQDNs:

```hcl
destination_fqdns = [
  "login.microsoftonline.com",
  "enterpriseregistration.windows.net",
  "device.login.microsoftonline.com",
  "pas.windows.net",
  "swedencentral.handler.control.monitor.azure.com",
  "global.handler.control.monitor.azure.com",
  "${azurerm_log_analytics_workspace.log_space.workspace_id}.ods.opinsights.azure.com",
  "dc.services.visualstudio.com",
  "ctldl.windowsupdate.com",
  "*.microsoft.com",
  "*.digicert.com"
]
```
*.microsoft.com is allowed for simplicity in the lab. In production, this would be replaced with Azure Firewall FQDN tags and tenant restrictions.

An Azure Monitor alert rule notifies the action group when more than 5 denied requests are logged within 5 minutes.

<img width="777" height="253" alt="image" src="https://github.com/user-attachments/assets/5072363d-5372-40dc-85d4-efbcb2a18d11" />


