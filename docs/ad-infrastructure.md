# Onze - Local Infrastructure

**Domain:** `onze.internal`


### Machines

**DC:** Windows Server 2025 domain controller providing Active Directory, DNS, Kerberos authentication and Group Policy.

**PC01:** Windows 11 employee workstation.

**PC02:** Windows 11 IT administration workstation.

**DEV01:** Ubuntu developer workstation.

**OPNsense:** Firewall and router providing LAN access control, NAT and network filtering.



### Network

**Domain and LAN:** `onze.internal` on `10.10.10.0/24`, using VMware VMnet2 (host-only, DHCP disabled).

**IP addresses:** DC: `10.10.10.10`, PC01: `10.10.10.21`, PC02: `10.10.10.22`, DEV01: `10.10.10.40`, OPNsense LAN: `10.10.10.254`.

**DNS and routing:** DC provides domain DNS. OPNsense is the default gateway at `10.10.10.254`, with WAN connectivity through VMware VMnet8 NAT.

**Tailscale:** DC advertises `10.10.10.10/32` for remote access to the domain controller.

### Active Directory Groups

**Directory structure:** `OU=Accounts` with Employees, Administrators and Service Accounts, plus `OU=Groups`, `OU=Workstations` and `OU=Domain Controllers`.

- **`GG-Employees`:** Standard employee access without administrative privileges.
- **`GG-Developers`:** Developer access, including Lena Peeters's developer role.
- **`GG-IT`:** IT staff group associated with Milan Janssens's regular account.
- **`GG-Workstation-Admins`:** Local administrator access on Windows workstations through Group Policy. Includes `adm.ws.mjanssens` and does not grant domain administration rights.
- **`Domain Users`:** Standard domain accounts with basic domain access.
- **`Domain Admins`:** Domain-level administration, including the built-in `Administrator` account.

**Administrative tiers:** Tier 0 for Active Directory, Tier 1 for servers and Tier 2 for workstations. Separate administrator accounts are used for each tier.



### Users

- **`j.vermeulen`:** Jan Vermeulen, employee and developer using PC01.
- **`l.peeters`:** Lena Peeters, developer using DEV01 and associated with `GG-Developers`.
- **`m.janssens`:** Milan Janssens, IT employee using PC02 and associated with `GG-IT`.
- **`s.devos`:** Standard domain user.
- **`adm.ws.mjanssens`:** Milan Janssens's Tier 2 account for Windows workstation administration, assigned to `GG-Workstation-Admins`.
- **`adm.srv.mjanssens`:** Milan Janssens's separate Tier 1 server administration account.
- **`adm.ad.mjanssens`:** Milan Janssens's separate Tier 0 Active Directory administration account.
- **`Administrator`:** Built-in domain administrator for domain controller and Active Directory management.




### Group Policies (GPO)

Workstation policies apply to `OU=Workstations`. Domain controller policies apply to `OU=Domain Controllers`.

- **Workstations - Security:** Enables Windows Defender Firewall for domain and standard network profiles.
- **Workstations - Logging:** Enables PowerShell Script Block Logging (Event ID `4104`) and command-line details in process creation events (`4688`).
- **Workstations - Audit:** Audits logons, account lockouts, process creation, scheduled tasks, file shares, account and group changes, security policy changes and system integrity. Sets the Security log size to 256 MiB.
- **Workstations - Defender ASR Audit:** Enables audit-mode Attack Surface Reduction rules for Office child processes, obfuscated scripts, downloaded executables, WMI persistence, ransomware activity and vulnerable signed drivers.
- **Workstations - Local Admins:** Adds `GG-Workstation-Admins` to the built-in local Administrators group on Windows workstations without removing existing members.
- **DC - Logging:** Enables PowerShell Script Block Logging and command-line details for process creation.
- **DC - Security Audit:** Audits authentication, Kerberos activity, account and group management, process creation, security policy changes, directory changes and system integrity.




### Collected Logs

#### DC: Domain Controller

Windows Event Logs include Security, System, Application, Directory Service, DNS Server, PowerShell and Sysmon channels.

**Windows Event IDs:**

- `4624`, `4625`, `4634`: Successful logon, failed logon and logoff.
- `4648`, `4672`, `4740`: Explicit-credential logon, privileged logon and account lockout.
- `4768`, `4769`: Kerberos ticket-granting and service ticket requests.
- `4771`, `4776`: Kerberos pre-authentication failure and NTLM credential validation.
- `4720`, `4722`, `4724`, `4726`: User creation, enablement, password reset attempt and deletion.
- `4728`, `4729`, `4732`, `4733`, `4756`, `4757`: Changes to security group membership.
- `4741`, `4742`, `4743`: Computer account creation, modification and deletion.
- `5136`, `5137`, `4662`: Directory object modification, creation and access.
- `4719`, `1102`: Audit policy changes and Security log clearing.
- `4688`: Process creation.
- `4698`, `4702`: Scheduled task creation and updates.
- `7045`: Windows service installation.
- `4104`: PowerShell script block execution.

**Sysmon Event IDs:**

- `1`, `3`: Process creation and network connections.
- `6`, `8`, `9`, `10`: Driver loading, remote thread creation, raw disk access and process access (including LSASS).
- `11`, `12`, `13`, `14`: File creation and registry changes.
- `17`, `18`: Named pipe creation and connections.
- `19`, `20`, `21`: WMI persistence activity.
- `22`, `25`, `29`: DNS queries, process tampering and executable file creation.


#### PC01 and PC02: Windows Workstations

Both workstations use the same Windows Security, System, Application, PowerShell and Sysmon logging approach.

**Windows Event IDs:**

- `4624`, `4625`, `4634`: Successful logon, failed logon and logoff.
- `4648`, `4672`: Explicit-credential logon and privileged logon.
- `4688`: Process creation with command-line details.
- `4698`, `4702`: Scheduled task creation and updates.
- `4732`, `4733`: Local security group membership changes.
- `5140`: Access to network shares.
- `4719`, `1102`: Audit policy changes and Security log clearing.
- `7045`: Windows service installation.
- `4104`: PowerShell script block execution.

**Sysmon Event IDs:**

- `1`, `3`, `5`: Process creation, network connections and process termination.
- `6`, `7`, `8`: Driver and selected DLL loading, and remote thread creation.
- `9`, `10`, `11`: Raw disk access, process access and file creation.
- `12`, `13`, `14`, `15`: Registry changes and alternate data streams.
- `17`, `18`: Named pipe activity.
- `19`, `20`, `21`: WMI persistence activity.
- `22`, `25`, `29`: DNS queries, process tampering and executable file creation.


#### DEV01: Ubuntu Developer Workstation

Linux logging covers authentication, command execution, privilege use and system changes. These records use syslog and auditd event types rather than Windows Event IDs.

- **SSH and authentication:** Login attempts, authentication failures and user sessions.
- **Privilege activity:** `sudo`, PAM activity and sensitive account changes.
- **Process execution:** `auditd` records for `execve` and `execveat`.
- **Persistence:** Changes to cron jobs and systemd services.
- **System security:** Changes to firewall rules, audit settings, network configuration, time settings and kernel modules.


#### OPNsense: Firewall

OPNsense provides network and system logs through syslog.

- **Firewall traffic:** Allowed and blocked connections, interfaces, directions, protocols, IP addresses and ports.
- **Network security:** Blocked traffic, port scans and rejected connection attempts.
- **System activity:** Firewall service events, gateway status, routing, web interface access and DNS or DHCP activity.
