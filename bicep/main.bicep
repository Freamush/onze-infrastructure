targetScope = 'resourceGroup'

@description('Existing Log Analytics Workspace in Secure-Landing-Zone-Monitor')
param workspaceName string = 'azure-log-analytics'

@description('Set true only after KQL and source schemas are verified. All newly deployed rules start disabled by default.')
param enableRules bool = false

@description('Deploy domain/Windows SecurityEvent rules')
param deployAD bool = false

@description('Deploy Windows non-Sysmon Event rules')
param deployWindowsEvent bool = false

@description('Deploy Sysmon Event rules')
param deploySysmon bool = false

@description('Deploy Linux Syslog rules')
param deployLinux bool = false

@description('Deploy OPNsense Syslog rules')
param deployOPNsense bool = false

@description('Deploy Entra and ARM Azure rules')
param deployAzure bool = false

@description('Deploy Azure App Service HTTP rules')
param deployAppService bool = false

@description('Deploy expected-host Heartbeat rule')
param deployHeartbeat bool = false

@description('Deploy Microsoft Defender XDR email rule')
param deployEmail bool = false

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

var adRules = [
  {
    id: 'failed-logons'
    name: 'Windows Brute Force'
    severity: 'Medium'
    tactic: 'CredentialAccess'
    technique: 'T1110.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/failed_logons.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IpAddress'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'TargetUserName'
          }
        ]
      }
    ]
  }
  {
    id: 'kerberos-password-spray'
    name: 'Kerberos Password Spray'
    severity: 'High'
    tactic: 'CredentialAccess'
    technique: 'T1110.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/kerberos_password_spray.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SourceIP'
          }
        ]
      }
    ]
  }
  {
    id: 'kerberoasting'
    name: 'Suspicious Kerberos Service Ticket Requests'
    severity: 'High'
    tactic: 'CredentialAccess'
    technique: 'T1558.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/kerberoasting.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SrcIP'
          }
        ]
      }
    ]
  }
  {
    id: 'asrep-without-preauth'
    name: 'Kerberos AS-REP Without Preauth'
    severity: 'Medium'
    tactic: 'CredentialAccess'
    technique: 'T1558.004'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/asrep_without_preauth.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'TargetUserName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IpAddress'
          }
        ]
      }
    ]
  }
  {
    id: 'dcsync'
    name: 'Possible AD Replication Rights Abuse'
    severity: 'High'
    tactic: 'CredentialAccess'
    technique: 'T1003.006'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/dcsync.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'SubjectUserName'
          }
        ]
      }
    ]
  }
  {
    id: 'privileged-group'
    name: 'Privileged Group Membership Changed'
    severity: 'High'
    tactic: 'PrivilegeEscalation'
    technique: 'T1098.007'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/privileged_group.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'ModifiedBy'
          }
        ]
      }
    ]
  }
  {
    id: 'account-lifecycle'
    name: 'AD Account Lifecycle Changes'
    severity: 'Medium'
    tactic: 'Persistence'
    technique: 'T1136.002'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/account_lifecycle.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'TargetUserName'
          }
        ]
      }
    ]
  }
  {
    id: 'gpo-modified'
    name: 'Group Policy AD Object Modified'
    severity: 'High'
    tactic: 'DefenseEvasion'
    technique: 'T1484.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/gpo_modified.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'SubjectUserName'
          }
        ]
      }
    ]
  }
  {
    id: 'dc-rdp'
    name: 'RDP Logon to Domain Controller'
    severity: 'Medium'
    tactic: 'LateralMovement'
    technique: 'T1021.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/dc_rdp.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'TargetUserName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IpAddress'
          }
        ]
      }
    ]
  }
  {
    id: 'security-log-tampering'
    name: 'Security Logs or Audit Policy Changed'
    severity: 'High'
    tactic: 'DefenseEvasion'
    technique: 'T1070.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/security_log_tampering.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'SubjectUserName'
          }
        ]
      }
    ]
  }
  {
    id: 'scheduled-task-security'
    name: 'New or Updated Windows Scheduled Task'
    severity: 'Medium'
    tactic: 'Persistence'
    technique: 'T1053.005'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/ad/scheduled_task_security.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'SubjectUserName'
          }
        ]
      }
    ]
  }
]

var windowsRules = [
  {
    id: 'new-service'
    name: 'New Windows Service'
    severity: 'Medium'
    tactic: 'Persistence'
    technique: 'T1543.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/windows/new_service.kql')
    entityMappings: [
    ]
  }
  {
    id: 'powershell-scriptblock'
    name: 'PowerShell Script Block Indicators'
    severity: 'High'
    tactic: 'Execution'
    technique: 'T1059.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/windows/powershell_scriptblock.kql')
    entityMappings: [
    ]
  }
  {
    id: 'defender-activity'
    name: 'Defender Threat or Configuration Change'
    severity: 'High'
    tactic: 'DefenseEvasion'
    technique: 'T1562.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/windows/defender_activity.kql')
    entityMappings: [
    ]
  }
]

var sysmonRules = [
  {
    id: 'encoded-powershell'
    name: 'Encoded or Downloading PowerShell'
    severity: 'High'
    tactic: 'Execution'
    technique: 'T1059.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/encoded_powershell.kql')
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Account'
          }
        ]
      }
    ]
  }
  {
    id: 'browser-office-shell'
    name: 'Browser or Office Spawns Shell'
    severity: 'High'
    tactic: 'Execution'
    technique: 'T1204.002'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/browser_office_shell.kql')
    entityMappings: [
    ]
  }
  {
    id: 'lsass-access'
    name: 'Process Opens LSASS'
    severity: 'High'
    tactic: 'CredentialAccess'
    technique: 'T1003.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/lsass_access.kql')
    entityMappings: [
    ]
  }
  {
    id: 'registry-run-key'
    name: 'Run Key or Winlogon Persistence'
    severity: 'Medium'
    tactic: 'Persistence'
    technique: 'T1547.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/registry_run_key.kql')
    entityMappings: [
    ]
  }
  {
    id: 'remote-admin-process'
    name: 'Remote Execution Tool Indicators'
    severity: 'Medium'
    tactic: 'LateralMovement'
    technique: 'T1021'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/remote_admin_process.kql')
    entityMappings: [
    ]
  }
  {
    id: 'lateral-movement-connections'
    name: 'Multiple Internal Hosts Contacted on Admin Ports'
    severity: 'Medium'
    tactic: 'LateralMovement'
    technique: 'T1021'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/lateral_movement_connections.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SrcIP'
          }
        ]
      }
    ]
  }
  {
    id: 'internal-port-sweep'
    name: 'Many Successful Connections to Different Ports'
    severity: 'Medium'
    tactic: 'Discovery'
    technique: 'T1046'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/internal_port_sweep.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SrcIP'
          }
        ]
      }
    ]
  }
  {
    id: 'dns-tunnel-indicators'
    name: 'Unusually Long DNS Queries'
    severity: 'Medium'
    tactic: 'CommandAndControl'
    technique: 'T1071.004'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/dns_tunnel_indicators.kql')
    entityMappings: [
    ]
  }
  {
    id: 'regular-outbound-connections'
    name: 'Regular Outbound Network Activity'
    severity: 'Low'
    tactic: 'CommandAndControl'
    technique: 'T1071.001'
    frequency: 'PT15M'
    period: 'PT1H'
    query: loadTextContent('rules/sysmon/regular_outbound_connections.kql')
    entityMappings: [
    ]
  }
  {
    id: 'exfil-tools'
    name: 'Possible Data Upload via Transfer Utilities'
    severity: 'Medium'
    tactic: 'Exfiltration'
    technique: 'T1567.002'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/exfil_tools.kql')
    entityMappings: [
    ]
  }
  {
    id: 'ransomware-recovery'
    name: 'Shadow Copy or Recovery Removal'
    severity: 'High'
    tactic: 'Impact'
    technique: 'T1490'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/ransomware_recovery.kql')
    entityMappings: [
    ]
  }
  {
    id: 'mass-file-creation'
    name: 'High Rate of File Creation in User Folders'
    severity: 'Low'
    tactic: 'Impact'
    technique: 'T1486'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/mass_file_creation.kql')
    entityMappings: [
    ]
  }
  {
    id: 'wmi-subscription'
    name: 'WMI Permanent Event Subscription'
    severity: 'High'
    tactic: 'Persistence'
    technique: 'T1546.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/sysmon/wmi_subscription.kql')
    entityMappings: [
    ]
  }
]

var linuxRules = [
  {
    id: 'ssh-bruteforce'
    name: 'Linux SSH Password Guessing'
    severity: 'Medium'
    tactic: 'CredentialAccess'
    technique: 'T1110.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/linux/ssh_bruteforce.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SourceIP'
          }
        ]
      }
    ]
  }
  {
    id: 'sudo-privilege-changes'
    name: 'Linux Sudo Sensitive Commands'
    severity: 'Medium'
    tactic: 'PrivilegeEscalation'
    technique: 'T1548.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/linux/sudo_privilege_changes.kql')
    entityMappings: [
    ]
  }
  {
    id: 'linux-persistence-commands'
    name: 'Linux Persistence Configuration Commands'
    severity: 'Medium'
    tactic: 'Persistence'
    technique: 'T1053.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/linux/linux_persistence_commands.kql')
    entityMappings: [
    ]
  }
]

var networkRules = [
  {
    id: 'opnsense-blocked-port-sweep'
    name: 'OPNsense Blocked Multi-Port Sweep'
    severity: 'Medium'
    tactic: 'Discovery'
    technique: 'T1046'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/network/opnsense_blocked_port_sweep.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SrcIP'
          }
        ]
      }
    ]
  }
]

var cloudRules = [
  {
    id: 'entra-password-spray'
    name: 'Entra Multi-Account Failed Signins'
    severity: 'High'
    tactic: 'CredentialAccess'
    technique: 'T1110.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/cloud/entra_password_spray.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
    ]
  }
  {
    id: 'entra-role-changes'
    name: 'Entra Directory Role Changes'
    severity: 'High'
    tactic: 'PrivilegeEscalation'
    technique: 'T1098.003'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/cloud/entra_role_changes.kql')
    entityMappings: [
    ]
  }
  {
    id: 'entra-app-consent'
    name: 'Entra Application Consent Events'
    severity: 'Medium'
    tactic: 'Persistence'
    technique: 'T1098.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/cloud/entra_app_consent.kql')
    entityMappings: [
    ]
  }
  {
    id: 'azure-sensitive-changes'
    name: 'Azure Sensitive Management Actions'
    severity: 'High'
    tactic: 'DefenseEvasion'
    technique: 'T1562.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/cloud/azure_sensitive_changes.kql')
    entityMappings: [
    ]
  }
]

var webRules = [
  {
    id: 'appservice-attack-probes'
    name: 'App Service Injection and Path Probes'
    severity: 'Medium'
    tactic: 'InitialAccess'
    technique: 'T1190'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/web/appservice_attack_probes.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'CIp'
          }
        ]
      }
    ]
  }
  {
    id: 'appservice-4xx-sweep'
    name: 'App Service Client 4xx Burst'
    severity: 'Medium'
    tactic: 'Reconnaissance'
    technique: 'T1595'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/web/appservice_4xx_sweep.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'CIp'
          }
        ]
      }
    ]
  }
  {
    id: 'appservice-bulk-download'
    name: 'App Service Large HTTP Response Volume'
    severity: 'Medium'
    tactic: 'Exfiltration'
    technique: 'T1041'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/web/appservice_bulk_download.kql')
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'CIp'
          }
        ]
      }
    ]
  }
]

var monitorRules = [
  {
    id: 'agent-heartbeat-missing'
    name: 'Expected Azure Agent Heartbeat Missing'
    severity: 'Medium'
    tactic: 'DefenseEvasion'
    technique: 'T1562'
    frequency: 'PT15M'
    period: 'PT1H'
    query: loadTextContent('rules/monitor/agent_heartbeat_missing.kql')
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'HostName'
          }
        ]
      }
    ]
  }
]

var emailRules = [
  {
    id: 'phishing-email-detected'
    name: 'Defender Suspicious Email Delivered'
    severity: 'Medium'
    tactic: 'InitialAccess'
    technique: 'T1566.001'
    frequency: 'PT15M'
    period: 'PT15M'
    query: loadTextContent('rules/email/phishing_email_detected.kql')
    entityMappings: [
    ]
  }
]

var rules = concat(
  deployAD ? adRules : [],
  deployWindowsEvent ? windowsRules : [],
  deploySysmon ? sysmonRules : [],
  deployLinux ? linuxRules : [],
  deployOPNsense ? networkRules : [],
  deployAzure ? cloudRules : [],
  deployAppService ? webRules : [],
  deployHeartbeat ? monitorRules : [],
  deployEmail ? emailRules : []
)

resource alertRules 'Microsoft.SecurityInsights/alertRules@2024-03-01' = [for r in rules: {
  scope: ws
  name: guid(ws.id, r.id)
  kind: 'Scheduled'
  properties: union(
    {
      displayName: r.name
      description: 'Scheduled behavioral detection. Some categories require additional data connectors.'
      enabled: enableRules
      severity: r.severity
      tactics: [r.tactic]
      techniques: [split(r.technique, '.')[0]]
      query: r.query
      queryFrequency: r.frequency
      queryPeriod: r.period
      triggerOperator: 'GreaterThan'
      triggerThreshold: 0
      suppressionEnabled: false
      suppressionDuration: 'PT1H'
      eventGroupingSettings: {
        aggregationKind: 'AlertPerResult'
      }
      incidentConfiguration: {
        createIncident: true
      }
    },
    contains(r.technique, '.') ? { subTechniques: [r.technique] } : {},
    length(r.entityMappings) > 0 ? { entityMappings: r.entityMappings } : {}
  )
}]
