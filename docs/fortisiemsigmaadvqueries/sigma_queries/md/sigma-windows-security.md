# Sigma → FortiSIEM: Windows Security

> 144 rules · Generated 2026-03-17

## Table of Contents

- [Potential Access Token Abuse](#potential-access-token-abuse)
- [Admin User Remote Logon](#admin-user-remote-logon)
- [DiagTrackEoP Default Login Username](#diagtrackeop-default-login-username)
- [A Member Was Added to a Security-Enabled Global Group](#a-member-was-added-to-a-security-enabled-global-group)
- [A Member Was Removed From a Security-Enabled Global Group](#a-member-was-removed-from-a-security-enabled-global-group)
- [Successful Overpass the Hash Attempt](#successful-overpass-the-hash-attempt)
- [Pass the Hash Activity 2](#pass-the-hash-activity-2)
- [RDP Login from Localhost](#rdp-login-from-localhost)
- [A Security-Enabled Global Group Was Deleted](#a-security-enabled-global-group-was-deleted)
- [External Remote RDP Logon from Public IP](#external-remote-rdp-logon-from-public-ip)
- [External Remote SMB Logon from Public IP](#external-remote-smb-logon-from-public-ip)
- [Failed Logon From Public IP](#failed-logon-from-public-ip)
- [Outgoing Logon with New Credentials](#outgoing-logon-with-new-credentials)
- [Potential Privilege Escalation via Local Kerberos Relay over LDAP](#potential-privilege-escalation-via-local-kerberos-relay-over-ldap)
- [RottenPotato Like Attack Pattern](#rottenpotato-like-attack-pattern)
- [Successful Account Login Via WMI](#successful-account-login-via-wmi)
- [Windows Filtering Platform Blocked Connection From EDR Agent Binary](#windows-filtering-platform-blocked-connection-from-edr-agent-binary)
- [Azure AD Health Monitoring Agent Registry Keys Access](#azure-ad-health-monitoring-agent-registry-keys-access)
- [Azure AD Health Service Agents Registry Keys Access](#azure-ad-health-service-agents-registry-keys-access)
- [Powerview Add-DomainObjectAcl DCSync AD Extend Right](#powerview-add-domainobjectacl-dcsync-ad-extend-right)
- [AD Privileged Users or Groups Reconnaissance](#ad-privileged-users-or-groups-reconnaissance)
- [AD Object WriteDAC Access](#ad-object-writedac-access)
- [Active Directory Replication from Non Machine Account](#active-directory-replication-from-non-machine-account)
- [Potential AD User Enumeration From Non-Machine Account](#potential-ad-user-enumeration-from-non-machine-account)
- [ADCS Certificate Template Configuration Vulnerability](#adcs-certificate-template-configuration-vulnerability)
- [ADCS Certificate Template Configuration Vulnerability with Risky EKU](#adcs-certificate-template-configuration-vulnerability-with-risky-eku)
- [Add or Remove Computer from DC](#add-or-remove-computer-from-dc)
- [Access To ADMIN$ Network Share](#access-to-admin-network-share)
- [Enabled User Right in AD to Control User Objects](#enabled-user-right-in-ad-to-control-user-objects)
- [Active Directory User Backdoors](#active-directory-user-backdoors)
- [Weak Encryption Enabled and Kerberoast](#weak-encryption-enabled-and-kerberoast)
- [Hacktool Ruler](#hacktool-ruler)
- [Remote Task Creation via ATSVC Named Pipe](#remote-task-creation-via-atsvc-named-pipe)
- [Security Eventlog Cleared](#security-eventlog-cleared)
- [Processes Accessing the Microphone and Webcam](#processes-accessing-the-microphone-and-webcam)
- [CobaltStrike Service Installations - Security](#cobaltstrike-service-installations-security)
- [Failed Code Integrity Checks](#failed-code-integrity-checks)
- [DCERPC SMB Spoolss Named Pipe](#dcerpc-smb-spoolss-named-pipe)
- [DCOM InternetExplorer.Application Iertutil DLL Hijack - Security](#dcom-internetexplorerapplication-iertutil-dll-hijack-security)
- [Mimikatz DC Sync](#mimikatz-dc-sync)
- [Windows Default Domain GPO Modification](#windows-default-domain-gpo-modification)
- [Device Installation Blocked](#device-installation-blocked)
- [Windows Event Auditing Disabled](#windows-event-auditing-disabled)
- [Important Windows Event Auditing Disabled](#important-windows-event-auditing-disabled)
- [ETW Logging Disabled In .NET Processes - Registry](#etw-logging-disabled-in-net-processes-registry)
- [DPAPI Domain Backup Key Extraction](#dpapi-domain-backup-key-extraction)
- [DPAPI Domain Master Key Backup Attempt](#dpapi-domain-master-key-backup-attempt)
- [External Disk Drive Or USB Storage Device Was Recognized By The System](#external-disk-drive-or-usb-storage-device-was-recognized-by-the-system)
- [Persistence and Execution at Scale via GPO Scheduled Task](#persistence-and-execution-at-scale-via-gpo-scheduled-task)
- [Hidden Local User Creation](#hidden-local-user-creation)
- [HackTool - EDRSilencer Execution - Filter Added](#hacktool-edrsilencer-execution-filter-added)
- [HackTool - NoFilter Execution](#hacktool-nofilter-execution)
- [HybridConnectionManager Service Installation](#hybridconnectionmanager-service-installation)
- [Impacket PsExec Execution](#impacket-psexec-execution)
- [Possible Impacket SecretDump Remote Activity](#possible-impacket-secretdump-remote-activity)
- [Invoke-Obfuscation CLIP+ Launcher - Security](#invoke-obfuscation-clip-launcher-security)
- [Invoke-Obfuscation Obfuscated IEX Invocation - Security](#invoke-obfuscation-obfuscated-iex-invocation-security)
- [Invoke-Obfuscation STDIN+ Launcher - Security](#invoke-obfuscation-stdin-launcher-security)
- [Invoke-Obfuscation VAR+ Launcher - Security](#invoke-obfuscation-var-launcher-security)
- [Invoke-Obfuscation COMPRESS OBFUSCATION - Security](#invoke-obfuscation-compress-obfuscation-security)
- [Invoke-Obfuscation RUNDLL LAUNCHER - Security](#invoke-obfuscation-rundll-launcher-security)
- [Invoke-Obfuscation Via Stdin - Security](#invoke-obfuscation-via-stdin-security)
- [Invoke-Obfuscation Via Use Clip - Security](#invoke-obfuscation-via-use-clip-security)
- [Invoke-Obfuscation Via Use MSHTA - Security](#invoke-obfuscation-via-use-mshta-security)
- [Invoke-Obfuscation Via Use Rundll32 - Security](#invoke-obfuscation-via-use-rundll32-security)
- [Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security](#invoke-obfuscation-var-launcher-obfuscation-security)
- [ISO Image Mounted](#iso-image-mounted)
- [Kerberoasting Activity - Initial Query](#kerberoasting-activity-initial-query)
- [Potential AS-REP Roasting via Kerberos TGT Requests](#potential-as-rep-roasting-via-kerberos-tgt-requests)
- [Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation](#potential-kerberos-coercion-by-spoofing-spns-via-dns-manipulation)
- [First Time Seen Remote Named Pipe](#first-time-seen-remote-named-pipe)
- [LSASS Access From Non System Account](#lsass-access-from-non-system-account)
- [Credential Dumping Tools Service Execution - Security](#credential-dumping-tools-service-execution-security)
- [WCE wceaux.dll Access](#wce-wceauxdll-access)
- [Metasploit SMB Authentication](#metasploit-smb-authentication)
- [Metasploit Or Impacket Service Installation Via SMB PsExec](#metasploit-or-impacket-service-installation-via-smb-psexec)
- [Meterpreter or Cobalt Strike Getsystem Service Installation - Security](#meterpreter-or-cobalt-strike-getsystem-service-installation-security)
- [NetNTLM Downgrade Attack](#netntlm-downgrade-attack)
- [Windows Network Access Suspicious desktop.ini Action](#windows-network-access-suspicious-desktopini-action)
- [New or Renamed User Account with '$' Character](#new-or-renamed-user-account-with-character)
- [Denied Access To Remote Desktop](#denied-access-to-remote-desktop)
- [Password Policy Enumerated](#password-policy-enumerated)
- [Windows Pcap Drivers](#windows-pcap-drivers)
- [Possible PetitPotam Coerce Authentication Attempt](#possible-petitpotam-coerce-authentication-attempt)
- [PetitPotam Suspicious Kerberos TGT Request](#petitpotam-suspicious-kerberos-tgt-request)
- [Possible DC Shadow Attack](#possible-dc-shadow-attack)
- [PowerShell Scripts Installed as Services - Security](#powershell-scripts-installed-as-services-security)
- [Protected Storage Service Access](#protected-storage-service-access)
- [RDP over Reverse SSH Tunnel WFP](#rdp-over-reverse-ssh-tunnel-wfp)
- [Register new Logon Process by Rubeus](#register-new-logon-process-by-rubeus)
- [Service Registry Key Read Access Request](#service-registry-key-read-access-request)
- [Remote PowerShell Sessions Network Connections (WinRM)](#remote-powershell-sessions-network-connections-winrm)
- [Replay Attack Detected](#replay-attack-detected)
- [SAM Registry Hive Handle Request](#sam-registry-hive-handle-request)
- [SCM Database Handle Failure](#scm-database-handle-failure)
- [SCM Database Privileged Operation](#scm-database-privileged-operation)
- [Potential Secure Deletion with SDelete](#potential-secure-deletion-with-sdelete)
- [Remote Access Tool Services Have Been Installed - Security](#remote-access-tool-services-have-been-installed-security)
- [Service Installed By Unusual Client - Security](#service-installed-by-unusual-client-security)
- [File Access Of Signal Desktop Sensitive Data](#file-access-of-signal-desktop-sensitive-data)
- [SMB Create Remote File Admin Share](#smb-create-remote-file-admin-share)
- [A New Trust Was Created To A Domain](#a-new-trust-was-created-to-a-domain)
- [Addition of SID History to Active Directory Object](#addition-of-sid-history-to-active-directory-object)
- [Win Susp Computer Name Containing Samtheadmin](#win-susp-computer-name-containing-samtheadmin)
- [Password Change on Directory Service Restore Mode (DSRM) Account](#password-change-on-directory-service-restore-mode-dsrm-account)
- [Account Tampering - Suspicious Failed Logon Reasons](#account-tampering-suspicious-failed-logon-reasons)
- [Group Policy Abuse for Privilege Addition](#group-policy-abuse-for-privilege-addition)
- [Startup/Logon Script Added to Group Policy Object](#startuplogon-script-added-to-group-policy-object)
- [Kerberos Manipulation](#kerberos-manipulation)
- [Suspicious LDAP-Attributes Used](#suspicious-ldap-attributes-used)
- [Suspicious Windows ANONYMOUS LOGON Local Account Created](#suspicious-windows-anonymous-logon-local-account-created)
- [Suspicious Remote Logon with Explicit Credentials](#suspicious-remote-logon-with-explicit-credentials)
- [Password Dumper Activity on LSASS](#password-dumper-activity-on-lsass)
- [Potentially Suspicious AccessMask Requested From LSASS](#potentially-suspicious-accessmask-requested-from-lsass)
- [Reconnaissance Activity](#reconnaissance-activity)
- [Password Protected ZIP File Opened](#password-protected-zip-file-opened)
- [Password Protected ZIP File Opened (Suspicious Filenames)](#password-protected-zip-file-opened-suspicious-filenames)
- [Password Protected ZIP File Opened (Email Attachment)](#password-protected-zip-file-opened-email-attachment)
- [Uncommon Outbound Kerberos Connection - Security](#uncommon-outbound-kerberos-connection-security)
- [Possible Shadow Credentials Added](#possible-shadow-credentials-added)
- [Suspicious PsExec Execution](#suspicious-psexec-execution)
- [Suspicious Access to Sensitive File Extensions](#suspicious-access-to-sensitive-file-extensions)
- [Suspicious Kerberos RC4 Ticket Encryption](#suspicious-kerberos-rc4-ticket-encryption)
- [Suspicious Scheduled Task Creation](#suspicious-scheduled-task-creation)
- [Important Scheduled Task Deleted/Disabled](#important-scheduled-task-deleteddisabled)
- [Suspicious Scheduled Task Update](#suspicious-scheduled-task-update)
- [Unauthorized System Time Modification](#unauthorized-system-time-modification)
- [Remote Service Activity via SVCCTL Named Pipe](#remote-service-activity-via-svcctl-named-pipe)
- [SysKey Registry Keys Access](#syskey-registry-keys-access)
- [Sysmon Channel Reference Deletion](#sysmon-channel-reference-deletion)
- [Tap Driver Installation - Security](#tap-driver-installation-security)
- [Suspicious Teams Application Related ObjectAcess Event](#suspicious-teams-application-related-objectacess-event)
- [Transferring Files with Credential Data via Network Shares](#transferring-files-with-credential-data-via-network-shares)
- [User Added to Local Administrator Group](#user-added-to-local-administrator-group)
- [User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'](#user-couldnt-call-a-privileged-service-lsaregisterlogonprocess)
- [Local User Creation](#local-user-creation)
- [Potential Privileged System Service Operation - SeLoadDriverPrivilege](#potential-privileged-system-service-operation-seloaddriverprivilege)
- [User Logoff Event](#user-logoff-event)
- [VSSAudit Security Event Source Registration](#vssaudit-security-event-source-registration)
- [Windows Defender Exclusion List Modified](#windows-defender-exclusion-list-modified)
- [Windows Defender Exclusion Registry Key - Write Access Requested](#windows-defender-exclusion-registry-key-write-access-requested)
- [WMI Persistence - Security](#wmi-persistence-security)
- [T1047 Wmiprvse Wbemcomn DLL Hijack](#t1047-wmiprvse-wbemcomn-dll-hijack)
- [Locked Workstation](#locked-workstation)

## Potential Access Token Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `02f7c9c1-1ae8-4c6a-8add-04693807f92f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1134.001 |
| **Author** | Michaela Adams, Zach Mathis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_access_token_abuse.yml)**

> Detects potential token impersonation and theft. Example, when using "DuplicateToken(Ex)" and "ImpersonateLoggedOnUser" with the "LOGON32_LOGON_NEW_CREDENTIALS flag".

```sql
-- ============================================================
-- Title:        Potential Access Token Abuse
-- Sigma ID:     02f7c9c1-1ae8-4c6a-8add-04693807f92f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1134.001
-- Author:       Michaela Adams, Zach Mathis
-- Date:         2022-11-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_access_token_abuse.yml
-- Unmapped:     LogonProcessName, AuthenticationPackageName, ImpersonationLevel
-- False Pos:    Anti-Virus
-- ============================================================
-- UNMAPPED_FIELD: LogonProcessName
-- UNMAPPED_FIELD: AuthenticationPackageName
-- UNMAPPED_FIELD: ImpersonationLevel

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '9'
    AND rawEventMsg = 'Advapi'
    AND rawEventMsg = 'Negotiate'
    AND rawEventMsg = '%%1833')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Anti-Virus

**References:**
- https://www.elastic.co/fr/blog/how-attackers-abuse-access-token-manipulation
- https://www.manageengine.com/log-management/cyber-security/access-token-manipulation.html

---

## Admin User Remote Logon

| Field | Value |
|---|---|
| **Sigma ID** | `0f63e1ef-1eb9-4226-9d54-8927ca08520a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.001, T1078.002, T1078.003 |
| **Author** | juju4 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_admin_rdp_login.yml)**

> Detect remote login by Administrator user (depending on internal pattern).

```sql
-- ============================================================
-- Title:        Admin User Remote Logon
-- Sigma ID:     0f63e1ef-1eb9-4226-9d54-8927ca08520a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078.001, T1078.002, T1078.003
-- Author:       juju4
-- Date:         2017-10-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_admin_rdp_login.yml
-- Unmapped:     AuthenticationPackageName
-- False Pos:    Legitimate administrative activity.
-- ============================================================
-- UNMAPPED_FIELD: AuthenticationPackageName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  metrics_string.value[indexOf(metrics_string.name,'targetUser')] AS targetUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '10'
    AND rawEventMsg = 'Negotiate'
    AND indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] LIKE 'Admin%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity.

**References:**
- https://car.mitre.org/wiki/CAR-2016-04-005

---

## DiagTrackEoP Default Login Username

| Field | Value |
|---|---|
| **Sigma ID** | `2111118f-7e46-4fc8-974a-59fd8ec95196` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_diagtrack_eop_default_login_username.yml)**

> Detects the default "UserName" used by the DiagTrackEoP POC

```sql
-- ============================================================
-- Title:        DiagTrackEoP Default Login Username
-- Sigma ID:     2111118f-7e46-4fc8-974a-59fd8ec95196
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_diagtrack_eop_default_login_username.yml
-- Unmapped:     TargetOutboundUserName
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: TargetOutboundUserName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '9'
    AND rawEventMsg = 'thisisnotvaliduser')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/Wh04m1001/DiagTrackEoP/blob/3a2fc99c9700623eb7dc7d4b5f314fd9ce5ef51f/main.cpp#L46

---

## A Member Was Added to a Security-Enabled Global Group

| Field | Value |
|---|---|
| **Sigma ID** | `c43c26be-2e87-46c7-8661-284588c5a53e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Alexandr Yampolskyi, SOC Prime |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml)**

> Detects activity when a member is added to a security-enabled global group

```sql
-- ============================================================
-- Title:        A Member Was Added to a Security-Enabled Global Group
-- Sigma ID:     c43c26be-2e87-46c7-8661-284588c5a53e
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        persistence | T1098
-- Author:       Alexandr Yampolskyi, SOC Prime
-- Date:         2023-04-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4728', 'Win-Security-632')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('4728', '632')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisecurity.org/controls/cis-controls-list/
- https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
- https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4728
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=632

---

## A Member Was Removed From a Security-Enabled Global Group

| Field | Value |
|---|---|
| **Sigma ID** | `02c39d30-02b5-45d2-b435-8aebfe5a8629` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Alexandr Yampolskyi, SOC Prime |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml)**

> Detects activity when a member is removed from a security-enabled global group

```sql
-- ============================================================
-- Title:        A Member Was Removed From a Security-Enabled Global Group
-- Sigma ID:     02c39d30-02b5-45d2-b435-8aebfe5a8629
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        persistence | T1098
-- Author:       Alexandr Yampolskyi, SOC Prime
-- Date:         2023-04-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-633', 'Win-Security-4729')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('633', '4729')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisecurity.org/controls/cis-controls-list/
- https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
- https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4729
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=633

---

## Successful Overpass the Hash Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `192a0330-c20b-4356-90b6-7b7049ae0b87` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1550.002 |
| **Author** | Roberto Rodriguez (source), Dominik Schaudel (rule) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml)**

> Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.

```sql
-- ============================================================
-- Title:        Successful Overpass the Hash Attempt
-- Sigma ID:     192a0330-c20b-4356-90b6-7b7049ae0b87
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1550.002
-- Author:       Roberto Rodriguez (source), Dominik Schaudel (rule)
-- Date:         2018-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml
-- Unmapped:     LogonProcessName, AuthenticationPackageName
-- False Pos:    Runas command-line tool using /netonly parameter
-- ============================================================
-- UNMAPPED_FIELD: LogonProcessName
-- UNMAPPED_FIELD: AuthenticationPackageName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '9'
    AND rawEventMsg = 'seclogo'
    AND rawEventMsg = 'Negotiate')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Runas command-line tool using /netonly parameter

**References:**
- https://web.archive.org/web/20220419045003/https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html

---

## Pass the Hash Activity 2

| Field | Value |
|---|---|
| **Sigma ID** | `8eef149c-bd26-49f2-9e5a-9b00e3af499b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1550.002 |
| **Author** | Dave Kennedy, Jeff Warren (method) / David Vassallo (rule) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml)**

> Detects the attack technique pass the hash which is used to move laterally inside the network

```sql
-- ============================================================
-- Title:        Pass the Hash Activity 2
-- Sigma ID:     8eef149c-bd26-49f2-9e5a-9b00e3af499b
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1550.002
-- Author:       Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)
-- Date:         2019-06-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml
-- Unmapped:     (none)
-- False Pos:    Administrator activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'targetUser')] AS targetUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND NOT (indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] = 'ANONYMOUS LOGON'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator activity

**References:**
- https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
- https://web.archive.org/web/20170909091934/https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis
- https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/

---

## RDP Login from Localhost

| Field | Value |
|---|---|
| **Sigma ID** | `51e33403-2a37-4d66-a574-1fda1782cc31` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.001 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml)**

> RDP login with localhost source address may be a tunnelled login

```sql
-- ============================================================
-- Title:        RDP Login from Localhost
-- Sigma ID:     51e33403-2a37-4d66-a574-1fda1782cc31
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.001
-- Author:       Thomas Patzke
-- Date:         2019-01-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml
-- Unmapped:     IpAddress
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: IpAddress

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '10'
    AND rawEventMsg IN ('::1', '127.0.0.1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html

---

## A Security-Enabled Global Group Was Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `b237c54b-0f15-4612-a819-44b735e0de27` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Alexandr Yampolskyi, SOC Prime |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml)**

> Detects activity when a security-enabled global group is deleted

```sql
-- ============================================================
-- Title:        A Security-Enabled Global Group Was Deleted
-- Sigma ID:     b237c54b-0f15-4612-a819-44b735e0de27
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        persistence | T1098
-- Author:       Alexandr Yampolskyi, SOC Prime
-- Date:         2023-04-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4730', 'Win-Security-634')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('4730', '634')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisecurity.org/controls/cis-controls-list/
- https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
- https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4730
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=634

---

## External Remote RDP Logon from Public IP

| Field | Value |
|---|---|
| **Sigma ID** | `259a9cdf-c4dd-4fa2-b243-2269e5ab18a2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133, T1078, T1110 |
| **Author** | Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml)**

> Detects successful logon from public IP address via RDP. This can indicate a publicly-exposed RDP port.

```sql
-- ============================================================
-- Title:        External Remote RDP Logon from Public IP
-- Sigma ID:     259a9cdf-c4dd-4fa2-b243-2269e5ab18a2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1133, T1078, T1110
-- Author:       Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)
-- Date:         2023-01-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate or intentional inbound connections from public IP addresses on the RDP port.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '10')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate or intentional inbound connections from public IP addresses on the RDP port.

**References:**
- https://www.inversecos.com/2020/04/successful-4624-anonymous-logons-to.html
- https://twitter.com/Purp1eW0lf/status/1616144561965002752

---

## External Remote SMB Logon from Public IP

| Field | Value |
|---|---|
| **Sigma ID** | `78d5cab4-557e-454f-9fb9-a222bd0d5edc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133, T1078, T1110 |
| **Author** | Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml)**

> Detects successful logon from public IP address via SMB. This can indicate a publicly-exposed SMB port.

```sql
-- ============================================================
-- Title:        External Remote SMB Logon from Public IP
-- Sigma ID:     78d5cab4-557e-454f-9fb9-a222bd0d5edc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133, T1078, T1110
-- Author:       Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)
-- Date:         2023-01-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate or intentional inbound connections from public IP addresses on the SMB port.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '3')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate or intentional inbound connections from public IP addresses on the SMB port.

**References:**
- https://www.inversecos.com/2020/04/successful-4624-anonymous-logons-to.html
- https://twitter.com/Purp1eW0lf/status/1616144561965002752

---

## Failed Logon From Public IP

| Field | Value |
|---|---|
| **Sigma ID** | `f88e112a-21aa-44bd-9b01-6ee2a2bbbed1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1190, T1133 |
| **Author** | NVISO |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml)**

> Detects a failed logon attempt from a public IP. A login from a public IP can indicate a misconfigured firewall or network boundary.

```sql
-- ============================================================
-- Title:        Failed Logon From Public IP
-- Sigma ID:     f88e112a-21aa-44bd-9b01-6ee2a2bbbed1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078, T1190, T1133
-- Author:       NVISO
-- Date:         2020-05-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate logon attempts over the internet; IPv4-to-IPv6 mapped IPs
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4625')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4625'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate logon attempts over the internet; IPv4-to-IPv6 mapped IPs

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625

---

## Outgoing Logon with New Credentials

| Field | Value |
|---|---|
| **Sigma ID** | `def8b624-e08f-4ae1-8612-1ba21190da6b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1550 |
| **Author** | Max Altgelt (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml)**

> Detects logon events that specify new credentials

```sql
-- ============================================================
-- Title:        Outgoing Logon with New Credentials
-- Sigma ID:     def8b624-e08f-4ae1-8612-1ba21190da6b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1550
-- Author:       Max Altgelt (Nextron Systems)
-- Date:         2022-04-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate remote administration activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '9')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate remote administration activity

**References:**
- https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf

---

## Potential Privilege Escalation via Local Kerberos Relay over LDAP

| Field | Value |
|---|---|
| **Sigma ID** | `749c9f5e-b353-4b90-a9c1-05243357ca4b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548 |
| **Author** | Elastic, @SBousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml)**

> Detects a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, and the target user SID is the built-in local Administrator account.
This may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined limited user to local System privileges.


```sql
-- ============================================================
-- Title:        Potential Privilege Escalation via Local Kerberos Relay over LDAP
-- Sigma ID:     749c9f5e-b353-4b90-a9c1-05243357ca4b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548
-- Author:       Elastic, @SBousseaden
-- Date:         2022-04-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml
-- Unmapped:     AuthenticationPackageName, IpAddress, TargetUserSid
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AuthenticationPackageName
-- UNMAPPED_FIELD: IpAddress
-- UNMAPPED_FIELD: TargetUserSid

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '3'
    AND rawEventMsg = 'Kerberos'
    AND rawEventMsg = '127.0.0.1'
    AND rawEventMsg LIKE 'S-1-5-21-%'
    AND rawEventMsg LIKE '%-500')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/sbousseaden/status/1518976397364056071?s=12&t=qKO5eKHvWhAP19a50FTZ7g
- https://github.com/elastic/detection-rules/blob/5fe7833312031a4787e07893e27e4ea7a7665745/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml#L38

---

## RottenPotato Like Attack Pattern

| Field | Value |
|---|---|
| **Sigma ID** | `16f5d8ca-44bd-47c8-acbe-6fc95a16c12f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1557.001 |
| **Author** | @SBousseaden, Florian Roth |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_rottenpotato.yml)**

> Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like

```sql
-- ============================================================
-- Title:        RottenPotato Like Attack Pattern
-- Sigma ID:     16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1557.001
-- Author:       @SBousseaden, Florian Roth
-- Date:         2019-11-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_rottenpotato.yml
-- Unmapped:     WorkstationName, IpAddress
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: WorkstationName
-- UNMAPPED_FIELD: IpAddress

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  metrics_string.value[indexOf(metrics_string.name,'targetUser')] AS targetUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND winLogonType = '3'
    AND indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] = 'ANONYMOUS LOGON')
    AND rawEventMsg = '-'
    AND rawEventMsg IN ('127.0.0.1', '::1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1195284233729777665

---

## Successful Account Login Via WMI

| Field | Value |
|---|---|
| **Sigma ID** | `5af54681-df95-4c26-854f-2565e13cfab0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_wmi_login.yml)**

> Detects successful logon attempts performed with WMI

```sql
-- ============================================================
-- Title:        Successful Account Login Via WMI
-- Sigma ID:     5af54681-df95-4c26-854f-2565e13cfab0
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        execution | T1047
-- Author:       Thomas Patzke
-- Date:         2019-12-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_susp_wmi_login.yml
-- Unmapped:     ProcessName
-- False Pos:    Monitoring tools; Legitimate system administration
-- ============================================================
-- UNMAPPED_FIELD: ProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4624')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4624'
    AND rawEventMsg LIKE '%\\WmiPrvSE.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Monitoring tools; Legitimate system administration

**References:**
- Internal Research

---

## Windows Filtering Platform Blocked Connection From EDR Agent Binary

| Field | Value |
|---|---|
| **Sigma ID** | `bacf58c6-e199-4040-a94f-95dea0f1e45a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562 |
| **Author** | @gott_cyber |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/object_access/win_security_wfp_endpoint_agent_blocked.yml)**

> Detects a Windows Filtering Platform (WFP) blocked connection event involving common Endpoint Detection and Response (EDR) agents.
Adversaries may use WFP filters to prevent Endpoint Detection and Response (EDR) agents from reporting security events.


```sql
-- ============================================================
-- Title:        Windows Filtering Platform Blocked Connection From EDR Agent Binary
-- Sigma ID:     bacf58c6-e199-4040-a94f-95dea0f1e45a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562
-- Author:       @gott_cyber
-- Date:         2024-01-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/object_access/win_security_wfp_endpoint_agent_blocked.yml
-- Unmapped:     Application
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: Application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5157')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5157'
    AND (rawEventMsg LIKE '%\\AmSvc.exe' OR rawEventMsg LIKE '%\\cb.exe' OR rawEventMsg LIKE '%\\CETASvc.exe' OR rawEventMsg LIKE '%\\CNTAoSMgr.exe' OR rawEventMsg LIKE '%\\CrAmTray.exe' OR rawEventMsg LIKE '%\\CrsSvc.exe' OR rawEventMsg LIKE '%\\CSFalconContainer.exe' OR rawEventMsg LIKE '%\\CSFalconService.exe' OR rawEventMsg LIKE '%\\CybereasonAV.exe' OR rawEventMsg LIKE '%\\CylanceSvc.exe' OR rawEventMsg LIKE '%\\cyserver.exe' OR rawEventMsg LIKE '%\\CyveraService.exe' OR rawEventMsg LIKE '%\\CyvrFsFlt.exe' OR rawEventMsg LIKE '%\\EIConnector.exe' OR rawEventMsg LIKE '%\\elastic-agent.exe' OR rawEventMsg LIKE '%\\elastic-endpoint.exe' OR rawEventMsg LIKE '%\\EndpointBasecamp.exe' OR rawEventMsg LIKE '%\\ExecutionPreventionSvc.exe' OR rawEventMsg LIKE '%\\filebeat.exe' OR rawEventMsg LIKE '%\\fortiedr.exe' OR rawEventMsg LIKE '%\\hmpalert.exe' OR rawEventMsg LIKE '%\\hurukai.exe' OR rawEventMsg LIKE '%\\LogProcessorService.exe' OR rawEventMsg LIKE '%\\mcsagent.exe' OR rawEventMsg LIKE '%\\mcsclient.exe' OR rawEventMsg LIKE '%\\MsMpEng.exe' OR rawEventMsg LIKE '%\\MsSense.exe' OR rawEventMsg LIKE '%\\Ntrtscan.exe' OR rawEventMsg LIKE '%\\PccNTMon.exe' OR rawEventMsg LIKE '%\\QualysAgent.exe' OR rawEventMsg LIKE '%\\RepMgr.exe' OR rawEventMsg LIKE '%\\RepUtils.exe' OR rawEventMsg LIKE '%\\RepUx.exe' OR rawEventMsg LIKE '%\\RepWAV.exe' OR rawEventMsg LIKE '%\\RepWSC.exe' OR rawEventMsg LIKE '%\\sedservice.exe' OR rawEventMsg LIKE '%\\SenseCncProxy.exe' OR rawEventMsg LIKE '%\\SenseIR.exe' OR rawEventMsg LIKE '%\\SenseNdr.exe' OR rawEventMsg LIKE '%\\SenseSampleUploader.exe' OR rawEventMsg LIKE '%\\SentinelAgent.exe' OR rawEventMsg LIKE '%\\SentinelAgentWorker.exe' OR rawEventMsg LIKE '%\\SentinelBrowserNativeHost.exe' OR rawEventMsg LIKE '%\\SentinelHelperService.exe' OR rawEventMsg LIKE '%\\SentinelServiceHost.exe' OR rawEventMsg LIKE '%\\SentinelStaticEngine.exe' OR rawEventMsg LIKE '%\\SentinelStaticEngineScanner.exe' OR rawEventMsg LIKE '%\\sfc.exe' OR rawEventMsg LIKE '%\\sophos ui.exe' OR rawEventMsg LIKE '%\\sophosfilescanner.exe' OR rawEventMsg LIKE '%\\sophosfs.exe' OR rawEventMsg LIKE '%\\sophoshealth.exe' OR rawEventMsg LIKE '%\\sophosips.exe' OR rawEventMsg LIKE '%\\sophosLivequeryservice.exe' OR rawEventMsg LIKE '%\\sophosnetfilter.exe' OR rawEventMsg LIKE '%\\sophosntpservice.exe' OR rawEventMsg LIKE '%\\sophososquery.exe' OR rawEventMsg LIKE '%\\sspservice.exe' OR rawEventMsg LIKE '%\\TaniumClient.exe' OR rawEventMsg LIKE '%\\TaniumCX.exe' OR rawEventMsg LIKE '%\\TaniumDetectEngine.exe' OR rawEventMsg LIKE '%\\TMBMSRV.exe' OR rawEventMsg LIKE '%\\TmCCSF.exe' OR rawEventMsg LIKE '%\\TmListen.exe' OR rawEventMsg LIKE '%\\TmWSCSvc.exe' OR rawEventMsg LIKE '%\\Traps.exe' OR rawEventMsg LIKE '%\\winlogbeat.exe' OR rawEventMsg LIKE '%\\WSCommunicator.exe' OR rawEventMsg LIKE '%\\xagt.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/netero1010/EDRSilencer
- https://github.com/amjcyber/EDRNoiseMaker
- https://ghoulsec.medium.com/misc-series-4-forensics-on-edrsilencer-events-428b20b3f983

---

## Azure AD Health Monitoring Agent Registry Keys Access

| Field | Value |
|---|---|
| **Sigma ID** | `ff151c33-45fa-475d-af4f-c2f93571f4fe` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1012 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_aadhealth_mon_agent_regkey_access.yml)**

> This detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent.
This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent.


```sql
-- ============================================================
-- Title:        Azure AD Health Monitoring Agent Registry Keys Access
-- Sigma ID:     ff151c33-45fa-475d-af4f-c2f93571f4fe
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1012
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_aadhealth_mon_agent_regkey_access.yml
-- Unmapped:     ObjectType, ObjectName, ProcessName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: ProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId IN ('4656', '4663')
    AND rawEventMsg = 'Key'
    AND rawEventMsg = '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent')
  AND NOT ((rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.InsightsService.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.PshSurrogate.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://o365blog.com/post/hybridhealthagent/
- https://github.com/OTRF/Set-AuditRule/blob/c3dec5443414231714d850565d364ca73475ade5/rules/registry/aad_connect_health_monitoring_agent.yml

---

## Azure AD Health Service Agents Registry Keys Access

| Field | Value |
|---|---|
| **Sigma ID** | `1d2ab8ac-1a01-423b-9c39-001510eae8e8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1012 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_aadhealth_svc_agent_regkey_access.yml)**

> This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents (e.g AD FS).
Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud (e.g. Federation).
This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM:\SOFTWARE\Microsoft\ADHealthAgent.
Make sure you set the SACL to propagate to its sub-keys.


```sql
-- ============================================================
-- Title:        Azure AD Health Service Agents Registry Keys Access
-- Sigma ID:     1d2ab8ac-1a01-423b-9c39-001510eae8e8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1012
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_aadhealth_svc_agent_regkey_access.yml
-- Unmapped:     ObjectType, ObjectName, ProcessName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: ProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId IN ('4656', '4663')
    AND rawEventMsg = 'Key'
    AND rawEventMsg = '\REGISTRY\MACHINE\SOFTWARE\Microsoft\ADHealthAgent')
  AND NOT ((rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.InsightsService.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Adfs.PshSurrogate.exe%' OR rawEventMsg LIKE '%Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://o365blog.com/post/hybridhealthagent/
- https://github.com/OTRF/Set-AuditRule/blob/c3dec5443414231714d850565d364ca73475ade5/rules/registry/aad_connect_health_service_agent.yml

---

## Powerview Add-DomainObjectAcl DCSync AD Extend Right

| Field | Value |
|---|---|
| **Sigma ID** | `2c99737c-585d-4431-b61a-c911d86ff32f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Samir Bousseaden, Roberto Rodriguez @Cyb3rWard0g, oscd.community, Tim Shelton, Maxence Fossat |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml)**

> Backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\Add-DomainObjectAcl DCSync Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer

```sql
-- ============================================================
-- Title:        Powerview Add-DomainObjectAcl DCSync AD Extend Right
-- Sigma ID:     2c99737c-585d-4431-b61a-c911d86ff32f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Samir Bousseaden, Roberto Rodriguez @Cyb3rWard0g, oscd.community, Tim Shelton, Maxence Fossat
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml
-- Unmapped:     AttributeLDAPDisplayName, AttributeValue
-- False Pos:    New Domain Controller computer account, check user SIDs within the value attribute of event 5136 and verify if it's a regular user or DC computer account.
-- ============================================================
-- UNMAPPED_FIELD: AttributeLDAPDisplayName
-- UNMAPPED_FIELD: AttributeValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5136'
    AND rawEventMsg = 'ntSecurityDescriptor'
    AND (rawEventMsg LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%' OR rawEventMsg LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%' OR rawEventMsg LIKE '%89e95b76-444d-4c62-991a-0facbeda640c%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** New Domain Controller computer account, check user SIDs within the value attribute of event 5136 and verify if it's a regular user or DC computer account.

**References:**
- https://twitter.com/menasec1/status/1111556090137903104
- https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf

---

## AD Privileged Users or Groups Reconnaissance

| Field | Value |
|---|---|
| **Sigma ID** | `35ba1d85-724d-42a3-889f-2e2362bcaf23` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.002 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_account_discovery.yml)**

> Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs

```sql
-- ============================================================
-- Title:        AD Privileged Users or Groups Reconnaissance
-- Sigma ID:     35ba1d85-724d-42a3-889f-2e2362bcaf23
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1087.002
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_account_discovery.yml
-- Unmapped:     ObjectType, ObjectName
-- False Pos:    If source account name is not an admin then its super suspicious
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] AS subjectUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4661')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4661'
    AND rawEventMsg IN ('SAM_USER', 'SAM_GROUP'))
  AND ((rawEventMsg LIKE '%-512' OR rawEventMsg LIKE '%-502' OR rawEventMsg LIKE '%-500' OR rawEventMsg LIKE '%-505' OR rawEventMsg LIKE '%-519' OR rawEventMsg LIKE '%-520' OR rawEventMsg LIKE '%-544' OR rawEventMsg LIKE '%-551' OR rawEventMsg LIKE '%-555'))
  OR (rawEventMsg LIKE '%admin%')
  AND NOT (indexOf(metrics_string.name, 'subjectUsername') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] LIKE '%$')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If source account name is not an admin then its super suspicious

**References:**
- https://web.archive.org/web/20230329163438/https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html

---

## AD Object WriteDAC Access

| Field | Value |
|---|---|
| **Sigma ID** | `028c7842-4243-41cd-be6f-12f3cf1a26c7` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1222.001 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_ad_object_writedac_access.yml)**

> Detects WRITE_DAC access to a domain object

```sql
-- ============================================================
-- Title:        AD Object WriteDAC Access
-- Sigma ID:     028c7842-4243-41cd-be6f-12f3cf1a26c7
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1222.001
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_ad_object_writedac_access.yml
-- Unmapped:     ObjectServer, AccessMask, ObjectType
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectServer
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: ObjectType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4662'
    AND rawEventMsg = 'DS'
    AND rawEventMsg = '0x40000'
    AND rawEventMsg IN ('19195a5b-6da0-11d0-afd3-00c04fd930c9', 'domainDNS'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/180815-ADObjectAccessReplication/notebook.html
- https://threathunterplaybook.com/library/windows/active_directory_replication.html
- https://threathunterplaybook.com/hunts/windows/190101-ADModDirectoryReplication/notebook.html

---

## Active Directory Replication from Non Machine Account

| Field | Value |
|---|---|
| **Sigma ID** | `17d619c1-e020-4347-957e-1d1207455c93` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003.006 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml)**

> Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.

```sql
-- ============================================================
-- Title:        Active Directory Replication from Non Machine Account
-- Sigma ID:     17d619c1-e020-4347-957e-1d1207455c93
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003.006
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-07-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml
-- Unmapped:     AccessMask, Properties
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: Properties

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] AS subjectUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4662'
    AND rawEventMsg = '0x100'
    AND (rawEventMsg LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%' OR rawEventMsg LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%' OR rawEventMsg LIKE '%89e95b76-444d-4c62-991a-0facbeda640c%'))
  AND NOT ((indexOf(metrics_string.name, 'subjectUsername') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] LIKE '%$'))
  OR (indexOf(metrics_string.name, 'subjectUsername') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] LIKE 'MSOL\_%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/180815-ADObjectAccessReplication/notebook.html
- https://threathunterplaybook.com/library/windows/active_directory_replication.html
- https://threathunterplaybook.com/hunts/windows/190101-ADModDirectoryReplication/notebook.html

---

## Potential AD User Enumeration From Non-Machine Account

| Field | Value |
|---|---|
| **Sigma ID** | `ab6bffca-beff-4baa-af11-6733f296d57a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.002 |
| **Author** | Maxime Thiebaut (@0xThiebaut) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_ad_user_enumeration.yml)**

> Detects read access to a domain user from a non-machine account

```sql
-- ============================================================
-- Title:        Potential AD User Enumeration From Non-Machine Account
-- Sigma ID:     ab6bffca-beff-4baa-af11-6733f296d57a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1087.002
-- Author:       Maxime Thiebaut (@0xThiebaut)
-- Date:         2020-03-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_ad_user_enumeration.yml
-- Unmapped:     ObjectType, AccessMask
-- False Pos:    Administrators configuring new users.
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: AccessMask

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4662'
    AND rawEventMsg LIKE '%bf967aba-0de6-11d0-a285-00aa003049e2%'
    AND (rawEventMsg LIKE '%1?' OR rawEventMsg LIKE '%3?' OR rawEventMsg LIKE '%4?' OR rawEventMsg LIKE '%7?' OR rawEventMsg LIKE '%9?' OR rawEventMsg LIKE '%B?' OR rawEventMsg LIKE '%D?' OR rawEventMsg LIKE '%F?'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators configuring new users.

**References:**
- https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
- http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html
- https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662

---

## ADCS Certificate Template Configuration Vulnerability

| Field | Value |
|---|---|
| **Sigma ID** | `5ee3a654-372f-11ec-8d3d-0242ac130003` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | Orlinum , BlueDefenZer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability.yml)**

> Detects certificate creation with template allowing risk permission subject

```sql
-- ============================================================
-- Title:        ADCS Certificate Template Configuration Vulnerability
-- Sigma ID:     5ee3a654-372f-11ec-8d3d-0242ac130003
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        (none)
-- Author:       Orlinum , BlueDefenZer
-- Date:         2021-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability.yml
-- Unmapped:     TemplateContent, NewTemplateContent
-- False Pos:    Administrator activity; Proxy SSL certificate with subject modification; Smart card enrollement
-- ============================================================
-- UNMAPPED_FIELD: TemplateContent
-- UNMAPPED_FIELD: NewTemplateContent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4898', 'Win-Security-4899')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4898'
    AND rawEventMsg LIKE '%CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT%')
  OR (winEventId = '4899'
    AND rawEventMsg LIKE '%CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator activity; Proxy SSL certificate with subject modification; Smart card enrollement

**References:**
- https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf

---

## ADCS Certificate Template Configuration Vulnerability with Risky EKU

| Field | Value |
|---|---|
| **Sigma ID** | `bfbd3291-de87-4b7c-88a2-d6a5deb28668` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Orlinum , BlueDefenZer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability_eku.yml)**

> Detects certificate creation with template allowing risk permission subject and risky EKU

```sql
-- ============================================================
-- Title:        ADCS Certificate Template Configuration Vulnerability with Risky EKU
-- Sigma ID:     bfbd3291-de87-4b7c-88a2-d6a5deb28668
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Orlinum , BlueDefenZer
-- Date:         2021-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability_eku.yml
-- Unmapped:     TemplateContent, NewTemplateContent
-- False Pos:    Administrator activity; Proxy SSL certificate with subject modification; Smart card enrollement
-- ============================================================
-- UNMAPPED_FIELD: TemplateContent
-- UNMAPPED_FIELD: NewTemplateContent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4898', 'Win-Security-4899')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4898'
    AND (rawEventMsg LIKE '%1.3.6.1.5.5.7.3.2%' OR rawEventMsg LIKE '%1.3.6.1.5.2.3.4%' OR rawEventMsg LIKE '%1.3.6.1.4.1.311.20.2.2%' OR rawEventMsg LIKE '%2.5.29.37.0%'))
  AND rawEventMsg LIKE '%CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT%')
  OR ((winEventId = '4899'
    AND (rawEventMsg LIKE '%1.3.6.1.5.5.7.3.2%' OR rawEventMsg LIKE '%1.3.6.1.5.2.3.4%' OR rawEventMsg LIKE '%1.3.6.1.4.1.311.20.2.2%' OR rawEventMsg LIKE '%2.5.29.37.0%'))
  AND rawEventMsg LIKE '%CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator activity; Proxy SSL certificate with subject modification; Smart card enrollement

**References:**
- https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf

---

## Add or Remove Computer from DC

| Field | Value |
|---|---|
| **Sigma ID** | `20d96d95-5a20-4cf1-a483-f3bda8a7c037` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1207 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_add_remove_computer.yml)**

> Detects the creation or removal of a computer. Can be used to detect attacks such as DCShadow via the creation of a new SPN.

```sql
-- ============================================================
-- Title:        Add or Remove Computer from DC
-- Sigma ID:     20d96d95-5a20-4cf1-a483-f3bda8a7c037
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1207
-- Author:       frack113
-- Date:         2022-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_add_remove_computer.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4741', 'Win-Security-4743')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('4741', '4743')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4741
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4743

---

## Access To ADMIN$ Network Share

| Field | Value |
|---|---|
| **Sigma ID** | `098d7118-55bc-4912-a836-dc6483a8d150` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_admin_share_access.yml)**

> Detects access to ADMIN$ network share

```sql
-- ============================================================
-- Title:        Access To ADMIN$ Network Share
-- Sigma ID:     098d7118-55bc-4912-a836-dc6483a8d150
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_admin_share_access.yml
-- Unmapped:     ShareName
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: ShareName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5140')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5140'
    AND rawEventMsg = 'Admin$')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140

---

## Enabled User Right in AD to Control User Objects

| Field | Value |
|---|---|
| **Sigma ID** | `311b6ce2-7890-4383-a8c2-663a9f6b43cd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_active_directory_user_control.yml)**

> Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.

```sql
-- ============================================================
-- Title:        Enabled User Right in AD to Control User Objects
-- Sigma ID:     311b6ce2-7890-4383-a8c2-663a9f6b43cd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       @neu5ron
-- Date:         2017-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_active_directory_user_control.yml
-- Unmapped:     PrivilegeList
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: PrivilegeList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4704')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4704'
  AND rawEventMsg LIKE '%SeEnableDelegationPrivilege%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/

---

## Active Directory User Backdoors

| Field | Value |
|---|---|
| **Sigma ID** | `300bac00-e041-4ee2-9c36-e262656a6ecc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_ad_user_backdoors.yml)**

> Detects scenarios where one can control another users or computers account without having to use their credentials.

```sql
-- ============================================================
-- Title:        Active Directory User Backdoors
-- Sigma ID:     300bac00-e041-4ee2-9c36-e262656a6ecc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       @neu5ron
-- Date:         2017-04-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_ad_user_backdoors.yml
-- Unmapped:     AttributeLDAPDisplayName, ObjectClass
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AttributeLDAPDisplayName
-- UNMAPPED_FIELD: ObjectClass

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4738', 'Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4738'
  OR (winEventId = '5136'
    AND rawEventMsg = 'msDS-AllowedToDelegateTo')
  OR (winEventId = '5136'
    AND rawEventMsg = 'user'
    AND rawEventMsg = 'servicePrincipalName')
  OR (winEventId = '5136'
    AND rawEventMsg = 'msDS-AllowedToActOnBehalfOfOtherIdentity')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://msdn.microsoft.com/en-us/library/cc220234.aspx
- https://adsecurity.org/?p=3466
- https://blog.harmj0y.net/redteaming/another-word-on-delegation/

---

## Weak Encryption Enabled and Kerberoast

| Field | Value |
|---|---|
| **Sigma ID** | `f6de9536-0441-4b3f-a646-f4e00f300ffd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_enable_weak_encryption.yml)**

> Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.

```sql
-- ============================================================
-- Title:        Weak Encryption Enabled and Kerberoast
-- Sigma ID:     f6de9536-0441-4b3f-a646-f4e00f300ffd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       @neu5ron
-- Date:         2017-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_enable_weak_encryption.yml
-- Unmapped:     NewUacValue, OldUacValue
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: NewUacValue
-- UNMAPPED_FIELD: OldUacValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4738')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4738'
  AND (rawEventMsg LIKE '%8???' OR rawEventMsg LIKE '%9???' OR rawEventMsg LIKE '%A???' OR rawEventMsg LIKE '%B???' OR rawEventMsg LIKE '%C???' OR rawEventMsg LIKE '%D???' OR rawEventMsg LIKE '%E???' OR rawEventMsg LIKE '%F???')
  AND NOT ((rawEventMsg LIKE '%8???' OR rawEventMsg LIKE '%9???' OR rawEventMsg LIKE '%A???' OR rawEventMsg LIKE '%B???' OR rawEventMsg LIKE '%C???' OR rawEventMsg LIKE '%D???' OR rawEventMsg LIKE '%E???' OR rawEventMsg LIKE '%F???')))
  OR ((rawEventMsg LIKE '%1????' OR rawEventMsg LIKE '%3????' OR rawEventMsg LIKE '%5????' OR rawEventMsg LIKE '%7????' OR rawEventMsg LIKE '%9????' OR rawEventMsg LIKE '%B????' OR rawEventMsg LIKE '%D????' OR rawEventMsg LIKE '%F????')
  AND NOT ((rawEventMsg LIKE '%1????' OR rawEventMsg LIKE '%3????' OR rawEventMsg LIKE '%5????' OR rawEventMsg LIKE '%7????' OR rawEventMsg LIKE '%9????' OR rawEventMsg LIKE '%B????' OR rawEventMsg LIKE '%D????' OR rawEventMsg LIKE '%F????')))
  OR ((rawEventMsg LIKE '%8??' OR rawEventMsg LIKE '%9??' OR rawEventMsg LIKE '%A??' OR rawEventMsg LIKE '%B??' OR rawEventMsg LIKE '%C??' OR rawEventMsg LIKE '%D??' OR rawEventMsg LIKE '%E??' OR rawEventMsg LIKE '%F??')
  AND NOT ((rawEventMsg LIKE '%8??' OR rawEventMsg LIKE '%9??' OR rawEventMsg LIKE '%A??' OR rawEventMsg LIKE '%B??' OR rawEventMsg LIKE '%C??' OR rawEventMsg LIKE '%D??' OR rawEventMsg LIKE '%E??' OR rawEventMsg LIKE '%F??')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://adsecurity.org/?p=2053
- https://blog.harmj0y.net/redteaming/another-word-on-delegation/

---

## Hacktool Ruler

| Field | Value |
|---|---|
| **Sigma ID** | `24549159-ac1b-479c-8175-d42aea947cae` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery, execution, collection |
| **MITRE Techniques** | T1087, T1114, T1059, T1550.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_ruler.yml)**

> This events that are generated when using the hacktool Ruler by Sensepost

```sql
-- ============================================================
-- Title:        Hacktool Ruler
-- Sigma ID:     24549159-ac1b-479c-8175-d42aea947cae
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery, execution, collection | T1087, T1114, T1059, T1550.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-05-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_alert_ruler.yml
-- Unmapped:     (none)
-- False Pos:    Go utilities that use staaldraad awesome NTLM library
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4776', 'Win-Security-4624', 'Win-Security-4625')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Go utilities that use staaldraad awesome NTLM library

**References:**
- https://github.com/sensepost/ruler
- https://github.com/sensepost/ruler/issues/47
- https://github.com/staaldraad/go-ntlm/blob/cd032d41aa8ce5751c07cb7945400c0f5c81e2eb/ntlm/ntlmv1.go#L427
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624

---

## Remote Task Creation via ATSVC Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `f6de6525-4509-495a-8a82-1f8b0ed73a00` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.002 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_atsvc_task.yml)**

> Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

```sql
-- ============================================================
-- Title:        Remote Task Creation via ATSVC Named Pipe
-- Sigma ID:     f6de6525-4509-495a-8a82-1f8b0ed73a00
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.002
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_atsvc_task.yml
-- Unmapped:     ShareName, RelativeTargetName, AccessList
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName
-- UNMAPPED_FIELD: AccessList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\IPC$'
    AND rawEventMsg = 'atsvc'
    AND rawEventMsg LIKE '%WriteData%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230409194125/https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html

---

## Security Eventlog Cleared

| Field | Value |
|---|---|
| **Sigma ID** | `d99b79d2-0a6f-4f46-ad8b-260b6e17f982` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_audit_log_cleared.yml)**

> One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution

```sql
-- ============================================================
-- Title:        Security Eventlog Cleared
-- Sigma ID:     d99b79d2-0a6f-4f46-ad8b-260b6e17f982
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-01-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_audit_log_cleared.yml
-- Unmapped:     (none)
-- False Pos:    Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-517', 'Win-Security-1102')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '1102'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Eventlog'))
  OR (winEventId = '517'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Security'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)

**References:**
- https://twitter.com/deviouspolack/status/832535435960209408
- https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100
- https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/SecurityEvent/SecurityEventLogCleared.yaml

---

## Processes Accessing the Microphone and Webcam

| Field | Value |
|---|---|
| **Sigma ID** | `8cd538a4-62d5-4e83-810b-12d41e428d6e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1123 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_camera_microphone_access.yml)**

> Potential adversaries accessing the microphone and webcam in an endpoint.

```sql
-- ============================================================
-- Title:        Processes Accessing the Microphone and Webcam
-- Sigma ID:     8cd538a4-62d5-4e83-810b-12d41e428d6e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1123
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_camera_microphone_access.yml
-- Unmapped:     ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4657', 'Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4657', '4656', '4663')
    AND (rawEventMsg LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged%' OR rawEventMsg LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/duzvik/status/1269671601852813320
- https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

---

## CobaltStrike Service Installations - Security

| Field | Value |
|---|---|
| **Sigma ID** | `d7a95147-145f-4678-b85d-d1ff4a3bb3f6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1021.002, T1543.003, T1569.002 |
| **Author** | Florian Roth (Nextron Systems), Wojciech Lesicki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_cobaltstrike_service_installs.yml)**

> Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement

```sql
-- ============================================================
-- Title:        CobaltStrike Service Installations - Security
-- Sigma ID:     d7a95147-145f-4678-b85d-d1ff4a3bb3f6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1021.002, T1543.003, T1569.002
-- Author:       Florian Roth (Nextron Systems), Wojciech Lesicki
-- Date:         2021-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_cobaltstrike_service_installs.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4697'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.sans.org/webcasts/119395
- https://www.crowdstrike.com/blog/getting-the-bacon-from-cobalt-strike-beacon/
- https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/

---

## Failed Code Integrity Checks

| Field | Value |
|---|---|
| **Sigma ID** | `470ec5fa-7b4e-4071-b200-4c753100f49b` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1027.001 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_codeintegrity_check_failure.yml)**

> Detects code integrity failures such as missing page hashes or corrupted drivers due unauthorized modification. This could be a sign of tampered binaries.


```sql
-- ============================================================
-- Title:        Failed Code Integrity Checks
-- Sigma ID:     470ec5fa-7b4e-4071-b200-4c753100f49b
-- Level:        informational  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1027.001
-- Author:       Thomas Patzke
-- Date:         2019-12-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_codeintegrity_check_failure.yml
-- Unmapped:     (none)
-- False Pos:    Disk device errors
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5038', 'Win-Security-6281')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('5038', '6281')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Disk device errors

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5038
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6281

---

## DCERPC SMB Spoolss Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `214e8f95-100a-4e04-bb31-ef6cba8ce07e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.002 |
| **Author** | OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dce_rpc_smb_spoolss_named_pipe.yml)**

> Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.

```sql
-- ============================================================
-- Title:        DCERPC SMB Spoolss Named Pipe
-- Sigma ID:     214e8f95-100a-4e04-bb31-ef6cba8ce07e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.002
-- Author:       OTR (Open Threat Research)
-- Date:         2018-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dce_rpc_smb_spoolss_named_pipe.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Domain Controllers acting as printer servers too? :)
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\IPC$'
    AND rawEventMsg = 'spoolss')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Domain Controllers acting as printer servers too? :)

**References:**
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://dirkjanm.io/a-different-way-of-abusing-zerologon/
- https://twitter.com/_dirkjan/status/1309214379003588608

---

## DCOM InternetExplorer.Application Iertutil DLL Hijack - Security

| Field | Value |
|---|---|
| **Sigma ID** | `c39f0c81-7348-4965-ab27-2fde35a1b641` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002, T1021.003 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dcom_iertutil_dll_hijack.yml)**

> Detects a threat actor creating a file named `iertutil.dll` in the `C:\Program Files\Internet Explorer\` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.

```sql
-- ============================================================
-- Title:        DCOM InternetExplorer.Application Iertutil DLL Hijack - Security
-- Sigma ID:     c39f0c81-7348-4965-ab27-2fde35a1b641
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002, T1021.003
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dcom_iertutil_dll_hijack.yml
-- Unmapped:     RelativeTargetName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] AS subjectUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '5145'
    AND rawEventMsg LIKE '%\\Internet Explorer\\iertutil.dll')
  AND NOT (indexOf(metrics_string.name, 'subjectUsername') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] LIKE '%$')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html

---

## Mimikatz DC Sync

| Field | Value |
|---|---|
| **Sigma ID** | `611eab06-a145-4dfa-a295-3ccc5c20f59a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.006 |
| **Author** | Benjamin Delpy, Florian Roth (Nextron Systems), Scott Dermott, Sorina Ionescu |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dcsync.yml)**

> Detects Mimikatz DC sync security events

```sql
-- ============================================================
-- Title:        Mimikatz DC Sync
-- Sigma ID:     611eab06-a145-4dfa-a295-3ccc5c20f59a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.006
-- Author:       Benjamin Delpy, Florian Roth (Nextron Systems), Scott Dermott, Sorina Ionescu
-- Date:         2018-06-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dcsync.yml
-- Unmapped:     Properties, AccessMask
-- False Pos:    Valid DC Sync that is not covered by the filters; please report; Local Domain Admin account used for Azure AD Connect
-- ============================================================
-- UNMAPPED_FIELD: Properties
-- UNMAPPED_FIELD: AccessMask

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4662'
    AND (rawEventMsg LIKE '%Replicating Directory Changes All%' OR rawEventMsg LIKE '%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%' OR rawEventMsg LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%' OR rawEventMsg LIKE '%9923a32a-3607-11d2-b9be-0000f87a36b2%' OR rawEventMsg LIKE '%89e95b76-444d-4c62-991a-0facbeda640c%')
    AND rawEventMsg = '0x100')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid DC Sync that is not covered by the filters; please report; Local Domain Admin account used for Azure AD Connect

**References:**
- https://twitter.com/gentilkiwi/status/1003236624925413376
- https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
- https://blog.blacklanternsecurity.com/p/detecting-dcsync?s=r
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662

---

## Windows Default Domain GPO Modification

| Field | Value |
|---|---|
| **Sigma ID** | `e5ac86dd-2da1-454b-be74-05d26c769d7d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1484.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_default_domain_gpo_modification.yml)**

> Detects modifications to Default Domain or Default Domain Controllers Group Policy Objects (GPOs).
Adversaries may modify these default GPOs to deploy malicious configurations across the domain.


```sql
-- ============================================================
-- Title:        Windows Default Domain GPO Modification
-- Sigma ID:     e5ac86dd-2da1-454b-be74-05d26c769d7d
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1484.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_default_domain_gpo_modification.yml
-- Unmapped:     ObjectClass, ObjectDN
-- False Pos:    Legitimate modifications to Default Domain or Default Domain Controllers GPOs
-- ============================================================
-- UNMAPPED_FIELD: ObjectClass
-- UNMAPPED_FIELD: ObjectDN

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5136'
    AND rawEventMsg = 'groupPolicyContainer'
    AND (rawEventMsg LIKE 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM%' OR rawEventMsg LIKE 'CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate modifications to Default Domain or Default Domain Controllers GPOs

**References:**
- https://www.trendmicro.com/en_us/research/25/i/unmasking-the-gentlemen-ransomware.html
- https://adsecurity.org/?p=3377
- https://www.pentestpartners.com/security-blog/living-off-the-land-gpo-style/
- https://jgspiers.com/audit-group-policy-changes/

---

## Device Installation Blocked

| Field | Value |
|---|---|
| **Sigma ID** | `c9eb55c3-b468-40ab-9089-db2862e42137` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1200 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_device_installation_blocked.yml)**

> Detects an installation of a device that is forbidden by the system policy

```sql
-- ============================================================
-- Title:        Device Installation Blocked
-- Sigma ID:     c9eb55c3-b468-40ab-9089-db2862e42137
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1200
-- Author:       frack113
-- Date:         2022-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_device_installation_blocked.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-6423')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '6423'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6423

---

## Windows Event Auditing Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `69aeb277-f15f-4d2d-b32a-55e883609563` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.002 |
| **Author** | @neu5ron, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_disable_event_auditing.yml)**

> Detects scenarios where system auditing (i.e.: Windows event log auditing) is disabled.
This may be used in a scenario where an entity would want to bypass local logging to evade detection when Windows event logging is enabled and reviewed.
Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc".
Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications - however, it is recommended to perform these modifications in Active Directory anyways.


```sql
-- ============================================================
-- Title:        Windows Event Auditing Disabled
-- Sigma ID:     69aeb277-f15f-4d2d-b32a-55e883609563
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.002
-- Author:       @neu5ron, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2017-11-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_disable_event_auditing.yml
-- Unmapped:     AuditPolicyChanges
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AuditPolicyChanges

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4719')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4719'
    AND (rawEventMsg LIKE '%\%\%8448%' OR rawEventMsg LIKE '%\%\%8450%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit

---

## Important Windows Event Auditing Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `ab4561b1-6c7e-48a7-ad08-087cfb9ce8f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_disable_event_auditing_critical.yml)**

> Detects scenarios where system auditing for important events such as "Process Creation" or "Logon" events is disabled.

```sql
-- ============================================================
-- Title:        Important Windows Event Auditing Disabled
-- Sigma ID:     ab4561b1-6c7e-48a7-ad08-087cfb9ce8f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_disable_event_auditing_critical.yml
-- Unmapped:     SubcategoryGuid, AuditPolicyChanges
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: SubcategoryGuid
-- UNMAPPED_FIELD: AuditPolicyChanges

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4719')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4719'
    AND rawEventMsg IN ('{0CCE9210-69AE-11D9-BED3-505054503030}', '{0CCE9211-69AE-11D9-BED3-505054503030}', '{0CCE9212-69AE-11D9-BED3-505054503030}', '{0CCE9215-69AE-11D9-BED3-505054503030}', '{0CCE921B-69AE-11D9-BED3-505054503030}', '{0CCE922B-69AE-11D9-BED3-505054503030}', '{0CCE922F-69AE-11D9-BED3-505054503030}', '{0CCE9230-69AE-11D9-BED3-505054503030}', '{0CCE9235-69AE-11D9-BED3-505054503030}', '{0CCE9236-69AE-11D9-BED3-505054503030}', '{0CCE9237-69AE-11D9-BED3-505054503030}', '{0CCE923F-69AE-11D9-BED3-505054503030}', '{0CCE9240-69AE-11D9-BED3-505054503030}', '{0CCE9242-69AE-11D9-BED3-505054503030}')
    AND (rawEventMsg LIKE '%\%\%8448%' OR rawEventMsg LIKE '%\%\%8450%'))
  OR (winEventId = '4719'
    AND rawEventMsg = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    AND rawEventMsg LIKE '%\%\%8448%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://docs.google.com/presentation/d/1dkrldTTlN3La-OjWtkWJBb4hVk6vfsSMBFBERs6R8zA/edit
- https://github.com/SigmaHQ/sigma/blob/ad1bfd3d28aa0ccc9656240f845022518ef65a2e/documentation/logsource-guides/windows/service/security.md

---

## ETW Logging Disabled In .NET Processes - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `a4c90ea1-2634-4ca0-adbb-35eae169b6fc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112, T1562 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dot_net_etw_tamper.yml)**

> Potential adversaries stopping ETW providers recording loaded .NET assemblies.

```sql
-- ============================================================
-- Title:        ETW Logging Disabled In .NET Processes - Registry
-- Sigma ID:     a4c90ea1-2634-4ca0-adbb-35eae169b6fc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112, T1562
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-06-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dot_net_etw_tamper.yml
-- Unmapped:     ObjectName, ObjectValueName, NewValue
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: ObjectValueName
-- UNMAPPED_FIELD: NewValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4657')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4657'
    AND rawEventMsg LIKE '%\\Environment%'
    AND rawEventMsg IN ('COMPlus_ETWEnabled', 'COMPlus_ETWFlags')
    AND rawEventMsg = '0')
  OR (winEventId = '4657'
    AND rawEventMsg LIKE '%\\SOFTWARE\\Microsoft\\.NETFramework'
    AND rawEventMsg = 'ETWEnabled'
    AND rawEventMsg = '0')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/_xpn_/status/1268712093928378368
- https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
- https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
- https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
- https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
- https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
- https://bunnyinside.com/?term=f71e8cb9c76a
- http://managed670.rssing.com/chan-5590147/all_p1.html
- https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code
- https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf

---

## DPAPI Domain Backup Key Extraction

| Field | Value |
|---|---|
| **Sigma ID** | `4ac1f50b-3bd0-4968-902d-868b4647937e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.004 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dpapi_domain_backupkey_extraction.yml)**

> Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers

```sql
-- ============================================================
-- Title:        DPAPI Domain Backup Key Extraction
-- Sigma ID:     4ac1f50b-3bd0-4968-902d-868b4647937e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.004
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dpapi_domain_backupkey_extraction.yml
-- Unmapped:     ObjectType, AccessMask, ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4662'
    AND rawEventMsg = 'SecretObject'
    AND rawEventMsg = '0x2'
    AND rawEventMsg LIKE '%BCKUPKEY%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html

---

## DPAPI Domain Master Key Backup Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `39a94fd1-8c9a-4ff6-bf22-c058762f8014` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.004 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dpapi_domain_masterkey_backup_attempt.yml)**

> Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.

```sql
-- ============================================================
-- Title:        DPAPI Domain Master Key Backup Attempt
-- Sigma ID:     39a94fd1-8c9a-4ff6-bf22-c058762f8014
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.004
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dpapi_domain_masterkey_backup_attempt.yml
-- Unmapped:     (none)
-- False Pos:    If a computer is a member of a domain, DPAPI has a backup mechanism to allow unprotection of the data. Which will trigger this event.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4692')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4692'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If a computer is a member of a domain, DPAPI has a backup mechanism to allow unprotection of the data. Which will trigger this event.

**References:**
- https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html

---

## External Disk Drive Or USB Storage Device Was Recognized By The System

| Field | Value |
|---|---|
| **Sigma ID** | `f69a87ea-955e-4fb4-adb2-bb9fd6685632` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1091, T1200 |
| **Author** | Keith Wright |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_external_device.yml)**

> Detects external disk drives or plugged-in USB devices.

```sql
-- ============================================================
-- Title:        External Disk Drive Or USB Storage Device Was Recognized By The System
-- Sigma ID:     f69a87ea-955e-4fb4-adb2-bb9fd6685632
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1091, T1200
-- Author:       Keith Wright
-- Date:         2019-11-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_external_device.yml
-- Unmapped:     ClassName, DeviceDescription
-- False Pos:    Likely
-- ============================================================
-- UNMAPPED_FIELD: ClassName
-- UNMAPPED_FIELD: DeviceDescription

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-6416')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '6416'
  AND (rawEventMsg = 'DiskDrive')
  OR (rawEventMsg = 'USB Mass Storage Device'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6416

---

## Persistence and Execution at Scale via GPO Scheduled Task

| Field | Value |
|---|---|
| **Sigma ID** | `a8f29a7b-b137-4446-80a0-b804272f3da2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_gpo_scheduledtasks.yml)**

> Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale

```sql
-- ============================================================
-- Title:        Persistence and Execution at Scale via GPO Scheduled Task
-- Sigma ID:     a8f29a7b-b137-4446-80a0-b804272f3da2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_gpo_scheduledtasks.yml
-- Unmapped:     AttributeLDAPDisplayName, AttributeValue, ShareName, RelativeTargetName, AccessList
-- False Pos:    If the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduled tasks.
-- ============================================================
-- UNMAPPED_FIELD: AttributeLDAPDisplayName
-- UNMAPPED_FIELD: AttributeValue
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName
-- UNMAPPED_FIELD: AccessList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136', 'Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5136'
    AND rawEventMsg IN ('gPCMachineExtensionNames', 'gPCUserExtensionNames')
    AND (rawEventMsg LIKE '%CAB54552-DEEA-4691-817E-ED4A4D1AFC72%' OR rawEventMsg LIKE '%AADCED64-746C-4633-A97C-D61349046527%'))
  OR (winEventId = '5145'
    AND rawEventMsg LIKE '%\\SYSVOL'
    AND rawEventMsg LIKE '%ScheduledTasks.xml'
    AND (rawEventMsg LIKE '%WriteData%' OR rawEventMsg LIKE '%\%\%4417%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduled tasks.

**References:**
- https://twitter.com/menasec1/status/1106899890377052160
- https://www.secureworks.com/blog/ransomware-as-a-distraction
- https://www.elastic.co/guide/en/security/7.17/prebuilt-rule-0-16-1-scheduled-task-execution-at-scale-via-gpo.html

---

## Hidden Local User Creation

| Field | Value |
|---|---|
| **Sigma ID** | `7b449a5e-1db5-4dd0-a2dc-4e3a67282538` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hidden_user_creation.yml)**

> Detects the creation of a local hidden user account which should not happen for event ID 4720.

```sql
-- ============================================================
-- Title:        Hidden Local User Creation
-- Sigma ID:     7b449a5e-1db5-4dd0-a2dc-4e3a67282538
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1136.001
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-05-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hidden_user_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'targetUser')] AS targetUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4720')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4720'
    AND indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] LIKE '%$'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1387743867663958021

---

## HackTool - EDRSilencer Execution - Filter Added

| Field | Value |
|---|---|
| **Sigma ID** | `98054878-5eab-434c-85d4-72d4e5a3361b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562 |
| **Author** | Thodoris Polyzos (@SmoothDeploy) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hktl_edr_silencer.yml)**

> Detects execution of EDRSilencer, a tool that abuses the Windows Filtering Platform (WFP) to block the outbound traffic of running EDR agents based on specific hardcoded filter names.


```sql
-- ============================================================
-- Title:        HackTool - EDRSilencer Execution - Filter Added
-- Sigma ID:     98054878-5eab-434c-85d4-72d4e5a3361b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562
-- Author:       Thodoris Polyzos (@SmoothDeploy)
-- Date:         2024-01-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hktl_edr_silencer.yml
-- Unmapped:     FilterName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: FilterName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5441', 'Win-Security-5447')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('5441', '5447')
    AND rawEventMsg LIKE '%Custom Outbound Filter%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/netero1010/EDRSilencer

---

## HackTool - NoFilter Execution

| Field | Value |
|---|---|
| **Sigma ID** | `7b14c76a-c602-4ae6-9717-eff868153fc0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1134, T1134.001 |
| **Author** | Stamatis Chatzimangou (st0pp3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hktl_nofilter.yml)**

> Detects execution of NoFilter, a tool for abusing the Windows Filtering Platform for privilege escalation via hardcoded policy name indicators


```sql
-- ============================================================
-- Title:        HackTool - NoFilter Execution
-- Sigma ID:     7b14c76a-c602-4ae6-9717-eff868153fc0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1134, T1134.001
-- Author:       Stamatis Chatzimangou (st0pp3r)
-- Date:         2024-01-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hktl_nofilter.yml
-- Unmapped:     FilterName, ProviderContextName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: FilterName
-- UNMAPPED_FIELD: ProviderContextName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5447', 'Win-Security-5449')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5447'
    AND rawEventMsg LIKE '%RonPolicy%')
  OR (winEventId = '5449'
    AND rawEventMsg LIKE '%RonPolicy%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/deepinstinct/NoFilter/blob/121d215ab130c5e8e3ad45a7e7fcd56f4de97b4d/NoFilter/Consts.cpp
- https://github.com/deepinstinct/NoFilter
- https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation
- https://x.com/_st0pp3r_/status/1742203752361128162?s=20

---

## HybridConnectionManager Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `0ee4d8a5-4e67-4faf-acfa-62a78457d1f2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1554 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hybridconnectionmgr_svc_installation.yml)**

> Rule to detect the Hybrid Connection Manager service installation.

```sql
-- ============================================================
-- Title:        HybridConnectionManager Service Installation
-- Sigma ID:     0ee4d8a5-4e67-4faf-acfa-62a78457d1f2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1554
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2021-04-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_hybridconnectionmgr_svc_installation.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Legitimate use of Hybrid Connection Manager via Azure function apps.
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND serviceName = 'HybridConnectionManager'
    AND rawEventMsg LIKE '%HybridConnectionManager%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Hybrid Connection Manager via Azure function apps.

**References:**
- https://twitter.com/Cyb3rWard0g/status/1381642789369286662

---

## Impacket PsExec Execution

| Field | Value |
|---|---|
| **Sigma ID** | `32d56ea1-417f-44ff-822b-882873f5f43b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_impacket_psexec.yml)**

> Detects execution of Impacket's psexec.py.

```sql
-- ============================================================
-- Title:        Impacket PsExec Execution
-- Sigma ID:     32d56ea1-417f-44ff-822b-882873f5f43b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Bhabesh Raj
-- Date:         2020-12-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_impacket_psexec.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\IPC$'
    AND (rawEventMsg LIKE '%RemCom\_stdin%' OR rawEventMsg LIKE '%RemCom\_stdout%' OR rawEventMsg LIKE '%RemCom\_stderr%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329171218/https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html

---

## Possible Impacket SecretDump Remote Activity

| Field | Value |
|---|---|
| **Sigma ID** | `252902e3-5830-4cf6-bf21-c22083dfd5cf` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002, T1003.004, T1003.003 |
| **Author** | Samir Bousseaden, wagga |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_impacket_secretdump.yml)**

> Detect AD credential dumping using impacket secretdump HKTL

```sql
-- ============================================================
-- Title:        Possible Impacket SecretDump Remote Activity
-- Sigma ID:     252902e3-5830-4cf6-bf21-c22083dfd5cf
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002, T1003.004, T1003.003
-- Author:       Samir Bousseaden, wagga
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_impacket_secretdump.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\ADMIN$'
    AND rawEventMsg LIKE '%SYSTEM32\\%' AND rawEventMsg LIKE '%.tmp%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329153811/https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html

---

## Invoke-Obfuscation CLIP+ Launcher - Security

| Field | Value |
|---|---|
| **Sigma ID** | `4edf51e1-cb83-4e1a-bc39-800e396068e3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_clip_services_security.yml)**

> Detects Obfuscated use of Clip.exe to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation CLIP+ Launcher - Security
-- Sigma ID:     4edf51e1-cb83-4e1a-bc39-800e396068e3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_clip_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%&&%' AND rawEventMsg LIKE '%clipboard]::%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Obfuscated IEX Invocation - Security

| Field | Value |
|---|---|
| **Sigma ID** | `fd0f5778-d3cb-4c9a-9695-66759d04702a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027 |
| **Author** | Daniel Bohannon (@Mandiant/@FireEye), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_obfuscated_iex_services_security.yml)**

> Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the code block linked in the references

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Obfuscated IEX Invocation - Security
-- Sigma ID:     fd0f5778-d3cb-4c9a-9695-66759d04702a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027
-- Author:       Daniel Bohannon (@Mandiant/@FireEye), oscd.community
-- Date:         2019-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_obfuscated_iex_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
  AND (match(rawEventMsg, '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['))
  OR (match(rawEventMsg, '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\['))
  OR (match(rawEventMsg, '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\['))
  OR (match(rawEventMsg, '\$env:ComSpec\[(\s*\d{1,3}\s*,){2}'))
  OR (match(rawEventMsg, '\\*mdr\*\W\s*\)\.Name'))
  OR (match(rawEventMsg, '\$VerbosePreference\.ToString\('))
  OR (match(rawEventMsg, '\String\]\s*\$VerbosePreference')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/danielbohannon/Invoke-Obfuscation/blob/f20e7f843edd0a3a7716736e9eddfa423395dd26/Out-ObfuscatedStringCommand.ps1#L873-L888

---

## Invoke-Obfuscation STDIN+ Launcher - Security

| Field | Value |
|---|---|
| **Sigma ID** | `0c718a5e-4284-4fb9-b4d9-b9a50b3a1974` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_stdin_services_security.yml)**

> Detects Obfuscated use of stdin to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation STDIN+ Launcher - Security
-- Sigma ID:     0c718a5e-4284-4fb9-b4d9-b9a50b3a1974
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_stdin_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4697'
    AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%powershell%')
  AND (rawEventMsg LIKE '%${input}%' OR rawEventMsg LIKE '%noexit%')
  AND (rawEventMsg LIKE '% /c %' OR rawEventMsg LIKE '% /r %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR+ Launcher - Security

| Field | Value |
|---|---|
| **Sigma ID** | `dcf2db1f-f091-425b-a821-c05875b8925a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_var_services_security.yml)**

> Detects Obfuscated use of Environment Variables to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR+ Launcher - Security
-- Sigma ID:     dcf2db1f-f091-425b-a821-c05875b8925a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_var_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%"set%' AND rawEventMsg LIKE '%-f%'
    AND (rawEventMsg LIKE '%/c%' OR rawEventMsg LIKE '%/r%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation COMPRESS OBFUSCATION - Security

| Field | Value |
|---|---|
| **Sigma ID** | `7a922f1b-2635-4d6c-91ef-af228b198ad3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_compress_services_security.yml)**

> Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation COMPRESS OBFUSCATION - Security
-- Sigma ID:     7a922f1b-2635-4d6c-91ef-af228b198ad3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_compress_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%new-object%' AND rawEventMsg LIKE '%text.encoding]::ascii%' AND rawEventMsg LIKE '%readtoend%'
    AND (rawEventMsg LIKE '%system.io.compression.deflatestream%' OR rawEventMsg LIKE '%system.io.streamreader%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation RUNDLL LAUNCHER - Security

| Field | Value |
|---|---|
| **Sigma ID** | `f241cf1b-3a6b-4e1a-b4f9-133c00dd95ca` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_rundll_services_security.yml)**

> Detects Obfuscated Powershell via RUNDLL LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation RUNDLL LAUNCHER - Security
-- Sigma ID:     f241cf1b-3a6b-4e1a-b4f9-133c00dd95ca
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_rundll_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%rundll32.exe%' AND rawEventMsg LIKE '%shell32.dll%' AND rawEventMsg LIKE '%shellexec\_rundll%' AND rawEventMsg LIKE '%powershell%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Stdin - Security

| Field | Value |
|---|---|
| **Sigma ID** | `80b708f3-d034-40e4-a6c8-d23b7a7db3d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_stdin_services_security.yml)**

> Detects Obfuscated Powershell via Stdin in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Stdin - Security
-- Sigma ID:     80b708f3-d034-40e4-a6c8-d23b7a7db3d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_stdin_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%set%' AND rawEventMsg LIKE '%&&%'
    AND (rawEventMsg LIKE '%environment%' OR rawEventMsg LIKE '%invoke%' OR rawEventMsg LIKE '%${input)%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Clip - Security

| Field | Value |
|---|---|
| **Sigma ID** | `1a0a2ff1-611b-4dac-8216-8a7b47c618a6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_clip_services_security.yml)**

> Detects Obfuscated Powershell via use Clip.exe in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Clip - Security
-- Sigma ID:     1a0a2ff1-611b-4dac-8216-8a7b47c618a6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_clip_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%(Clipboard|i%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use MSHTA - Security

| Field | Value |
|---|---|
| **Sigma ID** | `9b8d9203-4e0f-4cd9-bb06-4cc4ea6d0e9a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_mshta_services_security.yml)**

> Detects Obfuscated Powershell via use MSHTA in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use MSHTA - Security
-- Sigma ID:     9b8d9203-4e0f-4cd9-bb06-4cc4ea6d0e9a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_mshta_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%mshta%' AND rawEventMsg LIKE '%vbscript:createobject%' AND rawEventMsg LIKE '%.run%' AND rawEventMsg LIKE '%window.close%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Rundll32 - Security

| Field | Value |
|---|---|
| **Sigma ID** | `cd0f7229-d16f-42de-8fe3-fba365fbcb3a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_rundll32_services_security.yml)**

> Detects Obfuscated Powershell via use Rundll32 in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Rundll32 - Security
-- Sigma ID:     cd0f7229-d16f-42de-8fe3-fba365fbcb3a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_rundll32_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%&&%' AND rawEventMsg LIKE '%rundll32%' AND rawEventMsg LIKE '%shell32.dll%' AND rawEventMsg LIKE '%shellexec\_rundll%'
    AND (rawEventMsg LIKE '%value%' OR rawEventMsg LIKE '%invoke%' OR rawEventMsg LIKE '%comspec%' OR rawEventMsg LIKE '%iex%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security

| Field | Value |
|---|---|
| **Sigma ID** | `4c54ba8f-73d2-4d40-8890-d9cf1dca3d30` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_var_services_security.yml)**

> Detects Obfuscated Powershell via VAR++ LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security
-- Sigma ID:     4c54ba8f-73d2-4d40-8890-d9cf1dca3d30
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_invoke_obfuscation_via_var_services_security.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%&&set%' AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%/c%' AND rawEventMsg LIKE '%-f%'
    AND (rawEventMsg LIKE '%{0}%' OR rawEventMsg LIKE '%{1}%' OR rawEventMsg LIKE '%{2}%' OR rawEventMsg LIKE '%{3}%' OR rawEventMsg LIKE '%{4}%' OR rawEventMsg LIKE '%{5}%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## ISO Image Mounted

| Field | Value |
|---|---|
| **Sigma ID** | `0248a7bc-8a9a-4cd8-a57e-3ae8e073a073` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1566.001 |
| **Author** | Syed Hasan (@syedhasan009) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_iso_mount.yml)**

> Detects the mount of an ISO image on an endpoint

```sql
-- ============================================================
-- Title:        ISO Image Mounted
-- Sigma ID:     0248a7bc-8a9a-4cd8-a57e-3ae8e073a073
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1566.001
-- Author:       Syed Hasan (@syedhasan009)
-- Date:         2021-05-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_iso_mount.yml
-- Unmapped:     ObjectServer, ObjectType, ObjectName
-- False Pos:    Software installation ISO files
-- ============================================================
-- UNMAPPED_FIELD: ObjectServer
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4663'
    AND rawEventMsg = 'Security'
    AND rawEventMsg = 'File'
    AND rawEventMsg LIKE '\\Device\\CdRom%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Software installation ISO files

**References:**
- https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
- https://www.proofpoint.com/us/blog/threat-insight/threat-actor-profile-ta2719-uses-colorful-lures-deliver-rats-local-languages
- https://twitter.com/MsftSecIntel/status/1257324139515269121
- https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1553.005/T1553.005.md#atomic-test-1---mount-iso-image

---

## Kerberoasting Activity - Initial Query

| Field | Value |
|---|---|
| **Sigma ID** | `d04ae2b8-ad54-4de0-bd87-4bc1da66aa59` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1558.003 |
| **Author** | @kostastsale |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberoasting_activity.yml)**

> This rule will collect the data needed to start looking into possible kerberoasting activity.
Further analysis or computation within the query is needed focusing on requests from one specific host/IP towards multiple service names within a time period of 5 seconds.
You can then set a threshold for the number of requests and time between the requests to turn this into an alert.


```sql
-- ============================================================
-- Title:        Kerberoasting Activity - Initial Query
-- Sigma ID:     d04ae2b8-ad54-4de0-bd87-4bc1da66aa59
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1558.003
-- Author:       @kostastsale
-- Date:         2022-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberoasting_activity.yml
-- Unmapped:     Status, TicketEncryptionType
-- False Pos:    Legacy applications.
-- ============================================================
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: TicketEncryptionType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4769')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4769'
    AND rawEventMsg = '0x0'
    AND rawEventMsg = '0x17')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legacy applications.

**References:**
- https://www.trustedsec.com/blog/art_of_kerberoast/
- https://adsecurity.org/?p=3513

---

## Potential AS-REP Roasting via Kerberos TGT Requests

| Field | Value |
|---|---|
| **Sigma ID** | `3e2f1b2c-4d5e-11ee-be56-0242ac120002` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | ANosir |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml)**

> Detects suspicious Kerberos TGT requests with pre-authentication disabled (Pre-Authentication Type = 0) and Ticket Encryption Type (0x17) i.e, RC4-HMAC.
This may indicate an AS-REP Roasting attack, where attackers request AS-REP messages for accounts without pre-authentication and attempt to crack the encrypted ticket offline to recover user passwords.


```sql
-- ============================================================
-- Title:        Potential AS-REP Roasting via Kerberos TGT Requests
-- Sigma ID:     3e2f1b2c-4d5e-11ee-be56-0242ac120002
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        (none)
-- Author:       ANosir
-- Date:         2025-05-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml
-- Unmapped:     TicketEncryptionType, PreAuthType
-- False Pos:    Legacy systems or applications that legitimately use RC4 encryption; Misconfigured accounts with pre-authentication disabled
-- ============================================================
-- UNMAPPED_FIELD: TicketEncryptionType
-- UNMAPPED_FIELD: PreAuthType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4768')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4768'
    AND rawEventMsg = '0x17'
    AND serviceName = 'krbtgt'
    AND rawEventMsg = '0')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legacy systems or applications that legitimately use RC4 encryption; Misconfigured accounts with pre-authentication disabled

**References:**
- https://medium.com/system-weakness/detecting-as-rep-roasting-attacks-b5b3965f9714
- https://www.picussecurity.com/resource/blog/as-rep-roasting-attack-explained-mitre-attack-t1558.004

---

## Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation

| Field | Value |
|---|---|
| **Sigma ID** | `b07e58cf-cacc-4135-8473-ccb2eba63dd2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection, persistence |
| **MITRE Techniques** | T1557.003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberos_coercion_via_dns_object.yml)**

> Detects modifications to DNS records in Active Directory where the Distinguished Name (DN) contains a base64-encoded blob
matching the pattern "1UWhRCAAAAA...BAAAA". This pattern corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure,
commonly used in Kerberos coercion attacks. Adversaries may exploit this to coerce victim systems into authenticating to
attacker-controlled hosts by spoofing SPNs via DNS. It is one of the strong indicators of a Kerberos coercion attack,.
where adversaries manipulate DNS records to spoof Service Principal Names (SPNs) and redirect authentication requests like CVE-2025-33073.
Please investigate the user account that made the changes, as it is likely a low-privileged account that has been compromised.


```sql
-- ============================================================
-- Title:        Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation
-- Sigma ID:     b07e58cf-cacc-4135-8473-ccb2eba63dd2
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        collection, persistence | T1557.003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberos_coercion_via_dns_object.yml
-- Unmapped:     AdditionalInfo, ObjectClass, ObjectDN
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AdditionalInfo
-- UNMAPPED_FIELD: ObjectClass
-- UNMAPPED_FIELD: ObjectDN

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136', 'Win-Security-5137', 'Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4662'
    AND rawEventMsg LIKE '%UWhRCA%' AND rawEventMsg LIKE '%BAAAA%' AND rawEventMsg LIKE '%CN=MicrosoftDNS%')
  OR (winEventId IN ('5136', '5137')
    AND rawEventMsg = 'dnsNode'
    AND rawEventMsg LIKE '%UWhRCA%' AND rawEventMsg LIKE '%BAAAA%' AND rawEventMsg LIKE '%CN=MicrosoftDNS%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
- https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025

---

## First Time Seen Remote Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `52d8b0c6-53d6-439a-9e41-52ad442ad9ad` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_lm_namedpipe.yml)**

> This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes

```sql
-- ============================================================
-- Title:        First Time Seen Remote Named Pipe
-- Sigma ID:     52d8b0c6-53d6-439a-9e41-52ad442ad9ad
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_lm_namedpipe.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Update the excluded named pipe to filter out any newly observed legit named pipe
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\IPC$')
  AND NOT (rawEventMsg IN ('atsvc', 'samr', 'lsarpc', 'lsass', 'winreg', 'netlogon', 'srvsvc', 'protected_storage', 'wkssvc', 'browser', 'netdfs', 'svcctl', 'spoolss', 'ntsvcs', 'LSM_API_service', 'HydraLsPipe', 'TermSrv_API_service', 'MsFteWds', 'sql\query', 'eventlog')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Update the excluded named pipe to filter out any newly observed legit named pipe

**References:**
- https://twitter.com/menasec1/status/1104489274387451904

---

## LSASS Access From Non System Account

| Field | Value |
|---|---|
| **Sigma ID** | `962fe167-e48d-4fd6-9974-11e5b9a5d6d1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_lsass_access_non_system_account.yml)**

> Detects potential mimikatz-like tools accessing LSASS from non system account

```sql
-- ============================================================
-- Title:        LSASS Access From Non System Account
-- Sigma ID:     962fe167-e48d-4fd6-9974-11e5b9a5d6d1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_lsass_access_non_system_account.yml
-- Unmapped:     AccessMask, ObjectType, ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4663', 'Win-Security-4656')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4663', '4656')
    AND rawEventMsg IN ('0x100000', '0x1010', '0x1400', '0x1410', '0x1418', '0x1438', '0x143a', '0x1f0fff', '0x1f1fff', '0x1f2fff', '0x1f3fff', '0x40', '143a', '1f0fff', '1f1fff', '1f2fff', '1f3fff')
    AND rawEventMsg = 'Process'
    AND rawEventMsg LIKE '%\\lsass.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/170105-LSASSMemoryReadAccess/notebook.html

---

## Credential Dumping Tools Service Execution - Security

| Field | Value |
|---|---|
| **Sigma ID** | `f0d1feba-4344-4ca9-8121-a6c97bd6df52` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1003.001, T1003.002, T1003.004, T1003.005, T1003.006, T1569.002 |
| **Author** | Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_mal_creddumper.yml)**

> Detects well-known credential dumping tools execution via service execution events

```sql
-- ============================================================
-- Title:        Credential Dumping Tools Service Execution - Security
-- Sigma ID:     f0d1feba-4344-4ca9-8121-a6c97bd6df52
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1003.001, T1003.002, T1003.004, T1003.005, T1003.006, T1569.002
-- Author:       Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_mal_creddumper.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Legitimate Administrator using credential dumping tool for password recovery
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND (rawEventMsg LIKE '%cachedump%' OR rawEventMsg LIKE '%dumpsvc%' OR rawEventMsg LIKE '%fgexec%' OR rawEventMsg LIKE '%gsecdump%' OR rawEventMsg LIKE '%mimidrv%' OR rawEventMsg LIKE '%pwdump%' OR rawEventMsg LIKE '%servpw%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator using credential dumping tool for password recovery

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---

## WCE wceaux.dll Access

| Field | Value |
|---|---|
| **Sigma ID** | `1de68c67-af5c-4097-9c85-fe5578e09e67` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_mal_wceaux_dll.yml)**

> Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host

```sql
-- ============================================================
-- Title:        WCE wceaux.dll Access
-- Sigma ID:     1de68c67-af5c-4097-9c85-fe5578e09e67
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003
-- Author:       Thomas Patzke
-- Date:         2017-06-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_mal_wceaux_dll.yml
-- Unmapped:     ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4656', '4663')
    AND rawEventMsg LIKE '%\\wceaux.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.jpcert.or.jp/english/pub/sr/ir_research.html
- https://jpcertcc.github.io/ToolAnalysisResultSheet

---

## Metasploit SMB Authentication

| Field | Value |
|---|---|
| **Sigma ID** | `72124974-a68b-4366-b990-d30e0b2a190d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Chakib Gzenayi (@Chak092), Hosni Mribah |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_metasploit_authentication.yml)**

> Alerts on Metasploit host's authentications on the domain.

```sql
-- ============================================================
-- Title:        Metasploit SMB Authentication
-- Sigma ID:     72124974-a68b-4366-b990-d30e0b2a190d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Chakib Gzenayi (@Chak092), Hosni Mribah
-- Date:         2020-05-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_metasploit_authentication.yml
-- Unmapped:     AuthenticationPackageName, WorkstationName, Workstation
-- False Pos:    Linux hostnames composed of 16 characters.
-- ============================================================
-- UNMAPPED_FIELD: AuthenticationPackageName
-- UNMAPPED_FIELD: WorkstationName
-- UNMAPPED_FIELD: Workstation

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  winLogonType,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4625', 'Win-Security-4624', 'Win-Security-4776')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4625', '4624')
    AND winLogonType = '3'
    AND rawEventMsg = 'NTLM'
    AND match(rawEventMsg, '^[A-Za-z0-9]{16}$'))
  OR (winEventId = '4776'
    AND match(rawEventMsg, '^[A-Za-z0-9]{16}$'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Linux hostnames composed of 16 characters.

**References:**
- https://github.com/rapid7/metasploit-framework/blob/1416b5776d963f21b7b5b45d19f3e961201e0aed/lib/rex/proto/smb/client.rb

---

## Metasploit Or Impacket Service Installation Via SMB PsExec

| Field | Value |
|---|---|
| **Sigma ID** | `6fb63b40-e02a-403e-9ffd-3bcc1d749442` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1021.002, T1570, T1569.002 |
| **Author** | Bartlomiej Czyz, Relativity |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml)**

> Detects usage of Metasploit SMB PsExec (exploit/windows/smb/psexec) and Impacket psexec.py by triggering on specific service installation

```sql
-- ============================================================
-- Title:        Metasploit Or Impacket Service Installation Via SMB PsExec
-- Sigma ID:     6fb63b40-e02a-403e-9ffd-3bcc1d749442
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1021.002, T1570, T1569.002
-- Author:       Bartlomiej Czyz, Relativity
-- Date:         2021-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml
-- Unmapped:     ServiceFileName, ServiceStartType, ServiceType
-- False Pos:    Possible, different agents with a 8 character binary and a 4, 8 or 16 character service name
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName
-- UNMAPPED_FIELD: ServiceStartType
-- UNMAPPED_FIELD: ServiceType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4697'
    AND match(rawEventMsg, '^%systemroot%\\[a-zA-Z]{8}\.exe$')
    AND match(serviceName, '(^[a-zA-Z]{4}$)|(^[a-zA-Z]{8}$)|(^[a-zA-Z]{16}$)')
    AND rawEventMsg = '3'
    AND rawEventMsg = '0x10')
  AND NOT (serviceName = 'PSEXESVC'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Possible, different agents with a 8 character binary and a 4, 8 or 16 character service name

**References:**
- https://bczyz1.github.io/2021/01/30/psexec.html

---

## Meterpreter or Cobalt Strike Getsystem Service Installation - Security

| Field | Value |
|---|---|
| **Sigma ID** | `ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1134.001, T1134.002 |
| **Author** | Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml)**

> Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation

```sql
-- ============================================================
-- Title:        Meterpreter or Cobalt Strike Getsystem Service Installation - Security
-- Sigma ID:     ecbc5e16-58e0-4521-9c60-eb9a7ea4ad34
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1134.001, T1134.002
-- Author:       Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems)
-- Date:         2019-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4697'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
- https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

---

## NetNTLM Downgrade Attack

| Field | Value |
|---|---|
| **Sigma ID** | `d3abac66-f11c-4ed0-8acb-50cc29c97eed` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.001, T1112 |
| **Author** | Florian Roth (Nextron Systems), wagga |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_net_ntlm_downgrade.yml)**

> Detects NetNTLM downgrade attack

```sql
-- ============================================================
-- Title:        NetNTLM Downgrade Attack
-- Sigma ID:     d3abac66-f11c-4ed0-8acb-50cc29c97eed
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1562.001, T1112
-- Author:       Florian Roth (Nextron Systems), wagga
-- Date:         2018-03-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_net_ntlm_downgrade.yml
-- Unmapped:     ObjectName, ObjectValueName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: ObjectValueName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4657')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4657'
    AND rawEventMsg LIKE '%\\REGISTRY\\MACHINE\\SYSTEM%' AND rawEventMsg LIKE '%ControlSet%' AND rawEventMsg LIKE '%\\Control\\Lsa%'
    AND rawEventMsg IN ('LmCompatibilityLevel', 'NtlmMinClientSec', 'RestrictSendingNTLMTraffic'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks

---

## Windows Network Access Suspicious desktop.ini Action

| Field | Value |
|---|---|
| **Sigma ID** | `35bc7e28-ee6b-492f-ab04-da58fcf6402e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.009 |
| **Author** | Tim Shelton (HAWK.IO) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_net_share_obj_susp_desktop_ini.yml)**

> Detects unusual processes accessing desktop.ini remotely over network share, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

```sql
-- ============================================================
-- Title:        Windows Network Access Suspicious desktop.ini Action
-- Sigma ID:     35bc7e28-ee6b-492f-ab04-da58fcf6402e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.009
-- Author:       Tim Shelton (HAWK.IO)
-- Date:         2021-12-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_net_share_obj_susp_desktop_ini.yml
-- Unmapped:     ObjectType, RelativeTargetName, AccessList
-- False Pos:    Read only access list authority
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: RelativeTargetName
-- UNMAPPED_FIELD: AccessList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg = 'File'
    AND rawEventMsg LIKE '%\\desktop.ini'
    AND (rawEventMsg LIKE '%WriteData%' OR rawEventMsg LIKE '%DELETE%' OR rawEventMsg LIKE '%WriteDAC%' OR rawEventMsg LIKE '%AppendData%' OR rawEventMsg LIKE '%AddSubdirectory%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Read only access list authority

**References:**
- https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/

---

## New or Renamed User Account with '$' Character

| Field | Value |
|---|---|
| **Sigma ID** | `cfeed607-6aa4-4bbd-9627-b637deb723c8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036 |
| **Author** | Ilyas Ochkov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_new_or_renamed_user_account_with_dollar_sign.yml)**

> Detects the creation of a user with the "$" character. This can be used by attackers to hide a user or trick detection systems that lack the parsing mechanisms.


```sql
-- ============================================================
-- Title:        New or Renamed User Account with '$' Character
-- Sigma ID:     cfeed607-6aa4-4bbd-9627-b637deb723c8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036
-- Author:       Ilyas Ochkov, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_new_or_renamed_user_account_with_dollar_sign.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4720', 'Win-Security-4781')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1387743867663958021

---

## Denied Access To Remote Desktop

| Field | Value |
|---|---|
| **Sigma ID** | `8e5c03fa-b7f0-11ea-b242-07e0576828d9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.001 |
| **Author** | Pushkarev Dmitry |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_not_allowed_rdp_access.yml)**

> This event is generated when an authenticated user who is not allowed to log on remotely attempts to connect to this computer through Remote Desktop.
Often, this event can be generated by attackers when searching for available windows servers in the network.


```sql
-- ============================================================
-- Title:        Denied Access To Remote Desktop
-- Sigma ID:     8e5c03fa-b7f0-11ea-b242-07e0576828d9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.001
-- Author:       Pushkarev Dmitry
-- Date:         2020-06-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_not_allowed_rdp_access.yml
-- Unmapped:     (none)
-- False Pos:    Valid user was not added to RDP group
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4825')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4825'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid user was not added to RDP group

**References:**
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4825

---

## Password Policy Enumerated

| Field | Value |
|---|---|
| **Sigma ID** | `12ba6a38-adb3-4d6b-91ba-a7fb248e3199` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1201 |
| **Author** | Zach Mathis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_password_policy_enumerated.yml)**

> Detects when the password policy is enumerated.

```sql
-- ============================================================
-- Title:        Password Policy Enumerated
-- Sigma ID:     12ba6a38-adb3-4d6b-91ba-a7fb248e3199
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1201
-- Author:       Zach Mathis
-- Date:         2023-05-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_password_policy_enumerated.yml
-- Unmapped:     AccessList, ObjectServer
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_FIELD: AccessList
-- UNMAPPED_FIELD: ObjectServer

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4661')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4661'
    AND rawEventMsg LIKE '%\%\%5392%'
    AND rawEventMsg = 'Security Account Manager')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4661
- https://github.com/jpalanco/alienvault-ossim/blob/f74359c0c027e42560924b5cff25cdf121e5505a/os-sim/agent/src/ParserUtil.py#L951

---

## Windows Pcap Drivers

| Field | Value |
|---|---|
| **Sigma ID** | `7b687634-ab20-11ea-bb37-0242ac130002` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1040 |
| **Author** | Cian Heasley |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_pcap_drivers.yml)**

> Detects Windows Pcap driver installation based on a list of associated .sys files.

```sql
-- ============================================================
-- Title:        Windows Pcap Drivers
-- Sigma ID:     7b687634-ab20-11ea-bb37-0242ac130002
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1040
-- Author:       Cian Heasley
-- Date:         2020-06-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_pcap_drivers.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND (rawEventMsg LIKE '%pcap%' OR rawEventMsg LIKE '%npcap%' OR rawEventMsg LIKE '%npf%' OR rawEventMsg LIKE '%nm3%' OR rawEventMsg LIKE '%ndiscap%' OR rawEventMsg LIKE '%nmnt%' OR rawEventMsg LIKE '%windivert%' OR rawEventMsg LIKE '%USBPcap%' OR rawEventMsg LIKE '%pktmon%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://ragged-lab.blogspot.com/2020/06/capturing-pcap-driver-installations.html#more

---

## Possible PetitPotam Coerce Authentication Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `1ce8c8a3-2723-48ed-8246-906ac91061a6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1187 |
| **Author** | Mauricio Velazco, Michael Haag |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_petitpotam_network_share.yml)**

> Detect PetitPotam coerced authentication activity.

```sql
-- ============================================================
-- Title:        Possible PetitPotam Coerce Authentication Attempt
-- Sigma ID:     1ce8c8a3-2723-48ed-8246-906ac91061a6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1187
-- Author:       Mauricio Velazco, Michael Haag
-- Date:         2021-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_petitpotam_network_share.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Unknown. Feedback welcomed.
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] AS subjectUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg LIKE '\\\\\\\\%'
    AND rawEventMsg LIKE '%\\IPC$'
    AND rawEventMsg = 'lsarpc'
    AND indexOf(metrics_string.name, 'subjectUsername') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] = 'ANONYMOUS LOGON'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown. Feedback welcomed.

**References:**
- https://github.com/topotam/PetitPotam
- https://github.com/splunk/security_content/blob/0dd6de32de2118b2818550df9e65255f4109a56d/detections/endpoint/petitpotam_network_share_access_request.yml

---

## PetitPotam Suspicious Kerberos TGT Request

| Field | Value |
|---|---|
| **Sigma ID** | `6a53d871-682d-40b6-83e0-b7c1a6c4e3a5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1187 |
| **Author** | Mauricio Velazco, Michael Haag |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_petitpotam_susp_tgt_request.yml)**

> Detect suspicious Kerberos TGT requests.
Once an attacer obtains a computer certificate by abusing Active Directory Certificate Services in combination with PetitPotam, the next step would be to leverage the certificate for malicious purposes.
One way of doing this is to request a Kerberos Ticket Granting Ticket using a tool like Rubeus.
This request will generate a 4768 event with some unusual fields depending on the environment.
This analytic will require tuning, we recommend filtering Account_Name to the Domain Controller computer accounts.


```sql
-- ============================================================
-- Title:        PetitPotam Suspicious Kerberos TGT Request
-- Sigma ID:     6a53d871-682d-40b6-83e0-b7c1a6c4e3a5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1187
-- Author:       Mauricio Velazco, Michael Haag
-- Date:         2021-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_petitpotam_susp_tgt_request.yml
-- Unmapped:     CertThumbprint
-- False Pos:    False positives are possible if the environment is using certificates for authentication. We recommend filtering Account_Name to the Domain Controller computer accounts.
-- ============================================================
-- UNMAPPED_FIELD: CertThumbprint

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'targetUser')] AS targetUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4768')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4768'
    AND indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] LIKE '%$')
    AND rawEventMsg LIKE '%*%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives are possible if the environment is using certificates for authentication. We recommend filtering Account_Name to the Domain Controller computer accounts.

**References:**
- https://github.com/topotam/PetitPotam
- https://isc.sans.edu/forums/diary/Active+Directory+Certificate+Services+ADCS+PKI+domain+admin+vulnerability/27668/
- https://github.com/splunk/security_content/blob/88d689fe8a055d8284337b9fad5d9152b42043db/detections/endpoint/petitpotam_suspicious_kerberos_tgt_request.yml

---

## Possible DC Shadow Attack

| Field | Value |
|---|---|
| **Sigma ID** | `32e19d25-4aed-4860-a55a-be99cb0bf7ed` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1207 |
| **Author** | Ilyas Ochkov, oscd.community, Chakib Gzenayi (@Chak092), Hosni Mribah |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_possible_dc_shadow.yml)**

> Detects DCShadow via create new SPN

```sql
-- ============================================================
-- Title:        Possible DC Shadow Attack
-- Sigma ID:     32e19d25-4aed-4860-a55a-be99cb0bf7ed
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1207
-- Author:       Ilyas Ochkov, oscd.community, Chakib Gzenayi (@Chak092), Hosni Mribah
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_possible_dc_shadow.yml
-- Unmapped:     ServicePrincipalNames, AttributeLDAPDisplayName, AttributeValue
-- False Pos:    Valid on domain controllers; exclude known DCs
-- ============================================================
-- UNMAPPED_FIELD: ServicePrincipalNames
-- UNMAPPED_FIELD: AttributeLDAPDisplayName
-- UNMAPPED_FIELD: AttributeValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4742', 'Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4742'
    AND rawEventMsg LIKE '%GC/%')
  OR (winEventId = '5136'
    AND rawEventMsg = 'servicePrincipalName'
    AND rawEventMsg LIKE 'GC/%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid on domain controllers; exclude known DCs

**References:**
- https://twitter.com/gentilkiwi/status/1003236624925413376
- https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
- https://web.archive.org/web/20180203014709/https://blog.alsid.eu/dcshadow-explained-4510f52fc19d?gi=c426ac876c48

---

## PowerShell Scripts Installed as Services - Security

| Field | Value |
|---|---|
| **Sigma ID** | `2a926e6a-4b81-4011-8a96-e36cc8c04302` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | oscd.community, Natalia Shornikova |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml)**

> Detects powershell script installed as a Service

```sql
-- ============================================================
-- Title:        PowerShell Scripts Installed as Services - Security
-- Sigma ID:     2a926e6a-4b81-4011-8a96-e36cc8c04302
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       oscd.community, Natalia Shornikova
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND (rawEventMsg LIKE '%powershell%' OR rawEventMsg LIKE '%pwsh%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

---

## Protected Storage Service Access

| Field | Value |
|---|---|
| **Sigma ID** | `45545954-4016-43c6-855e-eae8f1c369dc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_protected_storage_service_access.yml)**

> Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers

```sql
-- ============================================================
-- Title:        Protected Storage Service Access
-- Sigma ID:     45545954-4016-43c6-855e-eae8f1c369dc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_protected_storage_service_access.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg LIKE '%IPC%'
    AND rawEventMsg = 'protected_storage')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html

---

## RDP over Reverse SSH Tunnel WFP

| Field | Value |
|---|---|
| **Sigma ID** | `5bed80b6-b3e8-428e-a3ae-d3c757589e41` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090.001, T1090.002, T1021.001 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml)**

> Detects svchost hosting RDP termsvcs communicating with the loopback address

```sql
-- ============================================================
-- Title:        RDP over Reverse SSH Tunnel WFP
-- Sigma ID:     5bed80b6-b3e8-428e-a3ae-d3c757589e41
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090.001, T1090.002, T1021.001
-- Author:       Samir Bousseaden
-- Date:         2019-02-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml
-- Unmapped:     (none)
-- False Pos:    Programs that connect locally to the RDP port
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5156')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '5156'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Programs that connect locally to the RDP port

**References:**
- https://twitter.com/SBousseaden/status/1096148422984384514
- https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/44fbe85f72ee91582876b49678f9a26292a155fb/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx

---

## Register new Logon Process by Rubeus

| Field | Value |
|---|---|
| **Sigma ID** | `12e6d621-194f-4f59-90cc-1959e21e69f7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1558.003 |
| **Author** | Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml)**

> Detects potential use of Rubeus via registered new trusted logon process

```sql
-- ============================================================
-- Title:        Register new Logon Process by Rubeus
-- Sigma ID:     12e6d621-194f-4f59-90cc-1959e21e69f7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1558.003
-- Author:       Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml
-- Unmapped:     LogonProcessName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: LogonProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4611')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4611'
    AND rawEventMsg = 'User32LogonProcesss')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1

---

## Service Registry Key Read Access Request

| Field | Value |
|---|---|
| **Sigma ID** | `11d00fff-5dc3-428c-8184-801f292faec0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.011 |
| **Author** | Center for Threat Informed Defense (CTID) Summiting the Pyramid Team |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_registry_permissions_weakness_check.yml)**

> Detects "read access" requests on the services registry key.
Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts.


```sql
-- ============================================================
-- Title:        Service Registry Key Read Access Request
-- Sigma ID:     11d00fff-5dc3-428c-8184-801f292faec0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1574.011
-- Author:       Center for Threat Informed Defense (CTID) Summiting the Pyramid Team
-- Date:         2023-09-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_registry_permissions_weakness_check.yml
-- Unmapped:     ObjectName, AccessList
-- False Pos:    Likely from legitimate applications reading their key. Requires heavy tuning
-- ============================================================
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: AccessList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4663'
    AND rawEventMsg LIKE '%\\SYSTEM\\%' AND rawEventMsg LIKE '%ControlSet\\Services\\%'
    AND rawEventMsg LIKE '%\%\%1538%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely from legitimate applications reading their key. Requires heavy tuning

**References:**
- https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/analytics/service_registry_permissions_weakness_check/
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.011/T1574.011.md#atomic-test-1---service-registry-permissions-weakness

---

## Remote PowerShell Sessions Network Connections (WinRM)

| Field | Value |
|---|---|
| **Sigma ID** | `13acf386-b8c6-4fe0-9a6e-c4756b974698` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_remote_powershell_session.yml)**

> Detects basic PowerShell Remoting (WinRM) by monitoring for network inbound connections to ports 5985 OR 5986

```sql
-- ============================================================
-- Title:        Remote PowerShell Sessions Network Connections (WinRM)
-- Sigma ID:     13acf386-b8c6-4fe0-9a6e-c4756b974698
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_remote_powershell_session.yml
-- Unmapped:     DestPort, LayerRTID
-- False Pos:    Legitimate use of remote PowerShell execution
-- ============================================================
-- UNMAPPED_FIELD: DestPort
-- UNMAPPED_FIELD: LayerRTID

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5156')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5156'
    AND rawEventMsg IN ('5985', '5986')
    AND rawEventMsg = '44')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of remote PowerShell execution

**References:**
- https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html

---

## Replay Attack Detected

| Field | Value |
|---|---|
| **Sigma ID** | `5a44727c-3b85-4713-8c44-4401d5499629` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1558 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_replay_attack_detected.yml)**

> Detects possible Kerberos Replay Attack on the domain controllers when "KRB_AP_ERR_REPEAT" Kerberos response is sent to the client

```sql
-- ============================================================
-- Title:        Replay Attack Detected
-- Sigma ID:     5a44727c-3b85-4713-8c44-4401d5499629
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1558
-- Author:       frack113
-- Date:         2022-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_replay_attack_detected.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4649')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4649'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4649

---

## SAM Registry Hive Handle Request

| Field | Value |
|---|---|
| **Sigma ID** | `f8748f2c-89dc-4d95-afb0-5a2dfdbad332` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1012, T1552.002 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.yml)**

> Detects handles requested to SAM registry hive

```sql
-- ============================================================
-- Title:        SAM Registry Hive Handle Request
-- Sigma ID:     f8748f2c-89dc-4d95-afb0-5a2dfdbad332
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1012, T1552.002
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.yml
-- Unmapped:     ObjectType, ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4656'
    AND rawEventMsg = 'Key'
    AND rawEventMsg LIKE '%\\SAM')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190725-SAMRegistryHiveHandleRequest/notebook.html

---

## SCM Database Handle Failure

| Field | Value |
|---|---|
| **Sigma ID** | `13addce7-47b2-4ca0-a98f-1de964d1d669` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1010 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_scm_database_handle_failure.yml)**

> Detects non-system users failing to get a handle of the SCM database.

```sql
-- ============================================================
-- Title:        SCM Database Handle Failure
-- Sigma ID:     13addce7-47b2-4ca0-a98f-1de964d1d669
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1010
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_scm_database_handle_failure.yml
-- Unmapped:     ObjectType, ObjectName, AccessMask, SubjectLogonId
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: SubjectLogonId

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4656'
    AND rawEventMsg = 'SC_MANAGER OBJECT'
    AND rawEventMsg = 'ServicesActive'
    AND rawEventMsg = '0xf003f')
  AND NOT (rawEventMsg = '0x3e4'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190826-RemoteSCMHandle/notebook.html

---

## SCM Database Privileged Operation

| Field | Value |
|---|---|
| **Sigma ID** | `dae8171c-5ec6-4396-b210-8466585b53e9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_scm_database_privileged_operation.yml)**

> Detects non-system users performing privileged operation os the SCM database

```sql
-- ============================================================
-- Title:        SCM Database Privileged Operation
-- Sigma ID:     dae8171c-5ec6-4396-b210-8466585b53e9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1548
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
-- Date:         2019-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_scm_database_privileged_operation.yml
-- Unmapped:     ObjectType, ObjectName, PrivilegeList, SubjectLogonId, ProcessName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: PrivilegeList
-- UNMAPPED_FIELD: SubjectLogonId
-- UNMAPPED_FIELD: ProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4674')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4674'
    AND rawEventMsg = 'SC_MANAGER OBJECT'
    AND rawEventMsg = 'servicesactive'
    AND rawEventMsg = 'SeTakeOwnershipPrivilege')
  AND NOT ((rawEventMsg = '0x3e4'
    AND rawEventMsg LIKE '%:\\Windows\\System32\\services.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190826-RemoteSCMHandle/notebook.html

---

## Potential Secure Deletion with SDelete

| Field | Value |
|---|---|
| **Sigma ID** | `39a80702-d7ca-4a83-b776-525b1f86a36d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1070.004, T1027.005, T1485, T1553.002 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.yml)**

> Detects files that have extensions commonly seen while SDelete is used to wipe files.

```sql
-- ============================================================
-- Title:        Potential Secure Deletion with SDelete
-- Sigma ID:     39a80702-d7ca-4a83-b776-525b1f86a36d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1070.004, T1027.005, T1485, T1553.002
-- Author:       Thomas Patzke
-- Date:         2017-06-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.yml
-- Unmapped:     ObjectName
-- False Pos:    Legitimate usage of SDelete; Files that are interacted with that have these extensions legitimately
-- ============================================================
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663', 'Win-Security-4658')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4656', '4663', '4658')
    AND (rawEventMsg LIKE '%.AAA' OR rawEventMsg LIKE '%.ZZZ'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of SDelete; Files that are interacted with that have these extensions legitimately

**References:**
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/sdelete.htm
- https://www.jpcert.or.jp/english/pub/sr/ir_research.html
- https://learn.microsoft.com/en-gb/sysinternals/downloads/sdelete

---

## Remote Access Tool Services Have Been Installed - Security

| Field | Value |
|---|---|
| **Sigma ID** | `c8b00925-926c-47e3-beea-298fd563728e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1543.003, T1569.002 |
| **Author** | Connor Martin, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_service_install_remote_access_software.yml)**

> Detects service installation of different remote access tools software. These software are often abused by threat actors to perform

```sql
-- ============================================================
-- Title:        Remote Access Tool Services Have Been Installed - Security
-- Sigma ID:     c8b00925-926c-47e3-beea-298fd563728e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution | T1543.003, T1569.002
-- Author:       Connor Martin, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_service_install_remote_access_software.yml
-- Unmapped:     (none)
-- False Pos:    The rule doesn't look for anything suspicious so false positives are expected. If you use one of the tools mentioned, comment it out
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND (serviceName LIKE '%AmmyyAdmin%' OR serviceName LIKE '%AnyDesk%' OR serviceName LIKE '%Atera%' OR serviceName LIKE '%BASupportExpressSrvcUpdater%' OR serviceName LIKE '%BASupportExpressStandaloneService%' OR serviceName LIKE '%chromoting%' OR serviceName LIKE '%GoToAssist%' OR serviceName LIKE '%GoToMyPC%' OR serviceName LIKE '%jumpcloud%' OR serviceName LIKE '%LMIGuardianSvc%' OR serviceName LIKE '%LogMeIn%' OR serviceName LIKE '%monblanking%' OR serviceName LIKE '%Parsec%' OR serviceName LIKE '%RManService%' OR serviceName LIKE '%RPCPerformanceService%' OR serviceName LIKE '%RPCService%' OR serviceName LIKE '%SplashtopRemoteService%' OR serviceName LIKE '%SSUService%' OR serviceName LIKE '%TeamViewer%' OR serviceName LIKE '%TightVNC%' OR serviceName LIKE '%vncserver%' OR serviceName LIKE '%Zoho%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The rule doesn't look for anything suspicious so false positives are expected. If you use one of the tools mentioned, comment it out

**References:**
- https://redcanary.com/blog/misbehaving-rats/

---

## Service Installed By Unusual Client - Security

| Field | Value |
|---|---|
| **Sigma ID** | `c4e92a97-a9ff-4392-9d2d-7a4c642768ca` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543 |
| **Author** | Tim Rauch (Nextron Systems), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_service_installation_by_unusal_client.yml)**

> Detects a service installed by a client which has PID 0 or whose parent has PID 0

```sql
-- ============================================================
-- Title:        Service Installed By Unusual Client - Security
-- Sigma ID:     c4e92a97-a9ff-4392-9d2d-7a4c642768ca
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543
-- Author:       Tim Rauch (Nextron Systems), Elastic (idea)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_service_installation_by_unusal_client.yml
-- Unmapped:     ClientProcessId, ParentProcessId
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ClientProcessId
-- UNMAPPED_FIELD: ParentProcessId

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
  AND (rawEventMsg = '0')
  OR (rawEventMsg = '0'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.elastic.co/guide/en/security/current/windows-service-installed-via-an-unusual-client.html
- https://www.x86matthew.com/view_post?id=create_svc_rpc
- https://twitter.com/SBousseaden/status/1490608838701166596

---

## File Access Of Signal Desktop Sensitive Data

| Field | Value |
|---|---|
| **Sigma ID** | `5d6c375a-18ae-4952-b4f6-8b803f6c8555` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003 |
| **Author** | Andreas Braathen (mnemonic.io) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_signal_sensitive_config_access.yml)**

> Detects access to Signal Desktop's sensitive data files: db.sqlite and config.json.
The db.sqlite file in Signal Desktop stores all locally saved messages in an encrypted SQLite database, while the config.json contains the decryption key needed to access that data.
Since the key is stored in plain text, a threat actor who gains access to both files can decrypt and read sensitive messages without needing the users credentials.
Currently the rule only covers the default Signal installation path in AppData\Roaming. Signal Portable installations may use different paths based on user configuration. Additional paths can be added to the selection as needed.


```sql
-- ============================================================
-- Title:        File Access Of Signal Desktop Sensitive Data
-- Sigma ID:     5d6c375a-18ae-4952-b4f6-8b803f6c8555
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1003
-- Author:       Andreas Braathen (mnemonic.io)
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_signal_sensitive_config_access.yml
-- Unmapped:     ObjectType, ObjectName
-- False Pos:    Unlikely, but possible from AV or backup software accessing the files.
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4663'
    AND rawEventMsg = 'File'
    AND rawEventMsg LIKE '%\\AppData\\Roaming\\Signal\\%'
    AND (rawEventMsg LIKE '%\\config.json' OR rawEventMsg LIKE '%\\db.sqlite'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely, but possible from AV or backup software accessing the files.

**References:**
- https://cloud.google.com/blog/topics/threat-intelligence/russia-targeting-signal-messenger/
- https://vmois.dev/query-signal-desktop-messages-sqlite/

---

## SMB Create Remote File Admin Share

| Field | Value |
|---|---|
| **Sigma ID** | `b210394c-ba12-4f89-9117-44a2464b9511` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml)**

> Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).

```sql
-- ============================================================
-- Title:        SMB Create Remote File Admin Share
-- Sigma ID:     b210394c-ba12-4f89-9117-44a2464b9511
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research)
-- Date:         2020-08-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml
-- Unmapped:     ShareName, AccessMask
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: AccessMask

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg LIKE '%C$'
    AND rawEventMsg = '0x2')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/OTRF/ThreatHunter-Playbook/blob/f7a58156dbfc9b019f17f638b8c62d22e557d350/playbooks/WIN-201012004336.yaml
- https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806015757.html?highlight=create%20file

---

## A New Trust Was Created To A Domain

| Field | Value |
|---|---|
| **Sigma ID** | `0255a820-e564-4e40-af2b-6ac61160335c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_add_domain_trust.yml)**

> Addition of domains is seldom and should be verified for legitimacy.

```sql
-- ============================================================
-- Title:        A New Trust Was Created To A Domain
-- Sigma ID:     0255a820-e564-4e40-af2b-6ac61160335c
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        persistence | T1098
-- Author:       Thomas Patzke
-- Date:         2019-12-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_add_domain_trust.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate extension of domain structure
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4706')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4706'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate extension of domain structure

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4706

---

## Addition of SID History to Active Directory Object

| Field | Value |
|---|---|
| **Sigma ID** | `2632954e-db1c-49cb-9936-67d1ef1d17d2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1134.005 |
| **Author** | Thomas Patzke, @atc_project (improvements) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_add_sid_history.yml)**

> An attacker can use the SID history attribute to gain additional privileges.

```sql
-- ============================================================
-- Title:        Addition of SID History to Active Directory Object
-- Sigma ID:     2632954e-db1c-49cb-9936-67d1ef1d17d2
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        persistence | T1134.005
-- Author:       Thomas Patzke, @atc_project (improvements)
-- Date:         2017-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_add_sid_history.yml
-- Unmapped:     SidHistory
-- False Pos:    Migration of an account into a new domain
-- ============================================================
-- UNMAPPED_FIELD: SidHistory

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4765', 'Win-Security-4766', 'Win-Security-4738')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('4765', '4766')
  OR (winEventId = '4738'
  AND NOT (rawEventMsg IN ('-', '%%1793'))
  AND NOT (rawEventMsg = 'None'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Migration of an account into a new domain

**References:**
- https://adsecurity.org/?p=1772

---

## Win Susp Computer Name Containing Samtheadmin

| Field | Value |
|---|---|
| **Sigma ID** | `39698b3f-da92-4bc6-bfb5-645a98386e45` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | elhoim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_computer_name.yml)**

> Detects suspicious computer name samtheadmin-{1..100}$ generated by hacktool

```sql
-- ============================================================
-- Title:        Win Susp Computer Name Containing Samtheadmin
-- Sigma ID:     39698b3f-da92-4bc6-bfb5-645a98386e45
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       elhoim
-- Date:         2022-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_computer_name.yml
-- Unmapped:     SamAccountName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SamAccountName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'targetUser')] AS targetUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'SAMTHEADMIN-%'
    AND rawEventMsg LIKE '%$')
  OR (indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] LIKE 'SAMTHEADMIN-%')
    AND indexOf(metrics_string.name, 'targetUser') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'targetUser')] LIKE '%$'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/malmoeb/status/1511760068743766026
- https://github.com/helloexp/0day/blob/614227a7b9beb0e91e7e2c6a5e532e6f7a8e883c/00-CVE_EXP/CVE-2021-42287/sam-the-admin/sam_the_admin.py

---

## Password Change on Directory Service Restore Mode (DSRM) Account

| Field | Value |
|---|---|
| **Sigma ID** | `53ad8e36-f573-46bf-97e4-15ba5bf4bb51` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_dsrm_password_change.yml)**

> Detects potential attempts made to set the Directory Services Restore Mode administrator password.
The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers.
Attackers may change the password in order to obtain persistence.


```sql
-- ============================================================
-- Title:        Password Change on Directory Service Restore Mode (DSRM) Account
-- Sigma ID:     53ad8e36-f573-46bf-97e4-15ba5bf4bb51
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        persistence | T1098
-- Author:       Thomas Patzke
-- Date:         2017-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_dsrm_password_change.yml
-- Unmapped:     (none)
-- False Pos:    Initial installation of a domain controller.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4794')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4794'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Initial installation of a domain controller.

**References:**
- https://adsecurity.org/?p=1714
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4794

---

## Account Tampering - Suspicious Failed Logon Reasons

| Field | Value |
|---|---|
| **Sigma ID** | `9eb99343-d336-4020-a3cd-67f3819e68ee` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_failed_logon_reasons.yml)**

> This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.

```sql
-- ============================================================
-- Title:        Account Tampering - Suspicious Failed Logon Reasons
-- Sigma ID:     9eb99343-d336-4020-a3cd-67f3819e68ee
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_failed_logon_reasons.yml
-- Unmapped:     SubjectUserSid
-- False Pos:    User using a disabled account
-- ============================================================
-- UNMAPPED_FIELD: SubjectUserSid

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4625', 'Win-Security-4776')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND NOT (rawEventMsg = 'S-1-0-0')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User using a disabled account

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- https://twitter.com/SBousseaden/status/1101431884540710913

---

## Group Policy Abuse for Privilege Addition

| Field | Value |
|---|---|
| **Sigma ID** | `1c480e10-7ee1-46d4-8ed2-85f9789e3ce4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1484.001 |
| **Author** | Elastic, Josh Nickels, Marius Rothenbücher |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_group_policy_abuse_privilege_addition.yml)**

> Detects the first occurrence of a modification to Group Policy Object Attributes to add privileges to user accounts or use them to add users as local admins.


```sql
-- ============================================================
-- Title:        Group Policy Abuse for Privilege Addition
-- Sigma ID:     1c480e10-7ee1-46d4-8ed2-85f9789e3ce4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1484.001
-- Author:       Elastic, Josh Nickels, Marius Rothenbücher
-- Date:         2024-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_group_policy_abuse_privilege_addition.yml
-- Unmapped:     AttributeLDAPDisplayName, AttributeValue
-- False Pos:    Users allowed to perform these modifications (user found in field SubjectUserName)
-- ============================================================
-- UNMAPPED_FIELD: AttributeLDAPDisplayName
-- UNMAPPED_FIELD: AttributeValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5136'
    AND rawEventMsg = 'gPCMachineExtensionNames'
    AND (rawEventMsg LIKE '%827D319E-6EAC-11D2-A4EA-00C04F79F83A%' OR rawEventMsg LIKE '%803E14A0-B4FB-11D0-A0D0-00A0C90F574B%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Users allowed to perform these modifications (user found in field SubjectUserName)

**References:**
- https://www.elastic.co/guide/en/security/current/group-policy-abuse-for-privilege-addition.html#_setup_275

---

## Startup/Logon Script Added to Group Policy Object

| Field | Value |
|---|---|
| **Sigma ID** | `123e4e6d-b123-48f8-b261-7214938acaf0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1484.001, T1547 |
| **Author** | Elastic, Josh Nickels, Marius Rothenbücher |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_group_policy_startup_script_added_to_gpo.yml)**

> Detects the modification of Group Policy Objects (GPO) to add a startup/logon script to users or computer objects.


```sql
-- ============================================================
-- Title:        Startup/Logon Script Added to Group Policy Object
-- Sigma ID:     123e4e6d-b123-48f8-b261-7214938acaf0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1484.001, T1547
-- Author:       Elastic, Josh Nickels, Marius Rothenbücher
-- Date:         2024-09-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_group_policy_startup_script_added_to_gpo.yml
-- Unmapped:     ShareName, RelativeTargetName, AccessList
-- False Pos:    Legitimate execution by system administrators.
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName
-- UNMAPPED_FIELD: AccessList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136', 'Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('5136', '5145')
  OR (rawEventMsg LIKE '%\\SYSVOL'
    AND (rawEventMsg LIKE '%\\scripts.ini' OR rawEventMsg LIKE '%\\psscripts.ini')
    AND rawEventMsg LIKE '%\%\%4417%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate execution by system administrators.

**References:**
- https://www.elastic.co/guide/en/security/current/startup-logon-script-added-to-group-policy-object.html

---

## Kerberos Manipulation

| Field | Value |
|---|---|
| **Sigma ID** | `f7644214-0eb0-4ace-9455-331ec4c09253` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1212 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_kerberos_manipulation.yml)**

> Detects failed Kerberos TGT issue operation. This can be a sign of manipulations of TGT messages by an attacker.

```sql
-- ============================================================
-- Title:        Kerberos Manipulation
-- Sigma ID:     f7644214-0eb0-4ace-9455-331ec4c09253
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1212
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-02-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_kerberos_manipulation.yml
-- Unmapped:     Status
-- False Pos:    Faulty legacy applications
-- ============================================================
-- UNMAPPED_FIELD: Status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-675', 'Win-Security-4768', 'Win-Security-4769', 'Win-Security-4771')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('675', '4768', '4769', '4771')
    AND rawEventMsg IN ('0x9', '0xA', '0xB', '0xF', '0x10', '0x11', '0x13', '0x14', '0x1A', '0x1F', '0x21', '0x22', '0x23', '0x24', '0x26', '0x27', '0x28', '0x29', '0x2C', '0x2D', '0x2E', '0x2F', '0x31', '0x32', '0x3E', '0x3F', '0x40', '0x41', '0x43', '0x44'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Faulty legacy applications

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771

---

## Suspicious LDAP-Attributes Used

| Field | Value |
|---|---|
| **Sigma ID** | `d00a9a72-2c09-4459-ad03-5e0a23351e36` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1001.003 |
| **Author** | xknow @xknow_infosec |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_ldap_dataexchange.yml)**

> Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.

```sql
-- ============================================================
-- Title:        Suspicious LDAP-Attributes Used
-- Sigma ID:     d00a9a72-2c09-4459-ad03-5e0a23351e36
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1001.003
-- Author:       xknow @xknow_infosec
-- Date:         2019-03-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_ldap_dataexchange.yml
-- Unmapped:     AttributeValue, AttributeLDAPDisplayName
-- False Pos:    Companies, who may use these default LDAP-Attributes for personal information
-- ============================================================
-- UNMAPPED_FIELD: AttributeValue
-- UNMAPPED_FIELD: AttributeLDAPDisplayName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5136'
    AND rawEventMsg LIKE '%*%'
    AND rawEventMsg IN ('primaryInternationalISDNNumber', 'otherFacsimileTelephoneNumber', 'primaryTelexNumber'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Companies, who may use these default LDAP-Attributes for personal information

**References:**
- https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
- https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
- https://github.com/fox-it/LDAPFragger

---

## Suspicious Windows ANONYMOUS LOGON Local Account Created

| Field | Value |
|---|---|
| **Sigma ID** | `1bbf25b9-8038-4154-a50b-118f2a32be27` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001, T1136.002 |
| **Author** | James Pemberton / @4A616D6573 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_local_anon_logon_created.yml)**

> Detects the creation of suspicious accounts similar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.

```sql
-- ============================================================
-- Title:        Suspicious Windows ANONYMOUS LOGON Local Account Created
-- Sigma ID:     1bbf25b9-8038-4154-a50b-118f2a32be27
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1136.001, T1136.002
-- Author:       James Pemberton / @4A616D6573
-- Date:         2019-10-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_local_anon_logon_created.yml
-- Unmapped:     SamAccountName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SamAccountName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4720')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4720'
    AND rawEventMsg LIKE '%ANONYMOUS%' AND rawEventMsg LIKE '%LOGON%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1189469425482829824

---

## Suspicious Remote Logon with Explicit Credentials

| Field | Value |
|---|---|
| **Sigma ID** | `941e5c45-cda7-4864-8cea-bbb7458d194a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_logon_explicit_credentials.yml)**

> Detects suspicious processes logging on with explicit credentials

```sql
-- ============================================================
-- Title:        Suspicious Remote Logon with Explicit Credentials
-- Sigma ID:     941e5c45-cda7-4864-8cea-bbb7458d194a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Tim Shelton
-- Date:         2020-10-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_logon_explicit_credentials.yml
-- Unmapped:     ProcessName
-- False Pos:    Administrators that use the RunAS command or scheduled tasks
-- ============================================================
-- UNMAPPED_FIELD: ProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4648')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4648'
    AND (rawEventMsg LIKE '%\\cmd.exe' OR rawEventMsg LIKE '%\\powershell.exe' OR rawEventMsg LIKE '%\\pwsh.exe' OR rawEventMsg LIKE '%\\winrs.exe' OR rawEventMsg LIKE '%\\wmic.exe' OR rawEventMsg LIKE '%\\net.exe' OR rawEventMsg LIKE '%\\net1.exe' OR rawEventMsg LIKE '%\\reg.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators that use the RunAS command or scheduled tasks

**References:**
- https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view

---

## Password Dumper Activity on LSASS

| Field | Value |
|---|---|
| **Sigma ID** | `aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | sigma |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_lsass_dump.yml)**

> Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN

```sql
-- ============================================================
-- Title:        Password Dumper Activity on LSASS
-- Sigma ID:     aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       sigma
-- Date:         2017-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_lsass_dump.yml
-- Unmapped:     ProcessName, AccessMask, ObjectType
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ProcessName
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: ObjectType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4656'
    AND rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg = '0x705'
    AND rawEventMsg = 'SAM_DOMAIN')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/jackcr/status/807385668833968128

---

## Potentially Suspicious AccessMask Requested From LSASS

| Field | Value |
|---|---|
| **Sigma ID** | `4a1b6da0-d94f-4fc3-98fc-2d9cb9e5ee76` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Roberto Rodriguez, Teymur Kheirkhabarov, Dimitrios Slamaris, Mark Russinovich, Aleksey Potapov, oscd.community (update) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_lsass_dump_generic.yml)**

> Detects process handle on LSASS process with certain access mask

```sql
-- ============================================================
-- Title:        Potentially Suspicious AccessMask Requested From LSASS
-- Sigma ID:     4a1b6da0-d94f-4fc3-98fc-2d9cb9e5ee76
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Roberto Rodriguez, Teymur Kheirkhabarov, Dimitrios Slamaris, Mark Russinovich, Aleksey Potapov, oscd.community (update)
-- Date:         2019-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_lsass_dump_generic.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it

**References:**
- https://web.archive.org/web/20230208123920/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---

## Reconnaissance Activity

| Field | Value |
|---|---|
| **Sigma ID** | `968eef52-9cff-4454-8992-1e74b9cbad6c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.002, T1069.002 |
| **Author** | Florian Roth (Nextron Systems), Jack Croock (method), Jonhnathan Ribeiro (improvements), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_net_recon_activity.yml)**

> Detects activity as "net user administrator /domain" and "net group domain admins /domain"

```sql
-- ============================================================
-- Title:        Reconnaissance Activity
-- Sigma ID:     968eef52-9cff-4454-8992-1e74b9cbad6c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1087.002, T1069.002
-- Author:       Florian Roth (Nextron Systems), Jack Croock (method), Jonhnathan Ribeiro (improvements), oscd.community
-- Date:         2017-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_net_recon_activity.yml
-- Unmapped:     AccessMask, ObjectType, ObjectName
-- False Pos:    Administrator activity
-- ============================================================
-- UNMAPPED_FIELD: AccessMask
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4661')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4661'
    AND rawEventMsg = '0x2d'
    AND rawEventMsg IN ('SAM_USER', 'SAM_GROUP')
    AND rawEventMsg LIKE 'S-1-5-21-%'
    AND (rawEventMsg LIKE '%-500' OR rawEventMsg LIKE '%-512'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator activity

**References:**
- https://findingbad.blogspot.de/2017/01/hunting-what-does-it-look-like.html

---

## Password Protected ZIP File Opened

| Field | Value |
|---|---|
| **Sigma ID** | `00ba9da1-b510-4f6b-b258-8d338836180f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1027 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip.yml)**

> Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.

```sql
-- ============================================================
-- Title:        Password Protected ZIP File Opened
-- Sigma ID:     00ba9da1-b510-4f6b-b258-8d338836180f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1027
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip.yml
-- Unmapped:     TargetName
-- False Pos:    Legitimate used of encrypted ZIP files
-- ============================================================
-- UNMAPPED_FIELD: TargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5379')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '5379'
    AND rawEventMsg LIKE '%Microsoft\_Windows\_Shell\_ZipFolder:filename%')
  AND NOT (rawEventMsg LIKE '%\\Temporary Internet Files\\Content.Outlook%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate used of encrypted ZIP files

**References:**
- https://twitter.com/sbousseaden/status/1523383197513379841

---

## Password Protected ZIP File Opened (Suspicious Filenames)

| Field | Value |
|---|---|
| **Sigma ID** | `54f0434b-726f-48a1-b2aa-067df14516e4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027, T1105, T1036 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_filename.yml)**

> Detects the extraction of password protected ZIP archives with suspicious file names. See the filename variable for more details on which file has been opened.

```sql
-- ============================================================
-- Title:        Password Protected ZIP File Opened (Suspicious Filenames)
-- Sigma ID:     54f0434b-726f-48a1-b2aa-067df14516e4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027, T1105, T1036
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_filename.yml
-- Unmapped:     TargetName
-- False Pos:    Legitimate used of encrypted ZIP files
-- ============================================================
-- UNMAPPED_FIELD: TargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5379')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '5379'
    AND rawEventMsg LIKE '%Microsoft\_Windows\_Shell\_ZipFolder:filename%')
  AND (rawEventMsg LIKE '%invoice%' OR rawEventMsg LIKE '%new order%' OR rawEventMsg LIKE '%rechnung%' OR rawEventMsg LIKE '%factura%' OR rawEventMsg LIKE '%delivery%' OR rawEventMsg LIKE '%purchase%' OR rawEventMsg LIKE '%order%' OR rawEventMsg LIKE '%payment%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate used of encrypted ZIP files

**References:**
- https://twitter.com/sbousseaden/status/1523383197513379841

---

## Password Protected ZIP File Opened (Email Attachment)

| Field | Value |
|---|---|
| **Sigma ID** | `571498c8-908e-40b4-910b-d2369159a3da` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027, T1566.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_outlook.yml)**

> Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.

```sql
-- ============================================================
-- Title:        Password Protected ZIP File Opened (Email Attachment)
-- Sigma ID:     571498c8-908e-40b4-910b-d2369159a3da
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027, T1566.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_outlook.yml
-- Unmapped:     TargetName
-- False Pos:    Legitimate used of encrypted ZIP files
-- ============================================================
-- UNMAPPED_FIELD: TargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5379')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5379'
    AND rawEventMsg LIKE '%Microsoft\_Windows\_Shell\_ZipFolder:filename%' AND rawEventMsg LIKE '%\\Temporary Internet Files\\Content.Outlook%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate used of encrypted ZIP files

**References:**
- https://twitter.com/sbousseaden/status/1523383197513379841

---

## Uncommon Outbound Kerberos Connection - Security

| Field | Value |
|---|---|
| **Sigma ID** | `eca91c7c-9214-47b9-b4c5-cb1d7e4f2350` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1558.003 |
| **Author** | Ilyas Ochkov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_outbound_kerberos_connection.yml)**

> Detects uncommon outbound network activity via Kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.


```sql
-- ============================================================
-- Title:        Uncommon Outbound Kerberos Connection - Security
-- Sigma ID:     eca91c7c-9214-47b9-b4c5-cb1d7e4f2350
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1558.003
-- Author:       Ilyas Ochkov, oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_outbound_kerberos_connection.yml
-- Unmapped:     DestPort
-- False Pos:    Web Browsers and third party application might generate similar activity. An initial baseline is required.
-- ============================================================
-- UNMAPPED_FIELD: DestPort

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5156')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5156'
    AND rawEventMsg = '88')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Web Browsers and third party application might generate similar activity. An initial baseline is required.

**References:**
- https://github.com/GhostPack/Rubeus

---

## Possible Shadow Credentials Added

| Field | Value |
|---|---|
| **Sigma ID** | `f598ea0c-c25a-4f72-a219-50c44411c791` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_possible_shadow_credentials_added.yml)**

> Detects possible addition of shadow credentials to an active directory object.

```sql
-- ============================================================
-- Title:        Possible Shadow Credentials Added
-- Sigma ID:     f598ea0c-c25a-4f72-a219-50c44411c791
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       Nasreddine Bencherchali (Nextron Systems), Elastic (idea)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_possible_shadow_credentials_added.yml
-- Unmapped:     AttributeLDAPDisplayName
-- False Pos:    Modifications in the msDS-KeyCredentialLink attribute can be done legitimately by the Azure AD Connect synchronization account or the ADFS service account. These accounts can be added as Exceptions. (From elastic FP section)
-- ============================================================
-- UNMAPPED_FIELD: AttributeLDAPDisplayName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5136')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5136'
    AND rawEventMsg = 'msDS-KeyCredentialLink')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Modifications in the msDS-KeyCredentialLink attribute can be done legitimately by the Azure AD Connect synchronization account or the ADFS service account. These accounts can be added as Exceptions. (From elastic FP section)

**References:**
- https://www.elastic.co/guide/en/security/8.4/potential-shadow-credentials-added-to-ad-object.html
- https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/
- https://twitter.com/SBousseaden/status/1581300963650187264?

---

## Suspicious PsExec Execution

| Field | Value |
|---|---|
| **Sigma ID** | `c462f537-a1e3-41a6-b5fc-b2c2cef9bf82` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_psexec.yml)**

> detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

```sql
-- ============================================================
-- Title:        Suspicious PsExec Execution
-- Sigma ID:     c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_psexec.yml
-- Unmapped:     ShareName, RelativeTargetName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\IPC$'
    AND (rawEventMsg LIKE '%-stdin' OR rawEventMsg LIKE '%-stdout' OR rawEventMsg LIKE '%-stderr'))
  AND NOT (rawEventMsg LIKE 'PSEXESVC%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329171218/https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html

---

## Suspicious Access to Sensitive File Extensions

| Field | Value |
|---|---|
| **Sigma ID** | `91c945bc-2ad1-4799-a591-4d00198a1215` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1039 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_raccess_sensitive_fext.yml)**

> Detects known sensitive file extensions accessed on a network share

```sql
-- ============================================================
-- Title:        Suspicious Access to Sensitive File Extensions
-- Sigma ID:     91c945bc-2ad1-4799-a591-4d00198a1215
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1039
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_raccess_sensitive_fext.yml
-- Unmapped:     RelativeTargetName
-- False Pos:    Help Desk operator doing backup or re-imaging end user machine or backup software; Users working with these data types or exchanging message files
-- ============================================================
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND (rawEventMsg LIKE '%.bak' OR rawEventMsg LIKE '%.dmp' OR rawEventMsg LIKE '%.edb' OR rawEventMsg LIKE '%.kirbi' OR rawEventMsg LIKE '%.msg' OR rawEventMsg LIKE '%.nsf' OR rawEventMsg LIKE '%.nst' OR rawEventMsg LIKE '%.oab' OR rawEventMsg LIKE '%.ost' OR rawEventMsg LIKE '%.pst' OR rawEventMsg LIKE '%.rdp'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Help Desk operator doing backup or re-imaging end user machine or backup software; Users working with these data types or exchanging message files

**References:**
- Internal Research

---

## Suspicious Kerberos RC4 Ticket Encryption

| Field | Value |
|---|---|
| **Sigma ID** | `496a0e47-0a33-4dca-b009-9e6ca3591f39` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1558.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml)**

> Detects service ticket requests using RC4 encryption type

```sql
-- ============================================================
-- Title:        Suspicious Kerberos RC4 Ticket Encryption
-- Sigma ID:     496a0e47-0a33-4dca-b009-9e6ca3591f39
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1558.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-02-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml
-- Unmapped:     TicketOptions, TicketEncryptionType
-- False Pos:    Service accounts used on legacy systems (e.g. NetApp); Windows Domains with DFL 2003 and legacy systems
-- ============================================================
-- UNMAPPED_FIELD: TicketOptions
-- UNMAPPED_FIELD: TicketEncryptionType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4769')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4769'
    AND rawEventMsg = '0x40810000'
    AND rawEventMsg = '0x17')
  AND NOT (serviceName LIKE '%$'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service accounts used on legacy systems (e.g. NetApp); Windows Domains with DFL 2003 and legacy systems

**References:**
- https://adsecurity.org/?p=3458
- https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity

---

## Suspicious Scheduled Task Creation

| Field | Value |
|---|---|
| **Sigma ID** | `3a734d25-df5c-4b99-8034-af1ddb5883a4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_creation.yml)**

> Detects suspicious scheduled task creation events. Based on attributes such as paths, commands line flags, etc.

```sql
-- ============================================================
-- Title:        Suspicious Scheduled Task Creation
-- Sigma ID:     3a734d25-df5c-4b99-8034-af1ddb5883a4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_creation.yml
-- Unmapped:     TaskContent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TaskContent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4698')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%regsvr32%' OR rawEventMsg LIKE '%rundll32%' OR rawEventMsg LIKE '%cmd.exe</Command>%' OR rawEventMsg LIKE '%cmd</Command>%' OR rawEventMsg LIKE '%<Arguments>/c %' OR rawEventMsg LIKE '%<Arguments>/k %' OR rawEventMsg LIKE '%<Arguments>/r %' OR rawEventMsg LIKE '%powershell%' OR rawEventMsg LIKE '%pwsh%' OR rawEventMsg LIKE '%mshta%' OR rawEventMsg LIKE '%wscript%' OR rawEventMsg LIKE '%cscript%' OR rawEventMsg LIKE '%certutil%' OR rawEventMsg LIKE '%bitsadmin%' OR rawEventMsg LIKE '%bash.exe%' OR rawEventMsg LIKE '%bash %' OR rawEventMsg LIKE '%scrcons%' OR rawEventMsg LIKE '%wmic %' OR rawEventMsg LIKE '%wmic.exe%' OR rawEventMsg LIKE '%forfiles%' OR rawEventMsg LIKE '%scriptrunner%' OR rawEventMsg LIKE '%hh.exe%')
  AND winEventId = '4698'
  AND (rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%' OR rawEventMsg LIKE '%\\AppData\\Roaming\\%' OR rawEventMsg LIKE '%\\Users\\Public\\%' OR rawEventMsg LIKE '%\\WINDOWS\\Temp\\%' OR rawEventMsg LIKE '%C:\\Temp\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\Downloads\\%' OR rawEventMsg LIKE '%\\Temporary Internet%' OR rawEventMsg LIKE '%C:\\ProgramData\\%' OR rawEventMsg LIKE '%C:\\Perflogs\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698

---

## Important Scheduled Task Deleted/Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `7595ba94-cf3b-4471-aa03-4f6baa9e5fad` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml)**

> Detects when adversaries stop services or processes by deleting or disabling their respective scheduled tasks in order to conduct data destructive activities

```sql
-- ============================================================
-- Title:        Important Scheduled Task Deleted/Disabled
-- Sigma ID:     7595ba94-cf3b-4471-aa03-4f6baa9e5fad
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml
-- Unmapped:     TaskName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TaskName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4699', 'Win-Security-4701')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4699', '4701')
    AND (rawEventMsg LIKE '%\\Windows\\SystemRestore\\SR%' OR rawEventMsg LIKE '%\\Windows\\Windows Defender\\%' OR rawEventMsg LIKE '%\\Windows\\BitLocker%' OR rawEventMsg LIKE '%\\Windows\\WindowsBackup\\%' OR rawEventMsg LIKE '%\\Windows\\WindowsUpdate\\%' OR rawEventMsg LIKE '%\\Windows\\UpdateOrchestrator\\Schedule%' OR rawEventMsg LIKE '%\\Windows\\ExploitGuard%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4701

---

## Suspicious Scheduled Task Update

| Field | Value |
|---|---|
| **Sigma ID** | `614cf376-6651-47c4-9dcc-6b9527f749f4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_update.yml)**

> Detects update to a scheduled task event that contain suspicious keywords.

```sql
-- ============================================================
-- Title:        Suspicious Scheduled Task Update
-- Sigma ID:     614cf376-6651-47c4-9dcc-6b9527f749f4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_update.yml
-- Unmapped:     TaskContentNew
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TaskContentNew

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4702')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%regsvr32%' OR rawEventMsg LIKE '%rundll32%' OR rawEventMsg LIKE '%cmd.exe</Command>%' OR rawEventMsg LIKE '%cmd</Command>%' OR rawEventMsg LIKE '%<Arguments>/c %' OR rawEventMsg LIKE '%<Arguments>/k %' OR rawEventMsg LIKE '%<Arguments>/r %' OR rawEventMsg LIKE '%powershell%' OR rawEventMsg LIKE '%pwsh%' OR rawEventMsg LIKE '%mshta%' OR rawEventMsg LIKE '%wscript%' OR rawEventMsg LIKE '%cscript%' OR rawEventMsg LIKE '%certutil%' OR rawEventMsg LIKE '%bitsadmin%' OR rawEventMsg LIKE '%bash.exe%' OR rawEventMsg LIKE '%bash %' OR rawEventMsg LIKE '%scrcons%' OR rawEventMsg LIKE '%wmic %' OR rawEventMsg LIKE '%wmic.exe%' OR rawEventMsg LIKE '%forfiles%' OR rawEventMsg LIKE '%scriptrunner%' OR rawEventMsg LIKE '%hh.exe%')
  AND winEventId = '4702'
  AND (rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%' OR rawEventMsg LIKE '%\\AppData\\Roaming\\%' OR rawEventMsg LIKE '%\\Users\\Public\\%' OR rawEventMsg LIKE '%\\WINDOWS\\Temp\\%' OR rawEventMsg LIKE '%C:\\Temp\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\Downloads\\%' OR rawEventMsg LIKE '%\\Temporary Internet%' OR rawEventMsg LIKE '%C:\\ProgramData\\%' OR rawEventMsg LIKE '%C:\\Perflogs\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698

---

## Unauthorized System Time Modification

| Field | Value |
|---|---|
| **Sigma ID** | `faa031b5-21ed-4e02-8881-2591f98d82ed` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1070.006 |
| **Author** | @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_time_modification.yml)**

> Detect scenarios where a potentially unauthorized application or user is modifying the system time.

```sql
-- ============================================================
-- Title:        Unauthorized System Time Modification
-- Sigma ID:     faa031b5-21ed-4e02-8881-2591f98d82ed
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1070.006
-- Author:       @neu5ron
-- Date:         2019-02-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_time_modification.yml
-- Unmapped:     (none)
-- False Pos:    HyperV or other virtualization technologies with binary not listed in filter portion of detection
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4616')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4616'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** HyperV or other virtualization technologies with binary not listed in filter portion of detection

**References:**
- Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)
- Live environment caused by malware
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616

---

## Remote Service Activity via SVCCTL Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1021.002 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_svcctl_remote_service.yml)**

> Detects remote service activity via remote access to the svcctl named pipe

```sql
-- ============================================================
-- Title:        Remote Service Activity via SVCCTL Named Pipe
-- Sigma ID:     586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1021.002
-- Author:       Samir Bousseaden
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_svcctl_remote_service.yml
-- Unmapped:     ShareName, RelativeTargetName, AccessList
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ShareName
-- UNMAPPED_FIELD: RelativeTargetName
-- UNMAPPED_FIELD: AccessList

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
    AND rawEventMsg = '\\\\\*\\IPC$'
    AND rawEventMsg = 'svcctl'
    AND rawEventMsg LIKE '%WriteData%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329155141/https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html

---

## SysKey Registry Keys Access

| Field | Value |
|---|---|
| **Sigma ID** | `9a4ff3b8-6187-4fd2-8e8b-e0eae1129495` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1012 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_syskey_registry_access.yml)**

> Detects handle requests and access operations to specific registry keys to calculate the SysKey

```sql
-- ============================================================
-- Title:        SysKey Registry Keys Access
-- Sigma ID:     9a4ff3b8-6187-4fd2-8e8b-e0eae1129495
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1012
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_syskey_registry_access.yml
-- Unmapped:     ObjectType, ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('4656', '4663')
    AND rawEventMsg = 'key'
    AND (rawEventMsg LIKE '%lsa\\JD' OR rawEventMsg LIKE '%lsa\\GBG' OR rawEventMsg LIKE '%lsa\\Skew1' OR rawEventMsg LIKE '%lsa\\Data'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190625-RegKeyAccessSyskey/notebook.html

---

## Sysmon Channel Reference Deletion

| Field | Value |
|---|---|
| **Sigma ID** | `18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_sysmon_channel_reference_deletion.yml)**

> Potential threat actor tampering with Sysmon manifest and eventually disabling it

```sql
-- ============================================================
-- Title:        Sysmon Channel Reference Deletion
-- Sigma ID:     18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-07-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_sysmon_channel_reference_deletion.yml
-- Unmapped:     ObjectName, ObjectValueName, NewValue, AccessMask
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: ObjectValueName
-- UNMAPPED_FIELD: NewValue
-- UNMAPPED_FIELD: AccessMask

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4657', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4657'
    AND (rawEventMsg LIKE '%WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}%' OR rawEventMsg LIKE '%WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational%')
    AND rawEventMsg = 'Enabled'
    AND rawEventMsg = '0')
  OR (winEventId = '4663'
    AND (rawEventMsg LIKE '%WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}%' OR rawEventMsg LIKE '%WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational%')
    AND rawEventMsg = '0x10000')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/Flangvik/status/1283054508084473861
- https://twitter.com/SecurityJosh/status/1283027365770276866
- https://securityjosh.github.io/2020/04/23/Mute-Sysmon.html
- https://gist.github.com/Cyb3rWard0g/cf08c38c61f7e46e8404b38201ca01c8

---

## Tap Driver Installation - Security

| Field | Value |
|---|---|
| **Sigma ID** | `9c8afa4d-0022-48f0-9456-3712466f9701` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048 |
| **Author** | Daniil Yugoslavskiy, Ian Davis, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_tap_driver_installation.yml)**

> Detects the installation of a well-known TAP driver service. This could be a sign of potential preparation for data exfiltration using tunnelling techniques.


```sql
-- ============================================================
-- Title:        Tap Driver Installation - Security
-- Sigma ID:     9c8afa4d-0022-48f0-9456-3712466f9701
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1048
-- Author:       Daniil Yugoslavskiy, Ian Davis, oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_tap_driver_installation.yml
-- Unmapped:     ServiceFileName
-- False Pos:    Legitimate OpenVPN TAP installation
-- ============================================================
-- UNMAPPED_FIELD: ServiceFileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4697')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4697'
    AND rawEventMsg LIKE '%tap0901%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate OpenVPN TAP installation

**References:**
- https://community.openvpn.net/openvpn/wiki/ManagingWindowsTAPDrivers

---

## Suspicious Teams Application Related ObjectAcess Event

| Field | Value |
|---|---|
| **Sigma ID** | `25cde13e-8e20-4c29-b949-4e795b76f16f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1528 |
| **Author** | @SerkinValery |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.yml)**

> Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.

```sql
-- ============================================================
-- Title:        Suspicious Teams Application Related ObjectAcess Event
-- Sigma ID:     25cde13e-8e20-4c29-b949-4e795b76f16f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1528
-- Author:       @SerkinValery
-- Date:         2022-09-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.yml
-- Unmapped:     ObjectName, ProcessName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ObjectName
-- UNMAPPED_FIELD: ProcessName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '4663'
    AND (rawEventMsg LIKE '%\\Microsoft\\Teams\\Cookies%' OR rawEventMsg LIKE '%\\Microsoft\\Teams\\Local Storage\\leveldb%'))
  AND NOT (rawEventMsg LIKE '%\\Microsoft\\Teams\\current\\Teams.exe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
- https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens

---

## Transferring Files with Credential Data via Network Shares

| Field | Value |
|---|---|
| **Sigma ID** | `910ab938-668b-401b-b08c-b596e80fdca5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.002, T1003.001, T1003.003 |
| **Author** | Teymur Kheirkhabarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_transf_files_with_cred_data_via_network_shares.yml)**

> Transferring files with well-known filenames (sensitive files with credential data) using network shares

```sql
-- ============================================================
-- Title:        Transferring Files with Credential Data via Network Shares
-- Sigma ID:     910ab938-668b-401b-b08c-b596e80fdca5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.002, T1003.001, T1003.003
-- Author:       Teymur Kheirkhabarov, oscd.community
-- Date:         2019-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_transf_files_with_cred_data_via_network_shares.yml
-- Unmapped:     RelativeTargetName
-- False Pos:    Transferring sensitive files for legitimate administration work by legitimate administrator
-- ============================================================
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '5145'
  AND ((rawEventMsg LIKE '%\\mimidrv%' OR rawEventMsg LIKE '%\\lsass%' OR rawEventMsg LIKE '%\\windows\\minidump\\%' OR rawEventMsg LIKE '%\\hiberfil%' OR rawEventMsg LIKE '%\\sqldmpr%'))
  OR (rawEventMsg IN ('Windows\NTDS\ntds.dit', 'Windows\System32\config\SAM', 'Windows\System32\config\SECURITY', 'Windows\System32\config\SYSTEM')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Transferring sensitive files for legitimate administration work by legitimate administrator

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---

## User Added to Local Administrator Group

| Field | Value |
|---|---|
| **Sigma ID** | `c265cf08-3f99-46c1-8d59-328247057d57` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1098 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml)**

> Detects the addition of a new member to the local administrator group, which could be legitimate activity or a sign of privilege escalation activity

```sql
-- ============================================================
-- Title:        User Added to Local Administrator Group
-- Sigma ID:     c265cf08-3f99-46c1-8d59-328247057d57
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        persistence | T1078, T1098
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4732')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

---

## User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'

| Field | Value |
|---|---|
| **Sigma ID** | `6daac7fc-77d1-449a-a71a-e6b4d59a0e54` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1558.003 |
| **Author** | Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_couldnt_call_priv_service_lsaregisterlogonprocess.yml)**

> The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.

```sql
-- ============================================================
-- Title:        User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'
-- Sigma ID:     6daac7fc-77d1-449a-a71a-e6b4d59a0e54
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1558.003
-- Author:       Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_couldnt_call_priv_service_lsaregisterlogonprocess.yml
-- Unmapped:     Service, Keywords
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Service
-- UNMAPPED_FIELD: Keywords

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4673')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4673'
    AND rawEventMsg = 'LsaRegisterLogonProcess()'
    AND rawEventMsg = '0x8010000000000000')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1

---

## Local User Creation

| Field | Value |
|---|---|
| **Sigma ID** | `66b6be3d-55d0-4f47-9855-d69df21740ea` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Patrick Bareiss |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_creation.yml)**

> Detects local user creation on Windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your Windows server logs and not on your DC logs.


```sql
-- ============================================================
-- Title:        Local User Creation
-- Sigma ID:     66b6be3d-55d0-4f47-9855-d69df21740ea
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1136.001
-- Author:       Patrick Bareiss
-- Date:         2019-04-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_creation.yml
-- Unmapped:     (none)
-- False Pos:    Domain Controller Logs; Local accounts managed by privileged account management tools
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4720')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4720'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Domain Controller Logs; Local accounts managed by privileged account management tools

**References:**
- https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/

---

## Potential Privileged System Service Operation - SeLoadDriverPrivilege

| Field | Value |
|---|---|
| **Sigma ID** | `f63508a0-c809-4435-b3be-ed819394d612` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | xknow (@xknow_infosec), xorxes (@xor_xes) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_driver_loaded.yml)**

> Detects the usage of the 'SeLoadDriverPrivilege' privilege. This privilege is required to load or unload a device driver.
With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode.
This user right does not apply to Plug and Play device drivers.
If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers.
This will detect Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs) and the usage of Sysinternals and various other tools. So you have to work with a whitelist to find the bad stuff.


```sql
-- ============================================================
-- Title:        Potential Privileged System Service Operation - SeLoadDriverPrivilege
-- Sigma ID:     f63508a0-c809-4435-b3be-ed819394d612
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       xknow (@xknow_infosec), xorxes (@xor_xes)
-- Date:         2019-04-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_driver_loaded.yml
-- Unmapped:     PrivilegeList, Service
-- False Pos:    Other legimate tools loading drivers. Including but not limited to, Sysinternals, CPU-Z, AVs etc. A baseline needs to be created according to the used products and allowed tools. A good thing to do is to try and exclude users who are allowed to load drivers.
-- ============================================================
-- UNMAPPED_FIELD: PrivilegeList
-- UNMAPPED_FIELD: Service

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4673')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4673'
    AND rawEventMsg = 'SeLoadDriverPrivilege'
    AND rawEventMsg = '-')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legimate tools loading drivers. Including but not limited to, Sysinternals, CPU-Z, AVs etc. A baseline needs to be created according to the used products and allowed tools. A good thing to do is to try and exclude users who are allowed to load drivers.

**References:**
- https://web.archive.org/web/20230331181619/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4673

---

## User Logoff Event

| Field | Value |
|---|---|
| **Sigma ID** | `0badd08f-c6a3-4630-90d3-6875cca440be` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_logoff.yml)**

> Detects a user log-off activity. Could be used for example to correlate information during forensic investigations

```sql
-- ============================================================
-- Title:        User Logoff Event
-- Sigma ID:     0badd08f-c6a3-4630-90d3-6875cca440be
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       frack113
-- Date:         2022-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_user_logoff.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4634', 'Win-Security-4647')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('4634', '4647')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647

---

## VSSAudit Security Event Source Registration

| Field | Value |
|---|---|
| **Sigma ID** | `e9faba72-4974-4ab2-a4c5-46e25ad59e9b` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.002 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_vssaudit_secevent_source_registration.yml)**

> Detects the registration of the security event source VSSAudit. It would usually trigger when volume shadow copy operations happen.

```sql
-- ============================================================
-- Title:        VSSAudit Security Event Source Registration
-- Sigma ID:     e9faba72-4974-4ab2-a4c5-46e25ad59e9b
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.002
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
-- Date:         2020-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_vssaudit_secevent_source_registration.yml
-- Unmapped:     AuditSourceName
-- False Pos:    Legitimate use of VSSVC. Maybe backup operations. It would usually be done by C:\Windows\System32\VSSVC.exe.
-- ============================================================
-- UNMAPPED_FIELD: AuditSourceName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4904', 'Win-Security-4905')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'VSSAudit'
    AND winEventId IN ('4904', '4905'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of VSSVC. Maybe backup operations. It would usually be done by C:\Windows\System32\VSSVC.exe.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy

---

## Windows Defender Exclusion List Modified

| Field | Value |
|---|---|
| **Sigma ID** | `46a68649-f218-4f86-aea1-16a759d81820` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | @BarryShooshooga |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_windows_defender_exclusions_registry_modified.yml)**

> Detects modifications to the Windows Defender exclusion registry key. This could indicate a potentially suspicious or even malicious activity by an attacker trying to add a new exclusion in order to bypass security.


```sql
-- ============================================================
-- Title:        Windows Defender Exclusion List Modified
-- Sigma ID:     46a68649-f218-4f86-aea1-16a759d81820
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       @BarryShooshooga
-- Date:         2019-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_windows_defender_exclusions_registry_modified.yml
-- Unmapped:     ObjectName
-- False Pos:    Intended exclusions by administrators
-- ============================================================
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4657')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4657'
    AND rawEventMsg LIKE '%\\Microsoft\\Windows Defender\\Exclusions\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Intended exclusions by administrators

**References:**
- https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/

---

## Windows Defender Exclusion Registry Key - Write Access Requested

| Field | Value |
|---|---|
| **Sigma ID** | `e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | @BarryShooshooga, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_windows_defender_exclusions_write_access.yml)**

> Detects write access requests to the Windows Defender exclusions registry keys. This could be an indication of an attacker trying to request a handle or access the object to write new exclusions in order to bypass security.


```sql
-- ============================================================
-- Title:        Windows Defender Exclusion Registry Key - Write Access Requested
-- Sigma ID:     e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       @BarryShooshooga, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2019-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_windows_defender_exclusions_write_access.yml
-- Unmapped:     AccessList, ObjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: AccessList
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4656', 'Win-Security-4663')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\%\%4417%' OR rawEventMsg LIKE '%\%\%4418%')
    AND winEventId IN ('4656', '4663')
    AND rawEventMsg LIKE '%\\Microsoft\\Windows Defender\\Exclusions\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/

---

## WMI Persistence - Security

| Field | Value |
|---|---|
| **Sigma ID** | `f033f3f3-fd24-4995-97d8-a3bb17550a88` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | Florian Roth (Nextron Systems), Gleb Sukhodolskiy, Timur Zinniatullin oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_wmi_persistence.yml)**

> Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.

```sql
-- ============================================================
-- Title:        WMI Persistence - Security
-- Sigma ID:     f033f3f3-fd24-4995-97d8-a3bb17550a88
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       Florian Roth (Nextron Systems), Gleb Sukhodolskiy, Timur Zinniatullin oscd.community
-- Date:         2017-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_wmi_persistence.yml
-- Unmapped:     ObjectType, ObjectName
-- False Pos:    Unknown (data set is too small; further testing needed)
-- ============================================================
-- UNMAPPED_FIELD: ObjectType
-- UNMAPPED_FIELD: ObjectName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4662')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4662'
    AND rawEventMsg = 'WMI Namespace'
    AND rawEventMsg LIKE '%subscription%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown (data set is too small; further testing needed)

**References:**
- https://twitter.com/mattifestation/status/899646620148539397
- https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/

---

## T1047 Wmiprvse Wbemcomn DLL Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `f6c68d5f-e101-4b86-8c84-7d96851fd65c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047, T1021.002 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_wmiprvse_wbemcomn_dll_hijack.yml)**

> Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network for a WMI DLL Hijack scenario.

```sql
-- ============================================================
-- Title:        T1047 Wmiprvse Wbemcomn DLL Hijack
-- Sigma ID:     f6c68d5f-e101-4b86-8c84-7d96851fd65c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1047, T1021.002
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_wmiprvse_wbemcomn_dll_hijack.yml
-- Unmapped:     RelativeTargetName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: RelativeTargetName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] AS subjectUserName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-5145')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '5145'
    AND rawEventMsg LIKE '%\\wbem\\wbemcomn.dll')
  AND NOT (indexOf(metrics_string.name, 'subjectUsername') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'subjectUsername')] LIKE '%$')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html

---

## Locked Workstation

| Field | Value |
|---|---|
| **Sigma ID** | `411742ad-89b0-49cb-a7b0-3971b5c1e0a4` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Alexandr Yampolskyi, SOC Prime |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_workstation_was_locked.yml)**

> Detects locked workstation session events that occur automatically after a standard period of inactivity.

```sql
-- ============================================================
-- Title:        Locked Workstation
-- Sigma ID:     411742ad-89b0-49cb-a7b0-3971b5c1e0a4
-- Level:        informational  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        impact
-- Author:       Alexandr Yampolskyi, SOC Prime
-- Date:         2019-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_workstation_was_locked.yml
-- Unmapped:     (none)
-- False Pos:    Likely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Security-4800')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '4800'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://www.cisecurity.org/controls/cis-controls-list/
- https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
- https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
- https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4800

---
