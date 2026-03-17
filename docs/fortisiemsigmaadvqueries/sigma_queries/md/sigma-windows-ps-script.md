# Sigma → FortiSIEM: Windows Ps Script

> 160 rules · Generated 2026-03-17

## Table of Contents

- [AADInternals PowerShell Cmdlets Execution - PsScript](#aadinternals-powershell-cmdlets-execution-psscript)
- [Access to Browser Login Data](#access-to-browser-login-data)
- [Potential Active Directory Enumeration Using AD Module - PsScript](#potential-active-directory-enumeration-using-ad-module-psscript)
- [Powershell Add Name Resolution Policy Table Rule](#powershell-add-name-resolution-policy-table-rule)
- [Add Windows Capability Via PowerShell Script](#add-windows-capability-via-powershell-script)
- [PowerShell ADRecon Execution](#powershell-adrecon-execution)
- [AMSI Bypass Pattern Assembly GetType](#amsi-bypass-pattern-assembly-gettype)
- [Potential AMSI Bypass Script Using NULL Bits](#potential-amsi-bypass-script-using-null-bits)
- [Silence.EDA Detection](#silenceeda-detection)
- [Get-ADUser Enumeration Using UserAccountControl Flags](#get-aduser-enumeration-using-useraccountcontrol-flags)
- [Potential Data Exfiltration Via Audio File](#potential-data-exfiltration-via-audio-file)
- [Automated Collection Command PowerShell](#automated-collection-command-powershell)
- [Windows Screen Capture with CopyFromScreen](#windows-screen-capture-with-copyfromscreen)
- [Clear PowerShell History - PowerShell](#clear-powershell-history-powershell)
- [Clearing Windows Console History](#clearing-windows-console-history)
- [Powershell Create Scheduled Task](#powershell-create-scheduled-task)
- [Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell](#computer-discovery-and-export-via-get-adcomputer-cmdlet-powershell)
- [Powershell Install a DLL in System Directory](#powershell-install-a-dll-in-system-directory)
- [Registry-Free Process Scope COR_PROFILER](#registry-free-process-scope-corprofiler)
- [PowerShell Create Local User](#powershell-create-local-user)
- [Create Volume Shadow Copy with Powershell](#create-volume-shadow-copy-with-powershell)
- [Powershell Detect Virtualization Environment](#powershell-detect-virtualization-environment)
- [DirectorySearcher Powershell Exploitation](#directorysearcher-powershell-exploitation)
- [Manipulation of User Computer or Group Security Principals Across AD](#manipulation-of-user-computer-or-group-security-principals-across-ad)
- [Disable Powershell Command History](#disable-powershell-command-history)
- [Disable-WindowsOptionalFeature Command PowerShell](#disable-windowsoptionalfeature-command-powershell)
- [Potential In-Memory Execution Using Reflection.Assembly](#potential-in-memory-execution-using-reflectionassembly)
- [Potential COM Objects Download Cradles Usage - PS Script](#potential-com-objects-download-cradles-usage-ps-script)
- [DSInternals Suspicious PowerShell Cmdlets - ScriptBlock](#dsinternals-suspicious-powershell-cmdlets-scriptblock)
- [Dump Credentials from Windows Credential Manager With PowerShell](#dump-credentials-from-windows-credential-manager-with-powershell)
- [Enable Windows Remote Management](#enable-windows-remote-management)
- [Potential Suspicious Windows Feature Enabled](#potential-suspicious-windows-feature-enabled)
- [Enumerate Credentials from Windows Credential Manager With PowerShell](#enumerate-credentials-from-windows-credential-manager-with-powershell)
- [Disable of ETW Trace - Powershell](#disable-of-etw-trace-powershell)
- [Certificate Exported Via PowerShell - ScriptBlock](#certificate-exported-via-powershell-scriptblock)
- [Suspicious FromBase64String Usage On Gzip Archive - Ps Script](#suspicious-frombase64string-usage-on-gzip-archive-ps-script)
- [Service Registry Permissions Weakness Check](#service-registry-permissions-weakness-check)
- [Active Directory Computers Enumeration With Get-AdComputer](#active-directory-computers-enumeration-with-get-adcomputer)
- [Active Directory Group Enumeration With Get-AdGroup](#active-directory-group-enumeration-with-get-adgroup)
- [Suspicious Get-ADReplAccount](#suspicious-get-adreplaccount)
- [Automated Collection Bookmarks Using Get-ChildItem PowerShell](#automated-collection-bookmarks-using-get-childitem-powershell)
- [Security Software Discovery Via Powershell Script](#security-software-discovery-via-powershell-script)
- [HackTool - Rubeus Execution - ScriptBlock](#hacktool-rubeus-execution-scriptblock)
- [HackTool - WinPwn Execution - ScriptBlock](#hacktool-winpwn-execution-scriptblock)
- [PowerShell Hotfix Enumeration](#powershell-hotfix-enumeration)
- [PowerShell ICMP Exfiltration](#powershell-icmp-exfiltration)
- [Import PowerShell Modules From Suspicious Directories](#import-powershell-modules-from-suspicious-directories)
- [Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript](#unsigned-appx-installation-attempt-using-add-appxpackage-psscript)
- [Execute Invoke-command on Remote Host](#execute-invoke-command-on-remote-host)
- [Powershell DNSExfiltration](#powershell-dnsexfiltration)
- [Invoke-Obfuscation CLIP+ Launcher - PowerShell](#invoke-obfuscation-clip-launcher-powershell)
- [Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell](#invoke-obfuscation-obfuscated-iex-invocation-powershell)
- [Invoke-Obfuscation STDIN+ Launcher - Powershell](#invoke-obfuscation-stdin-launcher-powershell)
- [Invoke-Obfuscation VAR+ Launcher - PowerShell](#invoke-obfuscation-var-launcher-powershell)
- [Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell](#invoke-obfuscation-compress-obfuscation-powershell)
- [Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell](#invoke-obfuscation-rundll-launcher-powershell)
- [Invoke-Obfuscation Via Stdin - Powershell](#invoke-obfuscation-via-stdin-powershell)
- [Invoke-Obfuscation Via Use Clip - Powershell](#invoke-obfuscation-via-use-clip-powershell)
- [Invoke-Obfuscation Via Use MSHTA - PowerShell](#invoke-obfuscation-via-use-mshta-powershell)
- [Invoke-Obfuscation Via Use Rundll32 - PowerShell](#invoke-obfuscation-via-use-rundll32-powershell)
- [Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell](#invoke-obfuscation-var-launcher-obfuscation-powershell)
- [Powershell Keylogging](#powershell-keylogging)
- [Powershell LocalAccount Manipulation](#powershell-localaccount-manipulation)
- [Suspicious PowerShell Mailbox Export to Share - PS](#suspicious-powershell-mailbox-export-to-share-ps)
- [Malicious PowerShell Commandlets - ScriptBlock](#malicious-powershell-commandlets-scriptblock)
- [Malicious PowerShell Keywords](#malicious-powershell-keywords)
- [Live Memory Dump Using Powershell](#live-memory-dump-using-powershell)
- [Modify Group Policy Settings - ScriptBlockLogging](#modify-group-policy-settings-scriptblocklogging)
- [Powershell MsXml COM Object](#powershell-msxml-com-object)
- [Malicious Nishang PowerShell Commandlets](#malicious-nishang-powershell-commandlets)
- [NTFS Alternate Data Stream](#ntfs-alternate-data-stream)
- [Code Executed Via Office Add-in XLL File](#code-executed-via-office-add-in-xll-file)
- [Potential Packet Capture Activity Via Start-NetEventSession - ScriptBlock](#potential-packet-capture-activity-via-start-neteventsession-scriptblock)
- [Potential Invoke-Mimikatz PowerShell Script](#potential-invoke-mimikatz-powershell-script)
- [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](#potential-unconstrained-delegation-discovery-via-get-adcomputer-scriptblock)
- [PowerShell Web Access Installation - PsScript](#powershell-web-access-installation-psscript)
- [PowerView PowerShell Cmdlets - ScriptBlock](#powerview-powershell-cmdlets-scriptblock)
- [PowerShell Credential Prompt](#powershell-credential-prompt)
- [PSAsyncShell - Asynchronous TCP Reverse Shell](#psasyncshell-asynchronous-tcp-reverse-shell)
- [PowerShell PSAttack](#powershell-psattack)
- [PowerShell Remote Session Creation](#powershell-remote-session-creation)
- [Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock](#potential-remotefxvgpudisablementexe-abuse-powershell-scriptblock)
- [Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock](#suspicious-kerberos-ticket-request-via-powershell-script-scriptblock)
- [PowerShell Script With File Hostname Resolving Capabilities](#powershell-script-with-file-hostname-resolving-capabilities)
- [Root Certificate Installed - PowerShell](#root-certificate-installed-powershell)
- [Suspicious Invoke-Item From Mount-DiskImage](#suspicious-invoke-item-from-mount-diskimage)
- [PowerShell Script With File Upload Capabilities](#powershell-script-with-file-upload-capabilities)
- [Powershell Sensitive File Discovery](#powershell-sensitive-file-discovery)
- [PowerShell Script Change Permission Via Set-Acl - PsScript](#powershell-script-change-permission-via-set-acl-psscript)
- [PowerShell Set-Acl On Windows Folder - PsScript](#powershell-set-acl-on-windows-folder-psscript)
- [Change PowerShell Policies to an Insecure Level - PowerShell](#change-powershell-policies-to-an-insecure-level-powershell)
- [PowerShell ShellCode](#powershell-shellcode)
- [Malicious ShellIntel PowerShell Commandlets](#malicious-shellintel-powershell-commandlets)
- [Detected Windows Software Discovery - PowerShell](#detected-windows-software-discovery-powershell)
- [Powershell Store File In Alternate Data Stream](#powershell-store-file-in-alternate-data-stream)
- [Potential Persistence Via Security Descriptors - ScriptBlock](#potential-persistence-via-security-descriptors-scriptblock)
- [AD Groups Or Users Enumeration Using PowerShell - ScriptBlock](#ad-groups-or-users-enumeration-using-powershell-scriptblock)
- [Potential PowerShell Obfuscation Using Character Join](#potential-powershell-obfuscation-using-character-join)
- [Suspicious Eventlog Clear](#suspicious-eventlog-clear)
- [Powershell Directory Enumeration](#powershell-directory-enumeration)
- [Suspicious PowerShell Download - Powershell Script](#suspicious-powershell-download-powershell-script)
- [Powershell Execute Batch Script](#powershell-execute-batch-script)
- [Extracting Information with PowerShell](#extracting-information-with-powershell)
- [Troubleshooting Pack Cmdlet Execution](#troubleshooting-pack-cmdlet-execution)
- [Password Policy Discovery With Get-AdDefaultDomainPasswordPolicy](#password-policy-discovery-with-get-addefaultdomainpasswordpolicy)
- [Suspicious PowerShell Get Current User](#suspicious-powershell-get-current-user)
- [Suspicious GPO Discovery With Get-GPO](#suspicious-gpo-discovery-with-get-gpo)
- [Suspicious Process Discovery With Get-Process](#suspicious-process-discovery-with-get-process)
- [PowerShell Get-Process LSASS in ScriptBlock](#powershell-get-process-lsass-in-scriptblock)
- [Suspicious GetTypeFromCLSID ShellExecute](#suspicious-gettypefromclsid-shellexecute)
- [Suspicious Hyper-V Cmdlets](#suspicious-hyper-v-cmdlets)
- [Suspicious PowerShell Invocations - Generic](#suspicious-powershell-invocations-generic)
- [Suspicious PowerShell Invocations - Specific](#suspicious-powershell-invocations-specific)
- [Change User Agents with WebRequest](#change-user-agents-with-webrequest)
- [Suspicious IO.FileStream](#suspicious-iofilestream)
- [Potential Keylogger Activity](#potential-keylogger-activity)
- [Potential Suspicious PowerShell Keywords](#potential-suspicious-powershell-keywords)
- [Suspicious Get Local Groups Information - PowerShell](#suspicious-get-local-groups-information-powershell)
- [Powershell Local Email Collection](#powershell-local-email-collection)
- [Suspicious Mount-DiskImage](#suspicious-mount-diskimage)
- [PowerShell Deleted Mounted Share](#powershell-deleted-mounted-share)
- [Suspicious Connection to Remote Account](#suspicious-connection-to-remote-account)
- [Suspicious New-PSDrive to Admin Share](#suspicious-new-psdrive-to-admin-share)
- [Suspicious TCP Tunnel Via PowerShell Script](#suspicious-tcp-tunnel-via-powershell-script)
- [Recon Information for Export with PowerShell](#recon-information-for-export-with-powershell)
- [Remove Account From Domain Admin Group](#remove-account-from-domain-admin-group)
- [Suspicious Service DACL Modification Via Set-Service Cmdlet - PS](#suspicious-service-dacl-modification-via-set-service-cmdlet-ps)
- [Potential PowerShell Obfuscation Using Alias Cmdlets](#potential-powershell-obfuscation-using-alias-cmdlets)
- [Suspicious Get Information for SMB Share](#suspicious-get-information-for-smb-share)
- [Suspicious SSL Connection](#suspicious-ssl-connection)
- [Suspicious Start-Process PassThru](#suspicious-start-process-passthru)
- [Suspicious Unblock-File](#suspicious-unblock-file)
- [Replace Desktop Wallpaper by Powershell](#replace-desktop-wallpaper-by-powershell)
- [Powershell Suspicious Win32_PnPEntity](#powershell-suspicious-win32pnpentity)
- [Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script](#deletion-of-volume-shadow-copies-via-wmi-with-powershell-ps-script)
- [Suspicious PowerShell WindowStyle Option](#suspicious-powershell-windowstyle-option)
- [PowerShell Write-EventLog Usage](#powershell-write-eventlog-usage)
- [Zip A Folder With PowerShell For Staging In Temp - PowerShell Script](#zip-a-folder-with-powershell-for-staging-in-temp-powershell-script)
- [SyncAppvPublishingServer Execution to Bypass Powershell Restriction](#syncappvpublishingserver-execution-to-bypass-powershell-restriction)
- [Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging](#tamper-windows-defender-remove-mppreference-scriptblocklogging)
- [Tamper Windows Defender - ScriptBlockLogging](#tamper-windows-defender-scriptblocklogging)
- [Testing Usage of Uncommonly Used Port](#testing-usage-of-uncommonly-used-port)
- [Powershell Timestomp](#powershell-timestomp)
- [User Discovery And Export Via Get-ADUser Cmdlet - PowerShell](#user-discovery-and-export-via-get-aduser-cmdlet-powershell)
- [Potential Persistence Via PowerShell User Profile Using Add-Content](#potential-persistence-via-powershell-user-profile-using-add-content)
- [Abuse of Service Permissions to Hide Services Via Set-Service - PS](#abuse-of-service-permissions-to-hide-services-via-set-service-ps)
- [Registry Modification Attempt Via VBScript - PowerShell](#registry-modification-attempt-via-vbscript-powershell)
- [Veeam Backup Servers Credential Dumping Script Execution](#veeam-backup-servers-credential-dumping-script-execution)
- [Usage Of Web Request Commands And Cmdlets - ScriptBlock](#usage-of-web-request-commands-and-cmdlets-scriptblock)
- [Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript](#potentially-suspicious-call-to-win32nteventlogfile-class-psscript)
- [PowerShell WMI Win32_Product Install MSI](#powershell-wmi-win32product-install-msi)
- [Potential WinAPI Calls Via PowerShell Scripts](#potential-winapi-calls-via-powershell-scripts)
- [Windows Defender Exclusions Added - PowerShell](#windows-defender-exclusions-added-powershell)
- [Windows Firewall Profile Disabled](#windows-firewall-profile-disabled)
- [Winlogon Helper DLL](#winlogon-helper-dll)
- [Powershell WMI Persistence](#powershell-wmi-persistence)
- [WMIC Unquoted Services Path Lookup - PowerShell](#wmic-unquoted-services-path-lookup-powershell)
- [WMImplant Hack Tool](#wmimplant-hack-tool)
- [Suspicious X509Enrollment - Ps Script](#suspicious-x509enrollment-ps-script)
- [Powershell XML Execute Command](#powershell-xml-execute-command)

## AADInternals PowerShell Cmdlets Execution - PsScript

| Field | Value |
|---|---|
| **Sigma ID** | `91e69562-2426-42ce-a647-711b8152ced6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, reconnaissance, discovery, impact |
| **Author** | Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_aadinternals_cmdlets_execution.yml)**

> Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.

```sql
-- ============================================================
-- Title:        AADInternals PowerShell Cmdlets Execution - PsScript
-- Sigma ID:     91e69562-2426-42ce-a647-711b8152ced6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, reconnaissance, discovery, impact
-- Author:       Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2022-12-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_aadinternals_cmdlets_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the library for administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Disable-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Grant-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Initialize-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Install-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Join-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Open-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Read-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Register-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Reset-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Resolve-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Restore-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Save-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Search-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Send-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Unprotect-AADInt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Update-AADInt%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the library for administrative activity

**References:**
- https://o365blog.com/aadinternals/
- https://github.com/Gerenios/AADInternals

---

## Access to Browser Login Data

| Field | Value |
|---|---|
| **Sigma ID** | `fc028194-969d-4122-8abe-0470d5b8f12f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_access_to_browser_login_data.yml)**

> Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.
Web browsers typically store the credentials in an encrypted format within a credential store.


```sql
-- ============================================================
-- Title:        Access to Browser Login Data
-- Sigma ID:     fc028194-969d-4122-8abe-0470d5b8f12f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1555.003
-- Author:       frack113
-- Date:         2022-01-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_access_to_browser_login_data.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Copy-Item%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Destination%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Opera Software\\Opera Stable\\Login Data%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Mozilla\\Firefox\\Profiles%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Microsoft\\Edge\\User Data\\Default%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Google\\Chrome\\User Data\\Default\\Login Data%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Google\\Chrome\\User Data\\Default\\Login Data For Account%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.003/T1555.003.md

---

## Potential Active Directory Enumeration Using AD Module - PsScript

| Field | Value |
|---|---|
| **Sigma ID** | `9e620995-f2d8-4630-8430-4afd89f77604` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance, discovery, impact |
| **Author** | frack113, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_active_directory_module_dll_import.yml)**

> Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.

```sql
-- ============================================================
-- Title:        Potential Active Directory Enumeration Using AD Module - PsScript
-- Sigma ID:     9e620995-f2d8-4630-8430-4afd89f77604
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance, discovery, impact
-- Author:       frack113, Nasreddine Bencherchali
-- Date:         2023-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_active_directory_module_dll_import.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the library for administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Microsoft.ActiveDirectory.Management.dll%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo Microsoft.ActiveDirectory.Management.dll%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the library for administrative activity

**References:**
- https://github.com/samratashok/ADModule
- https://twitter.com/cyb3rops/status/1617108657166061568?s=20
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges

---

## Powershell Add Name Resolution Policy Table Rule

| Field | Value |
|---|---|
| **Sigma ID** | `4368354e-1797-463c-bc39-a309effbe8d7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1565 |
| **Author** | Borna Talebi |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_add_dnsclient_rule.yml)**

> Detects powershell scripts that adds a Name Resolution Policy Table (NRPT) rule for the specified namespace.
This will bypass the default DNS server and uses a specified server for answering the query.


```sql
-- ============================================================
-- Title:        Powershell Add Name Resolution Policy Table Rule
-- Sigma ID:     4368354e-1797-463c-bc39-a309effbe8d7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1565
-- Author:       Borna Talebi
-- Date:         2021-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_add_dnsclient_rule.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-DnsClientNrptRule%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Namesp%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-NameSe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/NathanMcNulty/status/1569497348841287681
- https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule?view=windowsserver2022-ps

---

## Add Windows Capability Via PowerShell Script

| Field | Value |
|---|---|
| **Sigma ID** | `155c7fd5-47b4-49b2-bbeb-eb4fab335429` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_add_windows_capability.yml)**

> Detects usage of the "Add-WindowsCapability" cmdlet to add Windows capabilities. Notable capabilities could be "OpenSSH" and others.

```sql
-- ============================================================
-- Title:        Add Windows Capability Via PowerShell Script
-- Sigma ID:     155c7fd5-47b4-49b2-bbeb-eb4fab335429
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_add_windows_capability.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of the capabilities by administrators or users. Add additional filters accordingly.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Name OpenSSH.%')
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-WindowsCapability %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the capabilities by administrators or users. Add additional filters accordingly.

**References:**
- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell
- https://www.virustotal.com/gui/file/af1c82237b6e5a3a7cdbad82cc498d298c67845d92971bada450023d1335e267/content

---

## PowerShell ADRecon Execution

| Field | Value |
|---|---|
| **Sigma ID** | `bf72941a-cba0-41ea-b18c-9aca3925690d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_adrecon_execution.yml)**

> Detects execution of ADRecon.ps1 for AD reconnaissance which has been reported to be actively used by FIN7

```sql
-- ============================================================
-- Title:        PowerShell ADRecon Execution
-- Sigma ID:     bf72941a-cba0-41ea-b18c-9aca3925690d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery, execution | T1059.001
-- Author:       Bhabesh Raj
-- Date:         2021-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_adrecon_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Function Get-ADRExcelComOb%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADRGPO%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADRDomainController%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ADRecon-Report.xlsx%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/sense-of-security/ADRecon/blob/11881a24e9c8b207f31b56846809ce1fb189bcc9/ADRecon.ps1
- https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319

---

## AMSI Bypass Pattern Assembly GetType

| Field | Value |
|---|---|
| **Sigma ID** | `e0d6c087-2d1c-47fd-8799-3904103c5a98` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1562.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml)**

> Detects code fragments found in small and obfuscated AMSI bypass PowerShell scripts

```sql
-- ============================================================
-- Title:        AMSI Bypass Pattern Assembly GetType
-- Sigma ID:     e0d6c087-2d1c-47fd-8799-3904103c5a98
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1562.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-11-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Ref].Assembly.GetType%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SetValue($null,$true)%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%NonPublic,Static%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
- https://twitter.com/cyb3rops/status/1588574518057979905?s=20&t=A7hh93ONM7ni1Rj1jO5OaA

---

## Potential AMSI Bypass Script Using NULL Bits

| Field | Value |
|---|---|
| **Sigma ID** | `fa2559c8-1197-471d-9cdd-05a0273d4522` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_amsi_null_bits_bypass.yml)**

> Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities

```sql
-- ============================================================
-- Title:        Potential AMSI Bypass Script Using NULL Bits
-- Sigma ID:     fa2559c8-1197-471d-9cdd-05a0273d4522
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_amsi_null_bits_bypass.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%if(0){{{0}}}' -f $(0 -as [char]) +%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%#<NULL>%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-bypass-using-null-bits-satoshi

---

## Silence.EDA Detection

| Field | Value |
|---|---|
| **Sigma ID** | `3ceb2083-a27f-449a-be33-14ec1b7cc973` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution, impact |
| **MITRE Techniques** | T1059.001, T1071.004, T1572, T1529 |
| **Author** | Alina Stepchenkova, Group-IB, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_apt_silence_eda.yml)**

> Detects Silence EmpireDNSAgent as described in the Group-IP report

```sql
-- ============================================================
-- Title:        Silence.EDA Detection
-- Sigma ID:     3ceb2083-a27f-449a-be33-14ec1b7cc973
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        execution, impact | T1059.001, T1071.004, T1572, T1529
-- Author:       Alina Stepchenkova, Group-IB, oscd.community
-- Date:         2019-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_apt_silence_eda.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Diagnostics.Process%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Stop-Computer%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Restart-Computer%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Exception in execution%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$cmdargs%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Close-Dnscat2Tunnel%')
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%set type=$LookupType`nserver%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$Command | nslookup 2>&1 | Out-String%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-RandomDNSField%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Convert]::ToString($SYNOptions, 16)%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$Session.Dead = $True%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$Session["Driver"] -eq%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.group-ib.com/resources/threat-research/silence_2.0.going_global.pdf

---

## Get-ADUser Enumeration Using UserAccountControl Flags

| Field | Value |
|---|---|
| **Sigma ID** | `96c982fe-3d08-4df4-bed2-eb14e02f21c8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_as_rep_roasting.yml)**

> Detects AS-REP roasting is an attack that is often-overlooked. It is not very common as you have to explicitly set accounts that do not require pre-authentication.

```sql
-- ============================================================
-- Title:        Get-ADUser Enumeration Using UserAccountControl Flags
-- Sigma ID:     96c982fe-3d08-4df4-bed2-eb14e02f21c8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       frack113
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_as_rep_roasting.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADUser%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Filter%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%useraccountcontrol%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-band%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%4194304%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md#atomic-test-11---get-aduser-enumeration-using-useraccountcontrol-flags-as-rep-roasting
- https://shellgeek.com/useraccountcontrol-flags-to-manipulate-properties/

---

## Potential Data Exfiltration Via Audio File

| Field | Value |
|---|---|
| **Sigma ID** | `e4f93c99-396f-47c8-bb0f-201b1fa69034` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_audio_exfiltration.yml)**

> Detects potential exfiltration attempt via audio file using PowerShell

```sql
-- ============================================================
-- Title:        Potential Data Exfiltration Via Audio File
-- Sigma ID:     e4f93c99-396f-47c8-bb0f-201b1fa69034
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_audio_exfiltration.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Math]::%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[IO.FileMode]::%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%BinaryWriter%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/gtworek/PSBits/blob/e97cbbb173b31cbc4d37244d3412de0a114dacfb/NoDLP/bin2wav.ps1

---

## Automated Collection Command PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `c1dda054-d638-4c16-afc8-53e007f3fbc5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1119 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_automated_collection.yml)**

> Once established within a system or network, an adversary may use automated techniques for collecting internal data.

```sql
-- ============================================================
-- Title:        Automated Collection Command PowerShell
-- Sigma ID:     c1dda054-d638-4c16-afc8-53e007f3fbc5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1119
-- Author:       frack113
-- Date:         2021-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_automated_collection.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ChildItem%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Recurse %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Include %')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.doc%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.docx%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.xls%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.xlsx%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.ppt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.pptx%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.rtf%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.pdf%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.txt%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md

---

## Windows Screen Capture with CopyFromScreen

| Field | Value |
|---|---|
| **Sigma ID** | `d4a11f63-2390-411c-9adf-d791fd152830` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_capture_screenshots.yml)**

> Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations


```sql
-- ============================================================
-- Title:        Windows Screen Capture with CopyFromScreen
-- Sigma ID:     d4a11f63-2390-411c-9adf-d791fd152830
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_capture_screenshots.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.CopyFromScreen%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md#atomic-test-6---windows-screen-capture-copyfromscreen

---

## Clear PowerShell History - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `26b692dc-1722-49b2-b496-a8258aa6371d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.003 |
| **Author** | Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml)**

> Detects keywords that could indicate clearing PowerShell history

```sql
-- ============================================================
-- Title:        Clear PowerShell History - PowerShell
-- Sigma ID:     26b692dc-1722-49b2-b496-a8258aa6371d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.003
-- Author:       Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date:         2022-01-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-PSReadlineOption%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%–HistorySaveStyle%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SaveNothing%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-PSReadlineOption%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-HistorySaveStyle%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SaveNothing%')
  OR ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%del%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-Item%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rm%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%(Get-PSReadlineOption).HistorySavePath%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a

---

## Clearing Windows Console History

| Field | Value |
|---|---|
| **Sigma ID** | `bde47d4b-9987-405c-94c7-b080410e8ea7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070, T1070.003 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml)**

> Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.

```sql
-- ============================================================
-- Title:        Clearing Windows Console History
-- Sigma ID:     bde47d4b-9987-405c-94c7-b080410e8ea7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070, T1070.003
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Clear-History%')
  OR ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-Item%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rm%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConsoleHost\_history.txt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%(Get-PSReadlineOption).HistorySavePath%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://stefanos.cloud/blog/kb/how-to-clear-the-powershell-command-history/
- https://www.shellhacks.com/clear-history-powershell/
- https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics

---

## Powershell Create Scheduled Task

| Field | Value |
|---|---|
| **Sigma ID** | `363eccc0-279a-4ccf-a3ab-24c2e63b11fb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_cmdlet_scheduled_task.yml)**

> Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code

```sql
-- ============================================================
-- Title:        Powershell Create Scheduled Task
-- Sigma ID:     363eccc0-279a-4ccf-a3ab-24c2e63b11fb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_cmdlet_scheduled_task.yml
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
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.005/T1053.005.md#atomic-test-4---powershell-cmdlet-scheduled-task
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.005/T1053.005.md#atomic-test-6---wmi-invoke-cimmethod-scheduled-task

---

## Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `db885529-903f-4c5d-9864-28fe199e6370` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_computer_discovery_get_adcomputer.yml)**

> Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file

```sql
-- ============================================================
-- Title:        Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell
-- Sigma ID:     db885529-903f-4c5d-9864-28fe199e6370
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_computer_discovery_get_adcomputer.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADComputer %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Filter \\*%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% | Select %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-File%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Content%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-Content%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often

**References:**
- http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
- https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
- https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf

---

## Powershell Install a DLL in System Directory

| Field | Value |
|---|---|
| **Sigma ID** | `63bf8794-9917-45bc-88dd-e1b5abc0ecfd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556.002 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_copy_item_system_directory.yml)**

> Uses PowerShell to install/copy a file into a system directory such as "System32" or "SysWOW64"

```sql
-- ============================================================
-- Title:        Powershell Install a DLL in System Directory
-- Sigma ID:     63bf8794-9917-45bc-88dd-e1b5abc0ecfd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1556.002
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-12-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_copy_item_system_directory.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '(Copy-Item|cpi) .{2,128} -Destination .{1,32}\\Windows\\(System32|SysWOW64)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1556.002/T1556.002.md#atomic-test-1---install-and-register-password-filter-dll

---

## Registry-Free Process Scope COR_PROFILER

| Field | Value |
|---|---|
| **Sigma ID** | `23590215-4702-4a70-8805-8dc9e58314a2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.012 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_cor_profiler.yml)**

> Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR.
The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR).
These profiliers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.
(Citation: Microsoft Profiling Mar 2017)
(Citation: Microsoft COR_PROFILER Feb 2013)


```sql
-- ============================================================
-- Title:        Registry-Free Process Scope COR_PROFILER
-- Sigma ID:     23590215-4702-4a70-8805-8dc9e58314a2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.012
-- Author:       frack113
-- Date:         2021-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_cor_profiler.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$env:COR\_ENABLE\_PROFILING%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$env:COR\_PROFILER%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$env:COR\_PROFILER\_PATH%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.012/T1574.012.md#atomic-test-3---registry-free-process-scope-cor_profiler

---

## PowerShell Create Local User

| Field | Value |
|---|---|
| **Sigma ID** | `243de76f-4725-4f2e-8225-a8a69b15ad61` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1059.001, T1136.001 |
| **Author** | @ROxPinTeddy |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml)**

> Detects creation of a local user via PowerShell

```sql
-- ============================================================
-- Title:        PowerShell Create Local User
-- Sigma ID:     243de76f-4725-4f2e-8225-a8a69b15ad61
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1059.001, T1136.001
-- Author:       @ROxPinTeddy
-- Date:         2020-04-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate user creation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-LocalUser%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user creation

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.001/T1136.001.md

---

## Create Volume Shadow Copy with Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `afd12fed-b0ec-45c9-a13d-aa86625dac81` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml)**

> Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information

```sql
-- ============================================================
-- Title:        Create Volume Shadow Copy with Powershell
-- Sigma ID:     afd12fed-b0ec-45c9-a13d-aa86625dac81
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.003
-- Author:       frack113
-- Date:         2022-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_ShadowCopy%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%).Create(%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ClientAccessible%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1&viewFallbackFrom=powershell-7

---

## Powershell Detect Virtualization Environment

| Field | Value |
|---|---|
| **Sigma ID** | `d93129cd-1ee0-479f-bc03-ca6f129882e3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1497.001 |
| **Author** | frack113, Duc.Le-GTSC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_detect_vm_env.yml)**

> Adversaries may employ various system checks to detect and avoid virtualization and analysis environments.
This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox


```sql
-- ============================================================
-- Title:        Powershell Detect Virtualization Environment
-- Sigma ID:     d93129cd-1ee0-479f-bc03-ca6f129882e3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1497.001
-- Author:       frack113, Duc.Le-GTSC
-- Date:         2021-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_detect_vm_env.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WmiObject%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gwmi%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%MSAcpi\_ThermalZoneTemperature%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_ComputerSystem%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1497.001/T1497.001.md
- https://techgenix.com/malicious-powershell-scripts-evade-detection/

---

## DirectorySearcher Powershell Exploitation

| Field | Value |
|---|---|
| **Sigma ID** | `1f6399cf-2c80-4924-ace1-6fcff3393480` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1018 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_directorysearcher.yml)**

> Enumerates Active Directory to determine computers that are joined to the domain

```sql
-- ============================================================
-- Title:        DirectorySearcher Powershell Exploitation
-- Sigma ID:     1f6399cf-2c80-4924-ace1-6fcff3393480
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1018
-- Author:       frack113
-- Date:         2022-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_directorysearcher.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.DirectoryServices.DirectorySearcher%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.PropertiesToLoad.Add%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.findall()%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Properties.name%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md#atomic-test-15---enumerate-domain-computers-within-active-directory-using-directorysearcher

---

## Manipulation of User Computer or Group Security Principals Across AD

| Field | Value |
|---|---|
| **Sigma ID** | `b29a93fb-087c-4b5b-a84d-ee3309e69d08` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_directoryservices_accountmanagement.yml)**

> Adversaries may create a domain account to maintain access to victim systems.
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain..


```sql
-- ============================================================
-- Title:        Manipulation of User Computer or Group Security Principals Across AD
-- Sigma ID:     b29a93fb-087c-4b5b-a84d-ee3309e69d08
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1136.002
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_directoryservices_accountmanagement.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.DirectoryServices.AccountManagement%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.002/T1136.002.md#atomic-test-3---create-a-new-domain-account-using-powershell
- https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement?view=net-8.0

---

## Disable Powershell Command History

| Field | Value |
|---|---|
| **Sigma ID** | `602f5669-6927-4688-84db-0d4b7afb2150` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.003 |
| **Author** | Ali Alwashali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_disable_psreadline_command_history.yml)**

> Detects scripts or commands that disabled the Powershell command history by removing psreadline module

```sql
-- ============================================================
-- Title:        Disable Powershell Command History
-- Sigma ID:     602f5669-6927-4688-84db-0d4b7afb2150
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.003
-- Author:       Ali Alwashali
-- Date:         2022-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_disable_psreadline_command_history.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate script that disables the command history
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-Module%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%psreadline%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate script that disables the command history

**References:**
- https://twitter.com/DissectMalware/status/1062879286749773824

---

## Disable-WindowsOptionalFeature Command PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `99c4658d-2c5e-4d87-828d-7c066ca537c3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_disable_windows_optional_feature.yml)**

> Detect built in PowerShell cmdlet Disable-WindowsOptionalFeature, Deployment Image Servicing and Management tool.
Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images


```sql
-- ============================================================
-- Title:        Disable-WindowsOptionalFeature Command PowerShell
-- Sigma ID:     99c4658d-2c5e-4d87-828d-7c066ca537c3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       frack113
-- Date:         2022-09-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_disable_windows_optional_feature.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Disable-WindowsOptionalFeature%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Online%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-FeatureName%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Windows-Defender-Gui%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Windows-Defender-Features%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Windows-Defender%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Windows-Defender-ApplicationGuard%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/5b67c9b141fa3918017f8fa44f2f88f0b1ecb9e1/atomics/T1562.001/T1562.001.md
- https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature?view=windowsserver2022-ps

---

## Potential In-Memory Execution Using Reflection.Assembly

| Field | Value |
|---|---|
| **Sigma ID** | `ddcd88cb-7f62-4ce5-86f9-1704190feb0a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1620 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dotnet_assembly_from_file.yml)**

> Detects usage of "Reflection.Assembly" load functions to dynamically load assemblies in memory

```sql
-- ============================================================
-- Title:        Potential In-Memory Execution Using Reflection.Assembly
-- Sigma ID:     ddcd88cb-7f62-4ce5-86f9-1704190feb0a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1620
-- Author:       frack113
-- Date:         2022-12-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dotnet_assembly_from_file.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the library
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Reflection.Assembly]::load%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the library

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50

---

## Potential COM Objects Download Cradles Usage - PS Script

| Field | Value |
|---|---|
| **Sigma ID** | `3c7d1587-3b13-439f-9941-7d14313dbdfe` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_download_com_cradles.yml)**

> Detects usage of COM objects that can be abused to download files in PowerShell by CLSID

```sql
-- ============================================================
-- Title:        Potential COM Objects Download Cradles Usage - PS Script
-- Sigma ID:     3c7d1587-3b13-439f-9941-7d14313dbdfe
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113
-- Date:         2022-12-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_download_com_cradles.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the library
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Type]::GetTypeFromCLSID(%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%0002DF01-0000-0000-C000-000000000046%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%F6D90F16-9C73-11D3-B32E-00C04F990BB4%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%F5078F35-C551-11D3-89B9-0000F81FE221%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%88d96a0a-f192-11d4-a65f-0040963251e5%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%AFBA6B42-5692-48EA-8141-DC517DCF0EF1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%AFB40FFD-B609-40A3-9828-F88BBE11E4E3%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%88d96a0b-f192-11d4-a65f-0040963251e5%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%2087c2f4-2cef-4953-a8ab-66779b670495%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%000209FF-0000-0000-C000-000000000046%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%00024500-0000-0000-C000-000000000046%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the library

**References:**
- https://learn.microsoft.com/en-us/dotnet/api/system.type.gettypefromclsid?view=net-7.0
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=57

---

## DSInternals Suspicious PowerShell Cmdlets - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `846c7a87-8e14-4569-9d49-ecfd4276a01c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dsinternals_cmdlets.yml)**

> Detects execution and usage of the DSInternals PowerShell module. Which can be used to perform what might be considered as suspicious activity such as dumping DPAPI backup keys or manipulating NTDS.DIT files.
The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory. These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.


```sql
-- ============================================================
-- Title:        DSInternals Suspicious PowerShell Cmdlets - ScriptBlock
-- Sigma ID:     846c7a87-8e14-4569-9d49-ecfd4276a01c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-06-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dsinternals_cmdlets.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of DSInternals for administration or audit purpose.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-ADDBSidHistory%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-ADNgcKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-ADReplNgcKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertFrom-ADManagedPasswordBlob%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertFrom-GPPrefPassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertFrom-ManagedPasswordBlob%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertFrom-UnattendXmlPassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertFrom-UnicodePassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-AADHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-GPPrefPassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-KerberosKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-LMHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-MsoPasswordHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-NTHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-OrgIdHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-UnicodePassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Disable-ADDBAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-ADDBAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBBackupKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBDomainController%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBGroupManagedServiceAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBKdsRootKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBSchemaAttribute%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDBServiceAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADDefaultPasswordPolicy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADKeyCredential%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADPasswordPolicy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADReplAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADReplBackupKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADReplicationAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADSIAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-AzureADUserEx%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-BootKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-KeyCredential%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-LsaBackupKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-LsaPolicy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-SamPasswordPolicy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-SysKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-SystemKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-ADDBRestoreFromMediaScript%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-ADKeyCredential%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-ADNgcKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-NTHashSet%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-ADDBObject%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Save-DPAPIBlob%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADAccountPasswordHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADDBAccountPassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADDBBootKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADDBDomainController%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADDBPrimaryGroup%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADDBSysKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-AzureADUserEx%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-LsaPolicy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-SamAccountPasswordHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-WinUserPasswordHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Test-ADDBPasswordQuality%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Test-ADPasswordQuality%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Test-ADReplPasswordQuality%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Test-PasswordQuality%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Unlock-ADDBAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Write-ADNgcKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Write-ADReplNgcKey%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of DSInternals for administration or audit purpose.

**References:**
- https://github.com/MichaelGrafnetter/DSInternals/blob/39ee8a69bbdc1cfd12c9afdd7513b4788c4895d4/Src/DSInternals.PowerShell/DSInternals.psd1

---

## Dump Credentials from Windows Credential Manager With PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `99c49d9c-34ea-45f7-84a7-4751ae6b2cbc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dump_password_windows_credential_manager.yml)**

> Adversaries may search for common password storage locations to obtain user credentials.
Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.


```sql
-- ============================================================
-- Title:        Dump Credentials from Windows Credential Manager With PowerShell
-- Sigma ID:     99c49d9c-34ea-45f7-84a7-4751ae6b2cbc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1555
-- Author:       frack113
-- Date:         2021-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dump_password_windows_credential_manager.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-PasswordVaultCredentials%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-CredManCreds%'))
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Windows.Security.Credentials.PasswordVault%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Microsoft.CSharp.CSharpCodeProvider%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Collections.ArrayList%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.CodeDom.Compiler.CompilerParameters%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555/T1555.md

---

## Enable Windows Remote Management

| Field | Value |
|---|---|
| **Sigma ID** | `991a9744-f2f0-44f2-bd33-9092eba17dc3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_enable_psremoting.yml)**

> Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

```sql
-- ============================================================
-- Title:        Enable Windows Remote Management
-- Sigma ID:     991a9744-f2f0-44f2-bd33-9092eba17dc3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.006
-- Author:       frack113
-- Date:         2022-01-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_enable_psremoting.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-PSRemoting %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md#atomic-test-1---enable-windows-remote-management
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.2

---

## Potential Suspicious Windows Feature Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `55c925c1-7195-426b-a136-a9396800e29b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_enable_susp_windows_optional_feature.yml)**

> Detects usage of the built-in PowerShell cmdlet "Enable-WindowsOptionalFeature" used as a Deployment Image Servicing and Management tool.
Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images


```sql
-- ============================================================
-- Title:        Potential Suspicious Windows Feature Enabled
-- Sigma ID:     55c925c1-7195-426b-a136-a9396800e29b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2022-09-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_enable_susp_windows_optional_feature.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of the features listed in the rule.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-WindowsOptionalFeature%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Online%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-FeatureName%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TelnetServer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Internet-Explorer-Optional-amd64%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TFTP%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SMB1Protocol%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Client-ProjFS%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Microsoft-Windows-Subsystem-Linux%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the features listed in the rule.

**References:**
- https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature?view=windowsserver2022-ps
- https://learn.microsoft.com/en-us/windows/win32/projfs/enabling-windows-projected-file-system
- https://learn.microsoft.com/en-us/windows/wsl/install-on-server

---

## Enumerate Credentials from Windows Credential Manager With PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `603c6630-5225-49c1-8047-26c964553e0e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_enumerate_password_windows_credential_manager.yml)**

> Adversaries may search for common password storage locations to obtain user credentials.
Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.


```sql
-- ============================================================
-- Title:        Enumerate Credentials from Windows Credential Manager With PowerShell
-- Sigma ID:     603c6630-5225-49c1-8047-26c964553e0e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1555
-- Author:       frack113
-- Date:         2021-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_enumerate_password_windows_credential_manager.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%vaultcmd%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%/listcreds:%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Windows Credentials%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Web Credentials%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555/T1555.md

---

## Disable of ETW Trace - Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `115fdba9-f017-42e6-84cf-d5573bf2ddf8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070, T1562.006 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_etw_trace_evasion.yml)**

> Detects usage of powershell cmdlets to disable or remove ETW trace sessions

```sql
-- ============================================================
-- Title:        Disable of ETW Trace - Powershell
-- Sigma ID:     115fdba9-f017-42e6-84cf-d5573bf2ddf8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070, T1562.006
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_etw_trace_evasion.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-EtwTraceProvider %')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-EtwTraceProvider %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%0x11%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63

---

## Certificate Exported Via PowerShell - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `aa7a3fce-bef5-4311-9cc1-5f04bb8c308c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_export_certificate.yml)**

> Detects calls to cmdlets inside of PowerShell scripts that are used to export certificates from the local certificate store. Threat actors were seen abusing this to steal private keys from compromised machines.

```sql
-- ============================================================
-- Title:        Certificate Exported Via PowerShell - ScriptBlock
-- Sigma ID:     aa7a3fce-bef5-4311-9cc1-5f04bb8c308c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-04-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_export_certificate.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate certificate exports by administrators. Additional filters might be required.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-PfxCertificate%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-Certificate%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate certificate exports by administrators. Additional filters might be required.

**References:**
- https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
- https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2022-ps
- https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html

---

## Suspicious FromBase64String Usage On Gzip Archive - Ps Script

| Field | Value |
|---|---|
| **Sigma ID** | `df69cb1d-b891-4cd9-90c7-d617d90100ce` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1132.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_frombase64string_archive.yml)**

> Detects attempts of decoding a base64 Gzip archive in a PowerShell script. This technique is often used as a method to load malicious content into memory afterward.

```sql
-- ============================================================
-- Title:        Suspicious FromBase64String Usage On Gzip Archive - Ps Script
-- Sigma ID:     df69cb1d-b891-4cd9-90c7-d617d90100ce
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1132.001
-- Author:       frack113
-- Date:         2022-12-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_frombase64string_archive.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%FromBase64String%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%MemoryStream%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%H4sI%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=43

---

## Service Registry Permissions Weakness Check

| Field | Value |
|---|---|
| **Sigma ID** | `95afc12e-3cbb-40c3-9340-84a032e596a3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.011 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_acl_service.yml)**

> Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services


```sql
-- ============================================================
-- Title:        Service Registry Permissions Weakness Check
-- Sigma ID:     95afc12e-3cbb-40c3-9340-84a032e596a3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.011
-- Author:       frack113
-- Date:         2021-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_acl_service.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-acl%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.011/T1574.011.md#atomic-test-1---service-registry-permissions-weakness
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.4

---

## Active Directory Computers Enumeration With Get-AdComputer

| Field | Value |
|---|---|
| **Sigma ID** | `36bed6b2-e9a0-4fff-beeb-413a92b86138` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1018, T1087.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_adcomputer.yml)**

> Detects usage of the "Get-AdComputer" to enumerate Computers or properties within Active Directory.

```sql
-- ============================================================
-- Title:        Active Directory Computers Enumeration With Get-AdComputer
-- Sigma ID:     36bed6b2-e9a0-4fff-beeb-413a92b86138
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1018, T1087.002
-- Author:       frack113
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_adcomputer.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-AdComputer %')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Filter %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-LDAPFilter %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Properties %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
- https://github.com/redcanaryco/atomic-red-team/blob/02cb591f75064ffe1e0df9ac3ed5972a2e491c97/atomics/T1087.002/T1087.002.md

---

## Active Directory Group Enumeration With Get-AdGroup

| Field | Value |
|---|---|
| **Sigma ID** | `8c3a6607-b7dc-4f0d-a646-ef38c00b76ee` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_adgroup.yml)**

> Detects usage of the "Get-AdGroup" cmdlet to enumerate Groups within Active Directory

```sql
-- ============================================================
-- Title:        Active Directory Group Enumeration With Get-AdGroup
-- Sigma ID:     8c3a6607-b7dc-4f0d-a646-ef38c00b76ee
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.002
-- Author:       frack113
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_adgroup.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-AdGroup %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Filter%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md

---

## Suspicious Get-ADReplAccount

| Field | Value |
|---|---|
| **Sigma ID** | `060c3ef1-fd0a-4091-bf46-e7d625f60b73` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_adreplaccount.yml)**

> The DSInternals PowerShell Module exposes several internal features of Active Directory and Azure Active Directory.
These include FIDO2 and NGC key auditing, offline ntds.dit file manipulation, password auditing, DC recovery from IFM backups and password hash calculation.


```sql
-- ============================================================
-- Title:        Suspicious Get-ADReplAccount
-- Sigma ID:     060c3ef1-fd0a-4091-bf46-e7d625f60b73
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.006
-- Author:       frack113
-- Date:         2022-02-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_adreplaccount.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADReplAccount%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-All %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Server %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://www.powershellgallery.com/packages/DSInternals
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.006/T1003.006.md#atomic-test-2---run-dsinternals-get-adreplaccount

---

## Automated Collection Bookmarks Using Get-ChildItem PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `e0565f5d-d420-4e02-8a68-ac00d864f9cf` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1217 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_childitem_bookmarks.yml)**

> Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
internal network resources such as servers, tools/dashboards, or other related infrastructure.


```sql
-- ============================================================
-- Title:        Automated Collection Bookmarks Using Get-ChildItem PowerShell
-- Sigma ID:     e0565f5d-d420-4e02-8a68-ac00d864f9cf
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1217
-- Author:       frack113
-- Date:         2021-12-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_childitem_bookmarks.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ChildItem%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Recurse %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Path %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Filter Bookmarks%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ErrorAction SilentlyContinue%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Force%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1217/T1217.md

---

## Security Software Discovery Via Powershell Script

| Field | Value |
|---|---|
| **Sigma ID** | `904e8e61-8edf-4350-b59c-b905fc8e810c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1518.001 |
| **Author** | frack113, Anish Bogati, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_process_security_software_discovery.yml)**

> Detects calls to "get-process" where the output is piped to a "where-object" filter to search for security solution processes.
Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus


```sql
-- ============================================================
-- Title:        Security Software Discovery Via Powershell Script
-- Sigma ID:     904e8e61-8edf-4350-b59c-b905fc8e810c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1518.001
-- Author:       frack113, Anish Bogati, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-12-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_get_process_security_software_discovery.yml
-- Unmapped:     (none)
-- False Pos:    False positives might occur due to the nature of the ScriptBlock being ingested as a big blob. Initial tuning is required.; As the "selection_cmdlet" is common in scripts the matching engine might slow down the search. Change into regex or a more accurate string to avoid heavy resource consumption if experienced
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-process | \\?%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-process | where%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gps | \\?%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gps | where%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Company -like%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Description -like%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Name -like%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Path -like%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Product -like%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*avira\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*carbonblack\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*cylance\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*defender\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*kaspersky\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*malware\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*sentinel\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*symantec\\*%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\*virus\\*%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives might occur due to the nature of the ScriptBlock being ingested as a big blob. Initial tuning is required.; As the "selection_cmdlet" is common in scripts the matching engine might slow down the search. Change into regex or a more accurate string to avoid heavy resource consumption if experienced

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md#atomic-test-2---security-software-discovery---powershell

---

## HackTool - Rubeus Execution - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `3245cd30-e015-40ff-a31d-5cadd5f377ec` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003, T1558.003, T1550.003 |
| **Author** | Christian Burkard (Nextron Systems), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml)**

> Detects the execution of the hacktool Rubeus using specific command line flags

```sql
-- ============================================================
-- Title:        HackTool - Rubeus Execution - ScriptBlock
-- Sigma ID:     3245cd30-e015-40ff-a31d-5cadd5f377ec
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003, T1558.003, T1550.003
-- Author:       Christian Burkard (Nextron Systems), Florian Roth (Nextron Systems)
-- Date:         2023-04-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%asreproast %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%dump /service:krbtgt %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%dump /luid:0x%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%kerberoast %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%createnetonly /program:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ptt /ticket:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%/impersonateuser:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%renew /ticket:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%asktgt /user:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%harvest /interval:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%s4u /user:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%s4u /ticket:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%hash /password:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%golden /aes256:%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%silver /user:%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus
- https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
- https://github.com/GhostPack/Rubeus

---

## HackTool - WinPwn Execution - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `851fd622-b675-4d26-b803-14bc7baa517a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1046, T1082, T1106, T1518, T1548.002, T1552.001, T1555, T1555.003 |
| **Author** | Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_hktl_winpwn.yml)**

> Detects scriptblock text keywords indicative of potential usge of the tool WinPwn. A tool for Windows and Active Directory reconnaissance and exploitation.


```sql
-- ============================================================
-- Title:        HackTool - WinPwn Execution - ScriptBlock
-- Sigma ID:     851fd622-b675-4d26-b803-14bc7baa517a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery, execution | T1046, T1082, T1106, T1518, T1548.002, T1552.001, T1555, T1555.003
-- Author:       Swachchhanda Shrawan Poudel
-- Date:         2023-12-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_hktl_winpwn.yml
-- Unmapped:     (none)
-- False Pos:    As the script block is a blob of text. False positive may occur with scripts that contain the keyword as a reference or simply use it for detection.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Offline\_Winpwn%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WinPwn %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WinPwn.exe%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WinPwn.ps1%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** As the script block is a blob of text. False positive may occur with scripts that contain the keyword as a reference or simply use it for detection.

**References:**
- https://github.com/S3cur3Th1sSh1t/WinPwn
- https://www.publicnow.com/view/EB87DB49C654D9B63995FAD4C9DE3D3CC4F6C3ED?1671634841
- https://reconshell.com/winpwn-tool-for-internal-windows-pentesting-and-ad-security/
- https://github.com/redcanaryco/atomic-red-team/blob/4d6c4e8e23d465af7a2388620cfe3f8c76e16cf0/atomics/T1082/T1082.md
- https://grep.app/search?q=winpwn&filter[repo][0]=redcanaryco/atomic-red-team

---

## PowerShell Hotfix Enumeration

| Field | Value |
|---|---|
| **Sigma ID** | `f5d1def8-1de0-4a0e-9794-1f6f27dd605c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_hotfix_enum.yml)**

> Detects call to "Win32_QuickFixEngineering" in order to enumerate installed hotfixes often used in "enum" scripts by attackers

```sql
-- ============================================================
-- Title:        PowerShell Hotfix Enumeration
-- Sigma ID:     f5d1def8-1de0-4a0e-9794-1f6f27dd605c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_hotfix_enum.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_QuickFixEngineering%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%HotFixID%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration scripts

**References:**
- https://github.com/411Hall/JAWS/blob/233f142fcb1488172aa74228a666f6b3c5c48f1d/jaws-enum.ps1

---

## PowerShell ICMP Exfiltration

| Field | Value |
|---|---|
| **Sigma ID** | `4c4af3cd-2115-479c-8193-6b8bfce9001c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048.003 |
| **Author** | Bartlomiej Czyz @bczyz1, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_icmp_exfiltration.yml)**

> Detects Exfiltration Over Alternative Protocol - ICMP. Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.

```sql
-- ============================================================
-- Title:        PowerShell ICMP Exfiltration
-- Sigma ID:     4c4af3cd-2115-479c-8193-6b8bfce9001c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1048.003
-- Author:       Bartlomiej Czyz @bczyz1, oscd.community
-- Date:         2020-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_icmp_exfiltration.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of System.Net.NetworkInformation.Ping class
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Net.NetworkInformation.Ping%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.Send(%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of System.Net.NetworkInformation.Ping class

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1048.003/T1048.003.md#atomic-test-2---exfiltration-over-alternative-protocol---icmp

---

## Import PowerShell Modules From Suspicious Directories

| Field | Value |
|---|---|
| **Sigma ID** | `21f9162c-5f5d-4b01-89a8-b705bd7d10ab` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_import_module_susp_dirs.yml)**

> Detects powershell scripts that import modules from suspicious directories

```sql
-- ============================================================
-- Title:        Import PowerShell Modules From Suspicious Directories
-- Sigma ID:     21f9162c-5f5d-4b01-89a8-b705bd7d10ab
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_import_module_susp_dirs.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module "$Env:Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module '$Env:Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module $Env:Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module "$Env:Appdata\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module '$Env:Appdata\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module $Env:Appdata\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Module C:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo "$Env:Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo '$Env:Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo $Env:Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo "$Env:Appdata\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo '$Env:Appdata\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo $Env:Appdata\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ipmo C:\\Users\\Public\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md

---

## Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript

| Field | Value |
|---|---|
| **Sigma ID** | `975b2262-9a49-439d-92a6-0709cccdf0b2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_install_unsigned_appx_packages.yml)**

> Detects usage of the "Add-AppxPackage" or it's alias "Add-AppPackage" to install unsigned AppX packages

```sql
-- ============================================================
-- Title:        Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript
-- Sigma ID:     975b2262-9a49-439d-92a6-0709cccdf0b2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_install_unsigned_appx_packages.yml
-- Unmapped:     (none)
-- False Pos:    Installation of unsigned packages for testing purposes
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-AppPackage %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-AppxPackage %'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -AllowUnsigned%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Installation of unsigned packages for testing purposes

**References:**
- https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package
- https://twitter.com/WindowsDocs/status/1620078135080325122

---

## Execute Invoke-command on Remote Host

| Field | Value |
|---|---|
| **Sigma ID** | `7b836d7f-179c-4ba4-90a7-a7e60afb48e6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_command_remote.yml)**

> Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

```sql
-- ============================================================
-- Title:        Execute Invoke-command on Remote Host
-- Sigma ID:     7b836d7f-179c-4ba4-90a7-a7e60afb48e6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.006
-- Author:       frack113
-- Date:         2022-01-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_command_remote.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%invoke-command %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ComputerName %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md#atomic-test-2---invoke-command
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.4

---

## Powershell DNSExfiltration

| Field | Value |
|---|---|
| **Sigma ID** | `d59d7842-9a21-4bc6-ba98-64bfe0091355` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_dnsexfiltration.yml)**

> DNSExfiltrator allows for transferring (exfiltrate) a file over a DNS request covert channel

```sql
-- ============================================================
-- Title:        Powershell DNSExfiltration
-- Sigma ID:     d59d7842-9a21-4bc6-ba98-64bfe0091355
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1048
-- Author:       frack113
-- Date:         2022-01-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_dnsexfiltration.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DNSExfiltrator%'))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -i %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -d %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -p %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -doh %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -t %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1048/T1048.md#atomic-test-3---dnsexfiltration-doh
- https://github.com/Arno0x/DNSExfiltrator

---

## Invoke-Obfuscation CLIP+ Launcher - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `73e67340-0d25-11eb-adc1-0242ac120002` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_clip.yml)**

> Detects Obfuscated use of Clip.exe to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation CLIP+ Launcher - PowerShell
-- Sigma ID:     73e67340-0d25-11eb-adc1-0242ac120002
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_clip.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], 'cmd.{0,5}(?:/c|/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\"\{\d\}.+-f.+"'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `1b9dc62e-6e9e-42a3-8990-94d7a10007f7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Daniel Bohannon (@Mandiant/@FireEye), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_obfuscated_iex.yml)**

> Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the following code block \u2014

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell
-- Sigma ID:     1b9dc62e-6e9e-42a3-8990-94d7a10007f7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Daniel Bohannon (@Mandiant/@FireEye), oscd.community
-- Date:         2019-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_obfuscated_iex.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\[')))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\[')))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\[')))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '\$env:ComSpec\[(\s*\d{1,3}\s*,){2}')))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '\*mdr\*\W\s*\)\.Name')))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '\$VerbosePreference\.ToString\(')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/danielbohannon/Invoke-Obfuscation/blob/f20e7f843edd0a3a7716736e9eddfa423395dd26/Out-ObfuscatedStringCommand.ps1#L873-L888

---

## Invoke-Obfuscation STDIN+ Launcher - Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `779c8c12-0eb1-11eb-adc1-0242ac120002` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_stdin.yml)**

> Detects Obfuscated use of stdin to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation STDIN+ Launcher - Powershell
-- Sigma ID:     779c8c12-0eb1-11eb-adc1-0242ac120002
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_stdin.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], 'cmd.{0,5}(?:/c|/r).+powershell.+(?:\$?\{?input\}?|noexit).+"'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR+ Launcher - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `0adfbc14-0ed1-11eb-adc1-0242ac120002` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_var.yml)**

> Detects Obfuscated use of Environment Variables to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR+ Launcher - PowerShell
-- Sigma ID:     0adfbc14-0ed1-11eb-adc1-0242ac120002
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_var.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], 'cmd.{0,5}(?:/c|/r)(?:\s|)"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\"\s+?-f(?:.*\)){1,}.*"'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `20e5497e-331c-4cd5-8d36-935f6e2a9a07` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_compress.yml)**

> Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell
-- Sigma ID:     20e5497e-331c-4cd5-8d36-935f6e2a9a07
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_compress.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%new-object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%text.encoding]::ascii%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%system.io.compression.deflatestream%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%system.io.streamreader%'))
    AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%readtoend'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `e6cb92b4-b470-4eb8-8a9d-d63e8583aae0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_rundll.yml)**

> Detects Obfuscated Powershell via RUNDLL LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell
-- Sigma ID:     e6cb92b4-b470-4eb8-8a9d-d63e8583aae0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_rundll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rundll32.exe%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%shell32.dll%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%shellexec\_rundll%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%powershell%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Stdin - Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `86b896ba-ffa1-4fea-83e3-ee28a4c915c7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_stdin.yml)**

> Detects Obfuscated Powershell via Stdin in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Stdin - Powershell
-- Sigma ID:     86b896ba-ffa1-4fea-83e3-ee28a4c915c7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_stdin.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '(?i)(set).*&&\s?set.*(environment|invoke|\$\{?input).*&&.*"'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Clip - Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `db92dd33-a3ad-49cf-8c2c-608c3e30ace0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_clip.yml)**

> Detects Obfuscated Powershell via use Clip.exe in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Clip - Powershell
-- Sigma ID:     db92dd33-a3ad-49cf-8c2c-608c3e30ace0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_clip.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '(?i)echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use MSHTA - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `e55a5195-4724-480e-a77e-3ebe64bd3759` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_mhsta.yml)**

> Detects Obfuscated Powershell via use MSHTA in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use MSHTA - PowerShell
-- Sigma ID:     e55a5195-4724-480e-a77e-3ebe64bd3759
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_mhsta.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%set%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%&&%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%mshta%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%vbscript:createobject%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.run%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%(window.close)%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Rundll32 - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `a5a30a6e-75ca-4233-8b8c-42e0f2037d3b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_rundll32.yml)**

> Detects Obfuscated Powershell via use Rundll32 in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Rundll32 - PowerShell
-- Sigma ID:     a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2019-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_rundll32.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%&&%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rundll32%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%shell32.dll%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%shellexec\_rundll%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%value%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%invoke%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%comspec%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%iex%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `e54f5149-6ba3-49cf-b153-070d24679126` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_var.yml)**

> Detects Obfuscated Powershell via VAR++ LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell
-- Sigma ID:     e54f5149-6ba3-49cf-b153-070d24679126
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_var.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'script')], '(?i)&&set.*(\{\d\}){2,}\\"\s+?-f.*&&.*cmd.*/c'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Powershell Keylogging

| Field | Value |
|---|---|
| **Sigma ID** | `34f90d3c-c297-49e9-b26d-911b05a4866c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1056.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_keylogging.yml)**

> Adversaries may log user keystrokes to intercept credentials as the user types them.

```sql
-- ============================================================
-- Title:        Powershell Keylogging
-- Sigma ID:     34f90d3c-c297-49e9-b26d-911b05a4866c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1056.001
-- Author:       frack113
-- Date:         2021-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_keylogging.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Keystrokes%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ProcAddress user32.dll GetAsyncKeyState%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ProcAddress user32.dll GetForegroundWindow%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.001/src/Get-Keystrokes.ps1

---

## Powershell LocalAccount Manipulation

| Field | Value |
|---|---|
| **Sigma ID** | `4fdc44df-bfe9-4fcc-b041-68f5a2d3031c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_localuser.yml)**

> Adversaries may manipulate accounts to maintain access to victim systems.
Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups


```sql
-- ============================================================
-- Title:        Powershell LocalAccount Manipulation
-- Sigma ID:     4fdc44df-bfe9-4fcc-b041-68f5a2d3031c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_localuser.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Disable-LocalUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-LocalUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-LocalUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-LocalUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-LocalUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Rename-LocalUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-LocalUser%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1098/T1098.md#atomic-test-1---admin-account-manipulate
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/?view=powershell-5.1

---

## Suspicious PowerShell Mailbox Export to Share - PS

| Field | Value |
|---|---|
| **Sigma ID** | `4a241dea-235b-4a7e-8d76-50d817b146c4` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | exfiltration |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_mailboxexport_share.yml)**

> Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Mailbox Export to Share - PS
-- Sigma ID:     4a241dea-235b-4a7e-8d76-50d817b146c4
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        exfiltration
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_mailboxexport_share.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-MailboxExportRequest%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Mailbox %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -FilePath \\\\\\\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://youtu.be/5mqid-7zp8k?t=2481
- https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
- https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1
- https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/

---

## Malicious PowerShell Commandlets - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `89819aa4-bbd6-46bc-88ec-c7f7fe30efa6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, discovery |
| **MITRE Techniques** | T1482, T1087, T1087.001, T1087.002, T1069.001, T1069.002, T1069, T1059.001 |
| **Author** | Sean Metcalf, Florian Roth, Bartlomiej Czyz @bczyz1, oscd.community, Nasreddine Bencherchali, Tim Shelton, Mustafa Kaan Demir, Georg Lauenstein, Max Altgelt, Tobias Michalski, Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_malicious_commandlets.yml)**

> Detects Commandlet names from well-known PowerShell exploitation frameworks

```sql
-- ============================================================
-- Title:        Malicious PowerShell Commandlets - ScriptBlock
-- Sigma ID:     89819aa4-bbd6-46bc-88ec-c7f7fe30efa6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, discovery | T1482, T1087, T1087.001, T1087.002, T1069.001, T1069.002, T1069, T1059.001
-- Author:       Sean Metcalf, Florian Roth, Bartlomiej Czyz @bczyz1, oscd.community, Nasreddine Bencherchali, Tim Shelton, Mustafa Kaan Demir, Georg Lauenstein, Max Altgelt, Tobias Michalski, Austin Songer
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_malicious_commandlets.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-Exfiltration%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-Persistence%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-RegBackdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-RemoteRegBackdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-ScrnSaveBackdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ConvertTo-Rc4ByteStream%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Decrypt-Hash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Disable-ADIDNSNode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Do-Exfiltration%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-ADIDNSNode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enabled-DuplicateToken%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Exploit-Jboss%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-ADRCSV%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-ADRExcel%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-ADRHTML%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-ADRJSON%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-ADRXML%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-Fruit%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-GPOLocation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-TrustedDocuments%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADIDNSNodeAttribute%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADIDNSNodeOwner%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADIDNSNodeTombstoned%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADIDNSPermission%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADIDNSZone%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ChromeDump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ClipboardContents%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-FoxDump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-GPPPassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-IndexedItem%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-KerberosAESKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Keystrokes%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-LSASecret%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-PassHashes%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RegAlwaysInstallElevated%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RegAutoLogon%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RemoteBootKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RemoteCachedCredential%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RemoteLocalAccountHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RemoteLSAKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RemoteMachineAccountHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RemoteNLKMKey%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RickAstley%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-SecurityPackages%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ServiceFilePermission%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ServicePermission%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ServiceUnquoted%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-SiteListPassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-System%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-TimedScreenshot%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-UnattendedInstallFile%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Unconstrained%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-USBKeystrokes%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-VaultCredential%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-VulnAutoRun%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-VulnSchTask%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Grant-ADIDNSPermission%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Gupt-Backdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ACLScanner%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ADRecon%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ADSBackdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-AgentSmith%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-AllChecks%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ARPScan%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-AzureHound%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-BackdoorLNK%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-BadPotato%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-BetterSafetyKatz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-BypassUAC%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Carbuncle%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Certify%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ConPtyShell%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-CredentialInjection%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DAFT%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DCSync%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DinvokeKatz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DllInjection%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DNSUpdate%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DNSExfiltrator%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DomainPasswordSpray%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-DowngradeAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-EgressCheck%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Eyewitness%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-FakeLogonScreen%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Farmer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Get-RBCD-Threaded%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Gopher%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Grouper%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-HandleKatz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ImpersonatedProcess%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ImpersonateSystem%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-InteractiveSystemPowerShell%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Internalmonologue%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Inveigh%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-InveighRelay%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-KrbRelay%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-LdapSignCheck%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Lockless%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-MalSCCM%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Mimikatz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Mimikittenz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-MITM6%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-NanoDump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-NetRipper%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Nightmare%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-NinjaCopy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-OfficeScrape%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-OxidResolver%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-P0wnedshell%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Paranoia%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PortScan%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PoshRatHttp%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PostExfil%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PowerDump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PowerDPAPI%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PowerShellTCP%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PowerShellWMI%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PPLDump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PsExec%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PSInject%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PsUaCme%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ReflectivePEInjection%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ReverseDNSLookup%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Rubeus%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-RunAs%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SafetyKatz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SauronEye%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SCShell%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Seatbelt%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ServiceAbuse%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ShadowSpray%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Sharp%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Shellcode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SMBScanner%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Snaffler%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Spoolsample%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SpraySinglePassword%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SSHCommand%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-StandIn%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-StickyNotesExtract%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SystemCommand%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Tasksbackdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Tater%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Thunderfox%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ThunderStruck%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-TokenManipulation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Tokenvator%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-TotalExec%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-UrbanBishop%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-UserHunter%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-VoiceTroll%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Whisker%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WinEnum%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-winPEAS%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WireTap%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WmiCommand%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WMIExec%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WScriptBypassUAC%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Zerologon%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%MailRaider%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-ADIDNSNode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-HoneyHash%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-InMemoryModule%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-SOASerialNumberArray%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-Minidump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PowerBreach%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%powercat %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PowerUp%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PowerView%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-ADIDNSNode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-Update%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Rename-ADIDNSNode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Revoke-ADIDNSPermission%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ADIDNSNode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Show-TargetScreen%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-CaptureServer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-Dnscat2%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-WebcamRecorder%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%VolumeShadowCopyTools%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://adsecurity.org/?p=2921
- https://github.com/S3cur3Th1sSh1t/PowerSharpPack/tree/master/PowerSharpBinaries
- https://github.com/BC-SECURITY/Invoke-ZeroLogon/blob/111d17c7fec486d9bb23387e2e828b09a26075e4/Invoke-ZeroLogon.ps1
- https://github.com/xorrior/RandomPS-Scripts/blob/848c919bfce4e2d67b626cbcf4404341cfe3d3b6/Get-DXWebcamVideo.ps1
- https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/6f23bb41f9675d7e2d32bacccff75e931ae00554/OfficeMemScraper.ps1
- https://github.com/dafthack/DomainPasswordSpray/blob/b13d64a5834694aa73fd2aea9911a83027c465a7/DomainPasswordSpray.ps1
- https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/
- https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/
- https://github.com/calebstewart/CVE-2021-1675
- https://github.com/BloodHoundAD/BloodHound/blob/0927441f67161cc6dc08a53c63ceb8e333f55874/Collectors/AzureHound.ps1
- https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html
- https://github.com/HarmJ0y/DAMP
- https://github.com/samratashok/nishang
- https://github.com/DarkCoderSc/PowerRunAsSystem/
- https://github.com/besimorhino/powercat
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/adrecon/ADRecon
- https://github.com/adrecon/AzureADRecon
- https://github.com/The-Viper-One/Invoke-PowerDPAPI/
- https://github.com/Arno0x/DNSExfiltrator/

---

## Malicious PowerShell Keywords

| Field | Value |
|---|---|
| **Sigma ID** | `f62176f3-8128-4faa-bf6c-83261322e5eb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Sean Metcalf (source), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_malicious_keywords.yml)**

> Detects keywords from well-known PowerShell exploitation frameworks

```sql
-- ============================================================
-- Title:        Malicious PowerShell Keywords
-- Sigma ID:     f62176f3-8128-4faa-bf6c-83261322e5eb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Sean Metcalf (source), Florian Roth (Nextron Systems)
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_malicious_keywords.yml
-- Unmapped:     (none)
-- False Pos:    Depending on the scripts, this rule might require some initial tuning to fit the environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%AdjustTokenPrivileges%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%IMAGE\_NT\_OPTIONAL\_HDR64\_MAGIC%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Metasploit%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Microsoft.Win32.UnsafeNativeMethods%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Mimikatz%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%MiniDumpWriteDump%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PAGE\_EXECUTE\_READ%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ReadProcessMemory.Invoke%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SE\_PRIVILEGE\_ENABLED%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SECURITY\_DELEGATION%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_ADJUST\_PRIVILEGES%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_ALL\_ACCESS%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_ASSIGN\_PRIMARY%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_DUPLICATE%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_ELEVATION%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_IMPERSONATE%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_INFORMATION\_CLASS%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_PRIVILEGES%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TOKEN\_QUERY%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Depending on the scripts, this rule might require some initial tuning to fit the environment

**References:**
- https://adsecurity.org/?p=2921

---

## Live Memory Dump Using Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `cd185561-4760-45d6-a63e-a51325112cae` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003 |
| **Author** | Max Altgelt (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_memorydump_getstoragediagnosticinfo.yml)**

> Detects usage of a PowerShell command to dump the live memory of a Windows machine

```sql
-- ============================================================
-- Title:        Live Memory Dump Using Powershell
-- Sigma ID:     cd185561-4760-45d6-a63e-a51325112cae
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003
-- Author:       Max Altgelt (Nextron Systems)
-- Date:         2021-09-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_memorydump_getstoragediagnosticinfo.yml
-- Unmapped:     (none)
-- False Pos:    Diagnostics
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-StorageDiagnosticInfo%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-IncludeLiveDump%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Diagnostics

**References:**
- https://learn.microsoft.com/en-us/powershell/module/storage/get-storagediagnosticinfo?view=windowsserver2022-ps

---

## Modify Group Policy Settings - ScriptBlockLogging

| Field | Value |
|---|---|
| **Sigma ID** | `b7216a7d-687e-4c8d-82b1-3080b2ad961f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1484.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_modify_group_policy_settings.yml)**

> Detect malicious GPO modifications can be used to implement many other malicious behaviors.

```sql
-- ============================================================
-- Title:        Modify Group Policy Settings - ScriptBlockLogging
-- Sigma ID:     b7216a7d-687e-4c8d-82b1-3080b2ad961f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1484.001
-- Author:       frack113
-- Date:         2022-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_modify_group_policy_settings.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%GroupPolicyRefreshTimeDC%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%GroupPolicyRefreshTimeOffsetDC%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%GroupPolicyRefreshTime%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%GroupPolicyRefreshTimeOffset%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%EnableSmartScreen%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ShellSmartScreenLevel%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows\\System%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1484.001/T1484.001.md

---

## Powershell MsXml COM Object

| Field | Value |
|---|---|
| **Sigma ID** | `78aa1347-1517-4454-9982-b338d6df8343` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | frack113, MatilJ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_msxml_com.yml)**

> Adversaries may abuse PowerShell commands and scripts for execution.
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell)
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code


```sql
-- ============================================================
-- Title:        Powershell MsXml COM Object
-- Sigma ID:     78aa1347-1517-4454-9982-b338d6df8343
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       frack113, MatilJ
-- Date:         2022-01-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_msxml_com.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ComObject%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%MsXml2.%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%XmlHttp%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-7---powershell-msxml-com-object---with-prompt
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms766431(v=vs.85)
- https://www.trendmicro.com/en_id/research/22/e/uncovering-a-kingminer-botnet-attack-using-trend-micro-managed-x.html

---

## Malicious Nishang PowerShell Commandlets

| Field | Value |
|---|---|
| **Sigma ID** | `f772cee9-b7c2-4cb2-8f07-49870adc02e0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Alec Costello |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets.yml)**

> Detects Commandlet names and arguments from the Nishang exploitation framework

```sql
-- ============================================================
-- Title:        Malicious Nishang PowerShell Commandlets
-- Sigma ID:     f772cee9-b7c2-4cb2-8f07-49870adc02e0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Alec Costello
-- Date:         2019-05-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-ConstrainedDelegationBackdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Copy-VSS%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Create-MultipleSessions%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DataToEncode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DNS\_TXT\_Pwnage%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Do-Exfiltration-Dns%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Download\_Execute%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Download-Execute-PS%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DownloadAndExtractFromRemoteRegistry%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DumpCerts%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DumpCreds%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DumpHashes%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-DuplicateToken%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Enable-Duplication%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Execute-Command-MSSQL%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Execute-DNSTXT-Code%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Execute-OnTime%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ExetoText%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%exfill%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ExfilOption%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%FakeDC%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%FireBuster%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%FireListener%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Information %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-PassHints%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Web-Credentials%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WebCredentials%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WLAN-Keys%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%HTTP-Backdoor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-AmsiBypass%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-BruteForce%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-CredentialsPhish%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Decode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Encode%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Interceptor%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-JSRatRegsvr%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-JSRatRundll%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-MimikatzWDigestDowngrade%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-NetworkRelay%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PowerShellIcmp%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PowerShellUdp%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Prasadhak%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PSGcat%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-PsGcatAgent%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SessionGopher%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SSIDExfil%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%LoggedKeys%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Nishang%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%NotAllNameSpaces%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-CHM%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%OUT-DNSTXT%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-HTA%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-RundllCommand%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-SCF%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-SCT%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-Shortcut%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-WebQuery%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-Word%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Parse\_Keys%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Password-List%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Powerpreter%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-Persistence%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-PoshRat%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-Update%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Run-EXEonRemote%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-DCShadowPermissions%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-RemotePSRemoting%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-RemoteWMI%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Shellcode32%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Shellcode64%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%StringtoBase64%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%TexttoExe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/samratashok/nishang

---

## NTFS Alternate Data Stream

| Field | Value |
|---|---|
| **Sigma ID** | `8c521530-5169-495d-a199-0a3a881ad24e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1564.004, T1059.001 |
| **Author** | Sami Ruohonen |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_ntfs_ads_access.yml)**

> Detects writing data into NTFS alternate data streams from powershell. Needs Script Block Logging.

```sql
-- ============================================================
-- Title:        NTFS Alternate Data Stream
-- Sigma ID:     8c521530-5169-495d-a199-0a3a881ad24e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1564.004, T1059.001
-- Author:       Sami Ruohonen
-- Date:         2018-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_ntfs_ads_access.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%set-content%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%add-content%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-stream%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20220614030603/http://www.powertheshell.com/ntfsstreams/
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md

---

## Code Executed Via Office Add-in XLL File

| Field | Value |
|---|---|
| **Sigma ID** | `36fbec91-fa1b-4d5d-8df1-8d8edcb632ad` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_office_comobject_registerxll.yml)**

> Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
Office add-ins can be used to add functionality to Office programs


```sql
-- ============================================================
-- Title:        Code Executed Via Office Add-in XLL File
-- Sigma ID:     36fbec91-fa1b-4d5d-8df1-8d8edcb632ad
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137.006
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_office_comobject_registerxll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%new-object %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ComObject %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.application%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.RegisterXLL%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1137.006/T1137.006.md

---

## Potential Packet Capture Activity Via Start-NetEventSession - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `da34e323-1e65-42db-83be-a6725ac2caa3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1040 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_packet_capture.yml)**

> Detects the execution of powershell scripts with calls to the "Start-NetEventSession" cmdlet. Which allows an attacker to start event and packet capture for a network event session.
Adversaries may attempt to capture network to gather information over the course of an operation.
Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol.


```sql
-- ============================================================
-- Title:        Potential Packet Capture Activity Via Start-NetEventSession - ScriptBlock
-- Sigma ID:     da34e323-1e65-42db-83be-a6725ac2caa3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1040
-- Author:       frack113
-- Date:         2024-05-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_packet_capture.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate network diagnostic scripts.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-NetEventSession%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate network diagnostic scripts.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/5f866ca4517e837c4ea576e7309d0891e78080a8/atomics/T1040/T1040.md#atomic-test-16---powershell-network-sniffing
- https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/7b8935fe4c82cb64d61343de1a8b2e38dd968534/handbooks/10_post_exploitation.md
- https://github.com/forgottentq/powershell/blob/9e616363d497143dc955c4fdce68e5c18d28a6cb/captureWindows-Endpoint.ps1#L13

---

## Potential Invoke-Mimikatz PowerShell Script

| Field | Value |
|---|---|
| **Sigma ID** | `189e3b02-82b2-4b90-9662-411eb64486d4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003 |
| **Author** | Tim Rauch, Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml)**

> Detects Invoke-Mimikatz PowerShell script and alike. Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords.

```sql
-- ============================================================
-- Title:        Potential Invoke-Mimikatz PowerShell Script
-- Sigma ID:     189e3b02-82b2-4b90-9662-411eb64486d4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003
-- Author:       Tim Rauch, Elastic (idea)
-- Date:         2022-09-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml
-- Unmapped:     (none)
-- False Pos:    Mimikatz can be useful for testing the security of networks
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DumpCreds%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DumpCerts%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%sekurlsa::logonpasswords%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%crypto::certificates%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%CERT\_SYSTEM\_STORE\_LOCAL\_MACHINE%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Mimikatz can be useful for testing the security of networks

**References:**
- https://www.elastic.co/guide/en/security/current/potential-invoke-mimikatz-powershell-script.html#potential-invoke-mimikatz-powershell-script

---

## Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `cdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance, discovery |
| **MITRE Techniques** | T1018, T1558, T1589.002 |
| **Author** | frack113 |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_potential_unconstrained_delegation_discovery.yml)**

> Detects the use of the "Get-ADComputer" cmdlet in order to identify systems which are configured for unconstrained delegation.

```sql
-- ============================================================
-- Title:        Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock
-- Sigma ID:     cdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        reconnaissance, discovery | T1018, T1558, T1589.002
-- Author:       frack113
-- Date:         2025-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_potential_unconstrained_delegation_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the library for administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Properties*TrustedForDelegation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Properties*TrustedToAuthForDelegation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Properties*msDS-AllowedToDelegateTo%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Properties*PrincipalsAllowedToDelegateToAccount%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-LDAPFilter*(userAccountControl:1.2.840.113556.1.4.803:=524288)%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the library for administrative activity

**References:**
- https://pentestlab.blog/2022/03/21/unconstrained-delegation/
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2022-ps

---

## PowerShell Web Access Installation - PsScript

| Field | Value |
|---|---|
| **Sigma ID** | `5f9c7f1a-7c21-4c39-b2f3-8d8006e0e51f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Michael Haag |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_powershell_web_access_installation.yml)**

> Detects the installation and configuration of PowerShell Web Access, which could be used for remote access and potential abuse

```sql
-- ============================================================
-- Title:        PowerShell Web Access Installation - PsScript
-- Sigma ID:     5f9c7f1a-7c21-4c39-b2f3-8d8006e0e51f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1059.001
-- Author:       Michael Haag
-- Date:         2024-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_powershell_web_access_installation.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell Web Access installations by administrators
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-PswaAuthorizationRule%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-UserName *%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ComputerName *%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Install-PswaWebApplication%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Install-WindowsFeature WindowsPowerShellWebAccess%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell Web Access installations by administrators

**References:**
- https://docs.microsoft.com/en-us/powershell/module/powershellwebaccess/install-pswawebapplication
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- https://gist.github.com/MHaggis/7e67b659af9148fa593cf2402edebb41

---

## PowerView PowerShell Cmdlets - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `dcd74b95-3f36-4ed9-9598-0490951643aa` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_powerview_malicious_commandlets.yml)**

> Detects Cmdlet names from PowerView of the PowerSploit exploitation framework.

```sql
-- ============================================================
-- Title:        PowerView PowerShell Cmdlets - ScriptBlock
-- Sigma ID:     dcd74b95-3f36-4ed9-9598-0490951643aa
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Bhabesh Raj
-- Date:         2021-05-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_powerview_malicious_commandlets.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Export-PowerViewCSV%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-DomainLocalGroupMember%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-DomainObjectPropertyOutlier%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-DomainProcess%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-DomainShare%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-DomainUserEvent%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-DomainUserLocation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-ForeignGroup%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-ForeignUser%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-GPOComputerAdmin%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-GPOLocation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-InterestingDomain%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-InterestingFile%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-LocalAdminAccess%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Find-ManagedSecurityGroups%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-CachedRDPConnection%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DFSshare%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainDFSShare%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainDNSRecord%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainDNSZone%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainFileServer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainGPOComputerLocalGroupMapping%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainGPOLocalGroup%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-DomainGPOUserLocalGroupMapping%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-LastLoggedOn%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-LoggedOnLocal%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-NetFileServer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-NetForest%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-NetGPOGroup%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-NetProcess%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-NetRDPSession%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RegistryMountedDrive%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-RegLoggedOn%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WMIRegCachedRDPConnection%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WMIRegLastLoggedOn%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WMIRegMountedDrive%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WMIRegProxy%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ACLScanner%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-CheckLocalAdminAccess%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-EnumerateLocalAdmin%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-EventHunter%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-FileFinder%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Kerberoast%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-MapDomainTrust%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ProcessHunter%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-RevertToSelf%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-ShareFinder%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-UserHunter%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-UserImpersonation%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-RemoteConnection%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Request-SPNTicket%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Resolve-IPAddress%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://powersploit.readthedocs.io/en/stable/Recon/README
- https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- https://thedfirreport.com/2020/10/08/ryuks-return
- https://adsecurity.org/?p=2277

---

## PowerShell Credential Prompt

| Field | Value |
|---|---|
| **Sigma ID** | `ca8b77a9-d499-4095-b793-5d5f330d450e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | John Lambert (idea), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_prompt_credentials.yml)**

> Detects PowerShell calling a credential prompt

```sql
-- ============================================================
-- Title:        PowerShell Credential Prompt
-- Sigma ID:     ca8b77a9-d499-4095-b793-5d5f330d450e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       John Lambert (idea), Florian Roth (Nextron Systems)
-- Date:         2017-04-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_prompt_credentials.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PromptForCredential%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/JohnLaTwC/status/850381440629981184
- https://t.co/ezOTGy1a1G

---

## PSAsyncShell - Asynchronous TCP Reverse Shell

| Field | Value |
|---|---|
| **Sigma ID** | `afd3df04-948d-46f6-ae44-25966c44b97f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_psasyncshell.yml)**

> Detects the use of PSAsyncShell an Asynchronous TCP Reverse Shell written in powershell

```sql
-- ============================================================
-- Title:        PSAsyncShell - Asynchronous TCP Reverse Shell
-- Sigma ID:     afd3df04-948d-46f6-ae44-25966c44b97f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_psasyncshell.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PSAsyncShell%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/JoelGMSec/PSAsyncShell

---

## PowerShell PSAttack

| Field | Value |
|---|---|
| **Sigma ID** | `b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Sean Metcalf (source), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_psattack.yml)**

> Detects the use of PSAttack PowerShell hack tool

```sql
-- ============================================================
-- Title:        PowerShell PSAttack
-- Sigma ID:     b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Sean Metcalf (source), Florian Roth (Nextron Systems)
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_psattack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PS ATTACK!!!%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://adsecurity.org/?p=2921

---

## PowerShell Remote Session Creation

| Field | Value |
|---|---|
| **Sigma ID** | `a0edd39f-a0c6-4c17-8141-261f958e8d8f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_remote_session_creation.yml)**

> Adversaries may abuse PowerShell commands and scripts for execution.
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system


```sql
-- ============================================================
-- Title:        PowerShell Remote Session Creation
-- Sigma ID:     a0edd39f-a0c6-4c17-8141-261f958e8d8f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       frack113
-- Date:         2022-01-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_remote_session_creation.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-PSSession%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ComputerName %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-10---powershell-invoke-downloadcradle
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.4

---

## Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `cacef8fc-9d3d-41f7-956d-455c6e881bc5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_remotefxvgpudisablement_abuse.yml)**

> Detects PowerShell module creation where the module Contents are set to "function Get-VMRemoteFXPhysicalVideoAdapter". This could be a sign of potential abuse of the "RemoteFXvGPUDisablement.exe" binary which is known to be vulnerable to module load-order hijacking.

```sql
-- ============================================================
-- Title:        Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock
-- Sigma ID:     cacef8fc-9d3d-41f7-956d-455c6e881bc5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_remotefxvgpudisablement_abuse.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE 'function Get-VMRemoteFXPhysicalVideoAdapter {%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
- https://github.com/redcanaryco/AtomicTestHarnesses/blob/7e1e4da116801e3d6fcc6bedb207064577e40572/TestHarnesses/T1218_SignedBinaryProxyExecution/InvokeRemoteFXvGPUDisablementCommand.ps1

---

## Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `a861d835-af37-4930-bcd6-5b178bfb54df` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1558.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_request_kerberos_ticket.yml)**

> Detects PowerShell scripts that utilize native PowerShell Identity modules to request Kerberos tickets.
This behavior is typically seen during a Kerberos or silver ticket attack. A successful execution will output the SPNs for the endpoint in question.


```sql
-- ============================================================
-- Title:        Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock
-- Sigma ID:     a861d835-af37-4930-bcd6-5b178bfb54df
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1558.003
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_request_kerberos_ticket.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.IdentityModel.Tokens.KerberosRequestorSecurityToken%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.GetRequest()%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1558.003/T1558.003.md#atomic-test-4---request-a-single-ticket-via-powershell
- https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8.1

---

## PowerShell Script With File Hostname Resolving Capabilities

| Field | Value |
|---|---|
| **Sigma ID** | `fbc5e92f-3044-4e73-a5c6-1c4359b539de` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1020 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_resolve_list_of_ip_from_file.yml)**

> Detects PowerShell scripts that have capabilities to read files, loop through them and resolve DNS host entries.

```sql
-- ============================================================
-- Title:        PowerShell Script With File Hostname Resolving Capabilities
-- Sigma ID:     fbc5e92f-3044-4e73-a5c6-1c4359b539de
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1020
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_resolve_list_of_ip_from_file.yml
-- Unmapped:     (none)
-- False Pos:    The same functionality can be implemented by admin scripts, correlate with name and creator
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-content %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%foreach%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Net.Dns]::GetHostEntry%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-File%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The same functionality can be implemented by admin scripts, correlate with name and creator

**References:**
- https://www.fortypoundhead.com/showcontent.asp?artid=24022
- https://labs.withsecure.com/publications/fin7-target-veeam-servers

---

## Root Certificate Installed - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `42821614-9264-4761-acfc-5772c3286f76` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1553.004 |
| **Author** | oscd.community, @redcanary, Zach Stanford @svch0st |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_root_certificate_installed.yml)**

> Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.

```sql
-- ============================================================
-- Title:        Root Certificate Installed - PowerShell
-- Sigma ID:     42821614-9264-4761-acfc-5772c3286f76
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1553.004
-- Author:       oscd.community, @redcanary, Zach Stanford @svch0st
-- Date:         2020-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_root_certificate_installed.yml
-- Unmapped:     (none)
-- False Pos:    Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Move-Item%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Cert:\\LocalMachine\\Root%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Import-Certificate%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Cert:\\LocalMachine\\Root%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md

---

## Suspicious Invoke-Item From Mount-DiskImage

| Field | Value |
|---|---|
| **Sigma ID** | `902cedee-0398-4e3a-8183-6f3a89773a96` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1553.005 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_run_from_mount_diskimage.yml)**

> Adversaries may abuse container files such as disk image (.iso, .vhd) file formats to deliver malicious payloads that may not be tagged with MOTW.

```sql
-- ============================================================
-- Title:        Suspicious Invoke-Item From Mount-DiskImage
-- Sigma ID:     902cedee-0398-4e3a-8183-6f3a89773a96
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1553.005
-- Author:       frack113
-- Date:         2022-02-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_run_from_mount_diskimage.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Mount-DiskImage %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ImagePath %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Volume%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.DriveLetter%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%invoke-item %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%):\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.005/T1553.005.md#atomic-test-2---mount-an-iso-image-and-run-executable-from-the-iso
- https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage?view=windowsserver2022-ps

---

## PowerShell Script With File Upload Capabilities

| Field | Value |
|---|---|
| **Sigma ID** | `d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1020 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_script_with_upload_capabilities.yml)**

> Detects PowerShell scripts leveraging the "Invoke-WebRequest" cmdlet to send data via either "PUT" or "POST" method.

```sql
-- ============================================================
-- Title:        PowerShell Script With File Upload Capabilities
-- Sigma ID:     d2e3f2f6-7e09-4bf2-bc5d-90186809e7fb
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1020
-- Author:       frack113
-- Date:         2022-01-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_script_with_upload_capabilities.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-RestMethod%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WebRequest%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%irm %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%iwr %'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Method "POST"%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Method "PUT"%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Method POST%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Method PUT%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Method 'POST'%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Method 'PUT'%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1020/T1020.md
- https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.4

---

## Powershell Sensitive File Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `7d416556-6502-45b2-9bad-9d2f05f38997` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_sensitive_file_discovery.yml)**

> Detect adversaries enumerate sensitive files

```sql
-- ============================================================
-- Title:        Powershell Sensitive File Discovery
-- Sigma ID:     7d416556-6502-45b2-9bad-9d2f05f38997
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       frack113
-- Date:         2022-09-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_sensitive_file_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ls%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-childitem%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gci%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.pass%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.kdbx%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.kdb%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-recurse%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/malmoeb/status/1570814999370801158

---

## PowerShell Script Change Permission Via Set-Acl - PsScript

| Field | Value |
|---|---|
| **Sigma ID** | `cae80281-ef23-44c5-873b-fd48d2666f49` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1222 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_set_acl.yml)**

> Detects PowerShell scripts set ACL to of a file or a folder

```sql
-- ============================================================
-- Title:        PowerShell Script Change Permission Via Set-Acl - PsScript
-- Sigma ID:     cae80281-ef23-44c5-873b-fd48d2666f49
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1222
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_set_acl.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Acl %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-AclObject %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/74438b0237d141ee9c99747976447dc884cb1a39/atomics/T1505.005/T1505.005.md

---

## PowerShell Set-Acl On Windows Folder - PsScript

| Field | Value |
|---|---|
| **Sigma ID** | `3bf1d859-3a7e-44cb-8809-a99e066d3478` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1222 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_set_acl_susp_location.yml)**

> Detects PowerShell scripts to set the ACL to a file in the Windows folder

```sql
-- ============================================================
-- Title:        PowerShell Set-Acl On Windows Folder - PsScript
-- Sigma ID:     3bf1d859-3a7e-44cb-8809-a99e066d3478
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1222
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_set_acl_susp_location.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Acl %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-AclObject %')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path "C:\\Windows%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path "C:/Windows%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path 'C:\\Windows%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path 'C:/Windows%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path C:\\\\Windows%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path C:/Windows%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path $env:windir%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path "$env:windir%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path '$env:windir%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%FullControl%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Allow%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/74438b0237d141ee9c99747976447dc884cb1a39/atomics/T1505.005/T1505.005.md
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-5.1

---

## Change PowerShell Policies to an Insecure Level - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `61d0475c-173f-4844-86f7-f3eebae1c66b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_set_policies_to_unsecure_level.yml)**

> Detects changing the PowerShell script execution policy to a potentially insecure level using the "Set-ExecutionPolicy" cmdlet.

```sql
-- ============================================================
-- Title:        Change PowerShell Policies to an Insecure Level - PowerShell
-- Sigma ID:     61d0475c-173f-4844-86f7-f3eebae1c66b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       frack113
-- Date:         2021-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_set_policies_to_unsecure_level.yml
-- Unmapped:     (none)
-- False Pos:    Administrator script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator script

**References:**
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.4
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.4
- https://adsecurity.org/?p=2604

---

## PowerShell ShellCode

| Field | Value |
|---|---|
| **Sigma ID** | `16b37b70-6fcf-4814-a092-c36bd3aafcbd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1055, T1059.001 |
| **Author** | David Ledbetter (shellcode), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_shellcode_b64.yml)**

> Detects Base64 encoded Shellcode

```sql
-- ============================================================
-- Title:        PowerShell ShellCode
-- Sigma ID:     16b37b70-6fcf-4814-a092-c36bd3aafcbd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1055, T1059.001
-- Author:       David Ledbetter (shellcode), Florian Roth (Nextron Systems)
-- Date:         2018-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_shellcode_b64.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%OiCAAAAYInlM%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%OiJAAAAYInlM%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/cyb3rops/status/1063072865992523776

---

## Malicious ShellIntel PowerShell Commandlets

| Field | Value |
|---|---|
| **Sigma ID** | `402e1e1d-ad59-47b6-bf80-1ee44985b3a7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_shellintel_malicious_commandlets.yml)**

> Detects Commandlet names from ShellIntel exploitation scripts.

```sql
-- ============================================================
-- Title:        Malicious ShellIntel PowerShell Commandlets
-- Sigma ID:     402e1e1d-ad59-47b6-bf80-1ee44985b3a7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_shellintel_malicious_commandlets.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-SMBAutoBrute%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-GPOLinks%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Potato%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Shellntel/scripts/

---

## Detected Windows Software Discovery - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `2650dd1a-eb2a-412d-ac36-83f06c4f2282` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1518 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_software_discovery.yml)**

> Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.

```sql
-- ============================================================
-- Title:        Detected Windows Software Discovery - PowerShell
-- Sigma ID:     2650dd1a-eb2a-412d-ac36-83f06c4f2282
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1518
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_software_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-itemProperty%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\software\\%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%select-object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%format-table%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518/T1518.md
- https://github.com/harleyQu1nn/AggressorScripts

---

## Powershell Store File In Alternate Data Stream

| Field | Value |
|---|---|
| **Sigma ID** | `a699b30e-d010-46c8-bbd1-ee2e26765fe9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_store_file_in_alternate_data_stream.yml)**

> Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.

```sql
-- ============================================================
-- Title:        Powershell Store File In Alternate Data Stream
-- Sigma ID:     a699b30e-d010-46c8-bbd1-ee2e26765fe9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.004
-- Author:       frack113
-- Date:         2021-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_store_file_in_alternate_data_stream.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-Process%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-FilePath "$env:comspec" %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ArgumentList %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%>%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md

---

## Potential Persistence Via Security Descriptors - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `2f77047c-e6e9-4c11-b088-a3de399524cd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_ace_tampering.yml)**

> Detects usage of certain functions and keywords that are used to manipulate security descriptors in order to potentially set a backdoor. As seen used in the DAMP project.

```sql
-- ============================================================
-- Title:        Potential Persistence Via Security Descriptors - ScriptBlock
-- Sigma ID:     2f77047c-e6e9-4c11-b088-a3de399524cd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_ace_tampering.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%win32\_Trustee%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%win32\_Ace%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.AccessMask%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.AceType%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.SetSecurityDescriptor%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Lsa\\JD%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Lsa\\Skew1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Lsa\\Data%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\Lsa\\GBG%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/HarmJ0y/DAMP

---

## AD Groups Or Users Enumeration Using PowerShell - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `88f0884b-331d-403d-a3a1-b668cf035603` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_ad_group_reco.yml)**

> Adversaries may attempt to find domain-level groups and permission settings.
The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.
Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.


```sql
-- ============================================================
-- Title:        AD Groups Or Users Enumeration Using PowerShell - ScriptBlock
-- Sigma ID:     88f0884b-331d-403d-a3a1-b668cf035603
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       frack113
-- Date:         2021-12-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_ad_group_reco.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-ADPrincipalGroupMembership%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-aduser%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-f %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-pr %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DoesNotRequirePreAuth%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md

---

## Potential PowerShell Obfuscation Using Character Join

| Field | Value |
|---|---|
| **Sigma ID** | `e8314f79-564d-4f79-bc13-fbc0bf2660d8` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_alias_obfscuation.yml)**

> Detects specific techniques often seen used inside of PowerShell scripts to obfscuate Alias creation

```sql
-- ============================================================
-- Title:        Potential PowerShell Obfuscation Using Character Join
-- Sigma ID:     e8314f79-564d-4f79-bc13-fbc0bf2660d8
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_alias_obfscuation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Alias%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Value (-join(%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Suspicious Eventlog Clear

| Field | Value |
|---|---|
| **Sigma ID** | `0f017df3-8f5a-414f-ad6b-24aff1128278` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_clear_eventlog.yml)**

> Detects usage of known powershell cmdlets such as "Clear-EventLog" to clear the Windows event logs

```sql
-- ============================================================
-- Title:        Suspicious Eventlog Clear
-- Sigma ID:     0f017df3-8f5a-414f-ad6b-24aff1128278
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2022-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_clear_eventlog.yml
-- Unmapped:     (none)
-- False Pos:    Rare need to clear logs before doing something. Sometimes used by installers or cleaner scripts. The script should be investigated to determine if it's legitimate
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Clear-EventLog %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-EventLog %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Limit-EventLog %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Clear-WinEvent %')))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Eventing.Reader.EventLogSession%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ClearLog%'))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Diagnostics.EventLog%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Clear%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare need to clear logs before doing something. Sometimes used by installers or cleaner scripts. The script should be investigated to determine if it's legitimate

**References:**
- https://twitter.com/oroneequalsone/status/1568432028361830402
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.001/T1070.001.md
- https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html
- https://stackoverflow.com/questions/66011412/how-to-clear-a-event-log-in-powershell-7
- https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogsession.clearlog?view=windowsdesktop-9.0&viewFallbackFrom=dotnet-plat-ext-5.0#System_Diagnostics_Eventing_Reader_EventLogSession_ClearLog_System_String_
- https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlog.clear

---

## Powershell Directory Enumeration

| Field | Value |
|---|---|
| **Sigma ID** | `162e69a7-7981-4344-84a9-0f1c9a217a52` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_directory_enum.yml)**

> Detects technique used by MAZE ransomware to enumerate directories using Powershell

```sql
-- ============================================================
-- Title:        Powershell Directory Enumeration
-- Sigma ID:     162e69a7-7981-4344-84a9-0f1c9a217a52
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       frack113
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_directory_enum.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%foreach%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ChildItem%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ErrorAction %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SilentlyContinue%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-File %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-append%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md
- https://www.mandiant.com/resources/tactics-techniques-procedures-associated-with-maze-ransomware-incidents

---

## Suspicious PowerShell Download - Powershell Script

| Field | Value |
|---|---|
| **Sigma ID** | `403c2cc0-7f6b-4925-9423-bfa573bed7eb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_download.yml)**

> Detects suspicious PowerShell download command

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Download - Powershell Script
-- Sigma ID:     403c2cc0-7f6b-4925-9423-bfa573bed7eb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_download.yml
-- Unmapped:     (none)
-- False Pos:    PowerShell scripts that download content from the Internet
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Net.WebClient%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.DownloadFile(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.DownloadFileAsync(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.DownloadString(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.DownloadStringAsync(%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** PowerShell scripts that download content from the Internet

**References:**
- https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-8.0
- https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-8.0

---

## Powershell Execute Batch Script

| Field | Value |
|---|---|
| **Sigma ID** | `b5522a23-82da-44e5-9c8b-e10ed8955f88` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_execute_batch_script.yml)**

> Adversaries may abuse the Windows command shell for execution.
The Windows command shell ([cmd](https://attack.mitre.org/software/S0106)) is the primary command prompt on Windows systems.
The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands.
Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops.
Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple system


```sql
-- ============================================================
-- Title:        Powershell Execute Batch Script
-- Sigma ID:     b5522a23-82da-44e5-9c8b-e10ed8955f88
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.003
-- Author:       frack113
-- Date:         2022-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_execute_batch_script.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.cmd%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.bat%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-Process%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.003/T1059.003.md#atomic-test-1---create-and-execute-batch-script

---

## Extracting Information with PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `bd5971a7-626d-46ab-8176-ed643f694f68` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_extracting.yml)**

> Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.
These can be files created by users to store their own credentials, shared credential stores for a group of individuals,
configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.


```sql
-- ============================================================
-- Title:        Extracting Information with PowerShell
-- Sigma ID:     bd5971a7-626d-46ab-8176-ed643f694f68
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552.001
-- Author:       frack113
-- Date:         2021-12-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_extracting.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ls%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -R%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%select-string %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Pattern %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md

---

## Troubleshooting Pack Cmdlet Execution

| Field | Value |
|---|---|
| **Sigma ID** | `03409c93-a7c7-49ba-9a4c-a00badf2a153` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1202 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_follina_execution.yml)**

> Detects execution of "TroubleshootingPack" cmdlets to leverage CVE-2022-30190 or action similar to "msdt" lolbin (as described in LOLBAS)

```sql
-- ============================================================
-- Title:        Troubleshooting Pack Cmdlet Execution
-- Sigma ID:     03409c93-a7c7-49ba-9a4c-a00badf2a153
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1202
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_follina_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of "TroubleshootingPack" cmdlet for troubleshooting purposes
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-TroubleshootingPack%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%C:\\Windows\\Diagnostics\\System\\PCW%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-AnswerFile%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Unattended%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of "TroubleshootingPack" cmdlet for troubleshooting purposes

**References:**
- https://twitter.com/nas_bench/status/1537919885031772161
- https://lolbas-project.github.io/lolbas/Binaries/Msdt/

---

## Password Policy Discovery With Get-AdDefaultDomainPasswordPolicy

| Field | Value |
|---|---|
| **Sigma ID** | `bbb9495b-58fc-4016-b9df-9a3a1b67ca82` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1201 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_addefaultdomainpasswordpolicy.yml)**

> Detetcts PowerShell activity in which Get-Addefaultdomainpasswordpolicy is used to get the default password policy for an Active Directory domain.

```sql
-- ============================================================
-- Title:        Password Policy Discovery With Get-AdDefaultDomainPasswordPolicy
-- Sigma ID:     bbb9495b-58fc-4016-b9df-9a3a1b67ca82
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1201
-- Author:       frack113
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_addefaultdomainpasswordpolicy.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-AdDefaultDomainPasswordPolicy%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1201/T1201.md#atomic-test-9---enumerate-active-directory-password-policy-with-get-addefaultdomainpasswordpolicy
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2022-ps

---

## Suspicious PowerShell Get Current User

| Field | Value |
|---|---|
| **Sigma ID** | `4096a49c-7de4-4da0-a230-c66ccd56ea5a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_current_user.yml)**

> Detects the use of PowerShell to identify the current logged user.

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Get Current User
-- Sigma ID:     4096a49c-7de4-4da0-a230-c66ccd56ea5a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       frack113
-- Date:         2022-04-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_current_user.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Environment]::UserName%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$env:UserName%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Security.Principal.WindowsIdentity]::GetCurrent()%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md#atomic-test-4---user-discovery-with-env-vars-powershell-script
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md#atomic-test-5---getcurrent-user-with-powershell-script

---

## Suspicious GPO Discovery With Get-GPO

| Field | Value |
|---|---|
| **Sigma ID** | `eb2fd349-ec67-4caa-9143-d79c7fb34441` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1615 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_gpo.yml)**

> Detect use of Get-GPO to get one GPO or all the GPOs in a domain.

```sql
-- ============================================================
-- Title:        Suspicious GPO Discovery With Get-GPO
-- Sigma ID:     eb2fd349-ec67-4caa-9143-d79c7fb34441
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1615
-- Author:       frack113
-- Date:         2022-06-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_gpo.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-GPO%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1615/T1615.md
- https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo?view=windowsserver2022-ps

---

## Suspicious Process Discovery With Get-Process

| Field | Value |
|---|---|
| **Sigma ID** | `af4c87ce-bdda-4215-b998-15220772e993` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1057 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_process.yml)**

> Get the processes that are running on the local computer.

```sql
-- ============================================================
-- Title:        Suspicious Process Discovery With Get-Process
-- Sigma ID:     af4c87ce-bdda-4215-b998-15220772e993
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1057
-- Author:       frack113
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_get_process.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Process%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1057/T1057.md#atomic-test-3---process-discovery---get-process
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.4

---

## PowerShell Get-Process LSASS in ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `84c174ab-d3ef-481f-9c86-a50d0b8e3edb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml)**

> Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity

```sql
-- ============================================================
-- Title:        PowerShell Get-Process LSASS in ScriptBlock
-- Sigma ID:     84c174ab-d3ef-481f-9c86-a50d0b8e3edb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-04-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Process lsass%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)

**References:**
- https://web.archive.org/web/20220205033028/https://twitter.com/PythonResponder/status/1385064506049630211

---

## Suspicious GetTypeFromCLSID ShellExecute

| Field | Value |
|---|---|
| **Sigma ID** | `8bc063d5-3a3a-4f01-a140-bc15e55e8437` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_gettypefromclsid.yml)**

> Detects suspicious Powershell code that execute COM Objects

```sql
-- ============================================================
-- Title:        Suspicious GetTypeFromCLSID ShellExecute
-- Sigma ID:     8bc063d5-3a3a-4f01-a140-bc15e55e8437
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.015
-- Author:       frack113
-- Date:         2022-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_gettypefromclsid.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%::GetTypeFromCLSID(%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.ShellExecute(%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.015/T1546.015.md#atomic-test-2---powershell-execute-com-object

---

## Suspicious Hyper-V Cmdlets

| Field | Value |
|---|---|
| **Sigma ID** | `42d36aa1-3240-4db0-8257-e0118dcdd9cd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_hyper_v_condlet.yml)**

> Adversaries may carry out malicious operations using a virtual instance to avoid detection

```sql
-- ============================================================
-- Title:        Suspicious Hyper-V Cmdlets
-- Sigma ID:     42d36aa1-3240-4db0-8257-e0118dcdd9cd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.006
-- Author:       frack113
-- Date:         2022-04-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_hyper_v_condlet.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-VM%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-VMFirmware%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-VM%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.006/T1564.006.md#atomic-test-3---create-and-start-hyper-v-virtual-machine

---

## Suspicious PowerShell Invocations - Generic

| Field | Value |
|---|---|
| **Sigma ID** | `ed965133-513f-41d9-a441-e38076a0798f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invocation_generic.yml)**

> Detects suspicious PowerShell invocation command parameters

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Invocations - Generic
-- Sigma ID:     ed965133-513f-41d9-a441-e38076a0798f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invocation_generic.yml
-- Unmapped:     (none)
-- False Pos:    Very special / sneaky PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -enc %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -EncodedCommand %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ec %'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -w hidden %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -window hidden %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -windowstyle hidden %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -w 1 %'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -noni %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -noninteractive %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Very special / sneaky PowerShell scripts

**References:**
- Internal Research

---

## Suspicious PowerShell Invocations - Specific

| Field | Value |
|---|---|
| **Sigma ID** | `ae7fbf8e-f3cb-49fd-8db4-5f3bed522c71` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems), Jonhnathan Ribeiro |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invocation_specific.yml)**

> Detects suspicious PowerShell invocation command parameters

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Invocations - Specific
-- Sigma ID:     ae7fbf8e-f3cb-49fd-8db4-5f3bed522c71
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems), Jonhnathan Ribeiro
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invocation_specific.yml
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
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research
- https://github.com/HackTricks-wiki/hacktricks/blob/e4c7b21b8f36c97c35b7c622732b38a189ce18f7/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md

---

## Change User Agents with WebRequest

| Field | Value |
|---|---|
| **Sigma ID** | `d4488827-73af-4f8d-9244-7b7662ef046e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invoke_webrequest_useragent.yml)**

> Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.


```sql
-- ============================================================
-- Title:        Change User Agents with WebRequest
-- Sigma ID:     d4488827-73af-4f8d-9244-7b7662ef046e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       frack113
-- Date:         2022-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invoke_webrequest_useragent.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-UserAgent %')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WebRequest%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-RestMethod%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% irm %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%iwr %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1071.001/T1071.001.md#t1071001---web-protocols

---

## Suspicious IO.FileStream

| Field | Value |
|---|---|
| **Sigma ID** | `70ad982f-67c8-40e0-a955-b920c2fa05cb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_iofilestream.yml)**

> Open a handle on the drive volume via the \\.\ DOS device path specifier and perform direct access read of the first few bytes of the volume.

```sql
-- ============================================================
-- Title:        Suspicious IO.FileStream
-- Sigma ID:     70ad982f-67c8-40e0-a955-b920c2fa05cb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.003
-- Author:       frack113
-- Date:         2022-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_iofilestream.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%IO.FileStream%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\\\\\\\.\\\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1006/T1006.md

---

## Potential Keylogger Activity

| Field | Value |
|---|---|
| **Sigma ID** | `965e2db9-eddb-4cf6-a986-7a967df651e4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1056.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_keylogger_activity.yml)**

> Detects PowerShell scripts that contains reference to keystroke capturing functions

```sql
-- ============================================================
-- Title:        Potential Keylogger Activity
-- Sigma ID:     965e2db9-eddb-4cf6-a986-7a967df651e4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1056.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_keylogger_activity.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/ScumBots/status/1610626724257046529
- https://www.virustotal.com/gui/file/d4486b63512755316625230e0c9c81655093be93876e0d80732e7eeaf7d83476/content
- https://www.virustotal.com/gui/file/720a7ee9f2178c70501d7e3f4bcc28a4f456e200486dbd401b25af6da3b4da62/content
- https://learn.microsoft.com/en-us/dotnet/api/system.windows.input.keyboard.iskeydown?view=windowsdesktop-7.0

---

## Potential Suspicious PowerShell Keywords

| Field | Value |
|---|---|
| **Sigma ID** | `1f49f2ab-26bc-48b3-96cc-dcffbc93eadf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems), Perez Diego (@darkquassar), Tuan Le (NCSGroup) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_keywords.yml)**

> Detects potentially suspicious keywords that could indicate the use of a PowerShell exploitation framework

```sql
-- ============================================================
-- Title:        Potential Suspicious PowerShell Keywords
-- Sigma ID:     1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems), Perez Diego (@darkquassar), Tuan Le (NCSGroup)
-- Date:         2019-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_keywords.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Reflection.Assembly.Load($%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Reflection.Assembly]::Load($%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Reflection.Assembly]::Load($%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Reflection.AssemblyName%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Reflection.Emit.AssemblyBuilderAccess%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Reflection.Emit.CustomAttributeBuilder%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Runtime.InteropServices.UnmanagedType%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Runtime.InteropServices.DllImportAttribute%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SuspendThread%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rundll32%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
- https://github.com/PowerShellMafia/PowerSploit/blob/d943001a7defb5e0d1657085a77a0e78609be58f/CodeExecution/Invoke-ReflectivePEInjection.ps1
- https://github.com/hlldz/Phant0m/blob/30c2935d8cf4aafda17ee2fab7cd0c4aa9a607c2/old/Invoke-Phant0m.ps1
- https://gist.github.com/MHaggis/0dbe00ad401daa7137c81c99c268cfb7

---

## Suspicious Get Local Groups Information - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `fa6a5a45-3ee2-4529-aa14-ee5edc9e29cb` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_local_group_reco.yml)**

> Detects the use of PowerShell modules and cmdlets to gather local group information.
Adversaries may use local system permission groups to determine which groups exist and which users belong to a particular group such as the local administrators group.


```sql
-- ============================================================
-- Title:        Suspicious Get Local Groups Information - PowerShell
-- Sigma ID:     fa6a5a45-3ee2-4529-aa14-ee5edc9e29cb
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       frack113
-- Date:         2021-12-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_local_group_reco.yml
-- Unmapped:     (none)
-- False Pos:    Inventory scripts or admin tasks
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-localgroup %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-localgroupmember %'))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%win32\_group%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-wmiobject %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gwmi %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-ciminstance %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gcim %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Inventory scripts or admin tasks

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md

---

## Powershell Local Email Collection

| Field | Value |
|---|---|
| **Sigma ID** | `2837e152-93c8-43d2-85ba-c3cd3c2ae614` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1114.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mail_acces.yml)**

> Adversaries may target user email on local systems to collect sensitive information.
Files containing email data can be acquired from a users local system, such as Outlook storage or cache files.


```sql
-- ============================================================
-- Title:        Powershell Local Email Collection
-- Sigma ID:     2837e152-93c8-43d2-85ba-c3cd3c2ae614
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1114.001
-- Author:       frack113
-- Date:         2021-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mail_acces.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Inbox.ps1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Microsoft.Office.Interop.Outlook%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Microsoft.Office.Interop.Outlook.olDefaultFolders%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-comobject outlook.application%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1114.001/T1114.001.md

---

## Suspicious Mount-DiskImage

| Field | Value |
|---|---|
| **Sigma ID** | `29e1c216-6408-489d-8a06-ee9d151ef819` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1553.005 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mount_diskimage.yml)**

> Adversaries may abuse container files such as disk image (.iso, .vhd) file formats to deliver malicious payloads that may not be tagged with MOTW.

```sql
-- ============================================================
-- Title:        Suspicious Mount-DiskImage
-- Sigma ID:     29e1c216-6408-489d-8a06-ee9d151ef819
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1553.005
-- Author:       frack113
-- Date:         2022-02-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mount_diskimage.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Mount-DiskImage %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ImagePath %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.005/T1553.005.md#atomic-test-1---mount-iso-image
- https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage?view=windowsserver2022-ps

---

## PowerShell Deleted Mounted Share

| Field | Value |
|---|---|
| **Sigma ID** | `66a4d409-451b-4151-94f4-a55d559c49b0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.005 |
| **Author** | oscd.community, @redcanary, Zach Stanford @svch0st |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mounted_share_deletion.yml)**

> Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation

```sql
-- ============================================================
-- Title:        PowerShell Deleted Mounted Share
-- Sigma ID:     66a4d409-451b-4151-94f4-a55d559c49b0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.005
-- Author:       oscd.community, @redcanary, Zach Stanford @svch0st
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mounted_share_deletion.yml
-- Unmapped:     (none)
-- False Pos:    Administrators or Power users may remove their shares via cmd line
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-SmbShare%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-FileShare%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators or Power users may remove their shares via cmd line

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md

---

## Suspicious Connection to Remote Account

| Field | Value |
|---|---|
| **Sigma ID** | `1883444f-084b-419b-ac62-e0d0c5b3693f` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1110.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_networkcredential.yml)**

> Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.
Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism


```sql
-- ============================================================
-- Title:        Suspicious Connection to Remote Account
-- Sigma ID:     1883444f-084b-419b-ac62-e0d0c5b3693f
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1110.001
-- Author:       frack113
-- Date:         2021-12-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_networkcredential.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.DirectoryServices.Protocols.LdapDirectoryIdentifier%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Net.NetworkCredential%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.DirectoryServices.Protocols.LdapConnection%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1110.001/T1110.001.md#atomic-test-2---brute-force-credentials-of-single-active-directory-domain-user-via-ldap-against-domain-controller-ntlm-or-kerberos

---

## Suspicious New-PSDrive to Admin Share

| Field | Value |
|---|---|
| **Sigma ID** | `1c563233-030e-4a07-af8c-ee0490a66d3a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_new_psdrive.yml)**

> Adversaries may use to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

```sql
-- ============================================================
-- Title:        Suspicious New-PSDrive to Admin Share
-- Sigma ID:     1c563233-030e-4a07-af8c-ee0490a66d3a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.002
-- Author:       frack113
-- Date:         2022-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_new_psdrive.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-PSDrive%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-psprovider %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%filesystem%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-root %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%\\\\\\\\%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.002/T1021.002.md#atomic-test-2---map-admin-share-powershell
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.2

---

## Suspicious TCP Tunnel Via PowerShell Script

| Field | Value |
|---|---|
| **Sigma ID** | `bd33d2aa-497e-4651-9893-5c5364646595` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1090 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_proxy_scripts.yml)**

> Detects powershell scripts that creates sockets/listeners which could be indicative of tunneling activity

```sql
-- ============================================================
-- Title:        Suspicious TCP Tunnel Via PowerShell Script
-- Sigma ID:     bd33d2aa-497e-4651-9893-5c5364646595
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1090
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_proxy_scripts.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Net.HttpWebRequest]%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Net.Sockets.TcpListener%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%AcceptTcpClient%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Arno0x/PowerShellScripts/blob/a6b7d5490fbf0b20f91195838f3a11156724b4f7/proxyTunnel.ps1

---

## Recon Information for Export with PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `a9723fcc-881c-424c-8709-fd61442ab3c3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1119 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_recon_export.yml)**

> Once established within a system or network, an adversary may use automated techniques for collecting internal data

```sql
-- ============================================================
-- Title:        Recon Information for Export with PowerShell
-- Sigma ID:     a9723fcc-881c-424c-8709-fd61442ab3c3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1119
-- Author:       frack113
-- Date:         2021-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_recon_export.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Service %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ChildItem %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-Process %'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%> $env:TEMP\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md

---

## Remove Account From Domain Admin Group

| Field | Value |
|---|---|
| **Sigma ID** | `48a45d45-8112-416b-8a67-46e03a4b2107` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_remove_adgroupmember.yml)**

> Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.


```sql
-- ============================================================
-- Title:        Remove Account From Domain Admin Group
-- Sigma ID:     48a45d45-8112-416b-8a67-46e03a4b2107
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       frack113
-- Date:         2021-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_remove_adgroupmember.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-ADGroupMember%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Identity %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Members %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1531/T1531.md#atomic-test-3---remove-account-from-domain-admin-group

---

## Suspicious Service DACL Modification Via Set-Service Cmdlet - PS

| Field | Value |
|---|---|
| **Sigma ID** | `22d80745-6f2c-46da-826b-77adaededd74` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.011 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_service_dacl_modification_set_service.yml)**

> Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)

```sql
-- ============================================================
-- Title:        Suspicious Service DACL Modification Via Set-Service Cmdlet - PS
-- Sigma ID:     22d80745-6f2c-46da-826b-77adaededd74
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.011
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_service_dacl_modification_set_service.yml
-- Unmapped:     (none)
-- False Pos:    Rare intended use of hidden services; Rare FP could occur due to the non linearity of the ScriptBlockText log
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-SecurityDescriptorSddl %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-sd %'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Service %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%D;;%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%;;;IU%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%;;;SU%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%;;;BA%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%;;;SY%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%;;;WD%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare intended use of hidden services; Rare FP could occur due to the non linearity of the ScriptBlockText log

**References:**
- https://twitter.com/Alh4zr3d/status/1580925761996828672
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.2

---

## Potential PowerShell Obfuscation Using Alias Cmdlets

| Field | Value |
|---|---|
| **Sigma ID** | `96cd126d-f970-49c4-848a-da3a09f55c55` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_set_alias.yml)**

> Detects Set-Alias or New-Alias cmdlet usage. Which can be use as a mean to obfuscate PowerShell scripts

```sql
-- ============================================================
-- Title:        Potential PowerShell Obfuscation Using Alias Cmdlets
-- Sigma ID:     96cd126d-f970-49c4-848a-da3a09f55c55
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       frack113
-- Date:         2023-01-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_set_alias.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Alias %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Alias %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/1337Rin/Swag-PSO

---

## Suspicious Get Information for SMB Share

| Field | Value |
|---|---|
| **Sigma ID** | `95f0643a-ed40-467c-806b-aac9542ec5ab` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_smb_share_reco.yml)**

> Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as
a precursor for Collection and to identify potential systems of interest for Lateral Movement.
Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.


```sql
-- ============================================================
-- Title:        Suspicious Get Information for SMB Share
-- Sigma ID:     95f0643a-ed40-467c-806b-aac9542ec5ab
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       frack113
-- Date:         2021-12-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_smb_share_reco.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%get-smbshare%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md

---

## Suspicious SSL Connection

| Field | Value |
|---|---|
| **Sigma ID** | `195626f3-5f1b-4403-93b7-e6cfd4d6a078` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1573 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_ssl_keyword.yml)**

> Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

```sql
-- ============================================================
-- Title:        Suspicious SSL Connection
-- Sigma ID:     195626f3-5f1b-4403-93b7-e6cfd4d6a078
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1573
-- Author:       frack113
-- Date:         2022-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_ssl_keyword.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Net.Security.SslStream%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Net.Security.RemoteCertificateValidationCallback%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.AuthenticateAsClient%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1573/T1573.md#atomic-test-1---openssl-c2
- https://medium.com/walmartglobaltech/openssl-server-reverse-shell-from-windows-client-aee2dbfa0926

---

## Suspicious Start-Process PassThru

| Field | Value |
|---|---|
| **Sigma ID** | `0718cd72-f316-4aa2-988f-838ea8533277` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_start_process.yml)**

> Powershell use PassThru option to start in background

```sql
-- ============================================================
-- Title:        Suspicious Start-Process PassThru
-- Sigma ID:     0718cd72-f316-4aa2-988f-838ea8533277
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.003
-- Author:       frack113
-- Date:         2022-01-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_start_process.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-Process%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-PassThru %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-FilePath %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.003/T1036.003.md
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Start-Process?view=powershell-5.1&viewFallbackFrom=powershell-7

---

## Suspicious Unblock-File

| Field | Value |
|---|---|
| **Sigma ID** | `5947497f-1aa4-41dd-9693-c9848d58727d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1553.005 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_unblock_file.yml)**

> Remove the Zone.Identifier alternate data stream which identifies the file as downloaded from the internet.

```sql
-- ============================================================
-- Title:        Suspicious Unblock-File
-- Sigma ID:     5947497f-1aa4-41dd-9693-c9848d58727d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1553.005
-- Author:       frack113
-- Date:         2022-02-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_unblock_file.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Unblock-File %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Path %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.005/T1553.005.md#atomic-test-3---remove-the-zoneidentifier-alternate-data-stream
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-7.2

---

## Replace Desktop Wallpaper by Powershell

| Field | Value |
|---|---|
| **Sigma ID** | `c5ac6a1e-9407-45f5-a0ce-ca9a0806a287` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1491.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_wallpaper.yml)**

> An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users.
This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper


```sql
-- ============================================================
-- Title:        Replace Desktop Wallpaper by Powershell
-- Sigma ID:     c5ac6a1e-9407-45f5-a0ce-ca9a0806a287
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1491.001
-- Author:       frack113
-- Date:         2021-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_wallpaper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ItemProperty%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Registry::%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%HKEY\_CURRENT\_USER\\Control Panel\\Desktop\\%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WallPaper%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SystemParametersInfo(20,0,*,3)%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1491.001/T1491.001.md

---

## Powershell Suspicious Win32_PnPEntity

| Field | Value |
|---|---|
| **Sigma ID** | `b26647de-4feb-4283-af6b-6117661283c5` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1120 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_win32_pnpentity.yml)**

> Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.

```sql
-- ============================================================
-- Title:        Powershell Suspicious Win32_PnPEntity
-- Sigma ID:     b26647de-4feb-4283-af6b-6117661283c5
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1120
-- Author:       frack113
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_win32_pnpentity.yml
-- Unmapped:     (none)
-- False Pos:    Admin script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_PnPEntity%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1120/T1120.md

---

## Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script

| Field | Value |
|---|---|
| **Sigma ID** | `c1337eb8-921a-4b59-855b-4ba188ddcc42` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | Tim Rauch, frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml)**

> Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil

```sql
-- ============================================================
-- Title:        Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script
-- Sigma ID:     c1337eb8-921a-4b59-855b-4ba188ddcc42
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       Tim Rauch, frack113
-- Date:         2022-09-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.Delete()%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-WmiObject%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rwmi%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-CimInstance%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%rcim%'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WmiObject%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gwmi%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-CimInstance%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gcim%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_ShadowCopy%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-5---windows---delete-volume-shadow-copies-via-wmi-with-powershell
- https://www.elastic.co/guide/en/security/current/volume-shadow-copy-deletion-via-powershell.html

---

## Suspicious PowerShell WindowStyle Option

| Field | Value |
|---|---|
| **Sigma ID** | `313fbb0a-a341-4682-848d-6d6f8c4fab7c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.003 |
| **Author** | frack113, Tim Shelton (fp AWS) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_windowstyle.yml)**

> Adversaries may use hidden windows to conceal malicious activity from the plain sight of users.
In some cases, windows that would typically be displayed when an application carries out an operation can be hidden


```sql
-- ============================================================
-- Title:        Suspicious PowerShell WindowStyle Option
-- Sigma ID:     313fbb0a-a341-4682-848d-6d6f8c4fab7c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.003
-- Author:       frack113, Tim Shelton (fp AWS)
-- Date:         2021-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_windowstyle.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%powershell%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WindowStyle%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Hidden%')
  AND NOT (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%:\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%$PSScriptRoot\\Module\\WorkspaceScriptModule\\WorkspaceScriptModule%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.003/T1564.003.md

---

## PowerShell Write-EventLog Usage

| Field | Value |
|---|---|
| **Sigma ID** | `35f41cd7-c98e-469f-8a02-ec4ba0cc7a7e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_write_eventlog.yml)**

> Detects usage of the "Write-EventLog" cmdlet with 'RawData' flag. The cmdlet can be levreage to write malicious payloads to the EventLog and then retrieve them later for later use

```sql
-- ============================================================
-- Title:        PowerShell Write-EventLog Usage
-- Sigma ID:     35f41cd7-c98e-469f-8a02-ec4ba0cc7a7e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_write_eventlog.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications writing events via this cmdlet. Investigate alerts to determine if the action is benign
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Write-EventLog%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-RawData %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications writing events via this cmdlet. Investigate alerts to determine if the action is benign

**References:**
- https://www.blackhillsinfosec.com/windows-event-logs-for-red-teams/

---

## Zip A Folder With PowerShell For Staging In Temp - PowerShell Script

| Field | Value |
|---|---|
| **Sigma ID** | `b7a3c9a3-09ea-4934-8864-6a32cacd98d9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1074.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_zip_compress.yml)**

> Detects PowerShell scripts that make use of the "Compress-Archive" Cmdlet in order to compress folders and files where the output is stored in a potentially suspicious location that is used often by malware for exfiltration.
An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.


```sql
-- ============================================================
-- Title:        Zip A Folder With PowerShell For Staging In Temp - PowerShell Script
-- Sigma ID:     b7a3c9a3-09ea-4934-8864-6a32cacd98d9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1074.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2021-07-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_zip_compress.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Compress-Archive -Path*-DestinationPath $env:TEMP%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Compress-Archive -Path*-DestinationPath*\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Compress-Archive -Path*-DestinationPath*:\\Windows\\Temp\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1074.001/T1074.001.md
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a

---

## SyncAppvPublishingServer Execution to Bypass Powershell Restriction

| Field | Value |
|---|---|
| **Sigma ID** | `dddfebae-c46f-439c-af7a-fdb6bde90218` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218 |
| **Author** | Ensar Şamil, @sblmsrsn, OSCD Community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_syncappvpublishingserver_exe.yml)**

> Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.

```sql
-- ============================================================
-- Title:        SyncAppvPublishingServer Execution to Bypass Powershell Restriction
-- Sigma ID:     dddfebae-c46f-439c-af7a-fdb6bde90218
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218
-- Author:       Ensar Şamil, @sblmsrsn, OSCD Community
-- Date:         2020-10-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_syncappvpublishingserver_exe.yml
-- Unmapped:     (none)
-- False Pos:    App-V clients
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SyncAppvPublishingServer.exe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** App-V clients

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/

---

## Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging

| Field | Value |
|---|---|
| **Sigma ID** | `ae2bdd58-0681-48ac-be7f-58ab4e593458` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_rem_mp.yml)**

> Detects attempts to remove Windows Defender configuration using the 'MpPreference' cmdlet

```sql
-- ============================================================
-- Title:        Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging
-- Sigma ID:     ae2bdd58-0681-48ac-be7f-58ab4e593458
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_rem_mp.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Remove-MpPreference%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ControlledFolderAccessProtectedFolders %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-AttackSurfaceReductionRules\_Ids %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-AttackSurfaceReductionRules\_Actions %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-CheckForSignaturesBeforeRunningScan %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088

---

## Tamper Windows Defender - ScriptBlockLogging

| Field | Value |
|---|---|
| **Sigma ID** | `14c71865-6cd3-44ae-adaa-1db923fae5f2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml)**

> Detects PowerShell scripts attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.

```sql
-- ============================================================
-- Title:        Tamper Windows Defender - ScriptBlockLogging
-- Sigma ID:     14c71865-6cd3-44ae-adaa-1db923fae5f2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dbaf $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dbaf 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dbm $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dbm 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dips $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dips 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableArchiveScanning $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableArchiveScanning 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableBehaviorMonitoring $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableBehaviorMonitoring 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableBlockAtFirstSeen $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableBlockAtFirstSeen 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableCatchupFullScan $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableCatchupFullScan 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableCatchupQuickScan $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableCatchupQuickScan 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableIntrusionPreventionSystem $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableIntrusionPreventionSystem 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableIOAVProtection $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableIOAVProtection 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableRealtimeMonitoring $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableRealtimeMonitoring 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableRemovableDriveScanning $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableRemovableDriveScanning 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableScanningMappedNetworkDrivesForFullScan $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableScanningMappedNetworkDrivesForFullScan 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableScanningNetworkFiles $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableScanningNetworkFiles 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableScriptScanning $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-DisableScriptScanning 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-MAPSReporting $false%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-MAPSReporting 0%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-drdsc $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-drdsc 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-drtm $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-drtm 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dscrptsc $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dscrptsc 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dsmndf $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dsmndf 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dsnf $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dsnf 1%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dss $true%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-dss 1%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-MpPreference%'))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-MpPreference%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%HighThreatDefaultAction Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%htdefac Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%LowThreatDefaultAction Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ltdefac Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ModerateThreatDefaultAction Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%mtdefac Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%SevereThreatDefaultAction Allow%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%stdefac Allow%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
- https://bidouillesecurity.com/disable-windows-defender-in-powershell/

---

## Testing Usage of Uncommonly Used Port

| Field | Value |
|---|---|
| **Sigma ID** | `adf876b3-f1f8-4aa9-a4e4-a64106feec06` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1571 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_test_netconnection.yml)**

> Adversaries may communicate using a protocol and port paring that are typically not associated.
For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443.


```sql
-- ============================================================
-- Title:        Testing Usage of Uncommonly Used Port
-- Sigma ID:     adf876b3-f1f8-4aa9-a4e4-a64106feec06
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1571
-- Author:       frack113
-- Date:         2022-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_test_netconnection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Test-NetConnection%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ComputerName %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-port %')
  AND NOT ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% 443 %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% 80 %'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1571/T1571.md#atomic-test-1---testing-usage-of-uncommonly-used-port-with-powershell
- https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2022-ps

---

## Powershell Timestomp

| Field | Value |
|---|---|
| **Sigma ID** | `c6438007-e081-42ce-9483-b067fbef33c3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml)**

> Adversaries may modify file time attributes to hide new or changes to existing files.
Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder.


```sql
-- ============================================================
-- Title:        Powershell Timestomp
-- Sigma ID:     c6438007-e081-42ce-9483-b067fbef33c3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.006
-- Author:       frack113
-- Date:         2021-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.CreationTime =%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.LastWriteTime =%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.LastAccessTime =%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[IO.File]::SetCreationTime%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[IO.File]::SetLastAccessTime%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[IO.File]::SetLastWriteTime%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.006/T1070.006.md
- https://www.offensive-security.com/metasploit-unleashed/timestomp/

---

## User Discovery And Export Via Get-ADUser Cmdlet - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `c2993223-6da8-4b1a-88ee-668b8bf315e9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_user_discovery_get_aduser.yml)**

> Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file

```sql
-- ============================================================
-- Title:        User Discovery And Export Via Get-ADUser Cmdlet - PowerShell
-- Sigma ID:     c2993223-6da8-4b1a-88ee-668b8bf315e9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_user_discovery_get_aduser.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-ADUser %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Filter \\*%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% > %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% | Select %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Out-File%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Content%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-Content%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often

**References:**
- http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
- https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/

---

## Potential Persistence Via PowerShell User Profile Using Add-Content

| Field | Value |
|---|---|
| **Sigma ID** | `05b3e303-faf0-4f4a-9b30-46cc13e69152` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.013 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_user_profile_tampering.yml)**

> Detects calls to "Add-Content" cmdlet in order to modify the content of the user profile and potentially adding suspicious commands for persistence

```sql
-- ============================================================
-- Title:        Potential Persistence Via PowerShell User Profile Using Add-Content
-- Sigma ID:     05b3e303-faf0-4f4a-9b30-46cc13e69152
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.013
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-08-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_user_profile_tampering.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration and tuning scripts that aim to add functionality to a user PowerShell session
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-Content $profile%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value "IEX %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value "Invoke-Expression%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value "Invoke-WebRequest%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value "Start-Process%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value 'IEX %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value 'Invoke-Expression%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value 'Invoke-WebRequest%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Value 'Start-Process%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration and tuning scripts that aim to add functionality to a user PowerShell session

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.013/T1546.013.md

---

## Abuse of Service Permissions to Hide Services Via Set-Service - PS

| Field | Value |
|---|---|
| **Sigma ID** | `953945c5-22fe-4a92-9f8a-a9edc1e522da` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.011 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_using_set_service_to_hide_services.yml)**

> Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)

```sql
-- ============================================================
-- Title:        Abuse of Service Permissions to Hide Services Via Set-Service - PS
-- Sigma ID:     953945c5-22fe-4a92-9f8a-a9edc1e522da
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.011
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_using_set_service_to_hide_services.yml
-- Unmapped:     (none)
-- False Pos:    Rare intended use of hidden services; Rare FP could occur due to the non linearity of the ScriptBlockText log
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-Service %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DCLCWPDTSD%')
    AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-SecurityDescriptorSddl %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-sd %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare intended use of hidden services; Rare FP could occur due to the non linearity of the ScriptBlockText log

**References:**
- https://twitter.com/Alh4zr3d/status/1580925761996828672
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.2

---

## Registry Modification Attempt Via VBScript - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `2a0a169d-cc66-43ce-9ae2-6e678e54e46a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1112, T1059.005 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_vbscript_registry_modification.yml)**

> Detects attempts to modify the registry using VBScript's CreateObject("Wscript.shell") and RegWrite methods embedded within PowerShell scripts or commands.
Threat actors commonly embed VBScript code within PowerShell to perform registry modifications, attempting to evade detection that monitors for direct registry access through traditional tools.
This technique can be used for persistence, defense evasion, and privilege escalation by modifying registry keys without using regedit.exe, reg.exe, or PowerShell's native registry cmdlets.


```sql
-- ============================================================
-- Title:        Registry Modification Attempt Via VBScript - PowerShell
-- Sigma ID:     2a0a169d-cc66-43ce-9ae2-6e678e54e46a
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence, execution | T1112, T1059.005
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_vbscript_registry_modification.yml
-- Unmapped:     (none)
-- False Pos:    Some legitimate admin or install scripts may use these processes for registry modifications.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%CreateObject%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Wscript.shell%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.RegWrite%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some legitimate admin or install scripts may use these processes for registry modifications.

**References:**
- https://www.linkedin.com/posts/mauricefielenbach_livingofftheland-redteam-persistence-activity-7344801774182051843-TE00/
- https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/
- https://detect.fyi/hunting-fileless-malware-in-the-windows-registry-1339ccde00ad

---

## Veeam Backup Servers Credential Dumping Script Execution

| Field | Value |
|---|---|
| **Sigma ID** | `976d6e6f-a04b-4900-9713-0134a353e38b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_veeam_credential_dumping_script.yml)**

> Detects execution of a PowerShell script that contains calls to the "Veeam.Backup" class, in order to dump stored credentials.

```sql
-- ============================================================
-- Title:        Veeam Backup Servers Credential Dumping Script Execution
-- Sigma ID:     976d6e6f-a04b-4900-9713-0134a353e38b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_veeam_credential_dumping_script.yml
-- Unmapped:     (none)
-- False Pos:    Administrators backup scripts (must be investigated)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Credentials]%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[Veeam.Backup.Common.ProtectedStorage]::GetLocalString%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Sqlcmd%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Veeam Backup and Replication%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators backup scripts (must be investigated)

**References:**
- https://www.pwndefend.com/2021/02/15/retrieving-passwords-from-veeam-backup-servers/
- https://labs.withsecure.com/publications/fin7-target-veeam-servers

---

## Usage Of Web Request Commands And Cmdlets - ScriptBlock

| Field | Value |
|---|---|
| **Sigma ID** | `1139d2e2-84b1-4226-b445-354492eba8ba` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | James Pemberton / @4A616D6573 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_web_request_cmd_and_cmdlets.yml)**

> Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via PowerShell scriptblock logs

```sql
-- ============================================================
-- Title:        Usage Of Web Request Commands And Cmdlets - ScriptBlock
-- Sigma ID:     1139d2e2-84b1-4226-b445-354492eba8ba
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       James Pemberton / @4A616D6573
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_web_request_cmd_and_cmdlets.yml
-- Unmapped:     Path
-- False Pos:    Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.
-- ============================================================
-- UNMAPPED_FIELD: Path

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%[System.Net.WebRequest]::create%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%curl %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-RestMethod%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-WebRequest%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% irm %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%iwr %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Resume-BitsTransfer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Start-BitsTransfer%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%wget %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WinHttp.WinHttpRequest%'))
  AND NOT (rawEventMsg LIKE 'C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.

**References:**
- https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
- https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell

---

## Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript

| Field | Value |
|---|---|
| **Sigma ID** | `e2812b49-bae0-4b21-b366-7c142eafcde2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win32_nteventlogfile_usage.yml)**

> Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script

```sql
-- ============================================================
-- Title:        Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript
-- Sigma ID:     e2812b49-bae0-4b21-b366-7c142eafcde2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win32_nteventlogfile_usage.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration and backup scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_NTEventlogFile%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.BackupEventlog(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.ChangeSecurityPermissions(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.ChangeSecurityPermissionsEx(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.ClearEventLog(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.Delete(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.DeleteEx(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.Rename(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.TakeOwnerShip(%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.TakeOwnerShipEx(%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration and backup scripts

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394225(v=vs.85)

---

## PowerShell WMI Win32_Product Install MSI

| Field | Value |
|---|---|
| **Sigma ID** | `91109523-17f0-4248-a800-f81d9e7c081d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218.007 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win32_product_install_msi.yml)**

> Detects the execution of an MSI file using PowerShell and the WMI Win32_Product class

```sql
-- ============================================================
-- Title:        PowerShell WMI Win32_Product Install MSI
-- Sigma ID:     91109523-17f0-4248-a800-f81d9e7c081d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218.007
-- Author:       frack113
-- Date:         2022-04-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win32_product_install_msi.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-CimMethod %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ClassName %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Win32\_Product %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-MethodName %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.msi%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md

---

## Potential WinAPI Calls Via PowerShell Scripts

| Field | Value |
|---|---|
| **Sigma ID** | `03d83090-8cba-44a0-b02f-0b756a050306` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1106 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win_api_susp_access.yml)**

> Detects use of WinAPI functions in PowerShell scripts

```sql
-- ============================================================
-- Title:        Potential WinAPI Calls Via PowerShell Scripts
-- Sigma ID:     03d83090-8cba-44a0-b02f-0b756a050306
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001, T1106
-- Author:       Nasreddine Bencherchali (Nextron Systems), Nikita Nazarov, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win_api_susp_access.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%OpenProcessToken%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DuplicateTokenEx%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%CloseHandle%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%VirtualAlloc%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%OpenProcess%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WriteProcessMemory%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%CreateRemoteThread%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WriteProcessMemory%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%VirtualAlloc%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ReadProcessMemory%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%VirtualFree%')
  OR indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%OpenProcessToken%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%LookupPrivilegeValue%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%AdjustTokenPrivileges%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

---

## Windows Defender Exclusions Added - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `c1344fa2-323b-4d2e-9176-84b4d4821c88` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1562, T1059 |
| **Author** | Tim Rauch, Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win_defender_exclusions_added.yml)**

> Detects modifications to the Windows Defender configuration settings using PowerShell to add exclusions

```sql
-- ============================================================
-- Title:        Windows Defender Exclusions Added - PowerShell
-- Sigma ID:     c1344fa2-323b-4d2e-9176-84b4d4821c88
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1562, T1059
-- Author:       Tim Rauch, Elastic (idea)
-- Date:         2022-09-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_win_defender_exclusions_added.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ExclusionPath %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ExclusionExtension %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ExclusionProcess %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -ExclusionIpAddress %'))
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Add-MpPreference %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-MpPreference %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.elastic.co/guide/en/security/current/windows-defender-exclusions-added-via-powershell.html

---

## Windows Firewall Profile Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `488b44e7-3781-4a71-888d-c95abfacf44d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_windows_firewall_profile_disabled.yml)**

> Detects when a user disables the Windows Firewall via a Profile to help evade defense.

```sql
-- ============================================================
-- Title:        Windows Firewall Profile Disabled
-- Sigma ID:     488b44e7-3781-4a71-888d-c95abfacf44d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Austin Songer @austinsonger
-- Date:         2021-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_windows_firewall_profile_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-NetFirewallProfile %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -Enabled %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% False%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% -All %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Public%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Domain%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Private%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2022-ps
- https://www.tutorialspoint.com/how-to-get-windows-firewall-profile-settings-using-powershell
- https://web.archive.org/web/20230929023836/http://powershellhelp.space/commands/set-netfirewallrule-psv5.php
- http://woshub.com/manage-windows-firewall-powershell/
- https://www.elastic.co/guide/en/security/current/windows-firewall-disabled-via-powershell.html

---

## Winlogon Helper DLL

| Field | Value |
|---|---|
| **Sigma ID** | `851c506b-6b7c-4ce2-8802-c703009d03c0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.004 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_winlogon_helper_dll.yml)**

> Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.
Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are
used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to
load and execute malicious DLLs and/or executables.


```sql
-- ============================================================
-- Title:        Winlogon Helper DLL
-- Sigma ID:     851c506b-6b7c-4ce2-8802-c703009d03c0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.004
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2019-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_winlogon_helper_dll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%CurrentVersion\\Winlogon%')
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Set-ItemProperty%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Item%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.004/T1547.004.md

---

## Powershell WMI Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `9e07f6e7-83aa-45c6-998e-0af26efd0a85` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmi_persistence.yml)**

> Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.

```sql
-- ============================================================
-- Title:        Powershell WMI Persistence
-- Sigma ID:     9e07f6e7-83aa-45c6-998e-0af26efd0a85
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       frack113
-- Date:         2021-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmi_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-CimInstance %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Namespace root/subscription %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ClassName \_\_EventFilter %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Property %'))
  OR (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-CimInstance %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Namespace root/subscription %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-ClassName CommandLineEventConsumer %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%-Property %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.003/T1546.003.md
- https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/data/module_source/persistence/Persistence.psm1#L545

---

## WMIC Unquoted Services Path Lookup - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `09658312-bc27-4a3b-91c5-e49ab9046d1b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmi_unquoted_service_search.yml)**

> Detects known WMI recon method to look for unquoted service paths, often used by pentest inside of powershell scripts attackers enum scripts

```sql
-- ============================================================
-- Title:        WMIC Unquoted Services Path Lookup - PowerShell
-- Sigma ID:     09658312-bc27-4a3b-91c5-e49ab9046d1b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1047
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmi_unquoted_service_search.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Get-WmiObject %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%gwmi %'))
    AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% Win32\_Service %' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Name%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%DisplayName%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%PathName%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%StartMode%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nccgroup/redsnarf/blob/35949b30106ae543dc6f2bc3f1be10c6d9a8d40e/redsnarf.py
- https://github.com/S3cur3Th1sSh1t/Creds/blob/eac23d67f7f90c7fc8e3130587d86158c22aa398/PowershellScripts/jaws-enum.ps1
- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

---

## WMImplant Hack Tool

| Field | Value |
|---|---|
| **Sigma ID** | `8028c2c3-e25a-46e3-827f-bbb5abf181d7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047, T1059.001 |
| **Author** | NVISO |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmimplant.yml)**

> Detects parameters used by WMImplant

```sql
-- ============================================================
-- Title:        WMImplant Hack Tool
-- Sigma ID:     8028c2c3-e25a-46e3-827f-bbb5abf181d7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1047, T1059.001
-- Author:       NVISO
-- Date:         2020-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_wmimplant.yml
-- Unmapped:     (none)
-- False Pos:    Administrative scripts that use the same keywords.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%WMImplant%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% change\_user %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% gen\_cli %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% command\_exec %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% disable\_wdigest %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% disable\_winrm %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% enable\_wdigest %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% enable\_winrm %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% registry\_mod %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% remote\_posh %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% sched\_job %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% service\_mod %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% process\_kill %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% active\_users %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% basic\_info %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% power\_off %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% vacant\_system %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '% logon\_events %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts that use the same keywords.

**References:**
- https://github.com/FortyNorthSecurity/WMImplant

---

## Suspicious X509Enrollment - Ps Script

| Field | Value |
|---|---|
| **Sigma ID** | `504d63cb-0dba-4d02-8531-e72981aace2c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1553.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_x509enrollment.yml)**

> Detect use of X509Enrollment

```sql
-- ============================================================
-- Title:        Suspicious X509Enrollment - Ps Script
-- Sigma ID:     504d63cb-0dba-4d02-8531-e72981aace2c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1553.004
-- Author:       frack113
-- Date:         2022-12-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_x509enrollment.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%X509Enrollment.CBinaryConverter%' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%884e2002-217d-11da-b2a4-000e7bbb2b09%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=42
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=41
- https://learn.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.cx509enrollmentwebclassfactoryclass?view=hpc-sdk-5.1.6115

---

## Powershell XML Execute Command

| Field | Value |
|---|---|
| **Sigma ID** | `6c6c6282-7671-4fe9-a0ce-a2dcebdc342b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_xml_iex.yml)**

> Adversaries may abuse PowerShell commands and scripts for execution.
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell)
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code


```sql
-- ============================================================
-- Title:        Powershell XML Execute Command
-- Sigma ID:     6c6c6282-7671-4fe9-a0ce-a2dcebdc342b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       frack113
-- Date:         2022-01-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_xml_iex.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'script')] AS scriptBlockText,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%IEX %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Expression %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%Invoke-Command %' OR metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%ICM -%'))
  AND indexOf(metrics_string.name, 'script') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%New-Object%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%System.Xml.XmlDocument%' AND metrics_string.value[indexOf(metrics_string.name,'script')] LIKE '%.Load%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-8---powershell-xml-requests

---
