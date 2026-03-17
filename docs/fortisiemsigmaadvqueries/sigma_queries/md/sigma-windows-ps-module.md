# Sigma → FortiSIEM: Windows Ps Module

> 33 rules · Generated 2026-03-17

## Table of Contents

- [Potential Active Directory Enumeration Using AD Module - PsModule](#potential-active-directory-enumeration-using-ad-module-psmodule)
- [Alternate PowerShell Hosts - PowerShell Module](#alternate-powershell-hosts-powershell-module)
- [Bad Opsec Powershell Code Artifacts](#bad-opsec-powershell-code-artifacts)
- [Clear PowerShell History - PowerShell Module](#clear-powershell-history-powershell-module)
- [PowerShell Decompress Commands](#powershell-decompress-commands)
- [Malicious PowerShell Scripts - PoshModule](#malicious-powershell-scripts-poshmodule)
- [Suspicious Get-ADDBAccount Usage](#suspicious-get-addbaccount-usage)
- [PowerShell Get Clipboard](#powershell-get-clipboard)
- [HackTool - Evil-WinRm Execution - PowerShell Module](#hacktool-evil-winrm-execution-powershell-module)
- [Invoke-Obfuscation CLIP+ Launcher - PowerShell Module](#invoke-obfuscation-clip-launcher-powershell-module)
- [Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module](#invoke-obfuscation-obfuscated-iex-invocation-powershell-module)
- [Invoke-Obfuscation STDIN+ Launcher - PowerShell Module](#invoke-obfuscation-stdin-launcher-powershell-module)
- [Invoke-Obfuscation VAR+ Launcher - PowerShell Module](#invoke-obfuscation-var-launcher-powershell-module)
- [Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module](#invoke-obfuscation-compress-obfuscation-powershell-module)
- [Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module](#invoke-obfuscation-rundll-launcher-powershell-module)
- [Invoke-Obfuscation Via Stdin - PowerShell Module](#invoke-obfuscation-via-stdin-powershell-module)
- [Invoke-Obfuscation Via Use Clip - PowerShell Module](#invoke-obfuscation-via-use-clip-powershell-module)
- [Invoke-Obfuscation Via Use MSHTA - PowerShell Module](#invoke-obfuscation-via-use-mshta-powershell-module)
- [Invoke-Obfuscation Via Use Rundll32 - PowerShell Module](#invoke-obfuscation-via-use-rundll32-powershell-module)
- [Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module](#invoke-obfuscation-var-launcher-obfuscation-powershell-module)
- [Malicious PowerShell Commandlets - PoshModule](#malicious-powershell-commandlets-poshmodule)
- [Remote PowerShell Session (PS Module)](#remote-powershell-session-ps-module)
- [Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module](#potential-remotefxvgpudisablementexe-abuse-powershell-module)
- [AD Groups Or Users Enumeration Using PowerShell - PoshModule](#ad-groups-or-users-enumeration-using-powershell-poshmodule)
- [Suspicious PowerShell Download - PoshModule](#suspicious-powershell-download-poshmodule)
- [Use Get-NetTCPConnection - PowerShell Module](#use-get-nettcpconnection-powershell-module)
- [Suspicious PowerShell Invocations - Generic - PowerShell Module](#suspicious-powershell-invocations-generic-powershell-module)
- [Suspicious PowerShell Invocations - Specific - PowerShell Module](#suspicious-powershell-invocations-specific-powershell-module)
- [Suspicious Get Local Groups Information](#suspicious-get-local-groups-information)
- [Suspicious Computer Machine Password by PowerShell](#suspicious-computer-machine-password-by-powershell)
- [Suspicious Get Information for SMB Share - PowerShell Module](#suspicious-get-information-for-smb-share-powershell-module)
- [Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module](#zip-a-folder-with-powershell-for-staging-in-temp-powershell-module)
- [SyncAppvPublishingServer Bypass Powershell Restriction - PS Module](#syncappvpublishingserver-bypass-powershell-restriction-ps-module)

## Potential Active Directory Enumeration Using AD Module - PsModule

| Field | Value |
|---|---|
| **Sigma ID** | `74176142-4684-4d8a-8b0a-713257e7df8e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance, discovery, impact |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_active_directory_module_dll_import.yml)**

> Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.

```sql
-- ============================================================
-- Title:        Potential Active Directory Enumeration Using AD Module - PsModule
-- Sigma ID:     74176142-4684-4d8a-8b0a-713257e7df8e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance, discovery, impact
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2023-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_active_directory_module_dll_import.yml
-- Unmapped:     Payload
-- False Pos:    Legitimate use of the library for administrative activity
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%Import-Module %' OR rawEventMsg LIKE '%ipmo %')
  AND rawEventMsg LIKE '%Microsoft.ActiveDirectory.Management.dll%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the library for administrative activity

**References:**
- https://github.com/samratashok/ADModule
- https://twitter.com/cyb3rops/status/1617108657166061568?s=20
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges

---

## Alternate PowerShell Hosts - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `64e8e417-c19a-475a-8d19-98ea705394cc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_alternate_powershell_hosts.yml)**

> Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe

```sql
-- ============================================================
-- Title:        Alternate PowerShell Hosts - PowerShell Module
-- Sigma ID:     64e8e417-c19a-475a-8d19-98ea705394cc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_alternate_powershell_hosts.yml
-- Unmapped:     ContextInfo
-- False Pos:    Programs using PowerShell directly without invocation of a dedicated interpreter; MSP Detection Searcher; Citrix ConfigSync.ps1
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%*%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Programs using PowerShell directly without invocation of a dedicated interpreter; MSP Detection Searcher; Citrix ConfigSync.ps1

**References:**
- https://threathunterplaybook.com/hunts/windows/190610-PwshAlternateHosts/notebook.html

---

## Bad Opsec Powershell Code Artifacts

| Field | Value |
|---|---|
| **Sigma ID** | `8d31a8ce-46b5-4dd6-bdc3-680931f1db86` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | ok @securonix invrep_de, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_bad_opsec_artifacts.yml)**

> focuses on trivial artifacts observed in variants of prevalent offensive ps1 payloads, including
Cobalt Strike Beacon, PoshC2, Powerview, Letmein, Empire, Powersploit, and other attack payloads
that often undergo minimal changes by attackers due to bad opsec.


```sql
-- ============================================================
-- Title:        Bad Opsec Powershell Code Artifacts
-- Sigma ID:     8d31a8ce-46b5-4dd6-bdc3-680931f1db86
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       ok @securonix invrep_de, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_bad_opsec_artifacts.yml
-- Unmapped:     Payload
-- False Pos:    Moderate-to-low; Despite the shorter length/lower entropy for some of these, because of high specificity, fp appears to be fairly limited in many environments.
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%$DoIt%' OR rawEventMsg LIKE '%harmj0y%' OR rawEventMsg LIKE '%mattifestation%' OR rawEventMsg LIKE '%\_RastaMouse%' OR rawEventMsg LIKE '%tifkin\_%' OR rawEventMsg LIKE '%0xdeadbeef%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Moderate-to-low; Despite the shorter length/lower entropy for some of these, because of high specificity, fp appears to be fairly limited in many environments.

**References:**
- https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/
- https://labs.sentinelone.com/top-tier-russian-organized-cybercrime-group-unveils-fileless-stealthy-powertrick-backdoor-for-high-value-targets/
- https://www.mdeditor.tw/pl/pgRt

---

## Clear PowerShell History - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `f99276ad-d122-4989-a09a-d00904a5f9d2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.003 |
| **Author** | Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_clear_powershell_history.yml)**

> Detects keywords that could indicate clearing PowerShell history

```sql
-- ============================================================
-- Title:        Clear PowerShell History - PowerShell Module
-- Sigma ID:     f99276ad-d122-4989-a09a-d00904a5f9d2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.003
-- Author:       Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_clear_powershell_history.yml
-- Unmapped:     Payload
-- False Pos:    Legitimate PowerShell scripts
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Set-PSReadlineOption%' AND rawEventMsg LIKE '%–HistorySaveStyle%' AND rawEventMsg LIKE '%SaveNothing%'
  OR rawEventMsg LIKE '%Set-PSReadlineOption%' AND rawEventMsg LIKE '%-HistorySaveStyle%' AND rawEventMsg LIKE '%SaveNothing%'
  OR ((rawEventMsg LIKE '%del%' OR rawEventMsg LIKE '%Remove-Item%' OR rawEventMsg LIKE '%rm%')
  AND rawEventMsg LIKE '%(Get-PSReadlineOption).HistorySavePath%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts

**References:**
- https://gist.github.com/hook-s3c/7363a856c3cdbadeb71085147f042c1a

---

## PowerShell Decompress Commands

| Field | Value |
|---|---|
| **Sigma ID** | `1ddc1472-8e52-4f7d-9f11-eab14fc171f5` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1140 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_decompress_commands.yml)**

> A General detection for specific decompress commands in PowerShell logs. This could be an adversary decompressing files.

```sql
-- ============================================================
-- Title:        PowerShell Decompress Commands
-- Sigma ID:     1ddc1472-8e52-4f7d-9f11-eab14fc171f5
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1140
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_decompress_commands.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Expand-Archive%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/8
- https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/4.A.3_09F29912-8E93-461E-9E89-3F06F6763383.md

---

## Malicious PowerShell Scripts - PoshModule

| Field | Value |
|---|---|
| **Sigma ID** | `41025fd7-0466-4650-a813-574aaacbe7f4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_exploit_scripts.yml)**

> Detects the execution of known offensive powershell scripts used for exploitation or reconnaissance

```sql
-- ============================================================
-- Title:        Malicious PowerShell Scripts - PoshModule
-- Sigma ID:     41025fd7-0466-4650-a813-574aaacbe7f4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_exploit_scripts.yml
-- Unmapped:     ContextInfo
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Add-ConstrainedDelegationBackdoor.ps1%' OR rawEventMsg LIKE '%Add-Exfiltration.ps1%' OR rawEventMsg LIKE '%Add-Persistence.ps1%' OR rawEventMsg LIKE '%Add-RegBackdoor.ps1%' OR rawEventMsg LIKE '%Add-RemoteRegBackdoor.ps1%' OR rawEventMsg LIKE '%Add-ScrnSaveBackdoor.ps1%' OR rawEventMsg LIKE '%BadSuccessor.ps1%' OR rawEventMsg LIKE '%Check-VM.ps1%' OR rawEventMsg LIKE '%ConvertTo-ROT13.ps1%' OR rawEventMsg LIKE '%Copy-VSS.ps1%' OR rawEventMsg LIKE '%Create-MultipleSessions.ps1%' OR rawEventMsg LIKE '%DNS\_TXT\_Pwnage.ps1%' OR rawEventMsg LIKE '%dnscat2.ps1%' OR rawEventMsg LIKE '%Do-Exfiltration.ps1%' OR rawEventMsg LIKE '%DomainPasswordSpray.ps1%' OR rawEventMsg LIKE '%Download\_Execute.ps1%' OR rawEventMsg LIKE '%Download-Execute-PS.ps1%' OR rawEventMsg LIKE '%Enabled-DuplicateToken.ps1%' OR rawEventMsg LIKE '%Enable-DuplicateToken.ps1%' OR rawEventMsg LIKE '%Execute-Command-MSSQL.ps1%' OR rawEventMsg LIKE '%Execute-DNSTXT-Code.ps1%' OR rawEventMsg LIKE '%Execute-OnTime.ps1%' OR rawEventMsg LIKE '%ExetoText.ps1%' OR rawEventMsg LIKE '%Exploit-Jboss.ps1%' OR rawEventMsg LIKE '%Find-AVSignature.ps1%' OR rawEventMsg LIKE '%Find-Fruit.ps1%' OR rawEventMsg LIKE '%Find-GPOLocation.ps1%' OR rawEventMsg LIKE '%Find-TrustedDocuments.ps1%' OR rawEventMsg LIKE '%FireBuster.ps1%' OR rawEventMsg LIKE '%FireListener.ps1%' OR rawEventMsg LIKE '%Get-ApplicationHost.ps1%' OR rawEventMsg LIKE '%Get-ChromeDump.ps1%' OR rawEventMsg LIKE '%Get-ClipboardContents.ps1%' OR rawEventMsg LIKE '%Get-ComputerDetail.ps1%' OR rawEventMsg LIKE '%Get-FoxDump.ps1%' OR rawEventMsg LIKE '%Get-GPPAutologon.ps1%' OR rawEventMsg LIKE '%Get-GPPPassword.ps1%' OR rawEventMsg LIKE '%Get-IndexedItem.ps1%' OR rawEventMsg LIKE '%Get-Keystrokes.ps1%' OR rawEventMsg LIKE '%Get-LSASecret.ps1%' OR rawEventMsg LIKE '%Get-MicrophoneAudio.ps1%' OR rawEventMsg LIKE '%Get-PassHashes.ps1%' OR rawEventMsg LIKE '%Get-PassHints.ps1%' OR rawEventMsg LIKE '%Get-RegAlwaysInstallElevated.ps1%' OR rawEventMsg LIKE '%Get-RegAutoLogon.ps1%' OR rawEventMsg LIKE '%Get-RickAstley.ps1%' OR rawEventMsg LIKE '%Get-Screenshot.ps1%' OR rawEventMsg LIKE '%Get-SecurityPackages.ps1%' OR rawEventMsg LIKE '%Get-ServiceFilePermission.ps1%' OR rawEventMsg LIKE '%Get-ServicePermission.ps1%' OR rawEventMsg LIKE '%Get-ServiceUnquoted.ps1%' OR rawEventMsg LIKE '%Get-SiteListPassword.ps1%' OR rawEventMsg LIKE '%Get-System.ps1%' OR rawEventMsg LIKE '%Get-TimedScreenshot.ps1%' OR rawEventMsg LIKE '%Get-UnattendedInstallFile.ps1%' OR rawEventMsg LIKE '%Get-Unconstrained.ps1%' OR rawEventMsg LIKE '%Get-USBKeystrokes.ps1%' OR rawEventMsg LIKE '%Get-VaultCredential.ps1%' OR rawEventMsg LIKE '%Get-VulnAutoRun.ps1%' OR rawEventMsg LIKE '%Get-VulnSchTask.ps1%' OR rawEventMsg LIKE '%Get-WebConfig.ps1%' OR rawEventMsg LIKE '%Get-WebCredentials.ps1%' OR rawEventMsg LIKE '%Get-WLAN-Keys.ps1%' OR rawEventMsg LIKE '%Gupt-Backdoor.ps1%' OR rawEventMsg LIKE '%HTTP-Backdoor.ps1%' OR rawEventMsg LIKE '%HTTP-Login.ps1%' OR rawEventMsg LIKE '%Install-ServiceBinary.ps1%' OR rawEventMsg LIKE '%Install-SSP.ps1%' OR rawEventMsg LIKE '%Invoke-ACLScanner.ps1%' OR rawEventMsg LIKE '%Invoke-ADSBackdoor.ps1%' OR rawEventMsg LIKE '%Invoke-AmsiBypass.ps1%' OR rawEventMsg LIKE '%Invoke-ARPScan.ps1%' OR rawEventMsg LIKE '%Invoke-BackdoorLNK.ps1%' OR rawEventMsg LIKE '%Invoke-BadPotato.ps1%' OR rawEventMsg LIKE '%Invoke-BetterSafetyKatz.ps1%' OR rawEventMsg LIKE '%Invoke-BruteForce.ps1%' OR rawEventMsg LIKE '%Invoke-BypassUAC.ps1%' OR rawEventMsg LIKE '%Invoke-Carbuncle.ps1%' OR rawEventMsg LIKE '%Invoke-Certify.ps1%' OR rawEventMsg LIKE '%Invoke-ConPtyShell.ps1%' OR rawEventMsg LIKE '%Invoke-CredentialInjection.ps1%' OR rawEventMsg LIKE '%Invoke-CredentialsPhish.ps1%' OR rawEventMsg LIKE '%Invoke-DAFT.ps1%' OR rawEventMsg LIKE '%Invoke-DCSync.ps1%' OR rawEventMsg LIKE '%Invoke-Decode.ps1%' OR rawEventMsg LIKE '%Invoke-DinvokeKatz.ps1%' OR rawEventMsg LIKE '%Invoke-DllInjection.ps1%' OR rawEventMsg LIKE '%Invoke-DNSExfiltrator.ps1%' OR rawEventMsg LIKE '%Invoke-DowngradeAccount.ps1%' OR rawEventMsg LIKE '%Invoke-EgressCheck.ps1%' OR rawEventMsg LIKE '%Invoke-Encode.ps1%' OR rawEventMsg LIKE '%Invoke-EventViewer.ps1%' OR rawEventMsg LIKE '%Invoke-Eyewitness.ps1%' OR rawEventMsg LIKE '%Invoke-FakeLogonScreen.ps1%' OR rawEventMsg LIKE '%Invoke-Farmer.ps1%' OR rawEventMsg LIKE '%Invoke-Get-RBCD-Threaded.ps1%' OR rawEventMsg LIKE '%Invoke-Gopher.ps1%' OR rawEventMsg LIKE '%Invoke-Grouper2.ps1%' OR rawEventMsg LIKE '%Invoke-Grouper3.ps1%' OR rawEventMsg LIKE '%Invoke-HandleKatz.ps1%' OR rawEventMsg LIKE '%Invoke-Interceptor.ps1%' OR rawEventMsg LIKE '%Invoke-Internalmonologue.ps1%' OR rawEventMsg LIKE '%Invoke-Inveigh.ps1%' OR rawEventMsg LIKE '%Invoke-InveighRelay.ps1%' OR rawEventMsg LIKE '%Invoke-JSRatRegsvr.ps1%' OR rawEventMsg LIKE '%Invoke-JSRatRundll.ps1%' OR rawEventMsg LIKE '%Invoke-KrbRelay.ps1%' OR rawEventMsg LIKE '%Invoke-KrbRelayUp.ps1%' OR rawEventMsg LIKE '%Invoke-LdapSignCheck.ps1%' OR rawEventMsg LIKE '%Invoke-Lockless.ps1%' OR rawEventMsg LIKE '%Invoke-MalSCCM.ps1%' OR rawEventMsg LIKE '%Invoke-Mimikatz.ps1%' OR rawEventMsg LIKE '%Invoke-MimikatzWDigestDowngrade.ps1%' OR rawEventMsg LIKE '%Invoke-Mimikittenz.ps1%' OR rawEventMsg LIKE '%Invoke-MITM6.ps1%' OR rawEventMsg LIKE '%Invoke-NanoDump.ps1%' OR rawEventMsg LIKE '%Invoke-NetRipper.ps1%' OR rawEventMsg LIKE '%Invoke-NetworkRelay.ps1%' OR rawEventMsg LIKE '%Invoke-NinjaCopy.ps1%' OR rawEventMsg LIKE '%Invoke-OxidResolver.ps1%' OR rawEventMsg LIKE '%Invoke-P0wnedshell.ps1%' OR rawEventMsg LIKE '%Invoke-P0wnedshellx86.ps1%' OR rawEventMsg LIKE '%Invoke-Paranoia.ps1%' OR rawEventMsg LIKE '%Invoke-PortScan.ps1%' OR rawEventMsg LIKE '%Invoke-PoshRatHttp.ps1%' OR rawEventMsg LIKE '%Invoke-PoshRatHttps.ps1%' OR rawEventMsg LIKE '%Invoke-PostExfil.ps1%' OR rawEventMsg LIKE '%Invoke-PowerDump.ps1%' OR rawEventMsg LIKE '%Invoke-PowerDPAPI.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellIcmp.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellTCP.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellTcpOneLine.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellTcpOneLineBind.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellUdp.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellUdpOneLine.ps1%' OR rawEventMsg LIKE '%Invoke-PowerShellWMI.ps1%' OR rawEventMsg LIKE '%Invoke-PowerThIEf.ps1%' OR rawEventMsg LIKE '%Invoke-PPLDump.ps1%' OR rawEventMsg LIKE '%Invoke-Prasadhak.ps1%' OR rawEventMsg LIKE '%Invoke-PsExec.ps1%' OR rawEventMsg LIKE '%Invoke-PsGcat.ps1%' OR rawEventMsg LIKE '%Invoke-PsGcatAgent.ps1%' OR rawEventMsg LIKE '%Invoke-PSInject.ps1%' OR rawEventMsg LIKE '%Invoke-PsUaCme.ps1%' OR rawEventMsg LIKE '%Invoke-ReflectivePEInjection.ps1%' OR rawEventMsg LIKE '%Invoke-ReverseDNSLookup.ps1%' OR rawEventMsg LIKE '%Invoke-Rubeus.ps1%' OR rawEventMsg LIKE '%Invoke-RunAs.ps1%' OR rawEventMsg LIKE '%Invoke-SafetyKatz.ps1%' OR rawEventMsg LIKE '%Invoke-SauronEye.ps1%' OR rawEventMsg LIKE '%Invoke-SCShell.ps1%' OR rawEventMsg LIKE '%Invoke-Seatbelt.ps1%' OR rawEventMsg LIKE '%Invoke-ServiceAbuse.ps1%' OR rawEventMsg LIKE '%Invoke-SessionGopher.ps1%' OR rawEventMsg LIKE '%Invoke-ShellCode.ps1%' OR rawEventMsg LIKE '%Invoke-SMBScanner.ps1%' OR rawEventMsg LIKE '%Invoke-Snaffler.ps1%' OR rawEventMsg LIKE '%Invoke-Spoolsample.ps1%' OR rawEventMsg LIKE '%Invoke-SSHCommand.ps1%' OR rawEventMsg LIKE '%Invoke-SSIDExfil.ps1%' OR rawEventMsg LIKE '%Invoke-StandIn.ps1%' OR rawEventMsg LIKE '%Invoke-StickyNotesExtract.ps1%' OR rawEventMsg LIKE '%Invoke-Tater.ps1%' OR rawEventMsg LIKE '%Invoke-Thunderfox.ps1%' OR rawEventMsg LIKE '%Invoke-ThunderStruck.ps1%' OR rawEventMsg LIKE '%Invoke-TokenManipulation.ps1%' OR rawEventMsg LIKE '%Invoke-Tokenvator.ps1%' OR rawEventMsg LIKE '%Invoke-TotalExec.ps1%' OR rawEventMsg LIKE '%Invoke-UrbanBishop.ps1%' OR rawEventMsg LIKE '%Invoke-UserHunter.ps1%' OR rawEventMsg LIKE '%Invoke-VoiceTroll.ps1%' OR rawEventMsg LIKE '%Invoke-Whisker.ps1%' OR rawEventMsg LIKE '%Invoke-WinEnum.ps1%' OR rawEventMsg LIKE '%Invoke-winPEAS.ps1%' OR rawEventMsg LIKE '%Invoke-WireTap.ps1%' OR rawEventMsg LIKE '%Invoke-WmiCommand.ps1%' OR rawEventMsg LIKE '%Invoke-WScriptBypassUAC.ps1%' OR rawEventMsg LIKE '%Invoke-Zerologon.ps1%' OR rawEventMsg LIKE '%Keylogger.ps1%' OR rawEventMsg LIKE '%MailRaider.ps1%' OR rawEventMsg LIKE '%New-HoneyHash.ps1%' OR rawEventMsg LIKE '%OfficeMemScraper.ps1%' OR rawEventMsg LIKE '%Offline\_Winpwn.ps1%' OR rawEventMsg LIKE '%Out-CHM.ps1%' OR rawEventMsg LIKE '%Out-DnsTxt.ps1%' OR rawEventMsg LIKE '%Out-Excel.ps1%' OR rawEventMsg LIKE '%Out-HTA.ps1%' OR rawEventMsg LIKE '%Out-Java.ps1%' OR rawEventMsg LIKE '%Out-JS.ps1%' OR rawEventMsg LIKE '%Out-Minidump.ps1%' OR rawEventMsg LIKE '%Out-RundllCommand.ps1%' OR rawEventMsg LIKE '%Out-SCF.ps1%' OR rawEventMsg LIKE '%Out-SCT.ps1%' OR rawEventMsg LIKE '%Out-Shortcut.ps1%' OR rawEventMsg LIKE '%Out-WebQuery.ps1%' OR rawEventMsg LIKE '%Out-Word.ps1%' OR rawEventMsg LIKE '%Parse\_Keys.ps1%' OR rawEventMsg LIKE '%Port-Scan.ps1%' OR rawEventMsg LIKE '%PowerBreach.ps1%' OR rawEventMsg LIKE '%powercat.ps1%' OR rawEventMsg LIKE '%PowerRunAsSystem.psm1%' OR rawEventMsg LIKE '%PowerSharpPack.ps1%' OR rawEventMsg LIKE '%PowerUp.ps1%' OR rawEventMsg LIKE '%PowerUpSQL.ps1%' OR rawEventMsg LIKE '%PowerView.ps1%' OR rawEventMsg LIKE '%PSAsyncShell.ps1%' OR rawEventMsg LIKE '%RemoteHashRetrieval.ps1%' OR rawEventMsg LIKE '%Remove-Persistence.ps1%' OR rawEventMsg LIKE '%Remove-PoshRat.ps1%' OR rawEventMsg LIKE '%Remove-Update.ps1%' OR rawEventMsg LIKE '%Run-EXEonRemote.ps1%' OR rawEventMsg LIKE '%Schtasks-Backdoor.ps1%' OR rawEventMsg LIKE '%Set-DCShadowPermissions.ps1%' OR rawEventMsg LIKE '%Set-MacAttribute.ps1%' OR rawEventMsg LIKE '%Set-RemotePSRemoting.ps1%' OR rawEventMsg LIKE '%Set-RemoteWMI.ps1%' OR rawEventMsg LIKE '%Set-Wallpaper.ps1%' OR rawEventMsg LIKE '%Show-TargetScreen.ps1%' OR rawEventMsg LIKE '%Speak.ps1%' OR rawEventMsg LIKE '%Start-CaptureServer.ps1%' OR rawEventMsg LIKE '%Start-WebcamRecorder.ps1%' OR rawEventMsg LIKE '%StringToBase64.ps1%' OR rawEventMsg LIKE '%TexttoExe.ps1%' OR rawEventMsg LIKE '%Veeam-Get-Creds.ps1%' OR rawEventMsg LIKE '%VolumeShadowCopyTools.ps1%' OR rawEventMsg LIKE '%WinPwn.ps1%' OR rawEventMsg LIKE '%WSUSpendu.ps1%')
  OR rawEventMsg LIKE '%Invoke-Sharp%' AND rawEventMsg LIKE '%.ps1%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/PowerShellMafia/PowerSploit
- https://github.com/NetSPI/PowerUpSQL
- https://github.com/CsEnox/EventViewer-UACBypass
- https://web.archive.org/web/20210511204621/https://github.com/AlsidOfficial/WSUSpendu
- https://github.com/nettitude/Invoke-PowerThIEf
- https://github.com/S3cur3Th1sSh1t/WinPwn
- https://github.com/S3cur3Th1sSh1t/PowerSharpPack/tree/master/PowerSharpBinaries
- https://github.com/BC-SECURITY/Invoke-ZeroLogon/blob/111d17c7fec486d9bb23387e2e828b09a26075e4/Invoke-ZeroLogon.ps1
- https://github.com/xorrior/RandomPS-Scripts/blob/848c919bfce4e2d67b626cbcf4404341cfe3d3b6/Get-DXWebcamVideo.ps1
- https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/6f23bb41f9675d7e2d32bacccff75e931ae00554/OfficeMemScraper.ps1
- https://github.com/dafthack/DomainPasswordSpray/blob/b13d64a5834694aa73fd2aea9911a83027c465a7/DomainPasswordSpray.ps1
- https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/
- https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/
- https://github.com/HarmJ0y/DAMP
- https://github.com/samratashok/nishang
- https://github.com/DarkCoderSc/PowerRunAsSystem/
- https://github.com/besimorhino/powercat
- https://github.com/sadshade/veeam-creds/blob/6010eaf31ba41011b58d6af3950cffbf6f5cea32/Veeam-Get-Creds.ps1
- https://github.com/The-Viper-One/Invoke-PowerDPAPI/
- https://github.com/Arno0x/DNSExfiltrator/

---

## Suspicious Get-ADDBAccount Usage

| Field | Value |
|---|---|
| **Sigma ID** | `b140afd9-474b-4072-958e-2ebb435abd68` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_get_addbaccount.yml)**

> Detects suspicious invocation of the Get-ADDBAccount script that reads from a ntds.dit file and may be used to get access to credentials without using any credential dumpers

```sql
-- ============================================================
-- Title:        Suspicious Get-ADDBAccount Usage
-- Sigma ID:     b140afd9-474b-4072-958e-2ebb435abd68
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_get_addbaccount.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Get-ADDBAccount%' AND rawEventMsg LIKE '%BootKey %' AND rawEventMsg LIKE '%DatabasePath %'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
- https://github.com/MichaelGrafnetter/DSInternals/blob/7ba59c12ee9a1cb430d7dc186a3366842dd612c8/Documentation/PowerShell/Get-ADDBAccount.md

---

## PowerShell Get Clipboard

| Field | Value |
|---|---|
| **Sigma ID** | `4cbd4f12-2e22-43e3-882f-bff3247ffb78` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1115 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_get_clipboard.yml)**

> A General detection for the Get-Clipboard commands in PowerShell logs. This could be an adversary capturing clipboard contents.

```sql
-- ============================================================
-- Title:        PowerShell Get Clipboard
-- Sigma ID:     4cbd4f12-2e22-43e3-882f-bff3247ffb78
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1115
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_get_clipboard.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Get-Clipboard%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/16
- https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/7.A.2_F4609F7E-C4DB-4327-91D4-59A58C962A02.md

---

## HackTool - Evil-WinRm Execution - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `9fe55ea2-4cd6-4491-8a54-dd6871651b51` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_hktl_evil_winrm_execution.yml)**

> Detects the execution of Evil-WinRM via PowerShell Module logs by leveraging the hardcoded strings inside the utility.


```sql
-- ============================================================
-- Title:        HackTool - Evil-WinRm Execution - PowerShell Module
-- Sigma ID:     9fe55ea2-4cd6-4491-8a54-dd6871651b51
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_hktl_evil_winrm_execution.yml
-- Unmapped:     ContextInfo
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%:\\Windows\\System32\\wsmprovhost.exe%' OR rawEventMsg LIKE '%:\\Windows\\SysWOW64\\wsmprovhost.exe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Hackplayers/evil-winrm/blob/7514b055d67ec19836e95c05bd63e7cc47c4c2aa/evil-winrm.rb
- https://github.com/search?q=repo%3AHackplayers%2Fevil-winrm++shell.run%28&type=code

---

## Invoke-Obfuscation CLIP+ Launcher - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `a136cde0-61ad-4a61-9b82-8dc490e60dd2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_clip.yml)**

> Detects Obfuscated use of Clip.exe to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation CLIP+ Launcher - PowerShell Module
-- Sigma ID:     a136cde0-61ad-4a61-9b82-8dc490e60dd2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_clip.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, 'cmd.{0,5}(?:/c|/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\"\{\d\}.+-f.+"')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `2f211361-7dce-442d-b78a-c04039677378` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Daniel Bohannon (@Mandiant/@FireEye), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_obfuscated_iex.yml)**

> Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the code block cited in the reference section below

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module
-- Sigma ID:     2f211361-7dce-442d-b78a-c04039677378
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Daniel Bohannon (@Mandiant/@FireEye), oscd.community
-- Date:         2019-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_obfuscated_iex.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (match(rawEventMsg, '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['))
  OR (match(rawEventMsg, '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\['))
  OR (match(rawEventMsg, '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\['))
  OR (match(rawEventMsg, '\$env:ComSpec\[(\s*\d{1,3}\s*,){2}'))
  OR (match(rawEventMsg, '\*mdr\*\W\s*\)\.Name'))
  OR (match(rawEventMsg, '\$VerbosePreference\.ToString\('))
  OR (match(rawEventMsg, '\[String\]\s*\$VerbosePreference'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/danielbohannon/Invoke-Obfuscation/blob/f20e7f843edd0a3a7716736e9eddfa423395dd26/Out-ObfuscatedStringCommand.ps1#L873-L888

---

## Invoke-Obfuscation STDIN+ Launcher - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `9ac8b09b-45de-4a07-9da1-0de8c09304a3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_stdin.yml)**

> Detects Obfuscated use of stdin to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation STDIN+ Launcher - PowerShell Module
-- Sigma ID:     9ac8b09b-45de-4a07-9da1-0de8c09304a3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_stdin.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, 'cmd.{0,5}(?:/c|/r).+powershell.+(?:\$\{?input\}?|noexit).+"')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR+ Launcher - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `6bfb8fa7-b2e7-4f6c-8d9d-824e5d06ea9e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_var.yml)**

> Detects Obfuscated use of Environment Variables to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR+ Launcher - PowerShell Module
-- Sigma ID:     6bfb8fa7-b2e7-4f6c-8d9d-824e5d06ea9e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_var.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, 'cmd.{0,5}(?:/c|/r)(?:\s|)"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\"\s+?-f(?:.*\)){1,}.*"')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `7034cbbb-cc55-4dc2-8dad-36c0b942e8f1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_compress.yml)**

> Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module
-- Sigma ID:     7034cbbb-cc55-4dc2-8dad-36c0b942e8f1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_compress.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%new-object%' AND rawEventMsg LIKE '%text.encoding]::ascii%'
    AND (rawEventMsg LIKE '%system.io.compression.deflatestream%' OR rawEventMsg LIKE '%system.io.streamreader%')
    AND rawEventMsg LIKE '%readtoend')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `a23791fe-8846-485a-b16b-ca691e1b03d4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_rundll.yml)**

> Detects Obfuscated Powershell via RUNDLL LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module
-- Sigma ID:     a23791fe-8846-485a-b16b-ca691e1b03d4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_rundll.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%rundll32.exe%' AND rawEventMsg LIKE '%shell32.dll%' AND rawEventMsg LIKE '%shellexec\_rundll%' AND rawEventMsg LIKE '%powershell%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Stdin - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `c72aca44-8d52-45ad-8f81-f96c4d3c755e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_stdin.yml)**

> Detects Obfuscated Powershell via Stdin in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Stdin - PowerShell Module
-- Sigma ID:     c72aca44-8d52-45ad-8f81-f96c4d3c755e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_stdin.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, '(?i)(set).*&&\s?set.*(environment|invoke|\$?\{?input).*&&.*"')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Clip - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `ebdf49d8-b89c-46c9-8fdf-2c308406f6bd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_clip.yml)**

> Detects Obfuscated Powershell via use Clip.exe in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Clip - PowerShell Module
-- Sigma ID:     ebdf49d8-b89c-46c9-8fdf-2c308406f6bd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_clip.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, '(?i)echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use MSHTA - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `07ad2ea8-6a55-4ac6-bf3e-91b8e59676eb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_mhsta.yml)**

> Detects Obfuscated Powershell via use MSHTA in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use MSHTA - PowerShell Module
-- Sigma ID:     07ad2ea8-6a55-4ac6-bf3e-91b8e59676eb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_mhsta.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%set%' AND rawEventMsg LIKE '%&&%' AND rawEventMsg LIKE '%mshta%' AND rawEventMsg LIKE '%vbscript:createobject%' AND rawEventMsg LIKE '%.run%' AND rawEventMsg LIKE '%(window.close)%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Rundll32 - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `88a22f69-62f9-4b8a-aa00-6b0212f2f05a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_rundll32.yml)**

> Detects Obfuscated Powershell via use Rundll32 in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Rundll32 - PowerShell Module
-- Sigma ID:     88a22f69-62f9-4b8a-aa00-6b0212f2f05a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2019-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_rundll32.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%&&%' AND rawEventMsg LIKE '%rundll32%' AND rawEventMsg LIKE '%shell32.dll%' AND rawEventMsg LIKE '%shellexec\_rundll%'
    AND (rawEventMsg LIKE '%value%' OR rawEventMsg LIKE '%invoke%' OR rawEventMsg LIKE '%comspec%' OR rawEventMsg LIKE '%iex%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `f3c89218-8c3d-4ba9-9974-f1d8e6a1b4a6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_var.yml)**

> Detects Obfuscated Powershell via VAR++ LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module
-- Sigma ID:     f3c89218-8c3d-4ba9-9974-f1d8e6a1b4a6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_var.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, '(?i)&&set.*(\{\d\}){2,}\\"\s+?-f.*&&.*cmd.*/c')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Malicious PowerShell Commandlets - PoshModule

| Field | Value |
|---|---|
| **Sigma ID** | `7d0d0329-0ef1-4e84-a9f5-49500f9d7c6c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, discovery |
| **MITRE Techniques** | T1482, T1087, T1087.001, T1087.002, T1069.001, T1069.002, T1069, T1059.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_malicious_commandlets.yml)**

> Detects Commandlet names from well-known PowerShell exploitation frameworks

```sql
-- ============================================================
-- Title:        Malicious PowerShell Commandlets - PoshModule
-- Sigma ID:     7d0d0329-0ef1-4e84-a9f5-49500f9d7c6c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, discovery | T1482, T1087, T1087.001, T1087.002, T1069.001, T1069.002, T1069, T1059.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_malicious_commandlets.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Add-Exfiltration%' OR rawEventMsg LIKE '%Add-Persistence%' OR rawEventMsg LIKE '%Add-RegBackdoor%' OR rawEventMsg LIKE '%Add-RemoteRegBackdoor%' OR rawEventMsg LIKE '%Add-ScrnSaveBackdoor%' OR rawEventMsg LIKE '%BadSuccessor%' OR rawEventMsg LIKE '%Check-VM%' OR rawEventMsg LIKE '%ConvertTo-Rc4ByteStream%' OR rawEventMsg LIKE '%Decrypt-Hash%' OR rawEventMsg LIKE '%Disable-ADIDNSNode%' OR rawEventMsg LIKE '%Disable-MachineAccount%' OR rawEventMsg LIKE '%Do-Exfiltration%' OR rawEventMsg LIKE '%Enable-ADIDNSNode%' OR rawEventMsg LIKE '%Enable-MachineAccount%' OR rawEventMsg LIKE '%Enabled-DuplicateToken%' OR rawEventMsg LIKE '%Exploit-Jboss%' OR rawEventMsg LIKE '%Export-ADR%' OR rawEventMsg LIKE '%Export-ADRCSV%' OR rawEventMsg LIKE '%Export-ADRExcel%' OR rawEventMsg LIKE '%Export-ADRHTML%' OR rawEventMsg LIKE '%Export-ADRJSON%' OR rawEventMsg LIKE '%Export-ADRXML%' OR rawEventMsg LIKE '%Find-Fruit%' OR rawEventMsg LIKE '%Find-GPOLocation%' OR rawEventMsg LIKE '%Find-TrustedDocuments%' OR rawEventMsg LIKE '%Get-ADIDNS%' OR rawEventMsg LIKE '%Get-ApplicationHost%' OR rawEventMsg LIKE '%Get-ChromeDump%' OR rawEventMsg LIKE '%Get-ClipboardContents%' OR rawEventMsg LIKE '%Get-FoxDump%' OR rawEventMsg LIKE '%Get-GPPPassword%' OR rawEventMsg LIKE '%Get-IndexedItem%' OR rawEventMsg LIKE '%Get-KerberosAESKey%' OR rawEventMsg LIKE '%Get-Keystrokes%' OR rawEventMsg LIKE '%Get-LSASecret%' OR rawEventMsg LIKE '%Get-MachineAccountAttribute%' OR rawEventMsg LIKE '%Get-MachineAccountCreator%' OR rawEventMsg LIKE '%Get-PassHashes%' OR rawEventMsg LIKE '%Get-RegAlwaysInstallElevated%' OR rawEventMsg LIKE '%Get-RegAutoLogon%' OR rawEventMsg LIKE '%Get-RemoteBootKey%' OR rawEventMsg LIKE '%Get-RemoteCachedCredential%' OR rawEventMsg LIKE '%Get-RemoteLocalAccountHash%' OR rawEventMsg LIKE '%Get-RemoteLSAKey%' OR rawEventMsg LIKE '%Get-RemoteMachineAccountHash%' OR rawEventMsg LIKE '%Get-RemoteNLKMKey%' OR rawEventMsg LIKE '%Get-RickAstley%' OR rawEventMsg LIKE '%Get-Screenshot%' OR rawEventMsg LIKE '%Get-SecurityPackages%' OR rawEventMsg LIKE '%Get-ServiceFilePermission%' OR rawEventMsg LIKE '%Get-ServicePermission%' OR rawEventMsg LIKE '%Get-ServiceUnquoted%' OR rawEventMsg LIKE '%Get-SiteListPassword%' OR rawEventMsg LIKE '%Get-System%' OR rawEventMsg LIKE '%Get-TimedScreenshot%' OR rawEventMsg LIKE '%Get-UnattendedInstallFile%' OR rawEventMsg LIKE '%Get-Unconstrained%' OR rawEventMsg LIKE '%Get-USBKeystrokes%' OR rawEventMsg LIKE '%Get-VaultCredential%' OR rawEventMsg LIKE '%Get-VulnAutoRun%' OR rawEventMsg LIKE '%Get-VulnSchTask%' OR rawEventMsg LIKE '%Grant-ADIDNSPermission%' OR rawEventMsg LIKE '%Gupt-Backdoor%' OR rawEventMsg LIKE '%HTTP-Login%' OR rawEventMsg LIKE '%Install-ServiceBinary%' OR rawEventMsg LIKE '%Install-SSP%' OR rawEventMsg LIKE '%Invoke-ACLScanner%' OR rawEventMsg LIKE '%Invoke-ADRecon%' OR rawEventMsg LIKE '%Invoke-ADSBackdoor%' OR rawEventMsg LIKE '%Invoke-AgentSmith%' OR rawEventMsg LIKE '%Invoke-AllChecks%' OR rawEventMsg LIKE '%Invoke-ARPScan%' OR rawEventMsg LIKE '%Invoke-AzureHound%' OR rawEventMsg LIKE '%Invoke-BackdoorLNK%' OR rawEventMsg LIKE '%Invoke-BadPotato%' OR rawEventMsg LIKE '%Invoke-BetterSafetyKatz%' OR rawEventMsg LIKE '%Invoke-BypassUAC%' OR rawEventMsg LIKE '%Invoke-Carbuncle%' OR rawEventMsg LIKE '%Invoke-Certify%' OR rawEventMsg LIKE '%Invoke-ConPtyShell%' OR rawEventMsg LIKE '%Invoke-CredentialInjection%' OR rawEventMsg LIKE '%Invoke-DAFT%' OR rawEventMsg LIKE '%Invoke-DCSync%' OR rawEventMsg LIKE '%Invoke-DinvokeKatz%' OR rawEventMsg LIKE '%Invoke-DllInjection%' OR rawEventMsg LIKE '%Invoke-DNSUpdate%' OR rawEventMsg LIKE '%Invoke-DNSExfiltrator%' OR rawEventMsg LIKE '%Invoke-DomainPasswordSpray%' OR rawEventMsg LIKE '%Invoke-DowngradeAccount%' OR rawEventMsg LIKE '%Invoke-EgressCheck%' OR rawEventMsg LIKE '%Invoke-Eyewitness%' OR rawEventMsg LIKE '%Invoke-FakeLogonScreen%' OR rawEventMsg LIKE '%Invoke-Farmer%' OR rawEventMsg LIKE '%Invoke-Get-RBCD-Threaded%' OR rawEventMsg LIKE '%Invoke-Gopher%' OR rawEventMsg LIKE '%Invoke-Grouper%' OR rawEventMsg LIKE '%Invoke-HandleKatz%' OR rawEventMsg LIKE '%Invoke-ImpersonatedProcess%' OR rawEventMsg LIKE '%Invoke-ImpersonateSystem%' OR rawEventMsg LIKE '%Invoke-InteractiveSystemPowerShell%' OR rawEventMsg LIKE '%Invoke-Internalmonologue%' OR rawEventMsg LIKE '%Invoke-Inveigh%' OR rawEventMsg LIKE '%Invoke-InveighRelay%' OR rawEventMsg LIKE '%Invoke-KrbRelay%' OR rawEventMsg LIKE '%Invoke-LdapSignCheck%' OR rawEventMsg LIKE '%Invoke-Lockless%' OR rawEventMsg LIKE '%Invoke-MalSCCM%' OR rawEventMsg LIKE '%Invoke-Mimikatz%' OR rawEventMsg LIKE '%Invoke-Mimikittenz%' OR rawEventMsg LIKE '%Invoke-MITM6%' OR rawEventMsg LIKE '%Invoke-NanoDump%' OR rawEventMsg LIKE '%Invoke-NetRipper%' OR rawEventMsg LIKE '%Invoke-Nightmare%' OR rawEventMsg LIKE '%Invoke-NinjaCopy%' OR rawEventMsg LIKE '%Invoke-OfficeScrape%' OR rawEventMsg LIKE '%Invoke-OxidResolver%' OR rawEventMsg LIKE '%Invoke-P0wnedshell%' OR rawEventMsg LIKE '%Invoke-Paranoia%' OR rawEventMsg LIKE '%Invoke-PortScan%' OR rawEventMsg LIKE '%Invoke-PoshRatHttp%' OR rawEventMsg LIKE '%Invoke-PostExfil%' OR rawEventMsg LIKE '%Invoke-PowerDump%' OR rawEventMsg LIKE '%Invoke-PowerDPAPI%' OR rawEventMsg LIKE '%Invoke-PowerShellTCP%' OR rawEventMsg LIKE '%Invoke-PowerShellWMI%' OR rawEventMsg LIKE '%Invoke-PPLDump%' OR rawEventMsg LIKE '%Invoke-PsExec%' OR rawEventMsg LIKE '%Invoke-PSInject%' OR rawEventMsg LIKE '%Invoke-PsUaCme%' OR rawEventMsg LIKE '%Invoke-ReflectivePEInjection%' OR rawEventMsg LIKE '%Invoke-ReverseDNSLookup%' OR rawEventMsg LIKE '%Invoke-Rubeus%' OR rawEventMsg LIKE '%Invoke-RunAs%' OR rawEventMsg LIKE '%Invoke-SafetyKatz%' OR rawEventMsg LIKE '%Invoke-SauronEye%' OR rawEventMsg LIKE '%Invoke-SCShell%' OR rawEventMsg LIKE '%Invoke-Seatbelt%' OR rawEventMsg LIKE '%Invoke-ServiceAbuse%' OR rawEventMsg LIKE '%Invoke-ShadowSpray%' OR rawEventMsg LIKE '%Invoke-Sharp%' OR rawEventMsg LIKE '%Invoke-Shellcode%' OR rawEventMsg LIKE '%Invoke-SMBScanner%' OR rawEventMsg LIKE '%Invoke-Snaffler%' OR rawEventMsg LIKE '%Invoke-Spoolsample%' OR rawEventMsg LIKE '%Invoke-SpraySinglePassword%' OR rawEventMsg LIKE '%Invoke-SSHCommand%' OR rawEventMsg LIKE '%Invoke-StandIn%' OR rawEventMsg LIKE '%Invoke-StickyNotesExtract%' OR rawEventMsg LIKE '%Invoke-SystemCommand%' OR rawEventMsg LIKE '%Invoke-Tasksbackdoor%' OR rawEventMsg LIKE '%Invoke-Tater%' OR rawEventMsg LIKE '%Invoke-Thunderfox%' OR rawEventMsg LIKE '%Invoke-ThunderStruck%' OR rawEventMsg LIKE '%Invoke-TokenManipulation%' OR rawEventMsg LIKE '%Invoke-Tokenvator%' OR rawEventMsg LIKE '%Invoke-TotalExec%' OR rawEventMsg LIKE '%Invoke-UrbanBishop%' OR rawEventMsg LIKE '%Invoke-UserHunter%' OR rawEventMsg LIKE '%Invoke-VoiceTroll%' OR rawEventMsg LIKE '%Invoke-Whisker%' OR rawEventMsg LIKE '%Invoke-WinEnum%' OR rawEventMsg LIKE '%Invoke-winPEAS%' OR rawEventMsg LIKE '%Invoke-WireTap%' OR rawEventMsg LIKE '%Invoke-WmiCommand%' OR rawEventMsg LIKE '%Invoke-WMIExec%' OR rawEventMsg LIKE '%Invoke-WScriptBypassUAC%' OR rawEventMsg LIKE '%Invoke-Zerologon%' OR rawEventMsg LIKE '%MailRaider%' OR rawEventMsg LIKE '%New-ADIDNSNode%' OR rawEventMsg LIKE '%New-DNSRecordArray%' OR rawEventMsg LIKE '%New-HoneyHash%' OR rawEventMsg LIKE '%New-InMemoryModule%' OR rawEventMsg LIKE '%New-MachineAccount%' OR rawEventMsg LIKE '%New-SOASerialNumberArray%' OR rawEventMsg LIKE '%Out-Minidump%' OR rawEventMsg LIKE '%Port-Scan%' OR rawEventMsg LIKE '%PowerBreach%' OR rawEventMsg LIKE '%powercat %' OR rawEventMsg LIKE '%PowerUp%' OR rawEventMsg LIKE '%PowerView%' OR rawEventMsg LIKE '%Remove-ADIDNSNode%' OR rawEventMsg LIKE '%Remove-MachineAccount%' OR rawEventMsg LIKE '%Remove-Update%' OR rawEventMsg LIKE '%Rename-ADIDNSNode%' OR rawEventMsg LIKE '%Revoke-ADIDNSPermission%' OR rawEventMsg LIKE '%Set-ADIDNSNode%' OR rawEventMsg LIKE '%Set-MacAttribute%' OR rawEventMsg LIKE '%Set-MachineAccountAttribute%' OR rawEventMsg LIKE '%Set-Wallpaper%' OR rawEventMsg LIKE '%Show-TargetScreen%' OR rawEventMsg LIKE '%Start-CaptureServer%' OR rawEventMsg LIKE '%Start-Dnscat2%' OR rawEventMsg LIKE '%Start-WebcamRecorder%' OR rawEventMsg LIKE '%Veeam-Get-Creds%' OR rawEventMsg LIKE '%VolumeShadowCopyTools%')
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
- https://github.com/sadshade/veeam-creds/blob/6010eaf31ba41011b58d6af3950cffbf6f5cea32/Veeam-Get-Creds.ps1
- https://github.com/The-Viper-One/Invoke-PowerDPAPI/
- https://github.com/Arno0x/DNSExfiltrator/

---

## Remote PowerShell Session (PS Module)

| Field | Value |
|---|---|
| **Sigma ID** | `96b9f619-aa91-478f-bacb-c3e50f8df575` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1021.006 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_remote_powershell_session.yml)**

> Detects remote PowerShell sessions

```sql
-- ============================================================
-- Title:        Remote PowerShell Session (PS Module)
-- Sigma ID:     96b9f619-aa91-478f-bacb-c3e50f8df575
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001, T1021.006
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
-- Date:         2019-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_remote_powershell_session.yml
-- Unmapped:     ContextInfo
-- False Pos:    Legitimate use remote PowerShell sessions
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '% = ServerRemoteHost %' AND rawEventMsg LIKE '%wsmprovhost.exe%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use remote PowerShell sessions

**References:**
- https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html

---

## Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `38a7625e-b2cb-485d-b83d-aff137d859f4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_remotefxvgpudisablement_abuse.yml)**

> Detects PowerShell module creation where the module Contents are set to "function Get-VMRemoteFXPhysicalVideoAdapter". This could be a sign of potential abuse of the "RemoteFXvGPUDisablement.exe" binary which is known to be vulnerable to module load-order hijacking.

```sql
-- ============================================================
-- Title:        Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module
-- Sigma ID:     38a7625e-b2cb-485d-b83d-aff137d859f4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2021-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_remotefxvgpudisablement_abuse.yml
-- Unmapped:     Payload
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ModuleContents=function Get-VMRemoteFXPhysicalVideoAdapter {%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
- https://github.com/redcanaryco/AtomicTestHarnesses/blob/7e1e4da116801e3d6fcc6bedb207064577e40572/TestHarnesses/T1218_SignedBinaryProxyExecution/InvokeRemoteFXvGPUDisablementCommand.ps1

---

## AD Groups Or Users Enumeration Using PowerShell - PoshModule

| Field | Value |
|---|---|
| **Sigma ID** | `815bfc17-7fc6-4908-a55e-2f37b98cedb4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_ad_group_reco.yml)**

> Adversaries may attempt to find domain-level groups and permission settings.
The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.
Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.


```sql
-- ============================================================
-- Title:        AD Groups Or Users Enumeration Using PowerShell - PoshModule
-- Sigma ID:     815bfc17-7fc6-4908-a55e-2f37b98cedb4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       frack113
-- Date:         2021-12-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_ad_group_reco.yml
-- Unmapped:     Payload, ContextInfo
-- False Pos:    Administrator script
-- ============================================================
-- UNMAPPED_FIELD: Payload
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%get-ADPrincipalGroupMembership%')
  OR (rawEventMsg LIKE '%get-ADPrincipalGroupMembership%')
  OR (rawEventMsg LIKE '%get-aduser%' AND rawEventMsg LIKE '%-f %' AND rawEventMsg LIKE '%-pr %' AND rawEventMsg LIKE '%DoesNotRequirePreAuth%')
  OR (rawEventMsg LIKE '%get-aduser%' AND rawEventMsg LIKE '%-f %' AND rawEventMsg LIKE '%-pr %' AND rawEventMsg LIKE '%DoesNotRequirePreAuth%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md

---

## Suspicious PowerShell Download - PoshModule

| Field | Value |
|---|---|
| **Sigma ID** | `de41232e-12e8-49fa-86bc-c05c7e722df9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_download.yml)**

> Detects suspicious PowerShell download command

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Download - PoshModule
-- Sigma ID:     de41232e-12e8-49fa-86bc-c05c7e722df9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_download.yml
-- Unmapped:     ContextInfo
-- False Pos:    PowerShell scripts that download content from the Internet
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%.DownloadFile(%' OR rawEventMsg LIKE '%.DownloadString(%')
  AND rawEventMsg LIKE '%System.Net.WebClient%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** PowerShell scripts that download content from the Internet

**References:**
- https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-8.0
- https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-8.0

---

## Use Get-NetTCPConnection - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `aff815cc-e400-4bf0-a47a-5d8a2407d4e1` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1049 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_get_nettcpconnection.yml)**

> Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

```sql
-- ============================================================
-- Title:        Use Get-NetTCPConnection - PowerShell Module
-- Sigma ID:     aff815cc-e400-4bf0-a47a-5d8a2407d4e1
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1049
-- Author:       frack113
-- Date:         2021-12-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_get_nettcpconnection.yml
-- Unmapped:     ContextInfo
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Get-NetTCPConnection%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell

---

## Suspicious PowerShell Invocations - Generic - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `bbb80e91-5746-4fbe-8898-122e2cafdbf4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_invocation_generic.yml)**

> Detects suspicious PowerShell invocation command parameters

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Invocations - Generic - PowerShell Module
-- Sigma ID:     bbb80e91-5746-4fbe-8898-122e2cafdbf4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_invocation_generic.yml
-- Unmapped:     ContextInfo
-- False Pos:    Very special / sneaky PowerShell scripts
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '% -enc %' OR rawEventMsg LIKE '% -EncodedCommand %' OR rawEventMsg LIKE '% -ec %')
  AND (rawEventMsg LIKE '% -w hidden %' OR rawEventMsg LIKE '% -window hidden %' OR rawEventMsg LIKE '% -windowstyle hidden %' OR rawEventMsg LIKE '% -w 1 %')
  AND (rawEventMsg LIKE '% -noni %' OR rawEventMsg LIKE '% -noninteractive %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Very special / sneaky PowerShell scripts

**References:**
- Internal Research

---

## Suspicious PowerShell Invocations - Specific - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems), Jonhnathan Ribeiro |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_invocation_specific.yml)**

> Detects suspicious PowerShell invocation command parameters

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Invocations - Specific - PowerShell Module
-- Sigma ID:     8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems), Jonhnathan Ribeiro
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_invocation_specific.yml
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
WHERE eventType IN ('Win-PowerShell-4103')
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

## Suspicious Get Local Groups Information

| Field | Value |
|---|---|
| **Sigma ID** | `cef24b90-dddc-4ae1-a09a-8764872f69fc` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_local_group_reco.yml)**

> Detects the use of PowerShell modules and cmdlets to gather local group information.
Adversaries may use local system permission groups to determine which groups exist and which users belong to a particular group such as the local administrators group.


```sql
-- ============================================================
-- Title:        Suspicious Get Local Groups Information
-- Sigma ID:     cef24b90-dddc-4ae1-a09a-8764872f69fc
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       frack113
-- Date:         2021-12-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_local_group_reco.yml
-- Unmapped:     Payload, ContextInfo
-- False Pos:    Administrator script
-- ============================================================
-- UNMAPPED_FIELD: Payload
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%get-localgroup %' OR rawEventMsg LIKE '%get-localgroupmember %'))
  OR ((rawEventMsg LIKE '%get-localgroup %' OR rawEventMsg LIKE '%get-localgroupmember %'))
  OR ((rawEventMsg LIKE '%win32\_group%')
  OR (rawEventMsg LIKE '%win32\_group%')
  AND ((rawEventMsg LIKE '%get-wmiobject %' OR rawEventMsg LIKE '%gwmi %' OR rawEventMsg LIKE '%get-ciminstance %' OR rawEventMsg LIKE '%gcim %'))
  OR (rawEventMsg LIKE '%get-wmiobject %' AND rawEventMsg LIKE '%gwmi %' AND rawEventMsg LIKE '%get-ciminstance %' AND rawEventMsg LIKE '%gcim %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md

---

## Suspicious Computer Machine Password by PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `e3818659-5016-4811-a73c-dde4679169d2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_reset_computermachinepassword.yml)**

> The Reset-ComputerMachinePassword cmdlet changes the computer account password that the computers use to authenticate to the domain controllers in the domain.
You can use it to reset the password of the local computer.


```sql
-- ============================================================
-- Title:        Suspicious Computer Machine Password by PowerShell
-- Sigma ID:     e3818659-5016-4811-a73c-dde4679169d2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       frack113
-- Date:         2022-02-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_reset_computermachinepassword.yml
-- Unmapped:     ContextInfo
-- False Pos:    Administrator PowerShell scripts
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Reset-ComputerMachinePassword%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator PowerShell scripts

**References:**
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword?view=powershell-5.1
- https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

---

## Suspicious Get Information for SMB Share - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `6942bd25-5970-40ab-af49-944247103358` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_smb_share_reco.yml)**

> Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and
to identify potential systems of interest for Lateral Movement.
Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.


```sql
-- ============================================================
-- Title:        Suspicious Get Information for SMB Share - PowerShell Module
-- Sigma ID:     6942bd25-5970-40ab-af49-944247103358
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       frack113
-- Date:         2021-12-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_smb_share_reco.yml
-- Unmapped:     Payload, ContextInfo
-- False Pos:    Administrator script
-- ============================================================
-- UNMAPPED_FIELD: Payload
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%get-smbshare%')
  OR (rawEventMsg LIKE '%get-smbshare%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md

---

## Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module

| Field | Value |
|---|---|
| **Sigma ID** | `daf7eb81-35fd-410d-9d7a-657837e602bb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1074.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_zip_compress.yml)**

> Detects PowerShell scripts that make use of the "Compress-Archive" Cmdlet in order to compress folders and files where the output is stored in a potentially suspicious location that is used often by malware for exfiltration.
An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.


```sql
-- ============================================================
-- Title:        Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module
-- Sigma ID:     daf7eb81-35fd-410d-9d7a-657837e602bb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1074.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2021-07-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_susp_zip_compress.yml
-- Unmapped:     ContextInfo
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Compress-Archive -Path*-DestinationPath $env:TEMP%' AND rawEventMsg LIKE '%Compress-Archive -Path*-DestinationPath*\\AppData\\Local\\Temp\\%' AND rawEventMsg LIKE '%Compress-Archive -Path*-DestinationPath*:\\Windows\\Temp\\%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1074.001/T1074.001.md
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a

---

## SyncAppvPublishingServer Bypass Powershell Restriction - PS Module

| Field | Value |
|---|---|
| **Sigma ID** | `fe5ce7eb-dad8-467c-84a9-31ec23bd644a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218 |
| **Author** | Ensar Şamil, @sblmsrsn, OSCD Community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_syncappvpublishingserver_exe.yml)**

> Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.

```sql
-- ============================================================
-- Title:        SyncAppvPublishingServer Bypass Powershell Restriction - PS Module
-- Sigma ID:     fe5ce7eb-dad8-467c-84a9-31ec23bd644a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218
-- Author:       Ensar Şamil, @sblmsrsn, OSCD Community
-- Date:         2020-10-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_module/posh_pm_syncappvpublishingserver_exe.yml
-- Unmapped:     ContextInfo
-- False Pos:    App-V clients
-- ============================================================
-- UNMAPPED_FIELD: ContextInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-4103')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%SyncAppvPublishingServer.exe%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** App-V clients

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/

---
