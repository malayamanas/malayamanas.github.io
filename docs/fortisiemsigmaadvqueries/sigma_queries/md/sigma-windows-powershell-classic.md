# Sigma → FortiSIEM: Windows Powershell-Classic

> 3 rules · Generated 2026-03-17

## Table of Contents

- [Potential RemoteFXvGPUDisablement.EXE Abuse](#potential-remotefxvgpudisablementexe-abuse)
- [Zip A Folder With PowerShell For Staging In Temp - PowerShell](#zip-a-folder-with-powershell-for-staging-in-temp-powershell)
- [Suspicious Non PowerShell WSMAN COM Provider](#suspicious-non-powershell-wsman-com-provider)

## Potential RemoteFXvGPUDisablement.EXE Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `f65e22f9-819e-4f96-9c7b-498364ae7a25` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_remotefxvgpudisablement_abuse.yml)**

> Detects PowerShell module creation where the module Contents are set to "function Get-VMRemoteFXPhysicalVideoAdapter". This could be a sign of potential abuse of  the "RemoteFXvGPUDisablement.exe" binary which is known to be vulnerable to module load-order hijacking.

```sql
-- ============================================================
-- Title:        Potential RemoteFXvGPUDisablement.EXE Abuse
-- Sigma ID:     f65e22f9-819e-4f96-9c7b-498364ae7a25
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_remotefxvgpudisablement_abuse.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/powershell-classic

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
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

## Zip A Folder With PowerShell For Staging In Temp - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `71ff406e-b633-4989-96ec-bc49d825a412` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1074.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_susp_zip_compress.yml)**

> Detects PowerShell scripts that make use of the "Compress-Archive" Cmdlet in order to compress folders and files where the output is stored in a potentially suspicious location that is used often by malware for exfiltration.
An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.


```sql
-- ============================================================
-- Title:        Zip A Folder With PowerShell For Staging In Temp - PowerShell
-- Sigma ID:     71ff406e-b633-4989-96ec-bc49d825a412
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1074.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2021-07-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_susp_zip_compress.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/powershell-classic

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Compress-Archive -Path*-DestinationPath $env:TEMP%' OR rawEventMsg LIKE '%Compress-Archive -Path*-DestinationPath*\\AppData\\Local\\Temp\\%' OR rawEventMsg LIKE '%Compress-Archive -Path*-DestinationPath*:\\Windows\\Temp\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1074.001/T1074.001.md
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a

---

## Suspicious Non PowerShell WSMAN COM Provider

| Field | Value |
|---|---|
| **Sigma ID** | `df9a0e0e-fedb-4d6c-8668-d765dfc92aa7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1021.003 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_wsman_com_provider_no_powershell.yml)**

> Detects suspicious use of the WSMAN provider without PowerShell.exe as the host application.

```sql
-- ============================================================
-- Title:        Suspicious Non PowerShell WSMAN COM Provider
-- Sigma ID:     df9a0e0e-fedb-4d6c-8668-d765dfc92aa7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001, T1021.003
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_wsman_com_provider_no_powershell.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/powershell-classic

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ProviderName=WSMan%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/chadtilbury/status/1275851297770610688
- https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
- https://github.com/bohops/WSMan-WinRM

---
