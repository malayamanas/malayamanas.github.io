# Sigma → FortiSIEM: Windows Ps Classic Start

> 9 rules · Generated 2026-03-17

## Table of Contents

- [Nslookup PowerShell Download Cradle](#nslookup-powershell-download-cradle)
- [Delete Volume Shadow Copies Via WMI With PowerShell](#delete-volume-shadow-copies-via-wmi-with-powershell)
- [PowerShell Downgrade Attack - PowerShell](#powershell-downgrade-attack-powershell)
- [PowerShell Called from an Executable Version Mismatch](#powershell-called-from-an-executable-version-mismatch)
- [Netcat The Powershell Version](#netcat-the-powershell-version)
- [Remote PowerShell Session (PS Classic)](#remote-powershell-session-ps-classic)
- [Renamed Powershell Under Powershell Channel](#renamed-powershell-under-powershell-channel)
- [Suspicious PowerShell Download](#suspicious-powershell-download)
- [Use Get-NetTCPConnection](#use-get-nettcpconnection)

## Nslookup PowerShell Download Cradle

| Field | Value |
|---|---|
| **Sigma ID** | `999bff6d-dc15-44c9-9f5c-e1051bfc86e1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Sai Prashanth Pulisetti @pulisettis, Aishwarya Singam |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_abuse_nslookup_with_dns_records.yml)**

> Detects a powershell download cradle using nslookup. This cradle uses nslookup to extract payloads from DNS records.

```sql
-- ============================================================
-- Title:        Nslookup PowerShell Download Cradle
-- Sigma ID:     999bff6d-dc15-44c9-9f5c-e1051bfc86e1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Sai Prashanth Pulisetti @pulisettis, Aishwarya Singam
-- Date:         2022-12-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_abuse_nslookup_with_dns_records.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%powershell%' AND rawEventMsg LIKE '%nslookup%' AND rawEventMsg LIKE '%[1]%'
    AND (rawEventMsg LIKE '%-q=txt http%' OR rawEventMsg LIKE '%-querytype=txt http%' OR rawEventMsg LIKE '%-type=txt http%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/Alh4zr3d/status/1566489367232651264

---

## Delete Volume Shadow Copies Via WMI With PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `87df9ee1-5416-453a-8a08-e8d4a51e9ce1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml)**

> Shadow Copies deletion using operating systems utilities via PowerShell

```sql
-- ============================================================
-- Title:        Delete Volume Shadow Copies Via WMI With PowerShell
-- Sigma ID:     87df9ee1-5416-453a-8a08-e8d4a51e9ce1
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        impact | T1490
-- Author:       frack113
-- Date:         2021-06-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Get-WmiObject%' AND rawEventMsg LIKE '%Win32\_ShadowCopy%'
    AND (rawEventMsg LIKE '%Delete()%' OR rawEventMsg LIKE '%Remove-WmiObject%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md
- https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods

---

## PowerShell Downgrade Attack - PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `6331d09b-4785-4c13-980f-f96661356249` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems), Lee Holmes (idea), Harish Segar (improvements) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml)**

> Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0

```sql
-- ============================================================
-- Title:        PowerShell Downgrade Attack - PowerShell
-- Sigma ID:     6331d09b-4785-4c13-980f-f96661356249
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems), Lee Holmes (idea), Harish Segar (improvements)
-- Date:         2017-03-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%EngineVersion=2.%'
  AND NOT (rawEventMsg LIKE '%HostVersion=2.%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/

---

## PowerShell Called from an Executable Version Mismatch

| Field | Value |
|---|---|
| **Sigma ID** | `c70e019b-1479-4b65-b0cc-cd0c6093a599` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Sean Metcalf (source), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml)**

> Detects PowerShell called from an executable by the version mismatch method

```sql
-- ============================================================
-- Title:        PowerShell Called from an Executable Version Mismatch
-- Sigma ID:     c70e019b-1479-4b65-b0cc-cd0c6093a599
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Sean Metcalf (source), Florian Roth (Nextron Systems)
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%EngineVersion=2.%' OR rawEventMsg LIKE '%EngineVersion=4.%' OR rawEventMsg LIKE '%EngineVersion=5.%')
  AND rawEventMsg LIKE '%HostVersion=3.%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://adsecurity.org/?p=2921

---

## Netcat The Powershell Version

| Field | Value |
|---|---|
| **Sigma ID** | `c5b20776-639a-49bf-94c7-84f912b91c15` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1095 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_powercat.yml)**

> Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network

```sql
-- ============================================================
-- Title:        Netcat The Powershell Version
-- Sigma ID:     c5b20776-639a-49bf-94c7-84f912b91c15
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1095
-- Author:       frack113
-- Date:         2021-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_powercat.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%powercat %' OR rawEventMsg LIKE '%powercat.ps1%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://nmap.org/ncat/
- https://github.com/besimorhino/powercat
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1095/T1095.md

---

## Remote PowerShell Session (PS Classic)

| Field | Value |
|---|---|
| **Sigma ID** | `60167e5c-84b2-4c95-a7ac-86281f27c445` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1021.006 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_remote_powershell_session.yml)**

> Detects remote PowerShell sessions

```sql
-- ============================================================
-- Title:        Remote PowerShell Session (PS Classic)
-- Sigma ID:     60167e5c-84b2-4c95-a7ac-86281f27c445
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1059.001, T1021.006
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_remote_powershell_session.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use remote PowerShell sessions
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%HostName=ServerRemoteHost%' AND rawEventMsg LIKE '%wsmprovhost.exe%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use remote PowerShell sessions

**References:**
- https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html

---

## Renamed Powershell Under Powershell Channel

| Field | Value |
|---|---|
| **Sigma ID** | `30a8cb77-8eb3-4cfb-8e79-ad457c5a4592` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1036.003 |
| **Author** | Harish Segar, frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_renamed_powershell.yml)**

> Detects a renamed Powershell execution, which is a common technique used to circumvent security controls and bypass detection logic that's dependent on process names and process paths.


```sql
-- ============================================================
-- Title:        Renamed Powershell Under Powershell Channel
-- Sigma ID:     30a8cb77-8eb3-4cfb-8e79-ad457c5a4592
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1059.001, T1036.003
-- Author:       Harish Segar, frack113
-- Date:         2020-06-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_renamed_powershell.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%HostName=ConsoleHost%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

---

## Suspicious PowerShell Download

| Field | Value |
|---|---|
| **Sigma ID** | `3236fcd0-b7e3-4433-b4f8-86ad61a9af2d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_susp_download.yml)**

> Detects suspicious PowerShell download command

```sql
-- ============================================================
-- Title:        Suspicious PowerShell Download
-- Sigma ID:     3236fcd0-b7e3-4433-b4f8-86ad61a9af2d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_susp_download.yml
-- Unmapped:     (none)
-- False Pos:    PowerShell scripts that download content from the Internet
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%.DownloadFile(%' OR rawEventMsg LIKE '%.DownloadString(%')
  AND rawEventMsg LIKE '%Net.WebClient%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** PowerShell scripts that download content from the Internet

**References:**
- https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-exploits-proxyshell-in-attack.html

---

## Use Get-NetTCPConnection

| Field | Value |
|---|---|
| **Sigma ID** | `b366adb4-d63d-422d-8a2c-186463b5ded0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1049 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_susp_get_nettcpconnection.yml)**

> Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

```sql
-- ============================================================
-- Title:        Use Get-NetTCPConnection
-- Sigma ID:     b366adb4-d63d-422d-8a2c-186463b5ded0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1049
-- Author:       frack113
-- Date:         2021-12-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_susp_get_nettcpconnection.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ps_classic_start

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Get-NetTCPConnection%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell

---
