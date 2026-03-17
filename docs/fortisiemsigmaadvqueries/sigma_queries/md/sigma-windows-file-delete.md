# Sigma → FortiSIEM: Windows File Delete

> 12 rules · Generated 2026-03-17

## Table of Contents

- [Backup Files Deleted](#backup-files-deleted)
- [EventLog EVTX File Deleted](#eventlog-evtx-file-deleted)
- [Exchange PowerShell Cmdlet History Deleted](#exchange-powershell-cmdlet-history-deleted)
- [IIS WebServer Access Logs Deleted](#iis-webserver-access-logs-deleted)
- [Process Deletion of Its Own Executable](#process-deletion-of-its-own-executable)
- [PowerShell Console History Logs Deleted](#powershell-console-history-logs-deleted)
- [Prefetch File Deleted](#prefetch-file-deleted)
- [TeamViewer Log File Deleted](#teamviewer-log-file-deleted)
- [Tomcat WebServer Logs Deleted](#tomcat-webserver-logs-deleted)
- [File Deleted Via Sysinternals SDelete](#file-deleted-via-sysinternals-sdelete)
- [Unusual File Deletion by Dns.exe](#unusual-file-deletion-by-dnsexe)
- [ADS Zone.Identifier Deleted By Uncommon Application](#ads-zoneidentifier-deleted-by-uncommon-application)

## Backup Files Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `06125661-3814-4e03-bfa2-1e4411c60ac3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_backup_file.yml)**

> Detects deletion of files with extensions often used for backup files. Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.

```sql
-- ============================================================
-- Title:        Backup Files Deleted
-- Sigma ID:     06125661-3814-4e03-bfa2-1e4411c60ac3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       frack113
-- Date:         2022-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_backup_file.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\cmd.exe' OR procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe' OR procName LIKE '%\\wt.exe' OR procName LIKE '%\\rundll32.exe' OR procName LIKE '%\\regsvr32.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.VHD' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bac' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bak' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wbcat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bkf' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.set' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.win' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dsk')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-6---windows---delete-backup-files

---

## EventLog EVTX File Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `63c779ba-f638-40a0-a593-ddd45e8b1ddc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_event_log_files.yml)**

> Detects the deletion of the event log files which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        EventLog EVTX File Deleted
-- Sigma ID:     63c779ba-f638-40a0-a593-ddd45e8b1ddc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_event_log_files.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\winevt\\Logs\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.evtx'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Exchange PowerShell Cmdlet History Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `a55349d8-9588-4c5a-8e3b-1925fe2a4ffe` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.yml)**

> Detects the deletion of the Exchange PowerShell cmdlet History logs which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        Exchange PowerShell Cmdlet History Deleted
-- Sigma ID:     a55349d8-9588-4c5a-8e3b-1925fe2a4ffe
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.yml
-- Unmapped:     (none)
-- False Pos:    Possible FP during log rotation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '\\Logging\\CmdletInfra\\LocalPowerShell\\Cmdlet\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_Cmdlet\_%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Possible FP during log rotation

**References:**
- https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/

---

## IIS WebServer Access Logs Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `3eb8c339-a765-48cc-a150-4364c04652bf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Tim Rauch (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_iis_access_logs.yml)**

> Detects the deletion of IIS WebServer access logs which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        IIS WebServer Access Logs Deleted
-- Sigma ID:     3eb8c339-a765-48cc-a150-4364c04652bf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Tim Rauch (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_iis_access_logs.yml
-- Unmapped:     (none)
-- False Pos:    During uninstallation of the IIS service; During log rotation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\inetpub\\logs\\LogFiles\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.log'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** During uninstallation of the IIS service; During log rotation

**References:**
- https://www.elastic.co/guide/en/security/current/webserver-access-logs-deleted.html

---

## Process Deletion of Its Own Executable

| Field | Value |
|---|---|
| **Sigma ID** | `f01d1f70-cd41-42ec-9c0b-26dd9c22bf29` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Max Altgelt (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_own_image.yml)**

> Detects the deletion of a process's executable by itself. This is usually not possible without workarounds and may be used by malware to hide its traces.


```sql
-- ============================================================
-- Title:        Process Deletion of Its Own Executable
-- Sigma ID:     f01d1f70-cd41-42ec-9c0b-26dd9c22bf29
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Max Altgelt (Nextron Systems)
-- Date:         2024-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_own_image.yml
-- Unmapped:     (none)
-- False Pos:    Some false positives are to be expected from uninstallers.
-- ============================================================
-- UNSUPPORTED_MODIFIER: fieldref

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Image%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives are to be expected from uninstallers.

**References:**
- https://github.com/joaoviictorti/RustRedOps/tree/ce04369a246006d399e8c61d9fe0e6b34f988a49/Self_Deletion

---

## PowerShell Console History Logs Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `ff301988-c231-4bd0-834c-ac9d73b86586` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_powershell_command_history.yml)**

> Detects the deletion of the PowerShell console History logs which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        PowerShell Console History Logs Deleted
-- Sigma ID:     ff301988-c231-4bd0-834c-ac9d73b86586
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_powershell_command_history.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PSReadLine\\ConsoleHost\_history.txt')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Prefetch File Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `0a1f9d29-6465-4776-b091-7f43b26e4c89` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.004 |
| **Author** | Cedric MAURUGEON |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_prefetch.yml)**

> Detects the deletion of a prefetch file which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        Prefetch File Deleted
-- Sigma ID:     0a1f9d29-6465-4776-b091-7f43b26e4c89
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.004
-- Author:       Cedric MAURUGEON
-- Date:         2021-09-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_prefetch.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\Prefetch\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pf'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research
- https://www.group-ib.com/blog/hunting-for-ttps-with-prefetch-files/

---

## TeamViewer Log File Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `b1decb61-ed83-4339-8e95-53ea51901720` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1070.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_teamviewer_logs.yml)**

> Detects the deletion of the TeamViewer log files which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        TeamViewer Log File Deleted
-- Sigma ID:     b1decb61-ed83-4339-8e95-53ea51901720
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1070.004
-- Author:       frack113
-- Date:         2022-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_teamviewer_logs.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TeamViewer\_%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.log'))
  AND NOT (procName = 'C:\Windows\system32\svchost.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md

---

## Tomcat WebServer Logs Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `270185ff-5f50-4d6d-a27f-24c3b8c9fef8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_tomcat_logs.yml)**

> Detects the deletion of tomcat WebServer logs which may indicate an attempt to destroy forensic evidence

```sql
-- ============================================================
-- Title:        Tomcat WebServer Logs Deleted
-- Sigma ID:     270185ff-5f50-4d6d-a27f-24c3b8c9fef8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_delete_tomcat_logs.yml
-- Unmapped:     (none)
-- False Pos:    During uninstallation of the tomcat server; During log rotation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Tomcat%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\logs\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%catalina.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_access\_log.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%localhost.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** During uninstallation of the tomcat server; During log rotation

**References:**
- Internal Research
- https://linuxhint.com/view-tomcat-logs-windows/

---

## File Deleted Via Sysinternals SDelete

| Field | Value |
|---|---|
| **Sigma ID** | `6ddab845-b1b8-49c2-bbf7-1a11967f64bc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.004 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_sysinternals_sdelete_file_deletion.yml)**

> Detects the deletion of files by the Sysinternals SDelete utility. It looks for the common name pattern used to rename files.

```sql
-- ============================================================
-- Title:        File Deleted Via Sysinternals SDelete
-- Sigma ID:     6ddab845-b1b8-49c2-bbf7-1a11967f64bc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.004
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_sysinternals_sdelete_file_deletion.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.AAA' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ZZZ'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/9
- https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/4.B.4_83D62033-105A-4A02-8B75-DAB52D8D51EC.md

---

## Unusual File Deletion by Dns.exe

| Field | Value |
|---|---|
| **Sigma ID** | `8f0b1fb1-9bd4-4e74-8cdf-a8de4d2adfd0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | Tim Rauch (Nextron Systems), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_unusual_deletion_by_dns_exe.yml)**

> Detects an unexpected file being deleted by dns.exe which my indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)

```sql
-- ============================================================
-- Title:        Unusual File Deletion by Dns.exe
-- Sigma ID:     8f0b1fb1-9bd4-4e74-8cdf-a8de4d2adfd0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133
-- Author:       Tim Rauch (Nextron Systems), Elastic (idea)
-- Date:         2022-09-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_unusual_deletion_by_dns_exe.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\dns.exe'
  AND NOT (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\dns.log')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.elastic.co/guide/en/security/current/unusual-file-modification-by-dns-exe.html

---

## ADS Zone.Identifier Deleted By Uncommon Application

| Field | Value |
|---|---|
| **Sigma ID** | `3109530e-ab47-4cc6-a953-cac5ebcc93ae` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.004 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_zone_identifier_ads_uncommon.yml)**

> Detects the deletion of the "Zone.Identifier" ADS by an uncommon process. Attackers can leverage this in order to bypass security restrictions that make use of the ADS such as Microsoft Office apps.

```sql
-- ============================================================
-- Title:        ADS Zone.Identifier Deleted By Uncommon Application
-- Sigma ID:     3109530e-ab47-4cc6-a953-cac5ebcc93ae
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.004
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_delete/file_delete_win_zone_identifier_ads_uncommon.yml
-- Unmapped:     (none)
-- False Pos:    Other third party applications not listed.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-23-File-Delete')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:Zone.Identifier')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other third party applications not listed.

**References:**
- https://securityliterate.com/how-malware-abuses-the-zone-identifier-to-circumvent-detection-and-analysis/
- Internal Research

---
