# Sigma → FortiSIEM: Windows File Change

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Unusual File Modification by dns.exe](#unusual-file-modification-by-dnsexe)

## Unusual File Modification by dns.exe

| Field | Value |
|---|---|
| **Sigma ID** | `9f383dc0-fdeb-4d56-acbc-9f9f4f8f20f3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | Tim Rauch (Nextron Systems), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_change/file_change_win_unusual_modification_by_dns_exe.yml)**

> Detects an unexpected file being modified by dns.exe which my indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)

```sql
-- ============================================================
-- Title:        Unusual File Modification by dns.exe
-- Sigma ID:     9f383dc0-fdeb-4d56-acbc-9f9f4f8f20f3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133
-- Author:       Tim Rauch (Nextron Systems), Elastic (idea)
-- Date:         2022-09-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_change/file_change_win_unusual_modification_by_dns_exe.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_change

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
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
