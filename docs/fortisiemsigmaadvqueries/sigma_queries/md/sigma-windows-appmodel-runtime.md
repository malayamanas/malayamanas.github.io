# Sigma → FortiSIEM: Windows Appmodel-Runtime

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Sysinternals Tools AppX Versions Execution](#sysinternals-tools-appx-versions-execution)

## Sysinternals Tools AppX Versions Execution

| Field | Value |
|---|---|
| **Sigma ID** | `d29a20b2-be4b-4827-81f2-3d8a59eab5fc` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appmodel_runtime/win_appmodel_runtime_sysinternals_tools_appx_execution.yml)**

> Detects execution of Sysinternals tools via an AppX package.
Attackers could install the Sysinternals Suite to get access to tools such as psexec and procdump to avoid detection based on System paths.


```sql
-- ============================================================
-- Title:        Sysinternals Tools AppX Versions Execution
-- Sigma ID:     d29a20b2-be4b-4827-81f2-3d8a59eab5fc
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appmodel_runtime/win_appmodel_runtime_sysinternals_tools_appx_execution.yml
-- Unmapped:     ImageName
-- False Pos:    Legitimate usage of sysinternals applications from the Windows Store will trigger this. Apply exclusions as needed.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appmodel-runtime
-- UNMAPPED_FIELD: ImageName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '201'
    AND rawEventMsg IN ('procdump.exe', 'psloglist.exe', 'psexec.exe', 'livekd.exe', 'ADExplorer.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of sysinternals applications from the Windows Store will trigger this. Apply exclusions as needed.

**References:**
- https://learn.microsoft.com/en-us/sysinternals/downloads/microsoft-store

---
