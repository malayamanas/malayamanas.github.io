# Sigma → FortiSIEM: Windows Wmi

> 1 rule · Generated 2026-03-17

## Table of Contents

- [WMI Persistence](#wmi-persistence)

## WMI Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `0b7889b4-5577-4521-a60a-3376ee7f9f7b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | Florian Roth (Nextron Systems), Gleb Sukhodolskiy, Timur Zinniatullin oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/wmi/win_wmi_persistence.yml)**

> Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.

```sql
-- ============================================================
-- Title:        WMI Persistence
-- Sigma ID:     0b7889b4-5577-4521-a60a-3376ee7f9f7b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       Florian Roth (Nextron Systems), Gleb Sukhodolskiy, Timur Zinniatullin oscd.community
-- Date:         2017-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/wmi/win_wmi_persistence.yml
-- Unmapped:     Provider, Query, PossibleCause
-- False Pos:    Unknown (data set is too small; further testing needed)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/wmi
-- UNMAPPED_FIELD: Provider
-- UNMAPPED_FIELD: Query
-- UNMAPPED_FIELD: PossibleCause

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ActiveScriptEventConsumer%' OR rawEventMsg LIKE '%CommandLineEventConsumer%' OR rawEventMsg LIKE '%CommandLineTemplate%'
  OR NOT ((rawEventMsg = 'SCM Event Provider'
    AND rawEventMsg = 'select * from MSFT_SCMEventLogEvent'
    AND user = 'S-1-5-32-544'
    AND rawEventMsg = 'Permanent'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown (data set is too small; further testing needed)

**References:**
- https://twitter.com/mattifestation/status/899646620148539397
- https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/

---
