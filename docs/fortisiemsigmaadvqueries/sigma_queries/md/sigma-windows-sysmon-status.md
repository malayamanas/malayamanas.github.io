# Sigma → FortiSIEM: Windows Sysmon Status

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Sysmon Configuration Modification](#sysmon-configuration-modification)

## Sysmon Configuration Modification

| Field | Value |
|---|---|
| **Sigma ID** | `1f2b5353-573f-4880-8e33-7d04dcf97744` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_config_modification_status.yml)**

> Detects when an attacker tries to hide from Sysmon by disabling or stopping it

```sql
-- ============================================================
-- Title:        Sysmon Configuration Modification
-- Sigma ID:     1f2b5353-573f-4880-8e33-7d04dcf97744
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564
-- Author:       frack113
-- Date:         2021-06-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_config_modification_status.yml
-- Unmapped:     State
-- False Pos:    Legitimate administrative action
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/sysmon_status
-- UNMAPPED_FIELD: State

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND NOT (rawEventMsg = 'Started')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative action

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html

---
