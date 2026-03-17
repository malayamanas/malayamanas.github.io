# Sigma → FortiSIEM: Windows Sysmon Error

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Sysmon Configuration Error](#sysmon-configuration-error)

## Sysmon Configuration Error

| Field | Value |
|---|---|
| **Sigma ID** | `815cd91b-7dbc-4247-841a-d7dd1392b0a8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_config_modification_error.yml)**

> Detects when an adversary is trying to hide it's action from Sysmon logging based on error messages

```sql
-- ============================================================
-- Title:        Sysmon Configuration Error
-- Sigma ID:     815cd91b-7dbc-4247-841a-d7dd1392b0a8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564
-- Author:       frack113
-- Date:         2021-06-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_config_modification_error.yml
-- Unmapped:     Description
-- False Pos:    Legitimate administrative action
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/sysmon_error
-- UNMAPPED_FIELD: Description

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Failed to open service configuration with error%' OR rawEventMsg LIKE '%Failed to connect to the driver to update configuration%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative action

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://talesfrominfosec.blogspot.com/2017/12/killing-sysmon-silently.html

---
