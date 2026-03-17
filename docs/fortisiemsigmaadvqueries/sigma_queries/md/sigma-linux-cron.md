# Sigma → FortiSIEM: Linux Cron

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Modifying Crontab](#modifying-crontab)

## Modifying Crontab

| Field | Value |
|---|---|
| **Sigma ID** | `af202fd3-7bff-4212-a25a-fb34606cfcbe` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.003 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/cron/lnx_cron_crontab_file_modification.yml)**

> Detects suspicious modification of crontab file.

```sql
-- ============================================================
-- Title:        Modifying Crontab
-- Sigma ID:     af202fd3-7bff-4212-a25a-fb34606cfcbe
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.003
-- Author:       Pawel Mazur
-- Date:         2022-04-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/cron/lnx_cron_crontab_file_modification.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate modification of crontab
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux/cron

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%REPLACE%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate modification of crontab

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md

---
