# Sigma → FortiSIEM:  Database

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious SQL Query](#suspicious-sql-query)

## Suspicious SQL Query

| Field | Value |
|---|---|
| **Sigma ID** | `d84c0ded-edd7-4123-80ed-348bb3ccc4d5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration, persistence |
| **MITRE Techniques** | T1190, T1505.001 |
| **Author** | @juju4 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/category/database/db_anomalous_query.yml)**

> Detects suspicious SQL query keywrods that are often used during recon, exfiltration or destructive activities. Such as dropping tables and selecting wildcard fields

```sql
-- ============================================================
-- Title:        Suspicious SQL Query
-- Sigma ID:     d84c0ded-edd7-4123-80ed-348bb3ccc4d5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration, persistence | T1190, T1505.001
-- Author:       @juju4
-- Date:         2022-12-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/category/database/db_anomalous_query.yml
-- Unmapped:     (none)
-- False Pos:    Inventory and monitoring activity; Vulnerability scanners; Legitimate applications
-- ============================================================
-- UNMAPPED_LOGSOURCE: database

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%drop%' OR rawEventMsg LIKE '%truncate%' OR rawEventMsg LIKE '%dump%' OR rawEventMsg LIKE '%select \\*%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Inventory and monitoring activity; Vulnerability scanners; Legitimate applications

**References:**
- https://github.com/sqlmapproject/sqlmap

---
