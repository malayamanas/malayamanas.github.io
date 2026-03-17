# Sigma → FortiSIEM: Python Application

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Python SQL Exceptions](#python-sql-exceptions)

## Python SQL Exceptions

| Field | Value |
|---|---|
| **Sigma ID** | `19aefed0-ffd4-47dc-a7fc-f8b1425e84f9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/python/app_python_sql_exceptions.yml)**

> Generic rule for SQL exceptions in Python according to PEP 249

```sql
-- ============================================================
-- Title:        Python SQL Exceptions
-- Sigma ID:     19aefed0-ffd4-47dc-a7fc-f8b1425e84f9
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1190
-- Author:       Thomas Patzke
-- Date:         2017-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/python/app_python_sql_exceptions.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: python/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%DataError%' OR rawEventMsg LIKE '%IntegrityError%' OR rawEventMsg LIKE '%ProgrammingError%' OR rawEventMsg LIKE '%OperationalError%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://www.python.org/dev/peps/pep-0249/#exceptions

---
