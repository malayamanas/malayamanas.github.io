# Sigma → FortiSIEM: Sql Application

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious SQL Error Messages](#suspicious-sql-error-messages)

## Suspicious SQL Error Messages

| Field | Value |
|---|---|
| **Sigma ID** | `8a670c6d-7189-4b1c-8017-a417ca84a086` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Bjoern Kimminich |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/sql/app_sqlinjection_errors.yml)**

> Detects SQL error messages that indicate probing for an injection attack

```sql
-- ============================================================
-- Title:        Suspicious SQL Error Messages
-- Sigma ID:     8a670c6d-7189-4b1c-8017-a417ca84a086
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Bjoern Kimminich
-- Date:         2017-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/sql/app_sqlinjection_errors.yml
-- Unmapped:     (none)
-- False Pos:    A syntax error in MySQL also occurs in non-dynamic (safe) queries if there is an empty in() clause, that may often be the case.
-- ============================================================
-- UNMAPPED_LOGSOURCE: sql/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%quoted string not properly terminated%' OR rawEventMsg LIKE '%You have an error in your SQL syntax%' OR rawEventMsg LIKE '%Unclosed quotation mark%' OR rawEventMsg LIKE '%near "*": syntax error%' OR rawEventMsg LIKE '%SELECTs to the left and right of UNION do not have the same number of result columns%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A syntax error in MySQL also occurs in non-dynamic (safe) queries if there is an empty in() clause, that may often be the case.

**References:**
- http://www.sqlinjection.net/errors

---
