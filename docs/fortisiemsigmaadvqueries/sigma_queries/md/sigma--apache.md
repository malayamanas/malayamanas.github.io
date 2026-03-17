# Sigma → FortiSIEM:  Apache

> 2 rules · Generated 2026-03-17

## Table of Contents

- [Apache Segmentation Fault](#apache-segmentation-fault)
- [Apache Threading Error](#apache-threading-error)

## Apache Segmentation Fault

| Field | Value |
|---|---|
| **Sigma ID** | `1da8ce0b-855d-4004-8860-7d64d42063b1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1499.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/product/apache/web_apache_segfault.yml)**

> Detects a segmentation fault error message caused by a crashing apache worker process

```sql
-- ============================================================
-- Title:        Apache Segmentation Fault
-- Sigma ID:     1da8ce0b-855d-4004-8860-7d64d42063b1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1499.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-02-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/product/apache/web_apache_segfault.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: apache

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%exit signal Segmentation Fault%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://www.securityfocus.com/infocus/1633

---

## Apache Threading Error

| Field | Value |
|---|---|
| **Sigma ID** | `e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190, T1210 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/product/apache/web_apache_threading_error.yml)**

> Detects an issue in apache logs that reports threading related errors

```sql
-- ============================================================
-- Title:        Apache Threading Error
-- Sigma ID:     e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190, T1210
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/product/apache/web_apache_threading_error.yml
-- Unmapped:     (none)
-- False Pos:    3rd party apache modules - https://bz.apache.org/bugzilla/show_bug.cgi?id=46185
-- ============================================================
-- UNMAPPED_LOGSOURCE: apache

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%\_\_pthread\_tpp\_change\_priority: Assertion `new\_prio == -1 || (new\_prio >= fifo\_min\_prio && new\_prio <= fifo\_max\_prio)%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** 3rd party apache modules - https://bz.apache.org/bugzilla/show_bug.cgi?id=46185

**References:**
- https://github.com/hannob/apache-uaf/blob/da40f2be3684c8095ec6066fa68eb5c07a086233/README.md

---
