# Sigma → FortiSIEM:  Nginx

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Nginx Core Dump](#nginx-core-dump)

## Nginx Core Dump

| Field | Value |
|---|---|
| **Sigma ID** | `59ec40bb-322e-40ab-808d-84fa690d7e56` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1499.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/product/nginx/web_nginx_core_dump.yml)**

> Detects a core dump of a crashing Nginx worker process, which could be a signal of a serious problem or exploitation attempts.

```sql
-- ============================================================
-- Title:        Nginx Core Dump
-- Sigma ID:     59ec40bb-322e-40ab-808d-84fa690d7e56
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1499.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-05-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/product/nginx/web_nginx_core_dump.yml
-- Unmapped:     (none)
-- False Pos:    Serious issues with a configuration or plugin
-- ============================================================
-- UNMAPPED_LOGSOURCE: nginx

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%exited on signal 6 (core dumped)%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Serious issues with a configuration or plugin

**References:**
- https://docs.nginx.com/nginx/admin-guide/monitoring/debugging/#enabling-core-dumps
- https://www.x41-dsec.de/lab/advisories/x41-2021-002-nginx-resolver-copy/

---
