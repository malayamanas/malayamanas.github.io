# Sigma → FortiSIEM: Linux Guacamole

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Guacamole Two Users Sharing Session Anomaly](#guacamole-two-users-sharing-session-anomaly)

## Guacamole Two Users Sharing Session Anomaly

| Field | Value |
|---|---|
| **Sigma ID** | `1edd77db-0669-4fef-9598-165bda82826d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1212 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/guacamole/lnx_guacamole_susp_guacamole.yml)**

> Detects suspicious session with two users present

```sql
-- ============================================================
-- Title:        Guacamole Two Users Sharing Session Anomaly
-- Sigma ID:     1edd77db-0669-4fef-9598-165bda82826d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1212
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2020-07-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/guacamole/lnx_guacamole_susp_guacamole.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux/guacamole

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%(2 users now present)%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://research.checkpoint.com/2020/apache-guacamole-rce/

---
