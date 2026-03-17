# Sigma → FortiSIEM: Huawei Bgp

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Huawei BGP Authentication Failures](#huawei-bgp-authentication-failures)

## Huawei BGP Authentication Failures

| Field | Value |
|---|---|
| **Sigma ID** | `a557ffe6-ac54-43d2-ae69-158027082350` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence, collection |
| **MITRE Techniques** | T1078, T1110, T1557 |
| **Author** | Tim Brown |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/huawei/bgp/huawei_bgp_auth_failed.yml)**

> Detects BGP failures which may be indicative of brute force attacks to manipulate routing.

```sql
-- ============================================================
-- Title:        Huawei BGP Authentication Failures
-- Sigma ID:     a557ffe6-ac54-43d2-ae69-158027082350
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence, collection | T1078, T1110, T1557
-- Author:       Tim Brown
-- Date:         2023-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/huawei/bgp/huawei_bgp_auth_failed.yml
-- Unmapped:     
-- False Pos:    Unlikely. Except due to misconfigurations
-- ============================================================
-- UNMAPPED_LOGSOURCE: huawei/bgp
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%:179%' OR rawEventMsg LIKE '%BGP\_AUTH\_FAILED%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely. Except due to misconfigurations

**References:**
- https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf

---
