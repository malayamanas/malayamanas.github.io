# Sigma → FortiSIEM: Juniper Bgp

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Juniper BGP Missing MD5](#juniper-bgp-missing-md5)

## Juniper BGP Missing MD5

| Field | Value |
|---|---|
| **Sigma ID** | `a7c0ae48-8df8-42bf-91bd-2ea57e2f9d43` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence, collection |
| **MITRE Techniques** | T1078, T1110, T1557 |
| **Author** | Tim Brown |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/juniper/bgp/juniper_bgp_missing_md5.yml)**

> Detects juniper BGP missing MD5 digest. Which may be indicative of brute force attacks to manipulate routing.

```sql
-- ============================================================
-- Title:        Juniper BGP Missing MD5
-- Sigma ID:     a7c0ae48-8df8-42bf-91bd-2ea57e2f9d43
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence, collection | T1078, T1110, T1557
-- Author:       Tim Brown
-- Date:         2023-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/juniper/bgp/juniper_bgp_missing_md5.yml
-- Unmapped:     
-- False Pos:    Unlikely. Except due to misconfigurations
-- ============================================================
-- UNMAPPED_LOGSOURCE: juniper/bgp
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
  AND (rawEventMsg LIKE '%:179%' OR rawEventMsg LIKE '%missing MD5 digest%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely. Except due to misconfigurations

**References:**
- https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf

---
