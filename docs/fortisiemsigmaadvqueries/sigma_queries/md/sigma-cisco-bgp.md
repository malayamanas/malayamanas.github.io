# Sigma → FortiSIEM: Cisco Bgp

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Cisco BGP Authentication Failures](#cisco-bgp-authentication-failures)

## Cisco BGP Authentication Failures

| Field | Value |
|---|---|
| **Sigma ID** | `56fa3cd6-f8d6-4520-a8c7-607292971886` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence, collection |
| **MITRE Techniques** | T1078, T1110, T1557 |
| **Author** | Tim Brown |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/bgp/cisco_bgp_md5_auth_failed.yml)**

> Detects BGP failures which may be indicative of brute force attacks to manipulate routing

```sql
-- ============================================================
-- Title:        Cisco BGP Authentication Failures
-- Sigma ID:     56fa3cd6-f8d6-4520-a8c7-607292971886
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence, collection | T1078, T1110, T1557
-- Author:       Tim Brown
-- Date:         2023-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/bgp/cisco_bgp_md5_auth_failed.yml
-- Unmapped:     
-- False Pos:    Unlikely. Except due to misconfigurations
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/bgp
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
  AND (rawEventMsg LIKE '%:179%' OR rawEventMsg LIKE '%IP-TCP-3-BADAUTH%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely. Except due to misconfigurations

**References:**
- https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf

---
