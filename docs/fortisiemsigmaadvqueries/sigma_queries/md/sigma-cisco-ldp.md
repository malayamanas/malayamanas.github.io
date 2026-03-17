# Sigma → FortiSIEM: Cisco Ldp

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Cisco LDP Authentication Failures](#cisco-ldp-authentication-failures)

## Cisco LDP Authentication Failures

| Field | Value |
|---|---|
| **Sigma ID** | `50e606bf-04ce-4ca7-9d54-3449494bbd4b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence, collection |
| **MITRE Techniques** | T1078, T1110, T1557 |
| **Author** | Tim Brown |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/ldp/cisco_ldp_md5_auth_failed.yml)**

> Detects LDP failures which may be indicative of brute force attacks to manipulate MPLS labels

```sql
-- ============================================================
-- Title:        Cisco LDP Authentication Failures
-- Sigma ID:     50e606bf-04ce-4ca7-9d54-3449494bbd4b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence, collection | T1078, T1110, T1557
-- Author:       Tim Brown
-- Date:         2023-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/ldp/cisco_ldp_md5_auth_failed.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely. Except due to misconfigurations
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/ldp

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%LDP%'
  AND rawEventMsg LIKE '%SOCKET\_TCP\_PACKET\_MD5\_AUTHEN\_FAIL%' OR rawEventMsg LIKE '%TCPMD5AuthenFail%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely. Except due to misconfigurations

**References:**
- https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf

---
