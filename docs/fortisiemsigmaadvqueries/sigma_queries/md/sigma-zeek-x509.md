# Sigma → FortiSIEM: Zeek X509

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Default Cobalt Strike Certificate](#default-cobalt-strike-certificate)

## Default Cobalt Strike Certificate

| Field | Value |
|---|---|
| **Sigma ID** | `7100f7e3-92ce-4584-b7b7-01b40d3d4118` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_default_cobalt_strike_certificate.yml)**

> Detects the presence of default Cobalt Strike certificate in the HTTPS traffic

```sql
-- ============================================================
-- Title:        Default Cobalt Strike Certificate
-- Sigma ID:     7100f7e3-92ce-4584-b7b7-01b40d3d4118
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Bhabesh Raj
-- Date:         2021-06-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_default_cobalt_strike_certificate.yml
-- Unmapped:     certificate.serial
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/x509
-- UNMAPPED_FIELD: certificate.serial

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '8BB00EE'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://sergiusechel.medium.com/improving-the-network-based-detection-of-cobalt-strike-c2-servers-in-the-wild-while-reducing-the-6964205f6468

---
