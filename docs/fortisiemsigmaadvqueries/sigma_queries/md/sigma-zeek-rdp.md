# Sigma → FortiSIEM: Zeek Rdp

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Publicly Accessible RDP Service](#publicly-accessible-rdp-service)

## Publicly Accessible RDP Service

| Field | Value |
|---|---|
| **Sigma ID** | `1fc0809e-06bf-4de3-ad52-25e5263b7623` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.001 |
| **Author** | Josh Brower @DefensiveDepth |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_rdp_public_listener.yml)**

> Detects connections from routable IPs to an RDP listener. Which is indicative of a publicly-accessible RDP service.


```sql
-- ============================================================
-- Title:        Publicly Accessible RDP Service
-- Sigma ID:     1fc0809e-06bf-4de3-ad52-25e5263b7623
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.001
-- Author:       Josh Brower @DefensiveDepth
-- Date:         2020-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_rdp_public_listener.yml
-- Unmapped:     id.orig_h
-- False Pos:    Although it is recommended to NOT have RDP exposed to the internet, verify that this is a) allowed b) the server has not already been compromised via some brute force or remote exploit since it has been exposed to the internet. Work to secure the server if you are unable to remove it from being exposed to the internet.
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/rdp
-- UNMAPPED_FIELD: id.orig_h

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND NOT ((isIPAddressInRange(toString(rawEventMsg), '::1/128') OR isIPAddressInRange(toString(rawEventMsg), '10.0.0.0/8') OR isIPAddressInRange(toString(rawEventMsg), '127.0.0.0/8') OR isIPAddressInRange(toString(rawEventMsg), '172.16.0.0/12') OR isIPAddressInRange(toString(rawEventMsg), '192.168.0.0/16') OR isIPAddressInRange(toString(rawEventMsg), '169.254.0.0/16') OR isIPAddressInRange(toString(rawEventMsg), '2620:83:8000::/48') OR isIPAddressInRange(toString(rawEventMsg), 'fc00::/7') OR isIPAddressInRange(toString(rawEventMsg), 'fe80::/10')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Although it is recommended to NOT have RDP exposed to the internet, verify that this is a) allowed b) the server has not already been compromised via some brute force or remote exploit since it has been exposed to the internet. Work to secure the server if you are unable to remove it from being exposed to the internet.

---
