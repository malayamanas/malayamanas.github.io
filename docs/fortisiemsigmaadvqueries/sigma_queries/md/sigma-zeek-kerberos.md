# Sigma → FortiSIEM: Zeek Kerberos

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Kerberos Network Traffic RC4 Ticket Encryption](#kerberos-network-traffic-rc4-ticket-encryption)

## Kerberos Network Traffic RC4 Ticket Encryption

| Field | Value |
|---|---|
| **Sigma ID** | `503fe26e-b5f2-4944-a126-eab405cc06e5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1558.003 |
| **Author** | sigma |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_susp_kerberos_rc4.yml)**

> Detects kerberos TGS request using RC4 encryption which may be indicative of kerberoasting

```sql
-- ============================================================
-- Title:        Kerberos Network Traffic RC4 Ticket Encryption
-- Sigma ID:     503fe26e-b5f2-4944-a126-eab405cc06e5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1558.003
-- Author:       sigma
-- Date:         2020-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_susp_kerberos_rc4.yml
-- Unmapped:     request_type, cipher, service
-- False Pos:    Normal enterprise SPN requests activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/kerberos
-- UNMAPPED_FIELD: request_type
-- UNMAPPED_FIELD: cipher
-- UNMAPPED_FIELD: service

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'TGS'
    AND rawEventMsg = 'rc4-hmac')
  AND NOT (rawEventMsg LIKE '$%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Normal enterprise SPN requests activity

**References:**
- https://adsecurity.org/?p=3458

---
