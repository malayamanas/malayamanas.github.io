# Sigma → FortiSIEM:  Firewall

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Cleartext Protocol Usage](#cleartext-protocol-usage)

## Cleartext Protocol Usage

| Field | Value |
|---|---|
| **Sigma ID** | `d7fb8f0e-bd5f-45c2-b467-19571c490d7e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | Alexandr Yampolskyi, SOC Prime, Tim Shelton |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/firewall/net_firewall_cleartext_protocols.yml)**

> Ensure that all account usernames and authentication credentials are transmitted across networks using encrypted channels.
Ensure that an encryption is used for all sensitive information in transit. Ensure that an encrypted channels is used for all administrative account access.


```sql
-- ============================================================
-- Title:        Cleartext Protocol Usage
-- Sigma ID:     d7fb8f0e-bd5f-45c2-b467-19571c490d7e
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        (none)
-- Author:       Alexandr Yampolskyi, SOC Prime, Tim Shelton
-- Date:         2019-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/firewall/net_firewall_cleartext_protocols.yml
-- Unmapped:     dst_port
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: firewall
-- UNMAPPED_FIELD: dst_port

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('8080', '21', '80', '23', '50000', '1521', '27017', '3306', '1433', '11211', '15672', '5900', '5901', '5902', '5903', '5904')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisecurity.org/controls/cis-controls-list/
- https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf
- https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf

---
