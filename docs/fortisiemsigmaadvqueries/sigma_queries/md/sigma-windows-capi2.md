# Sigma → FortiSIEM: Windows Capi2

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Certificate Private Key Acquired](#certificate-private-key-acquired)

## Certificate Private Key Acquired

| Field | Value |
|---|---|
| **Sigma ID** | `e2b5163d-7deb-4566-9af3-40afea6858c3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1649 |
| **Author** | Zach Mathis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/capi2/win_capi2_acquire_certificate_private_key.yml)**

> Detects when an application acquires a certificate private key

```sql
-- ============================================================
-- Title:        Certificate Private Key Acquired
-- Sigma ID:     e2b5163d-7deb-4566-9af3-40afea6858c3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1649
-- Author:       Zach Mathis
-- Date:         2023-05-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/capi2/win_capi2_acquire_certificate_private_key.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate application requesting certificate exports will trigger this. Apply additional filters as needed
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/capi2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '70'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate application requesting certificate exports will trigger this. Apply additional filters as needed

**References:**
- https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html

---
