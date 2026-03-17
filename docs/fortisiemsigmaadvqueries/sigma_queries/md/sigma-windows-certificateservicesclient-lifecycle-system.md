# Sigma → FortiSIEM: Windows Certificateservicesclient-Lifecycle-System

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Certificate Exported From Local Certificate Store](#certificate-exported-from-local-certificate-store)

## Certificate Exported From Local Certificate Store

| Field | Value |
|---|---|
| **Sigma ID** | `58c0bff0-40a0-46e8-b5e8-b734b84d2017` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1649 |
| **Author** | Zach Mathis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml)**

> Detects when an application exports a certificate (and potentially the private key as well) from the local Windows certificate store.

```sql
-- ============================================================
-- Title:        Certificate Exported From Local Certificate Store
-- Sigma ID:     58c0bff0-40a0-46e8-b5e8-b734b84d2017
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1649
-- Author:       Zach Mathis
-- Date:         2023-05-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate application requesting certificate exports will trigger this. Apply additional filters as needed
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/certificateservicesclient-lifecycle-system

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
  AND winEventId = '1007'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate application requesting certificate exports will trigger this. Apply additional filters as needed

**References:**
- https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html

---
