# Sigma → FortiSIEM: Windows Appxpackaging-Om

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious Digital Signature Of AppX Package](#suspicious-digital-signature-of-appx-package)

## Suspicious Digital Signature Of AppX Package

| Field | Value |
|---|---|
| **Sigma ID** | `b5aa7d60-c17e-4538-97de-09029d6cd76b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxpackaging_om/win_appxpackaging_om_sups_appx_signature.yml)**

> Detects execution of AppX packages with known suspicious or malicious signature

```sql
-- ============================================================
-- Title:        Suspicious Digital Signature Of AppX Package
-- Sigma ID:     b5aa7d60-c17e-4538-97de-09029d6cd76b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxpackaging_om/win_appxpackaging_om_sups_appx_signature.yml
-- Unmapped:     subjectName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxpackaging-om
-- UNMAPPED_FIELD: subjectName

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
  AND (winEventId = '157'
    AND rawEventMsg = 'CN=Foresee Consulting Inc., O=Foresee Consulting Inc., L=North York, S=Ontario, C=CA, SERIALNUMBER=1004913-1, OID.1.3.6.1.4.1.311.60.2.1.3=CA, OID.2.5.4.15=Private Organization')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/

---
