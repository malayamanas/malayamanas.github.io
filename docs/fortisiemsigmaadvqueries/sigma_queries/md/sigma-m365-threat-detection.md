# Sigma → FortiSIEM: M365 Threat Detection

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Activity from Suspicious IP Addresses](#activity-from-suspicious-ip-addresses)

## Activity from Suspicious IP Addresses

| Field | Value |
|---|---|
| **Sigma ID** | `a3501e8e-af9e-43c6-8cd6-9360bdaae498` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1573 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_detection/microsoft365_from_susp_ip_addresses.yml)**

> Detects when a Microsoft Cloud App Security reported users were active from an IP address identified as risky by Microsoft Threat Intelligence.
These IP addresses are involved in malicious activities, such as Botnet C&C, and may indicate compromised account.


```sql
-- ============================================================
-- Title:        Activity from Suspicious IP Addresses
-- Sigma ID:     a3501e8e-af9e-43c6-8cd6-9360bdaae498
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1573
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_detection/microsoft365_from_susp_ip_addresses.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_detection
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Activity from suspicious IP addresses'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---
