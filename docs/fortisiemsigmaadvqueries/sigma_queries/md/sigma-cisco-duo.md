# Sigma → FortiSIEM: Cisco Duo

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Cisco Duo Successful MFA Authentication Via Bypass Code](#cisco-duo-successful-mfa-authentication-via-bypass-code)

## Cisco Duo Successful MFA Authentication Via Bypass Code

| Field | Value |
|---|---|
| **Sigma ID** | `6f7e1c10-2dc9-4312-adb6-9574ff09a5c8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nikita Khalimonenkov |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/cisco_duo/cisco_duo_mfa_bypass_via_bypass_code.yml)**

> Detects when a successful MFA authentication occurs due to the use of a bypass code.
A bypass code is a temporary passcode created by an administrator for a specific user to access a Duo-protected application. These are generally used as "backup codes," so that enrolled users who are having problems with their mobile devices (e.g., mobile service is disrupted, the device is lost or stolen, etc.) or who temporarily can't use their enrolled devices (on a plane without mobile data services) can still access their Duo-protected systems.


```sql
-- ============================================================
-- Title:        Cisco Duo Successful MFA Authentication Via Bypass Code
-- Sigma ID:     6f7e1c10-2dc9-4312-adb6-9574ff09a5c8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nikita Khalimonenkov
-- Date:         2024-04-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/cisco_duo/cisco_duo_mfa_bypass_via_bypass_code.yml
-- Unmapped:     event_type, reason
-- False Pos:    Legitimate user that was assigned on purpose to a bypass group
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/duo
-- UNMAPPED_FIELD: event_type
-- UNMAPPED_FIELD: reason

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'authentication'
    AND rawEventMsg = 'bypass_user')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user that was assigned on purpose to a bypass group

**References:**
- https://duo.com/docs/adminapi#logs
- https://help.duo.com/s/article/6327?language=en_US

---
