# Sigma → FortiSIEM: Windows Applocker

> 1 rule · Generated 2026-03-17

## Table of Contents

- [AppLocker Prevented Application or Script from Running](#applocker-prevented-application-or-script-from-running)

## AppLocker Prevented Application or Script from Running

| Field | Value |
|---|---|
| **Sigma ID** | `401e5d00-b944-11ea-8f9a-00163ecd60ae` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002, T1059.001, T1059.003, T1059.005, T1059.006, T1059.007 |
| **Author** | Pushkarev Dmitry |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml)**

> Detects when AppLocker prevents the execution of an Application, DLL, Script, MSI, or Packaged-App from running.


```sql
-- ============================================================
-- Title:        AppLocker Prevented Application or Script from Running
-- Sigma ID:     401e5d00-b944-11ea-8f9a-00163ecd60ae
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002, T1059.001, T1059.003, T1059.005, T1059.006, T1059.007
-- Author:       Pushkarev Dmitry
-- Date:         2020-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely, since this event notifies about blocked application execution. Tune your applocker rules to avoid blocking legitimate applications.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/applocker

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
  AND winEventId IN ('8004', '8007', '8022', '8025')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely, since this event notifies about blocked application execution. Tune your applocker rules to avoid blocking legitimate applications.

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/what-is-applocker
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/using-event-viewer-with-applocker
- https://nxlog.co/documentation/nxlog-user-guide/applocker.html

---
