# Sigma → FortiSIEM: Windows Iis-Configuration

> 4 rules · Generated 2026-03-17

## Table of Contents

- [ETW Logging/Processing Option Disabled On IIS Server](#etw-loggingprocessing-option-disabled-on-iis-server)
- [HTTP Logging Disabled On IIS Server](#http-logging-disabled-on-iis-server)
- [New Module Module Added To IIS Server](#new-module-module-added-to-iis-server)
- [Previously Installed IIS Module Was Removed](#previously-installed-iis-module-was-removed)

## ETW Logging/Processing Option Disabled On IIS Server

| Field | Value |
|---|---|
| **Sigma ID** | `a5b40a90-baf5-4bf7-a6f7-373494881d22` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.002, T1505.004 |
| **Author** | frack113, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_logging_etw_disabled.yml)**

> Detects changes to of the IIS server configuration in order to disable/remove the ETW logging/processing option.

```sql
-- ============================================================
-- Title:        ETW Logging/Processing Option Disabled On IIS Server
-- Sigma ID:     a5b40a90-baf5-4bf7-a6f7-373494881d22
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1562.002, T1505.004
-- Author:       frack113, Nasreddine Bencherchali
-- Date:         2024-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_logging_etw_disabled.yml
-- Unmapped:     Configuration, OldValue
-- False Pos:    Legitimate administrator activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/iis-configuration
-- UNMAPPED_FIELD: Configuration
-- UNMAPPED_FIELD: OldValue

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
  AND (winEventId = '29'
    AND rawEventMsg LIKE '%@logTargetW3C'
    AND rawEventMsg LIKE '%ETW%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity

**References:**
- https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis
- https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
- https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/

---

## HTTP Logging Disabled On IIS Server

| Field | Value |
|---|---|
| **Sigma ID** | `e8ebd53a-30c2-45bd-81bb-74befba07bdb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.002, T1505.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_logging_http_disabled.yml)**

> Detects changes to of the IIS server configuration in order to disable HTTP logging for successful requests.

```sql
-- ============================================================
-- Title:        HTTP Logging Disabled On IIS Server
-- Sigma ID:     e8ebd53a-30c2-45bd-81bb-74befba07bdb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1562.002, T1505.004
-- Author:       frack113
-- Date:         2024-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_logging_http_disabled.yml
-- Unmapped:     Configuration, NewValue
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/iis-configuration
-- UNMAPPED_FIELD: Configuration
-- UNMAPPED_FIELD: NewValue

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
  AND (winEventId = '29'
    AND rawEventMsg = '/system.webServer/httpLogging/@dontLog'
    AND rawEventMsg = 'true')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis
- https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
- https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httplogging

---

## New Module Module Added To IIS Server

| Field | Value |
|---|---|
| **Sigma ID** | `dd857d3e-0c6e-457b-9b48-e82ae7f86bd7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.002, T1505.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_module_added.yml)**

> Detects the addition of a new module to an IIS server.

```sql
-- ============================================================
-- Title:        New Module Module Added To IIS Server
-- Sigma ID:     dd857d3e-0c6e-457b-9b48-e82ae7f86bd7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1562.002, T1505.004
-- Author:       frack113
-- Date:         2024-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_module_added.yml
-- Unmapped:     Configuration
-- False Pos:    Legitimate administrator activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/iis-configuration
-- UNMAPPED_FIELD: Configuration

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
  AND (winEventId = '29'
    AND rawEventMsg LIKE '%/system.webServer/modules/add%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity

**References:**
- https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis
- https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
- https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
- https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/iis-modules-overview

---

## Previously Installed IIS Module Was Removed

| Field | Value |
|---|---|
| **Sigma ID** | `9e1a1fdf-ee58-40ce-8e15-b66ca5a80e1f` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.002, T1505.004 |
| **Author** | Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_module_removed.yml)**

> Detects the removal of a previously installed IIS module.

```sql
-- ============================================================
-- Title:        Previously Installed IIS Module Was Removed
-- Sigma ID:     9e1a1fdf-ee58-40ce-8e15-b66ca5a80e1f
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1562.002, T1505.004
-- Author:       Nasreddine Bencherchali
-- Date:         2024-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/iis-configuration/win_iis_module_removed.yml
-- Unmapped:     Configuration
-- False Pos:    Legitimate administrator activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/iis-configuration
-- UNMAPPED_FIELD: Configuration

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
  AND (winEventId = '29'
    AND rawEventMsg LIKE '%/system.webServer/modules/remove%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity

**References:**
- https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis
- https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
- https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
- https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/iis-modules-overview

---
