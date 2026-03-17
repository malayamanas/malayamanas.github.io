# Sigma → FortiSIEM: Windows Sysmon

> 4 rules · Generated 2026-03-17

## Table of Contents

- [Sysmon Configuration Change](#sysmon-configuration-change)
- [Sysmon Blocked Executable](#sysmon-blocked-executable)
- [Sysmon Blocked File Shredding](#sysmon-blocked-file-shredding)
- [Sysmon File Executable Creation Detected](#sysmon-file-executable-creation-detected)

## Sysmon Configuration Change

| Field | Value |
|---|---|
| **Sigma ID** | `8ac03a65-6c84-4116-acad-dc1558ff7a77` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_config_modification.yml)**

> Detects a Sysmon configuration change, which could be the result of a legitimate reconfiguration or someone trying manipulate the configuration

```sql
-- ============================================================
-- Title:        Sysmon Configuration Change
-- Sigma ID:     8ac03a65-6c84-4116-acad-dc1558ff7a77
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2022-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_config_modification.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative action
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-16')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '16'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative action

**References:**
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Sysmon Blocked Executable

| Field | Value |
|---|---|
| **Sigma ID** | `23b71bc5-953e-4971-be4c-c896cda73fc2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_file_block_executable.yml)**

> Triggers on any Sysmon "FileBlockExecutable" event, which indicates a violation of the configured block policy

```sql
-- ============================================================
-- Title:        Sysmon Blocked Executable
-- Sigma ID:     23b71bc5-953e-4971-be4c-c896cda73fc2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_file_block_executable.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-27')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '27'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://medium.com/@olafhartong/sysmon-14-0-fileblockexecutable-13d7ba3dff3e

---

## Sysmon Blocked File Shredding

| Field | Value |
|---|---|
| **Sigma ID** | `c3e5c1b1-45e9-4632-b242-27939c170239` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_file_block_shredding.yml)**

> Triggers on any Sysmon "FileBlockShredding" event, which indicates a violation of the configured shredding policy.

```sql
-- ============================================================
-- Title:        Sysmon Blocked File Shredding
-- Sigma ID:     c3e5c1b1-45e9-4632-b242-27939c170239
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2023-07-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_file_block_shredding.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-28')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '28'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Sysmon File Executable Creation Detected

| Field | Value |
|---|---|
| **Sigma ID** | `693a44e9-7f26-4cb6-b787-214867672d3a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_file_executable_detected.yml)**

> Triggers on any Sysmon "FileExecutableDetected" event, which triggers every time a PE that is monitored by the config is created.

```sql
-- ============================================================
-- Title:        Sysmon File Executable Creation Detected
-- Sigma ID:     693a44e9-7f26-4cb6-b787-214867672d3a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2023-07-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/sysmon/sysmon_file_executable_detected.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-29')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '29'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://medium.com/@olafhartong/sysmon-15-0-file-executable-detected-40fd64349f36

---
