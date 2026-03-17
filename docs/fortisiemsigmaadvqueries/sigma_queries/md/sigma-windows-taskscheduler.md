# Sigma → FortiSIEM: Windows Taskscheduler

> 3 rules · Generated 2026-03-17

## Table of Contents

- [Scheduled Task Executed From A Suspicious Location](#scheduled-task-executed-from-a-suspicious-location)
- [Scheduled Task Executed Uncommon LOLBIN](#scheduled-task-executed-uncommon-lolbin)
- [Important Scheduled Task Deleted](#important-scheduled-task-deleted)

## Scheduled Task Executed From A Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `424273ea-7cf8-43a6-b712-375f925e481f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/taskscheduler/win_taskscheduler_execution_from_susp_locations.yml)**

> Detects the execution of Scheduled Tasks where the Program being run is located in a suspicious location or it's an unusale program to be run from a Scheduled Task

```sql
-- ============================================================
-- Title:        Scheduled Task Executed From A Suspicious Location
-- Sigma ID:     424273ea-7cf8-43a6-b712-375f925e481f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/taskscheduler/win_taskscheduler_execution_from_susp_locations.yml
-- Unmapped:     Path
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Path

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-TaskScheduler-129')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '129'
    AND (rawEventMsg LIKE '%C:\\Windows\\Temp\\%' OR rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\Downloads\\%' OR rawEventMsg LIKE '%\\Users\\Public\\%' OR rawEventMsg LIKE '%C:\\Temp\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Scheduled Task Executed Uncommon LOLBIN

| Field | Value |
|---|---|
| **Sigma ID** | `f0767f15-0fb3-44b9-851e-e8d9a6d0005d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/taskscheduler/win_taskscheduler_lolbin_execution_via_task_scheduler.yml)**

> Detects the execution of Scheduled Tasks where the program being run is located in a suspicious location or where it is an unusual program to be run from a Scheduled Task

```sql
-- ============================================================
-- Title:        Scheduled Task Executed Uncommon LOLBIN
-- Sigma ID:     f0767f15-0fb3-44b9-851e-e8d9a6d0005d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/taskscheduler/win_taskscheduler_lolbin_execution_via_task_scheduler.yml
-- Unmapped:     Path
-- False Pos:    False positives may occur with some of the selected binaries if you have tasks using them (which could be very common in your environment). Exclude all the specific trusted tasks before using this rule
-- ============================================================
-- UNMAPPED_FIELD: Path

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-TaskScheduler-129')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '129'
    AND (rawEventMsg LIKE '%\\calc.exe' OR rawEventMsg LIKE '%\\cscript.exe' OR rawEventMsg LIKE '%\\mshta.exe' OR rawEventMsg LIKE '%\\mspaint.exe' OR rawEventMsg LIKE '%\\notepad.exe' OR rawEventMsg LIKE '%\\regsvr32.exe' OR rawEventMsg LIKE '%\\wscript.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives may occur with some of the selected binaries if you have tasks using them (which could be very common in your environment). Exclude all the specific trusted tasks before using this rule

**References:**
- Internal Research

---

## Important Scheduled Task Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `9e3cb244-bdb8-4632-8c90-6079c8f4f16d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1489 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/taskscheduler/win_taskscheduler_susp_schtasks_delete.yml)**

> Detects when adversaries try to stop system services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities


```sql
-- ============================================================
-- Title:        Important Scheduled Task Deleted
-- Sigma ID:     9e3cb244-bdb8-4632-8c90-6079c8f4f16d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1489
-- Author:       frack113
-- Date:         2023-01-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/taskscheduler/win_taskscheduler_susp_schtasks_delete.yml
-- Unmapped:     TaskName, UserName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TaskName
-- UNMAPPED_FIELD: UserName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-TaskScheduler-141')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((winEventId = '141'
    AND (rawEventMsg LIKE '%\\Windows\\SystemRestore\\SR%' OR rawEventMsg LIKE '%\\Windows\\Windows Defender\\%' OR rawEventMsg LIKE '%\\Windows\\BitLocker%' OR rawEventMsg LIKE '%\\Windows\\WindowsBackup\\%' OR rawEventMsg LIKE '%\\Windows\\WindowsUpdate\\%' OR rawEventMsg LIKE '%\\Windows\\UpdateOrchestrator\\%' OR rawEventMsg LIKE '%\\Windows\\ExploitGuard%'))
  AND NOT ((rawEventMsg LIKE '%AUTHORI%' OR rawEventMsg LIKE '%AUTORI%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/

---
