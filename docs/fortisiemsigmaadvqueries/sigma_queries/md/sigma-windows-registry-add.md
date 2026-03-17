# Sigma → FortiSIEM: Windows Registry Add

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potential Persistence Via Disk Cleanup Handler - Registry](#potential-persistence-via-disk-cleanup-handler-registry)

## Potential Persistence Via Disk Cleanup Handler - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `d4f4e0be-cf12-439f-9e25-4e2cdcf7df5a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_add/registry_add_persistence_disk_cleanup_handler_entry.yml)**

> Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence.
The disk cleanup manager is part of the operating system. It displays the dialog box […]
The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.


```sql
-- ============================================================
-- Title:        Potential Persistence Via Disk Cleanup Handler - Registry
-- Sigma ID:     d4f4e0be-cf12-439f-9e25-4e2cdcf7df5a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_add/registry_add_persistence_disk_cleanup_handler_entry.yml
-- Unmapped:     EventType
-- False Pos:    Legitimate new entry added by windows
-- ============================================================
-- UNMAPPED_FIELD: EventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'CreateKey'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate new entry added by windows

**References:**
- https://persistence-info.github.io/Data/diskcleanuphandler.html
- https://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/

---
