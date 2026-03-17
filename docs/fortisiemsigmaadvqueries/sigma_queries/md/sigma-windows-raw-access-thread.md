# Sigma → FortiSIEM: Windows Raw Access Thread

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potential Defense Evasion Via Raw Disk Access By Uncommon Tools](#potential-defense-evasion-via-raw-disk-access-by-uncommon-tools)

## Potential Defense Evasion Via Raw Disk Access By Uncommon Tools

| Field | Value |
|---|---|
| **Sigma ID** | `db809f10-56ce-4420-8c86-d6a7d793c79c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1006 |
| **Author** | Teymur Kheirkhabarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/raw_access_thread/raw_access_thread_susp_disk_access_using_uncommon_tools.yml)**

> Detects raw disk access using uncommon tools or tools that are located in suspicious locations (heavy filtering is required), which could indicate possible defense evasion attempts

```sql
-- ============================================================
-- Title:        Potential Defense Evasion Via Raw Disk Access By Uncommon Tools
-- Sigma ID:     db809f10-56ce-4420-8c86-d6a7d793c79c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1006
-- Author:       Teymur Kheirkhabarov, oscd.community
-- Date:         2019-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/raw_access_thread/raw_access_thread_susp_disk_access_using_uncommon_tools.yml
-- Unmapped:     (none)
-- False Pos:    Likely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/raw_access_thread

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---
