# Sigma → FortiSIEM: Windows Process Tampering

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potential Process Hollowing Activity](#potential-process-hollowing-activity)

## Potential Process Hollowing Activity

| Field | Value |
|---|---|
| **Sigma ID** | `c4b890e5-8d8c-4496-8c66-c805753817cd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1055.012 |
| **Author** | Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Sittikorn S |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_tampering/proc_tampering_susp_process_hollowing.yml)**

> Detects when a memory process image does not match the disk image, indicative of process hollowing.

```sql
-- ============================================================
-- Title:        Potential Process Hollowing Activity
-- Sigma ID:     c4b890e5-8d8c-4496-8c66-c805753817cd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1055.012
-- Author:       Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Sittikorn S
-- Date:         2022-01-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_tampering/proc_tampering_susp_process_hollowing.yml
-- Unmapped:     Type
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/process_tampering
-- UNMAPPED_FIELD: Type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Image is replaced'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SecurePeacock/status/1486054048390332423?s=20
- https://www.bleepingcomputer.com/news/microsoft/microsoft-sysmon-now-detects-malware-process-tampering-attempts/

---
