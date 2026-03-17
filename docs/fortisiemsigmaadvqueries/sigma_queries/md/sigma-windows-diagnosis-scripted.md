# Sigma → FortiSIEM: Windows Diagnosis-Scripted

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Loading Diagcab Package From Remote Path](#loading-diagcab-package-from-remote-path)

## Loading Diagcab Package From Remote Path

| Field | Value |
|---|---|
| **Sigma ID** | `50cb47b8-2c33-4b23-a2e9-4600657d9746` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/diagnosis/scripted/win_diagnosis_scripted_load_remote_diagcab.yml)**

> Detects loading of diagcab packages from a remote path, as seen in DogWalk vulnerability

```sql
-- ============================================================
-- Title:        Loading Diagcab Package From Remote Path
-- Sigma ID:     50cb47b8-2c33-4b23-a2e9-4600657d9746
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/diagnosis/scripted/win_diagnosis_scripted_load_remote_diagcab.yml
-- Unmapped:     PackagePath
-- False Pos:    Legitimate package hosted on a known and authorized remote location
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/diagnosis-scripted
-- UNMAPPED_FIELD: PackagePath

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
  AND (winEventId = '101'
    AND rawEventMsg LIKE '%\\\\\\\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate package hosted on a known and authorized remote location

**References:**
- https://twitter.com/nas_bench/status/1539679555908141061
- https://twitter.com/j00sean/status/1537750439701225472

---
