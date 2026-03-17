# Sigma → FortiSIEM: Windows Ps Classic Provider Start

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Tamper Windows Defender - PSClassic](#tamper-windows-defender-psclassic)

## Tamper Windows Defender - PSClassic

| Field | Value |
|---|---|
| **Sigma ID** | `ec19ebab-72dc-40e1-9728-4c0b805d722c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_tamper_windows_defender_set_mp.yml)**

> Attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.

```sql
-- ============================================================
-- Title:        Tamper Windows Defender - PSClassic
-- Sigma ID:     ec19ebab-72dc-40e1-9728-4c0b805d722c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_classic/posh_pc_tamper_windows_defender_set_mp.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-PowerShell-400')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Set-MpPreference%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

---
