# Sigma → FortiSIEM: Windows Security-Mitigations

> 2 rules · Generated 2026-03-17

## Table of Contents

- [Microsoft Defender Blocked from Loading Unsigned DLL](#microsoft-defender-blocked-from-loading-unsigned-dll)
- [Unsigned Binary Loaded From Suspicious Location](#unsigned-binary-loaded-from-suspicious-location)

## Microsoft Defender Blocked from Loading Unsigned DLL

| Field | Value |
|---|---|
| **Sigma ID** | `0b0ea3cc-99c8-4730-9c53-45deee2a4c86` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security_mitigations/win_security_mitigations_defender_load_unsigned_dll.yml)**

> Detects Code Integrity (CI) engine blocking Microsoft Defender's processes (MpCmdRun and NisSrv) from loading unsigned DLLs which may be an attempt to sideload arbitrary DLL

```sql
-- ============================================================
-- Title:        Microsoft Defender Blocked from Loading Unsigned DLL
-- Sigma ID:     0b0ea3cc-99c8-4730-9c53-45deee2a4c86
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Bhabesh Raj
-- Date:         2022-08-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security_mitigations/win_security_mitigations_defender_load_unsigned_dll.yml
-- Unmapped:     ProcessPath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/security-mitigations
-- UNMAPPED_FIELD: ProcessPath

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
  AND (winEventId IN ('11', '12')
    AND (rawEventMsg LIKE '%\\MpCmdRun.exe' OR rawEventMsg LIKE '%\\NisSrv.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool

---

## Unsigned Binary Loaded From Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `8289bf8c-4aca-4f5a-9db3-dc3d7afe5c10` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security_mitigations/win_security_mitigations_unsigned_dll_from_susp_location.yml)**

> Detects Code Integrity (CI) engine blocking processes from loading unsigned DLLs residing in suspicious locations

```sql
-- ============================================================
-- Title:        Unsigned Binary Loaded From Suspicious Location
-- Sigma ID:     8289bf8c-4aca-4f5a-9db3-dc3d7afe5c10
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security_mitigations/win_security_mitigations_unsigned_dll_from_susp_location.yml
-- Unmapped:     ImageName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/security-mitigations
-- UNMAPPED_FIELD: ImageName

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
  AND (winEventId IN ('11', '12')
    AND (rawEventMsg LIKE '%\\Users\\Public\\%' OR rawEventMsg LIKE '%\\PerfLogs\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\Downloads\\%' OR rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%' OR rawEventMsg LIKE '%C:\\Windows\\TEMP\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nasbench/EVTX-ETW-Resources/blob/45fd5be71a51aa518b1b36d4e1f36af498084e27/ETWEventsList/CSV/Windows11/21H2/W11_21H2_Pro_20220719_22000.795/Providers/Microsoft-Windows-Security-Mitigations.csv

---
