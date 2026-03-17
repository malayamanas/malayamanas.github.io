# Sigma → FortiSIEM: Windows Codeintegrity-Operational

> 10 rules · Generated 2026-03-17

## Table of Contents

- [CodeIntegrity - Unmet Signing Level Requirements By File Under Validation](#codeintegrity-unmet-signing-level-requirements-by-file-under-validation)
- [CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked](#codeintegrity-disallowed-file-for-protected-processes-has-been-blocked)
- [CodeIntegrity - Blocked Image/Driver Load For Policy Violation](#codeintegrity-blocked-imagedriver-load-for-policy-violation)
- [CodeIntegrity - Blocked Driver Load With Revoked Certificate](#codeintegrity-blocked-driver-load-with-revoked-certificate)
- [CodeIntegrity - Revoked Kernel Driver Loaded](#codeintegrity-revoked-kernel-driver-loaded)
- [CodeIntegrity - Blocked Image Load With Revoked Certificate](#codeintegrity-blocked-image-load-with-revoked-certificate)
- [CodeIntegrity - Revoked Image Loaded](#codeintegrity-revoked-image-loaded)
- [CodeIntegrity - Unsigned Kernel Module Loaded](#codeintegrity-unsigned-kernel-module-loaded)
- [CodeIntegrity - Unsigned Image Loaded](#codeintegrity-unsigned-image-loaded)
- [CodeIntegrity - Unmet WHQL Requirements For Loaded Kernel Module](#codeintegrity-unmet-whql-requirements-for-loaded-kernel-module)

## CodeIntegrity - Unmet Signing Level Requirements By File Under Validation

| Field | Value |
|---|---|
| **Sigma ID** | `f8931561-97f5-4c46-907f-0a4a592e47a7` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_attempted_dll_load.yml)**

> Detects attempted file load events that did not meet the signing level requirements. It often means the file's signature is revoked or a signature with the Lifetime Signing EKU has expired.
This event is best correlated with EID 3089 to determine the error of the validation.


```sql
-- ============================================================
-- Title:        CodeIntegrity - Unmet Signing Level Requirements By File Under Validation
-- Sigma ID:     f8931561-97f5-4c46-907f-0a4a592e47a7
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        execution
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_attempted_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Antivirus and other third party products are known to trigger this rule quite a lot. Initial filters and tuning is required before using this rule.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId IN ('3033', '3034')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Antivirus and other third party products are known to trigger this rule quite a lot. Initial filters and tuning is required before using this rule.

**References:**
- https://twitter.com/SBousseaden/status/1483810148602814466
- https://github.com/MicrosoftDocs/windows-itpro-docs/blob/40fe118976734578f83e5e839b9c63ae7a4af82d/windows/security/threat-protection/windows-defender-application-control/event-id-explanations.md#windows-codeintegrity-operational-log
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations

---

## CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked

| Field | Value |
|---|---|
| **Sigma ID** | `5daf11c3-022b-4969-adb9-365e6c078c7c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_blocked_protected_process_file.yml)**

> Detects block events for files that are disallowed by code integrity for protected processes

```sql
-- ============================================================
-- Title:        CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked
-- Sigma ID:     5daf11c3-022b-4969-adb9-365e6c078c7c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_blocked_protected_process_file.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId = '3104'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Blocked Image/Driver Load For Policy Violation

| Field | Value |
|---|---|
| **Sigma ID** | `e4be5675-4a53-426a-8c81-a8bb2387e947` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_enforced_policy_block.yml)**

> Detects blocked load events that did not meet the authenticode signing level requirements or violated the code integrity policy.

```sql
-- ============================================================
-- Title:        CodeIntegrity - Blocked Image/Driver Load For Policy Violation
-- Sigma ID:     e4be5675-4a53-426a-8c81-a8bb2387e947
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-11-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_enforced_policy_block.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId = '3077'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/wdormann/status/1590434950335320065
- https://github.com/MicrosoftDocs/windows-itpro-docs/blob/40fe118976734578f83e5e839b9c63ae7a4af82d/windows/security/threat-protection/windows-defender-application-control/event-id-explanations.md#windows-codeintegrity-operational-log
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations

---

## CodeIntegrity - Blocked Driver Load With Revoked Certificate

| Field | Value |
|---|---|
| **Sigma ID** | `9b72b82d-f1c5-4632-b589-187159bc6ec1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_blocked.yml)**

> Detects blocked load attempts of revoked drivers

```sql
-- ============================================================
-- Title:        CodeIntegrity - Blocked Driver Load With Revoked Certificate
-- Sigma ID:     9b72b82d-f1c5-4632-b589-187159bc6ec1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_blocked.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId = '3023'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Revoked Kernel Driver Loaded

| Field | Value |
|---|---|
| **Sigma ID** | `320fccbf-5e32-4101-82b8-2679c5f007c6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml)**

> Detects the load of a revoked kernel driver

```sql
-- ============================================================
-- Title:        CodeIntegrity - Revoked Kernel Driver Loaded
-- Sigma ID:     320fccbf-5e32-4101-82b8-2679c5f007c6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId IN ('3021', '3022')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Blocked Image Load With Revoked Certificate

| Field | Value |
|---|---|
| **Sigma ID** | `6f156c48-3894-4952-baf0-16193e9067d2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_blocked.yml)**

> Detects blocked image load events with revoked certificates by code integrity.

```sql
-- ============================================================
-- Title:        CodeIntegrity - Blocked Image Load With Revoked Certificate
-- Sigma ID:     6f156c48-3894-4952-baf0-16193e9067d2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_blocked.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId = '3036'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Revoked Image Loaded

| Field | Value |
|---|---|
| **Sigma ID** | `881b7725-47cc-4055-8000-425823344c59` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_loaded.yml)**

> Detects image load events with revoked certificates by code integrity.

```sql
-- ============================================================
-- Title:        CodeIntegrity - Revoked Image Loaded
-- Sigma ID:     881b7725-47cc-4055-8000-425823344c59
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_loaded.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId IN ('3032', '3035')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Unsigned Kernel Module Loaded

| Field | Value |
|---|---|
| **Sigma ID** | `951f8d29-f2f6-48a7-859f-0673ff105e6f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_driver_loaded.yml)**

> Detects the presence of a loaded unsigned kernel module on the system.

```sql
-- ============================================================
-- Title:        CodeIntegrity - Unsigned Kernel Module Loaded
-- Sigma ID:     951f8d29-f2f6-48a7-859f-0673ff105e6f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_driver_loaded.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId = '3001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Unsigned Image Loaded

| Field | Value |
|---|---|
| **Sigma ID** | `c92c24e7-f595-493f-9c98-53d5142f5c18` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_image_loaded.yml)**

> Detects loaded unsigned image on the system

```sql
-- ============================================================
-- Title:        CodeIntegrity - Unsigned Image Loaded
-- Sigma ID:     c92c24e7-f595-493f-9c98-53d5142f5c18
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_image_loaded.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId = '3037'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---

## CodeIntegrity - Unmet WHQL Requirements For Loaded Kernel Module

| Field | Value |
|---|---|
| **Sigma ID** | `2f8cd7a0-9d5a-4f62-9f8b-2c951aa0dd1f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_whql_failure.yml)**

> Detects loaded kernel modules that did not meet the WHQL signing requirements.

```sql
-- ============================================================
-- Title:        CodeIntegrity - Unmet WHQL Requirements For Loaded Kernel Module
-- Sigma ID:     2f8cd7a0-9d5a-4f62-9f8b-2c951aa0dd1f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_whql_failure.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/codeintegrity-operational

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
  AND winEventId IN ('3082', '3083')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-tag-explanations
- Internal Research

---
