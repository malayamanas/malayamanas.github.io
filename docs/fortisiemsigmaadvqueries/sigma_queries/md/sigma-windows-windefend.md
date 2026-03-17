# Sigma → FortiSIEM: Windows Windefend

> 16 rules · Generated 2026-03-17

## Table of Contents

- [Windows Defender Grace Period Expired](#windows-defender-grace-period-expired)
- [LSASS Access Detected via Attack Surface Reduction](#lsass-access-detected-via-attack-surface-reduction)
- [PSExec and WMI Process Creations Block](#psexec-and-wmi-process-creations-block)
- [Windows Defender Exclusions Added](#windows-defender-exclusions-added)
- [Windows Defender Exploit Guard Tamper](#windows-defender-exploit-guard-tamper)
- [Windows Defender Submit Sample Feature Disabled](#windows-defender-submit-sample-feature-disabled)
- [Windows Defender Malware Detection History Deletion](#windows-defender-malware-detection-history-deletion)
- [Windows Defender Malware And PUA Scanning Disabled](#windows-defender-malware-and-pua-scanning-disabled)
- [Windows Defender AMSI Trigger Detected](#windows-defender-amsi-trigger-detected)
- [Windows Defender Real-time Protection Disabled](#windows-defender-real-time-protection-disabled)
- [Windows Defender Real-Time Protection Failure/Restart](#windows-defender-real-time-protection-failurerestart)
- [Win Defender Restored Quarantine File](#win-defender-restored-quarantine-file)
- [Windows Defender Configuration Changes](#windows-defender-configuration-changes)
- [Microsoft Defender Tamper Protection Trigger](#microsoft-defender-tamper-protection-trigger)
- [Windows Defender Threat Detected](#windows-defender-threat-detected)
- [Windows Defender Virus Scanning Feature Disabled](#windows-defender-virus-scanning-feature-disabled)

## Windows Defender Grace Period Expired

| Field | Value |
|---|---|
| **Sigma ID** | `360a1340-398a-46b6-8d06-99b905dc69d2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Ján Trenčanský, frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_antimalware_platform_expired.yml)**

> Detects the expiration of the grace period of Windows Defender. This means protection against viruses, spyware, and other potentially unwanted software is disabled.


```sql
-- ============================================================
-- Title:        Windows Defender Grace Period Expired
-- Sigma ID:     360a1340-398a-46b6-8d06-99b905dc69d2
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Ján Trenčanský, frack113
-- Date:         2020-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_antimalware_platform_expired.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId = '5101'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5101
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://craigclouditpro.wordpress.com/2020/03/04/hunting-malicious-windows-defender-activity/

---

## LSASS Access Detected via Attack Surface Reduction

| Field | Value |
|---|---|
| **Sigma ID** | `a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Markus Neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_asr_lsass_access.yml)**

> Detects Access to LSASS Process

```sql
-- ============================================================
-- Title:        LSASS Access Detected via Attack Surface Reduction
-- Sigma ID:     a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Markus Neis
-- Date:         2018-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_asr_lsass_access.yml
-- Unmapped:     Path
-- False Pos:    Google Chrome GoogleUpdate.exe; Some Taskmgr.exe related activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
-- UNMAPPED_FIELD: Path

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
  AND (winEventId = '1121'
    AND rawEventMsg LIKE '%\\lsass.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Google Chrome GoogleUpdate.exe; Some Taskmgr.exe related activity

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction

---

## PSExec and WMI Process Creations Block

| Field | Value |
|---|---|
| **Sigma ID** | `97b9ce1e-c5ab-11ea-87d0-0242ac130003` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047, T1569.002 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_asr_psexec_wmi.yml)**

> Detects blocking of process creations originating from PSExec and WMI commands

```sql
-- ============================================================
-- Title:        PSExec and WMI Process Creations Block
-- Sigma ID:     97b9ce1e-c5ab-11ea-87d0-0242ac130003
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1047, T1569.002
-- Author:       Bhabesh Raj
-- Date:         2020-07-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_asr_psexec_wmi.yml
-- Unmapped:     ProcessName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
-- UNMAPPED_FIELD: ProcessName

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
  AND (winEventId = '1121'
    AND (rawEventMsg LIKE '%\\wmiprvse.exe' OR rawEventMsg LIKE '%\\psexesvc.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-process-creations-originating-from-psexec-and-wmi-commands
- https://twitter.com/duff22b/status/1280166329660497920

---

## Windows Defender Exclusions Added

| Field | Value |
|---|---|
| **Sigma ID** | `1321dc4e-a1fe-481d-a016-52c45f0c8b4f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_exclusion_added.yml)**

> Detects the Setting of Windows Defender Exclusions

```sql
-- ============================================================
-- Title:        Windows Defender Exclusions Added
-- Sigma ID:     1321dc4e-a1fe-481d-a016-52c45f0c8b4f
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-07-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_exclusion_added.yml
-- Unmapped:     NewValue
-- False Pos:    Administrator actions
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
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
  AND (winEventId = '5007'
    AND rawEventMsg LIKE '%\\Microsoft\\Windows Defender\\Exclusions%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions

**References:**
- https://twitter.com/_nullbind/status/1204923340810543109

---

## Windows Defender Exploit Guard Tamper

| Field | Value |
|---|---|
| **Sigma ID** | `a3ab73f1-bd46-4319-8f06-4b20d0617886` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_exploit_guard_tamper.yml)**

> Detects when someone is adding or removing applications or folders from exploit guard "ProtectedFolders" or "AllowedApplications"


```sql
-- ============================================================
-- Title:        Windows Defender Exploit Guard Tamper
-- Sigma ID:     a3ab73f1-bd46-4319-8f06-4b20d0617886
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_exploit_guard_tamper.yml
-- Unmapped:     NewValue, OldValue
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
-- UNMAPPED_FIELD: NewValue
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
  AND ((winEventId = '5007'
    AND rawEventMsg LIKE '%\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\AllowedApplications\\%')
  AND (rawEventMsg LIKE '%\\Users\\Public\\%' OR rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\PerfLogs\\%' OR rawEventMsg LIKE '%\\Windows\\Temp\\%'))
  OR (winEventId = '5007'
    AND rawEventMsg LIKE '%\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\ProtectedFolders\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088

---

## Windows Defender Submit Sample Feature Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `91903aba-1088-42ee-b680-d6d94fe002b0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_sample_submission_consent.yml)**

> Detects disabling of the "Automatic Sample Submission" feature of Windows Defender.

```sql
-- ============================================================
-- Title:        Windows Defender Submit Sample Feature Disabled
-- Sigma ID:     91903aba-1088-42ee-b680-d6d94fe002b0
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_sample_submission_consent.yml
-- Unmapped:     NewValue
-- False Pos:    Administrator activity (must be investigated)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
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
  AND (winEventId = '5007'
    AND rawEventMsg LIKE '%\\Real-Time Protection\\SubmitSamplesConsent = 0x0%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator activity (must be investigated)

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
- https://bidouillesecurity.com/disable-windows-defender-in-powershell/#DisableAntiSpyware

---

## Windows Defender Malware Detection History Deletion

| Field | Value |
|---|---|
| **Sigma ID** | `2afe6582-e149-11ea-87d0-0242ac130003` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **Author** | Cian Heasley |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_history_delete.yml)**

> Windows Defender logs when the history of detected infections is deleted.

```sql
-- ============================================================
-- Title:        Windows Defender Malware Detection History Deletion
-- Sigma ID:     2afe6582-e149-11ea-87d0-0242ac130003
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Cian Heasley
-- Date:         2020-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_history_delete.yml
-- Unmapped:     (none)
-- False Pos:    Deletion of Defender malware detections history for legitimate reasons
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId = '1013'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Deletion of Defender malware detections history for legitimate reasons

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
- https://web.archive.org/web/20160727113019/https://answers.microsoft.com/en-us/protect/forum/mse-protect_scanning/microsoft-antimalware-has-removed-history-of/f15af6c9-01a9-4065-8c6c-3f2bdc7de45e

---

## Windows Defender Malware And PUA Scanning Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `bc275be9-0bec-4d77-8c8f-281a2df6710f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Ján Trenčanský, frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml)**

> Detects disabling of the Windows Defender feature of scanning for malware and other potentially unwanted software

```sql
-- ============================================================
-- Title:        Windows Defender Malware And PUA Scanning Disabled
-- Sigma ID:     bc275be9-0bec-4d77-8c8f-281a2df6710f
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Ján Trenčanský, frack113
-- Date:         2020-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId = '5010'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5010
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://craigclouditpro.wordpress.com/2020/03/04/hunting-malicious-windows-defender-activity/

---

## Windows Defender AMSI Trigger Detected

| Field | Value |
|---|---|
| **Sigma ID** | `ea9bf0fa-edec-4fb8-8b78-b119f2528186` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Bhabesh Raj |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_malware_detected_amsi_source.yml)**

> Detects triggering of AMSI by Windows Defender.

```sql
-- ============================================================
-- Title:        Windows Defender AMSI Trigger Detected
-- Sigma ID:     ea9bf0fa-edec-4fb8-8b78-b119f2528186
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        execution | T1059
-- Author:       Bhabesh Raj
-- Date:         2020-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_malware_detected_amsi_source.yml
-- Unmapped:     SourceName
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
-- UNMAPPED_FIELD: SourceName

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
  AND (winEventId = '1116'
    AND rawEventMsg = 'AMSI')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps

---

## Windows Defender Real-time Protection Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `b28e58e4-2a72-4fae-bdee-0fbe904db642` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Ján Trenčanský, frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml)**

> Detects disabling of Windows Defender Real-time Protection. As this event doesn't contain a lot of information on who initiated this action you might want to reduce it to a "medium" level if this occurs too many times in your environment


```sql
-- ============================================================
-- Title:        Windows Defender Real-time Protection Disabled
-- Sigma ID:     b28e58e4-2a72-4fae-bdee-0fbe904db642
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Ján Trenčanský, frack113
-- Date:         2020-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Administrator actions (should be investigated); Seen being triggered occasionally during Windows 8 Defender Updates
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId = '5001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions (should be investigated); Seen being triggered occasionally during Windows 8 Defender Updates

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5001
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://craigclouditpro.wordpress.com/2020/03/04/hunting-malicious-windows-defender-activity/

---

## Windows Defender Real-Time Protection Failure/Restart

| Field | Value |
|---|---|
| **Sigma ID** | `dd80db93-6ec2-4f4c-a017-ad40da6ffe81` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Christopher Peacock '@securepeacock' (Update) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml)**

> Detects issues with Windows Defender Real-Time Protection features

```sql
-- ============================================================
-- Title:        Windows Defender Real-Time Protection Failure/Restart
-- Sigma ID:     dd80db93-6ec2-4f4c-a017-ad40da6ffe81
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Christopher Peacock '@securepeacock' (Update)
-- Date:         2023-03-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml
-- Unmapped:     (none)
-- False Pos:    Some crashes can occur sometimes and the event doesn't provide enough information to tune out these cases. Manual exception is required
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId IN ('3002', '3007')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some crashes can occur sometimes and the event doesn't provide enough information to tune out these cases. Manual exception is required

**References:**
- Internal Research
- https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/
- https://gist.github.com/nasbench/33732d6705cbdc712fae356f07666346

---

## Win Defender Restored Quarantine File

| Field | Value |
|---|---|
| **Sigma ID** | `bc92ca75-cd42-4d61-9a37-9d5aa259c88b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml)**

> Detects the restoration of files from the defender quarantine

```sql
-- ============================================================
-- Title:        Win Defender Restored Quarantine File
-- Sigma ID:     bc92ca75-cd42-4d61-9a37-9d5aa259c88b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator activity restoring a file
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId = '1009'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity restoring a file

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide

---

## Windows Defender Configuration Changes

| Field | Value |
|---|---|
| **Sigma ID** | `801bd44f-ceed-4eb6-887c-11544633c0aa` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_suspicious_features_tampering.yml)**

> Detects suspicious changes to the Windows Defender configuration

```sql
-- ============================================================
-- Title:        Windows Defender Configuration Changes
-- Sigma ID:     801bd44f-ceed-4eb6-887c-11544633c0aa
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_suspicious_features_tampering.yml
-- Unmapped:     NewValue
-- False Pos:    Administrator activity (must be investigated)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
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
  AND (winEventId = '5007'
    AND (rawEventMsg LIKE '%\\Windows Defender\\DisableAntiSpyware %' OR rawEventMsg LIKE '%\\Windows Defender\\Scan\\DisableRemovableDriveScanning %' OR rawEventMsg LIKE '%\\Windows Defender\\Scan\\DisableScanningMappedNetworkDrivesForFullScan %' OR rawEventMsg LIKE '%\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen %' OR rawEventMsg LIKE '%\\Real-Time Protection\\SpyNetReporting %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator activity (must be investigated)

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
- https://bidouillesecurity.com/disable-windows-defender-in-powershell/#DisableAntiSpyware

---

## Microsoft Defender Tamper Protection Trigger

| Field | Value |
|---|---|
| **Sigma ID** | `49e5bc24-8b86-49f1-b743-535f332c2856` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Bhabesh Raj, Nasreddine Bencherchali |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml)**

> Detects blocked attempts to change any of Defender's settings such as "Real Time Monitoring" and "Behavior Monitoring"

```sql
-- ============================================================
-- Title:        Microsoft Defender Tamper Protection Trigger
-- Sigma ID:     49e5bc24-8b86-49f1-b743-535f332c2856
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Bhabesh Raj, Nasreddine Bencherchali
-- Date:         2021-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml
-- Unmapped:     Value
-- False Pos:    Administrator might try to disable defender features during testing (must be investigated)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend
-- UNMAPPED_FIELD: Value

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
  AND (winEventId = '5013'
    AND (rawEventMsg LIKE '%\\Windows Defender\\DisableAntiSpyware' OR rawEventMsg LIKE '%\\Windows Defender\\DisableAntiVirus' OR rawEventMsg LIKE '%\\Windows Defender\\Scan\\DisableArchiveScanning' OR rawEventMsg LIKE '%\\Windows Defender\\Scan\\DisableScanningNetworkFiles' OR rawEventMsg LIKE '%\\Real-Time Protection\\DisableRealtimeMonitoring' OR rawEventMsg LIKE '%\\Real-Time Protection\\DisableBehaviorMonitoring' OR rawEventMsg LIKE '%\\Real-Time Protection\\DisableIOAVProtection' OR rawEventMsg LIKE '%\\Real-Time Protection\\DisableScriptScanning'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator might try to disable defender features during testing (must be investigated)

**References:**
- https://bhabeshraj.com/post/tampering-with-microsoft-defenders-tamper-protection
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide

---

## Windows Defender Threat Detected

| Field | Value |
|---|---|
| **Sigma ID** | `57b649ef-ff42-4fb0-8bf6-62da243a1708` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Ján Trenčanský |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_threat.yml)**

> Detects actions taken by Windows Defender malware detection engines

```sql
-- ============================================================
-- Title:        Windows Defender Threat Detected
-- Sigma ID:     57b649ef-ff42-4fb0-8bf6-62da243a1708
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        execution | T1059
-- Author:       Ján Trenčanský
-- Date:         2020-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_threat.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId IN ('1006', '1015', '1116', '1117')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus

---

## Windows Defender Virus Scanning Feature Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `686c0b4b-9dd3-4847-9077-d6c1bbe36fcb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Ján Trenčanský, frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml)**

> Detects disabling of the Windows Defender virus scanning feature

```sql
-- ============================================================
-- Title:        Windows Defender Virus Scanning Feature Disabled
-- Sigma ID:     686c0b4b-9dd3-4847-9077-d6c1bbe36fcb
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Ján Trenčanský, frack113
-- Date:         2020-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/windefend

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
  AND winEventId = '5012'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5012
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://craigclouditpro.wordpress.com/2020/03/04/hunting-malicious-windows-defender-activity/

---
