# Sigma → FortiSIEM: Windows Firewall-As

> 8 rules · Generated 2026-03-17

## Table of Contents

- [Uncommon New Firewall Rule Added In Windows Firewall Exception List](#uncommon-new-firewall-rule-added-in-windows-firewall-exception-list)
- [New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application](#new-firewall-rule-added-in-windows-firewall-exception-list-for-potential-suspicious-application)
- [New Firewall Rule Added In Windows Firewall Exception List Via WmiPrvSE.EXE](#new-firewall-rule-added-in-windows-firewall-exception-list-via-wmiprvseexe)
- [All Rules Have Been Deleted From The Windows Firewall Configuration](#all-rules-have-been-deleted-from-the-windows-firewall-configuration)
- [A Rule Has Been Deleted From The Windows Firewall Exception List](#a-rule-has-been-deleted-from-the-windows-firewall-exception-list)
- [The Windows Defender Firewall Service Failed To Load Group Policy](#the-windows-defender-firewall-service-failed-to-load-group-policy)
- [Windows Defender Firewall Has Been Reset To Its Default Configuration](#windows-defender-firewall-has-been-reset-to-its-default-configuration)
- [Windows Firewall Settings Have Been Changed](#windows-firewall-settings-have-been-changed)

## Uncommon New Firewall Rule Added In Windows Firewall Exception List

| Field | Value |
|---|---|
| **Sigma ID** | `cde0a575-7d3d-4a49-9817-b8004a7bf105` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule.yml)**

> Detects when a rule has been added to the Windows Firewall exception list

```sql
-- ============================================================
-- Title:        Uncommon New Firewall Rule Added In Windows Firewall Exception List
-- Sigma ID:     cde0a575-7d3d-4a49-9817-b8004a7bf105
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2022-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as

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
  AND winEventId IN ('2004', '2071', '2097')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)

---

## New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application

| Field | Value |
|---|---|
| **Sigma ID** | `9e2575e7-2cb9-4da1-adc8-ed94221dca5e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_susp_folder.yml)**

> Detects the addition of a new rule to the Windows Firewall exception list for an application located in a potentially suspicious location.

```sql
-- ============================================================
-- Title:        New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application
-- Sigma ID:     9e2575e7-2cb9-4da1-adc8-ed94221dca5e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2023-02-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_susp_folder.yml
-- Unmapped:     ApplicationPath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as
-- UNMAPPED_FIELD: ApplicationPath

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
  AND (winEventId IN ('2004', '2071', '2097')
    AND (rawEventMsg LIKE '%:\\PerfLogs\\%' OR rawEventMsg LIKE '%:\\Temp\\%' OR rawEventMsg LIKE '%:\\Tmp\\%' OR rawEventMsg LIKE '%:\\Users\\Public\\%' OR rawEventMsg LIKE '%:\\Windows\\Tasks\\%' OR rawEventMsg LIKE '%:\\Windows\\Temp\\%' OR rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
- https://app.any.run/tasks/7123e948-c91e-49e0-a813-00e8d72ab393/#

---

## New Firewall Rule Added In Windows Firewall Exception List Via WmiPrvSE.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `eca81e8d-09e1-4d04-8614-c91f44fd0519` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_wmiprvse.yml)**

> Detects the addition of a new "Allow" firewall rule by the WMI process (WmiPrvSE.EXE).
This can occur if an attacker leverages PowerShell cmdlets such as "New-NetFirewallRule", or directly uses WMI CIM classes such as "MSFT_NetFirewallRule".


```sql
-- ============================================================
-- Title:        New Firewall Rule Added In Windows Firewall Exception List Via WmiPrvSE.EXE
-- Sigma ID:     eca81e8d-09e1-4d04-8614-c91f44fd0519
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_wmiprvse.yml
-- Unmapped:     Action, ModifyingApplication
-- False Pos:    Administrator scripts or activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as
-- UNMAPPED_FIELD: Action
-- UNMAPPED_FIELD: ModifyingApplication

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
  AND (winEventId IN ('2004', '2071', '2097')
    AND rawEventMsg = '3'
    AND rawEventMsg LIKE '%:\\Windows\\System32\\wbem\\WmiPrvSE.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator scripts or activity.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md#atomic-test-24---set-a-firewall-rule-using-new-netfirewallrule
- https://malware.news/t/the-rhysida-ransomware-activity-analysis-and-ties-to-vice-society/72170
- https://cybersecuritynews.com/rhysida-ransomware-attacking-windows/

---

## All Rules Have Been Deleted From The Windows Firewall Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `79609c82-a488-426e-abcf-9f341a39365d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml)**

> Detects when a all the rules have been deleted from the Windows Defender Firewall configuration

```sql
-- ============================================================
-- Title:        All Rules Have Been Deleted From The Windows Firewall Configuration
-- Sigma ID:     79609c82-a488-426e-abcf-9f341a39365d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as

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
  AND winEventId IN ('2033', '2059')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)

---

## A Rule Has Been Deleted From The Windows Firewall Exception List

| Field | Value |
|---|---|
| **Sigma ID** | `c187c075-bb3e-4c62-b4fa-beae0ffc211f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml)**

> Detects when a single rules or all of the rules have been deleted from the Windows Defender Firewall

```sql
-- ============================================================
-- Title:        A Rule Has Been Deleted From The Windows Firewall Exception List
-- Sigma ID:     c187c075-bb3e-4c62-b4fa-beae0ffc211f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2022-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as

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
  AND winEventId IN ('2006', '2052')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)

---

## The Windows Defender Firewall Service Failed To Load Group Policy

| Field | Value |
|---|---|
| **Sigma ID** | `7ec15688-fd24-4177-ba43-1a950537ee39` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_failed_load_gpo.yml)**

> Detects activity when The Windows Defender Firewall service failed to load Group Policy

```sql
-- ============================================================
-- Title:        The Windows Defender Firewall Service Failed To Load Group Policy
-- Sigma ID:     7ec15688-fd24-4177-ba43-1a950537ee39
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2022-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_failed_load_gpo.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as

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
  AND winEventId = '2009'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)

---

## Windows Defender Firewall Has Been Reset To Its Default Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `04b60639-39c0-412a-9fbe-e82499c881a3` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml)**

> Detects activity when Windows Defender Firewall has been reset to its default configuration

```sql
-- ============================================================
-- Title:        Windows Defender Firewall Has Been Reset To Its Default Configuration
-- Sigma ID:     04b60639-39c0-412a-9fbe-e82499c881a3
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2022-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as

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
  AND winEventId IN ('2032', '2060')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)

---

## Windows Firewall Settings Have Been Changed

| Field | Value |
|---|---|
| **Sigma ID** | `00bb5bd5-1379-4fcf-a965-a5b6f7478064` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml)**

> Detects activity when the settings of the Windows firewall have been changed

```sql
-- ============================================================
-- Title:        Windows Firewall Settings Have Been Changed
-- Sigma ID:     00bb5bd5-1379-4fcf-a965-a5b6f7478064
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/firewall-as

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
  AND winEventId IN ('2002', '2083', '2003', '2082', '2008')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)

---
