# Sigma → FortiSIEM: Windows Registry Delete

> 10 rules · Generated 2026-03-17

## Table of Contents

- [Delete Defender Scan ShellEx Context Menu Registry Key](#delete-defender-scan-shellex-context-menu-registry-key)
- [Windows Credential Guard Related Registry Value Deleted - Registry](#windows-credential-guard-related-registry-value-deleted-registry)
- [Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted](#windows-recall-feature-enabled-disableaidataanalysis-value-deleted)
- [Folder Removed From Exploit Guard ProtectedFolders List - Registry](#folder-removed-from-exploit-guard-protectedfolders-list-registry)
- [Terminal Server Client Connection History Cleared - Registry](#terminal-server-client-connection-history-cleared-registry)
- [Removal Of AMSI Provider Registry Keys](#removal-of-amsi-provider-registry-keys)
- [Removal of Potential COM Hijacking Registry Keys](#removal-of-potential-com-hijacking-registry-keys)
- [RunMRU Registry Key Deletion - Registry](#runmru-registry-key-deletion-registry)
- [Removal Of Index Value to Hide Schedule Task - Registry](#removal-of-index-value-to-hide-schedule-task-registry)
- [Removal Of SD Value to Hide Schedule Task - Registry](#removal-of-sd-value-to-hide-schedule-task-registry)

## Delete Defender Scan ShellEx Context Menu Registry Key

| Field | Value |
|---|---|
| **Sigma ID** | `72a0369a-2576-4aaf-bfc9-6bb24a574ac6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Matt Anderson (Huntress) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_defender_context_menu.yml)**

> Detects deletion of registry key that adds 'Scan with Defender' option in context menu. Attackers may use this to make it harder for users to scan files that are suspicious.

```sql
-- ============================================================
-- Title:        Delete Defender Scan ShellEx Context Menu Registry Key
-- Sigma ID:     72a0369a-2576-4aaf-bfc9-6bb24a574ac6
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        (none)
-- Author:       Matt Anderson (Huntress)
-- Date:         2025-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_defender_context_menu.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely as this weakens defenses and normally would not be done even if using another AV.
-- ============================================================

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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%shellex\\ContextMenuHandlers\\EPP%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely as this weakens defenses and normally would not be done even if using another AV.

**References:**
- https://research.splunk.com/endpoint/395ed5fe-ad13-4366-9405-a228427bdd91/
- https://winaero.com/how-to-delete-scan-with-windows-defender-from-context-menu-in-windows-10/
- https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
- https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/

---

## Windows Credential Guard Related Registry Value Deleted - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `d645ef86-2396-48a1-a2b6-b629ca3f57ff` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_disable_credential_guard.yml)**

> Detects attempts to disable Windows Credential Guard by deleting registry values. Credential Guard uses virtualization-based security to isolate secrets so that only privileged system software can access them.
Adversaries may disable Credential Guard to gain access to sensitive credentials stored in the system, such as NTLM hashes and Kerberos tickets, which can be used for lateral movement and privilege escalation.


```sql
-- ============================================================
-- Title:        Windows Credential Guard Related Registry Value Deleted - Registry
-- Sigma ID:     d645ef86-2396-48a1-a2b6-b629ca3f57ff
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_disable_credential_guard.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

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
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DeviceGuard\\EnableVirtualizationBasedSecurity' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DeviceGuard\\LsaCfgFlags' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DeviceGuard\\RequirePlatformSecurityFeatures' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Lsa\\LsaCfgFlags'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/DambergC/SaveFolder/blob/90e945eba80fae85f2d54b4616e05a44ec90c500/Cygate%20Installation%20tool%206.22/Script/OSD/OSDeployment-CredentialGuardDisable.ps1#L50
- https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure

---

## Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `5dfc1465-8f65-4fde-8eb5-6194380c6a62` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | Sajid Nawaz Khan |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_enable_windows_recall.yml)**

> Detects the enabling of the Windows Recall feature via registry manipulation. Windows Recall can be enabled by deleting the existing "DisableAIDataAnalysis" registry value.
Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities.
This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary.


```sql
-- ============================================================
-- Title:        Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted
-- Sigma ID:     5dfc1465-8f65-4fde-8eb5-6194380c6a62
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       Sajid Nawaz Khan
-- Date:         2024-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_enable_windows_recall.yml
-- Unmapped:     EventType
-- False Pos:    Legitimate use/activation of Windows Recall
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
  AND (rawEventMsg = 'DeleteValue'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use/activation of Windows Recall

**References:**
- https://learn.microsoft.com/en-us/windows/client-management/manage-recall
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis

---

## Folder Removed From Exploit Guard ProtectedFolders List - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `272e55a4-9e6b-4211-acb6-78f51f0b1b40` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_exploit_guard_protected_folders.yml)**

> Detects the removal of folders from the "ProtectedFolders" list of of exploit guard. This could indicate an attacker trying to launch an encryption process or trying to manipulate data inside of the protected folder

```sql
-- ============================================================
-- Title:        Folder Removed From Exploit Guard ProtectedFolders List - Registry
-- Sigma ID:     272e55a4-9e6b-4211-acb6-78f51f0b1b40
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_exploit_guard_protected_folders.yml
-- Unmapped:     EventType
-- False Pos:    Legitimate administrators removing applications (should always be investigated)
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
  AND (rawEventMsg = 'DeleteValue'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\ProtectedFolders%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrators removing applications (should always be investigated)

**References:**
- https://www.microsoft.com/security/blog/2017/10/23/windows-defender-exploit-guard-reduce-the-attack-surface-against-next-generation-malware/

---

## Terminal Server Client Connection History Cleared - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `07bdd2f5-9c58-4f38-aec8-e101bb79ef8d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1070, T1112 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.yml)**

> Detects the deletion of registry keys containing the MSTSC connection history

```sql
-- ============================================================
-- Title:        Terminal Server Client Connection History Cleared - Registry
-- Sigma ID:     07bdd2f5-9c58-4f38-aec8-e101bb79ef8d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1070, T1112
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.yml
-- Unmapped:     EventType
-- False Pos:    Unknown
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
  AND (rawEventMsg = 'DeleteValue'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Terminal Server Client\\Default\\MRU%'))
  OR (rawEventMsg = 'DeleteKey'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Terminal Server Client\\Servers\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer
- http://woshub.com/how-to-clear-rdp-connections-history/
- https://www.trendmicro.com/en_us/research/23/a/vice-society-ransomware-group-targets-manufacturing-companies.html

---

## Removal Of AMSI Provider Registry Keys

| Field | Value |
|---|---|
| **Sigma ID** | `41d1058a-aea7-4952-9293-29eaaf516465` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml)**

> Detects the deletion of AMSI provider registry key entries in HKLM\Software\Microsoft\AMSI. This technique could be used by an attacker in order to disable AMSI inspection.

```sql
-- ============================================================
-- Title:        Removal Of AMSI Provider Registry Keys
-- Sigma ID:     41d1058a-aea7-4952-9293-29eaaf516465
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       frack113
-- Date:         2021-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

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
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%{2781761E-28E0-4109-99FE-B9D127C57AFE}' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://seclists.org/fulldisclosure/2020/Mar/45

---

## Removal of Potential COM Hijacking Registry Keys

| Field | Value |
|---|---|
| **Sigma ID** | `96f697b0-b499-4e5d-9908-a67bec11cdb6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_removal_com_hijacking_registry_key.yml)**

> Detects any deletion of entries in ".*\shell\open\command" registry keys.
These registry keys might have been used for COM hijacking activities by a threat actor or an attacker and the deletion could indicate steps to remove its tracks.


```sql
-- ============================================================
-- Title:        Removal of Potential COM Hijacking Registry Keys
-- Sigma ID:     96f697b0-b499-4e5d-9908-a67bec11cdb6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_removal_com_hijacking_registry_key.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software (un)installations are known to cause false positives. Please add them as a filter when encountered
-- ============================================================

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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\shell\\open\\command')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software (un)installations are known to cause false positives. Please add them as a filter when encountered

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/7
- https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.C.1_22A46621-7A92-48C1-81BF-B3937EB4FDC3.md
- https://learn.microsoft.com/en-us/windows/win32/shell/launch
- https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexecutecommand
- https://learn.microsoft.com/en-us/windows/win32/shell/shell-and-managed-code

---

## RunMRU Registry Key Deletion - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `3a9b8c1e-5b2e-4f7a-9d1c-2a7f3b6e1c55` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_runmru.yml)**

> Detects attempts to delete the RunMRU registry key, which stores the history of commands executed via the run dialog.
In the clickfix techniques, the phishing lures instruct users to open a run dialog through (Win + R) and execute malicious commands.
Adversaries may delete this key to cover their tracks after executing commands.


```sql
-- ============================================================
-- Title:        RunMRU Registry Key Deletion - Registry
-- Sigma ID:     3a9b8c1e-5b2e-4f7a-9d1c-2a7f3b6e1c55
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1070.003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-09-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_runmru.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix

---

## Removal Of Index Value to Hide Schedule Task - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `526cc8bc-1cdc-48ad-8b26-f19bff969cec` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_index_value_removal.yml)**

> Detects when the "index" value of a scheduled task is removed or deleted from the registry. Which effectively hides it from any tooling such as "schtasks /query"

```sql
-- ============================================================
-- Title:        Removal Of Index Value to Hide Schedule Task - Registry
-- Sigma ID:     526cc8bc-1cdc-48ad-8b26-f19bff969cec
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_index_value_removal.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Index%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments

---

## Removal Of SD Value to Hide Schedule Task - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `acd74772-5f88-45c7-956b-6a7b36c294d2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562 |
| **Author** | Sittikorn S |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml)**

> Remove SD (Security Descriptor) value in \Schedule\TaskCache\Tree registry hive to hide schedule task. This technique is used by Tarrask malware

```sql
-- ============================================================
-- Title:        Removal Of SD Value to Hide Schedule Task - Registry
-- Sigma ID:     acd74772-5f88-45c7-956b-6a7b36c294d2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562
-- Author:       Sittikorn S
-- Date:         2022-04-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SD%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/

---
