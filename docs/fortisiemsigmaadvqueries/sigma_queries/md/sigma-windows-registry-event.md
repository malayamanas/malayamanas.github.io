# Sigma → FortiSIEM: Windows Registry Event

> 32 rules · Generated 2026-03-17

## Table of Contents

- [Creation of a Local Hidden User Account by Registry](#creation-of-a-local-hidden-user-account-by-registry)
- [UAC Bypass Via Wsreset](#uac-bypass-via-wsreset)
- [CMSTP Execution Registry Event](#cmstp-execution-registry-event)
- [Windows Defender Threat Severity Default Action Modified](#windows-defender-threat-severity-default-action-modified)
- [Disable Security Events Logging Adding Reg Key MiniNt](#disable-security-events-logging-adding-reg-key-minint)
- [Wdigest CredGuard Registry Modification](#wdigest-credguard-registry-modification)
- [Esentutl Volume Shadow Copy Service Keys](#esentutl-volume-shadow-copy-service-keys)
- [Windows Credential Editor Registry](#windows-credential-editor-registry)
- [HybridConnectionManager Service Installation - Registry](#hybridconnectionmanager-service-installation-registry)
- [Registry Entries For Azorult Malware](#registry-entries-for-azorult-malware)
- [Potential Qakbot Registry Activity](#potential-qakbot-registry-activity)
- [Path To Screensaver Binary Modified](#path-to-screensaver-binary-modified)
- [Narrator's Feedback-Hub Persistence](#narrators-feedback-hub-persistence)
- [NetNTLM Downgrade Attack - Registry](#netntlm-downgrade-attack-registry)
- [New DLL Added to AppCertDlls Registry Key](#new-dll-added-to-appcertdlls-registry-key)
- [New DLL Added to AppInit_DLLs Registry Key](#new-dll-added-to-appinitdlls-registry-key)
- [Office Application Startup - Office Test](#office-application-startup-office-test)
- [Windows Registry Trust Record Modification](#windows-registry-trust-record-modification)
- [Registry Persistence Mechanisms in Recycle Bin](#registry-persistence-mechanisms-in-recycle-bin)
- [New PortProxy Registry Entry Added](#new-portproxy-registry-entry-added)
- [RedMimicry Winnti Playbook Registry Manipulation](#redmimicry-winnti-playbook-registry-manipulation)
- [WINEKEY Registry Modification](#winekey-registry-modification)
- [Run Once Task Configuration in Registry](#run-once-task-configuration-in-registry)
- [Shell Open Registry Keys Manipulation](#shell-open-registry-keys-manipulation)
- [Potential Credential Dumping Via LSASS SilentProcessExit Technique](#potential-credential-dumping-via-lsass-silentprocessexit-technique)
- [Security Support Provider (SSP) Added to LSA Configuration](#security-support-provider-ssp-added-to-lsa-configuration)
- [Sticky Key Like Backdoor Usage - Registry](#sticky-key-like-backdoor-usage-registry)
- [Atbroker Registry Change](#atbroker-registry-change)
- [Suspicious Run Key from Download](#suspicious-run-key-from-download)
- [DLL Load via LSASS](#dll-load-via-lsass)
- [Suspicious Camera and Microphone Access](#suspicious-camera-and-microphone-access)
- [Registry Tampering by Potentially Suspicious Processes](#registry-tampering-by-potentially-suspicious-processes)

## Creation of a Local Hidden User Account by Registry

| Field | Value |
|---|---|
| **Sigma ID** | `460479f3-80b7-42da-9c43-2cc1d54dbccd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml)**

> Sysmon registry detection of a local hidden user account.

```sql
-- ============================================================
-- Title:        Creation of a Local Hidden User Account by Registry
-- Sigma ID:     460479f3-80b7-42da-9c43-2cc1d54dbccd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1136.001
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-05-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SAM\\SAM\\Domains\\Account\\Users\\Names\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%$\\(Default)')
    AND procName LIKE '%\\lsass.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1387530414185664538

---

## UAC Bypass Via Wsreset

| Field | Value |
|---|---|
| **Sigma ID** | `6ea3bf32-9680-422d-9f50-e90716b12a66` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | oscd.community, Dmitry Uchakin |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_bypass_via_wsreset.yml)**

> Unfixed method for UAC bypass from Windows 10. WSReset.exe file associated with the Windows Store. It will run a binary file contained in a low-privilege registry.

```sql
-- ============================================================
-- Title:        UAC Bypass Via Wsreset
-- Sigma ID:     6ea3bf32-9680-422d-9f50-e90716b12a66
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       oscd.community, Dmitry Uchakin
-- Date:         2020-10-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_bypass_via_wsreset.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.bleepingcomputer.com/news/security/trickbot-uses-a-new-windows-10-uac-bypass-to-launch-quietly
- https://lolbas-project.github.io/lolbas/Binaries/Wsreset

---

## CMSTP Execution Registry Event

| Field | Value |
|---|---|
| **Sigma ID** | `b6d235fc-1d38-4b12-adbe-325f06728f37` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1218.003 |
| **Author** | Nik Seetharaman |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.yml)**

> Detects various indicators of Microsoft Connection Manager Profile Installer execution

```sql
-- ============================================================
-- Title:        CMSTP Execution Registry Event
-- Sigma ID:     b6d235fc-1d38-4b12-adbe-325f06728f37
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        execution | T1218.003
-- Author:       Nik Seetharaman
-- Date:         2018-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate CMSTP use (unlikely in modern enterprise environments)
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\cmmgr32.exe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate CMSTP use (unlikely in modern enterprise environments)

**References:**
- https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/

---

## Windows Defender Threat Severity Default Action Modified

| Field | Value |
|---|---|
| **Sigma ID** | `5a9e1b2c-8f7d-4a1e-9b3c-0f6d7e5a4b1f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Matt Anderson (Huntress) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_defender_threat_action_modified.yml)**

> Detects modifications or creations of Windows Defender's default threat action settings based on severity to 'allow' or take 'no action'.
This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level,
allowing malicious software to run unimpeded. An attacker might use this technique to bypass defenses before executing payloads.


```sql
-- ============================================================
-- Title:        Windows Defender Threat Severity Default Action Modified
-- Sigma ID:     5a9e1b2c-8f7d-4a1e-9b3c-0f6d7e5a4b1f
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001
-- Author:       Matt Anderson (Huntress)
-- Date:         2025-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_defender_threat_action_modified.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration via scripts or tools (e.g., SCCM, Intune, GPO enforcement). Correlate with administrative activity.; Software installations that legitimately modify Defender settings (less common for these specific keys).
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\1' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\2' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\4' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\5'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('DWORD (0x00000006)', 'DWORD (0x00000009)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration via scripts or tools (e.g., SCCM, Intune, GPO enforcement). Correlate with administrative activity.; Software installations that legitimately modify Defender settings (less common for these specific keys).

**References:**
- https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference
- https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-threatseveritydefaultaction
- https://research.splunk.com/endpoint/7215831c-8252-4ae3-8d43-db588e82f952
- https://gist.github.com/Dump-GUY/8daef859f382b895ac6fd0cf094555d2
- https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/

---

## Disable Security Events Logging Adding Reg Key MiniNt

| Field | Value |
|---|---|
| **Sigma ID** | `919f2ef0-be2d-4a7a-b635-eb2b41fde044` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.002, T1112 |
| **Author** | Ilyas Ochkov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_disable_security_events_logging_adding_reg_key_minint.yml)**

> Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stop writing events.

```sql
-- ============================================================
-- Title:        Disable Security Events Logging Adding Reg Key MiniNt
-- Sigma ID:     919f2ef0-be2d-4a7a-b635-eb2b41fde044
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1562.002, T1112
-- Author:       Ilyas Ochkov, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_disable_security_events_logging_adding_reg_key_minint.yml
-- Unmapped:     EventType, NewName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: EventType
-- UNMAPPED_FIELD: NewName

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
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] = 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt')
    AND rawEventMsg = 'CreateKey'))
  OR (rawEventMsg = 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/0gtweet/status/1182516740955226112
- https://www.hackingarticles.in/defense-evasion-windows-event-logging-t1562-002/

---

## Wdigest CredGuard Registry Modification

| Field | Value |
|---|---|
| **Sigma ID** | `1a2d6c47-75b0-45bd-b133-2c0be75349fd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml)**

> Detects potential malicious modification of the property value of IsCredGuardEnabled from
HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to disable Cred Guard on a system.
This is usually used with UseLogonCredential to manipulate the caching credentials.


```sql
-- ============================================================
-- Title:        Wdigest CredGuard Registry Modification
-- Sigma ID:     1a2d6c47-75b0-45bd-b133-2c0be75349fd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2019-08-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\IsCredGuardEnabled')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://teamhydra.blog/2020/08/25/bypassing-credential-guard/

---

## Esentutl Volume Shadow Copy Service Keys

| Field | Value |
|---|---|
| **Sigma ID** | `5aad0995-46ab-41bd-a9ff-724f41114971` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_esentutl_volume_shadow_copy_service_keys.yml)**

> Detects the volume shadow copy service initialization and processing via esentutl. Registry keys such as HKLM\\System\\CurrentControlSet\\Services\\VSS\\Diag\\VolSnap\\Volume are captured.

```sql
-- ============================================================
-- Title:        Esentutl Volume Shadow Copy Service Keys
-- Sigma ID:     5aad0995-46ab-41bd-a9ff-724f41114971
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_esentutl_volume_shadow_copy_service_keys.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%System\\CurrentControlSet\\Services\\VSS%')
    AND procName LIKE '%esentutl.exe')
  AND NOT (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%System\\CurrentControlSet\\Services\\VSS\\Start%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy

---

## Windows Credential Editor Registry

| Field | Value |
|---|---|
| **Sigma ID** | `a6b33c02-8305-488f-8585-03cb2a7763f2` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_hack_wce_reg.yml)**

> Detects the use of Windows Credential Editor (WCE)

```sql
-- ============================================================
-- Title:        Windows Credential Editor Registry
-- Sigma ID:     a6b33c02-8305-488f-8585-03cb2a7763f2
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-12-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_hack_wce_reg.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Services\\WCESERVICE\\Start%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.ampliasecurity.com/research/windows-credentials-editor/

---

## HybridConnectionManager Service Installation - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `ac8866c7-ce44-46fd-8c17-b24acff96ca8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1608 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_hybridconnectionmgr_svc_installation.yml)**

> Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.

```sql
-- ============================================================
-- Title:        HybridConnectionManager Service Installation - Registry
-- Sigma ID:     ac8866c7-ce44-46fd-8c17-b24acff96ca8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1608
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2021-04-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_hybridconnectionmgr_svc_installation.yml
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
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\HybridConnectionManager%')
  OR (rawEventMsg = 'SetValue'
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Microsoft.HybridConnectionManager.Listener.exe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/Cyb3rWard0g/status/1381642789369286662

---

## Registry Entries For Azorult Malware

| Field | Value |
|---|---|
| **Sigma ID** | `f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1112 |
| **Author** | Trent Liffick |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_mal_azorult.yml)**

> Detects the presence of a registry key created during Azorult execution

```sql
-- ============================================================
-- Title:        Registry Entries For Azorult Malware
-- Sigma ID:     f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence, execution | T1112
-- Author:       Trent Liffick
-- Date:         2020-05-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_mal_azorult.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('12', '13')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SYSTEM\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\services\\localNETService'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a

---

## Potential Qakbot Registry Activity

| Field | Value |
|---|---|
| **Sigma ID** | `1c8e96cd-2bed-487d-9de0-b46c90cade56` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Hieu Tran |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_malware_qakbot_registry.yml)**

> Detects a registry key used by IceID in a campaign that distributes malicious OneNote files

```sql
-- ============================================================
-- Title:        Potential Qakbot Registry Activity
-- Sigma ID:     1c8e96cd-2bed-487d-9de0-b46c90cade56
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Hieu Tran
-- Date:         2023-03-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_malware_qakbot_registry.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\firm\\soft\\Name')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

---

## Path To Screensaver Binary Modified

| Field | Value |
|---|---|
| **Sigma ID** | `67a6c006-3fbe-46a7-9074-2ba3b82c3000` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.002 |
| **Author** | Bartlomiej Czyz @bczyz1, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_modify_screensaver_binary_path.yml)**

> Detects value modification of registry key containing path to binary used as screensaver.

```sql
-- ============================================================
-- Title:        Path To Screensaver Binary Modified
-- Sigma ID:     67a6c006-3fbe-46a7-9074-2ba3b82c3000
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.002
-- Author:       Bartlomiej Czyz @bczyz1, oscd.community
-- Date:         2020-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_modify_screensaver_binary_path.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate modification of screensaver
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control Panel\\Desktop\\SCRNSAVE.EXE')
  AND NOT ((procName LIKE '%\\rundll32.exe' OR procName LIKE '%\\explorer.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate modification of screensaver

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md
- https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf

---

## Narrator's Feedback-Hub Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `f663a6d9-9d1b-49b8-b2b1-0637914d199a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Dmitriy Lifanov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_narrator_feedback_persistance.yml)**

> Detects abusing Windows 10 Narrator's Feedback-Hub

```sql
-- ============================================================
-- Title:        Narrator's Feedback-Hub Persistence
-- Sigma ID:     f663a6d9-9d1b-49b8-b2b1-0637914d199a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Dmitriy Lifanov, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_narrator_feedback_persistance.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\DelegateExecute'))
  OR indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppXypsaf9f1qserqevf0sws76dx4k9a5206\\Shell\\open\\command\\(Default)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html

---

## NetNTLM Downgrade Attack - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `d67572a0-e2ec-45d6-b8db-c100d14b8ef2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.001, T1112 |
| **Author** | Florian Roth (Nextron Systems), wagga, Nasreddine Bencherchali (Splunk STRT) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_net_ntlm_downgrade.yml)**

> Detects NetNTLM downgrade attack

```sql
-- ============================================================
-- Title:        NetNTLM Downgrade Attack - Registry
-- Sigma ID:     d67572a0-e2ec-45d6-b8db-c100d14b8ef2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1562.001, T1112
-- Author:       Florian Roth (Nextron Systems), wagga, Nasreddine Bencherchali (Splunk STRT)
-- Date:         2018-03-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_net_ntlm_downgrade.yml
-- Unmapped:     (none)
-- False Pos:    Services or tools that set the values to more restrictive values
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SYSTEM\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ControlSet%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Lsa%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Services or tools that set the values to more restrictive values

**References:**
- https://web.archive.org/web/20171113231705/https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
- https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=NSrpcservers

---

## New DLL Added to AppCertDlls Registry Key

| Field | Value |
|---|---|
| **Sigma ID** | `6aa1d992-5925-4e9f-a49b-845e51d1de01` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.009 |
| **Author** | Ilyas Ochkov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_new_dll_added_to_appcertdlls_registry_key.yml)**

> Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation
by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.


```sql
-- ============================================================
-- Title:        New DLL Added to AppCertDlls Registry Key
-- Sigma ID:     6aa1d992-5925-4e9f-a49b-845e51d1de01
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.009
-- Author:       Ilyas Ochkov, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_new_dll_added_to_appcertdlls_registry_key.yml
-- Unmapped:     NewName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: NewName

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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'))
  OR (rawEventMsg = 'HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
- https://eqllib.readthedocs.io/en/latest/analytics/14f90406-10a0-4d36-a672-31cabe149f2f.html

---

## New DLL Added to AppInit_DLLs Registry Key

| Field | Value |
|---|---|
| **Sigma ID** | `4f84b697-c9ed-4420-8ab5-e09af5b2345d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.010 |
| **Author** | Ilyas Ochkov, oscd.community, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_new_dll_added_to_appinit_dlls_registry_key.yml)**

> DLLs that are specified in the AppInit_DLLs value in the Registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll

```sql
-- ============================================================
-- Title:        New DLL Added to AppInit_DLLs Registry Key
-- Sigma ID:     4f84b697-c9ed-4420-8ab5-e09af5b2345d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.010
-- Author:       Ilyas Ochkov, oscd.community, Tim Shelton
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_new_dll_added_to_appinit_dlls_registry_key.yml
-- Unmapped:     NewName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: NewName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit\_Dlls' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit\_Dlls')))
  OR ((rawEventMsg LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit\_Dlls' OR rawEventMsg LIKE '%\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit\_Dlls'))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://eqllib.readthedocs.io/en/latest/analytics/822dc4c5-b355-4df8-bd37-29c458997b8f.html

---

## Office Application Startup - Office Test

| Field | Value |
|---|---|
| **Sigma ID** | `3d27f6dd-1c74-4687-b4fa-ca849d128d1c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137.002 |
| **Author** | omkar72 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_office_test_regadd.yml)**

> Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started

```sql
-- ============================================================
-- Title:        Office Application Startup - Office Test
-- Sigma ID:     3d27f6dd-1c74-4687-b4fa-ca849d128d1c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1137.002
-- Author:       omkar72
-- Date:         2020-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_office_test_regadd.yml
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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Office test\\Special\\Perf%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/

---

## Windows Registry Trust Record Modification

| Field | Value |
|---|---|
| **Sigma ID** | `295a59c1-7b79-4b47-a930-df12c15fc9c2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1566.001 |
| **Author** | Antonlovesdnb, Trent Liffick (@tliffick) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_office_trust_record_modification.yml)**

> Alerts on trust record modification within the registry, indicating usage of macros

```sql
-- ============================================================
-- Title:        Windows Registry Trust Record Modification
-- Sigma ID:     295a59c1-7b79-4b47-a930-df12c15fc9c2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1566.001
-- Author:       Antonlovesdnb, Trent Liffick (@tliffick)
-- Date:         2020-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_office_trust_record_modification.yml
-- Unmapped:     (none)
-- False Pos:    This will alert on legitimate macro usage as well, additional tuning is required
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Security\\Trusted Documents\\TrustRecords%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This will alert on legitimate macro usage as well, additional tuning is required

**References:**
- https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
- http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
- https://twitter.com/inversecos/status/1494174785621819397

---

## Registry Persistence Mechanisms in Recycle Bin

| Field | Value |
|---|---|
| **Sigma ID** | `277efb8f-60be-4f10-b4d3-037802f37167` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_persistence_recycle_bin.yml)**

> Detects persistence registry keys for Recycle Bin

```sql
-- ============================================================
-- Title:        Registry Persistence Mechanisms in Recycle Bin
-- Sigma ID:     277efb8f-60be-4f10-b4d3-037802f37167
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547
-- Author:       frack113
-- Date:         2021-11-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_persistence_recycle_bin.yml
-- Unmapped:     EventType, NewName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: EventType
-- UNMAPPED_FIELD: NewName

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
  AND (rawEventMsg = 'RenameKey'
    AND rawEventMsg LIKE '%\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open%')
  OR (rawEventMsg = 'SetValue'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open\\command\\(Default)%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/vxunderground/VXUG-Papers/blob/751edb8d50f95bd7baa730adf2c6c3bb1b034276/The%20Persistence%20Series/Persistence%20via%20Recycle%20Bin/Persistence_via_Recycle_Bin.pdf
- https://persistence-info.github.io/Data/recyclebin.html
- https://www.hexacorn.com/blog/2018/05/28/beyond-good-ol-run-key-part-78-2/

---

## New PortProxy Registry Entry Added

| Field | Value |
|---|---|
| **Sigma ID** | `a54f842a-3713-4b45-8c84-5f136fdebd3c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1090 |
| **Author** | Andreas Hunkeler (@Karneades) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_portproxy_registry_key.yml)**

> Detects the modification of the PortProxy registry key which is used for port forwarding.

```sql
-- ============================================================
-- Title:        New PortProxy Registry Entry Added
-- Sigma ID:     a54f842a-3713-4b45-8c84-5f136fdebd3c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1090
-- Author:       Andreas Hunkeler (@Karneades)
-- Date:         2021-06-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_portproxy_registry_key.yml
-- Unmapped:     (none)
-- False Pos:    WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723); Synergy Software KVM (https://symless.com/synergy)
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\PortProxy\\v4tov4\\tcp\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723); Synergy Software KVM (https://symless.com/synergy)

**References:**
- https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
- https://adepts.of0x.cc/netsh-portproxy-code/
- https://www.dfirnotes.net/portproxy_detection/

---

## RedMimicry Winnti Playbook Registry Manipulation

| Field | Value |
|---|---|
| **Sigma ID** | `5b175490-b652-4b02-b1de-5b5b4083c5f8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Alexander Rausch |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_redmimicry_winnti_reg.yml)**

> Detects actions caused by the RedMimicry Winnti playbook

```sql
-- ============================================================
-- Title:        RedMimicry Winnti Playbook Registry Manipulation
-- Sigma ID:     5b175490-b652-4b02-b1de-5b5b4083c5f8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Alexander Rausch
-- Date:         2020-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_redmimicry_winnti_reg.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%HKLM\\SOFTWARE\\Microsoft\\HTMLHelp\\data%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redmimicry.com

---

## WINEKEY Registry Modification

| Field | Value |
|---|---|
| **Sigma ID** | `b98968aa-dbc0-4a9c-ac35-108363cbf8d5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547 |
| **Author** | omkar72 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_runkey_winekey.yml)**

> Detects potential malicious modification of run keys by winekey or team9 backdoor

```sql
-- ============================================================
-- Title:        WINEKEY Registry Modification
-- Sigma ID:     b98968aa-dbc0-4a9c-ac35-108363cbf8d5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547
-- Author:       omkar72
-- Date:         2020-10-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_runkey_winekey.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backup Mgr')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html

---

## Run Once Task Configuration in Registry

| Field | Value |
|---|---|
| **Sigma ID** | `c74d7efc-8826-45d9-b8bb-f04fac9e4eff` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Avneet Singh @v3t0_, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_runonce_persistence.yml)**

> Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup

```sql
-- ============================================================
-- Title:        Run Once Task Configuration in Registry
-- Sigma ID:     c74d7efc-8826-45d9-b8bb-f04fac9e4eff
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Avneet Singh @v3t0_, oscd.community
-- Date:         2020-11-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_runonce_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate modification of the registry key by legitimate program
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Active Setup\\Installed Components%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\StubPath'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate modification of the registry key by legitimate program

**References:**
- https://twitter.com/pabraeken/status/990717080805789697
- https://lolbas-project.github.io/lolbas/Binaries/Runonce/

---

## Shell Open Registry Keys Manipulation

| Field | Value |
|---|---|
| **Sigma ID** | `152f3630-77c1-4284-bcc0-4cc68ab2f6e7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548.002, T1546.001 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.yml)**

> Detects the shell open key manipulation (exefile and ms-settings) used for persistence and the pattern of UAC Bypass using fodhelper.exe, computerdefaults.exe, slui.exe via registry keys (e.g. UACMe 33 or 62)

```sql
-- ============================================================
-- Title:        Shell Open Registry Keys Manipulation
-- Sigma ID:     152f3630-77c1-4284-bcc0-4cc68ab2f6e7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1548.002, T1546.001
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.yml
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
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SetValue'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\ms-settings\\shell\\open\\command\\SymbolicLinkValue')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Software\\Classes\\{%'))
  OR indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\ms-settings\\shell\\open\\command\\DelegateExecute')
  OR ((rawEventMsg = 'SetValue'
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\ms-settings\\shell\\open\\command\\(Default)' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\exefile\\shell\\open\\command\\(Default)')))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME
- https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
- https://github.com/RhinoSecurityLabs/Aggressor-Scripts/tree/master/UACBypass
- https://tria.ge/211119-gs7rtshcfr/behavioral2 [Lokibot sample from Nov 2021]

---

## Potential Credential Dumping Via LSASS SilentProcessExit Technique

| Field | Value |
|---|---|
| **Sigma ID** | `55e29995-75e7-451a-bef0-6225e2f13597` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.yml)**

> Detects changes to the Registry in which a monitor program gets registered to dump the memory of the lsass.exe process

```sql
-- ============================================================
-- Title:        Potential Credential Dumping Via LSASS SilentProcessExit Technique
-- Sigma ID:     55e29995-75e7-451a-bef0-6225e2f13597
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-02-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.yml
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
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/
- https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/

---

## Security Support Provider (SSP) Added to LSA Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.005 |
| **Author** | iwillkeepwatch |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_ssp_added_lsa_config.yml)**

> Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.


```sql
-- ============================================================
-- Title:        Security Support Provider (SSP) Added to LSA Configuration
-- Sigma ID:     eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.005
-- Author:       iwillkeepwatch
-- Date:         2019-01-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_ssp_added_lsa_config.yml
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
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Lsa\\Security Packages' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Lsa\\OSConfig\\Security Packages'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
- https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/data/module_source/persistence/Install-SSP.ps1#L157

---

## Sticky Key Like Backdoor Usage - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `baca5663-583c-45f9-b5dc-ea96a22ce542` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.008 |
| **Author** | Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_stickykey_like_backdoor.yml)**

> Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen

```sql
-- ============================================================
-- Title:        Sticky Key Like Backdoor Usage - Registry
-- Sigma ID:     baca5663-583c-45f9-b5dc-ea96a22ce542
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence | T1546.008
-- Author:       Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community
-- Date:         2018-03-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_stickykey_like_backdoor.yml
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\atbroker.exe\\Debugger' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\HelpPane.exe\\Debugger'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
- https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/

---

## Atbroker Registry Change

| Field | Value |
|---|---|
| **Sigma ID** | `9577edbb-851f-4243-8c91-1d5b50c1a39b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1218, T1547 |
| **Author** | Mateusz Wydra, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_atbroker_change.yml)**

> Detects creation/modification of Assistive Technology applications and persistence with usage of 'at'

```sql
-- ============================================================
-- Title:        Atbroker Registry Change
-- Sigma ID:     9577edbb-851f-4243-8c91-1d5b50c1a39b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1218, T1547
-- Author:       Mateusz Wydra, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_atbroker_change.yml
-- Unmapped:     (none)
-- False Pos:    Creation of non-default, legitimate at usage
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Creation of non-default, legitimate at usage

**References:**
- http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
- https://lolbas-project.github.io/lolbas/Binaries/Atbroker/

---

## Suspicious Run Key from Download

| Field | Value |
|---|---|
| **Sigma ID** | `9c5037d1-c568-49b3-88c7-9846a5bdc2be` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Florian Roth (Nextron Systems), Swachchhanda Shrawan Poude (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml)**

> Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories

```sql
-- ============================================================
-- Title:        Suspicious Run Key from Download
-- Sigma ID:     9c5037d1-c568-49b3-88c7-9846a5bdc2be
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Florian Roth (Nextron Systems), Swachchhanda Shrawan Poude (Nextron Systems)
-- Date:         2019-10-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml
-- Unmapped:     (none)
-- False Pos:    Software installers downloaded and used by users
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\AppData\\Local\\Packages\\Microsoft.Outlook\_%' OR procName LIKE '%\\AppData\\Local\\Microsoft\\Olk\\Attachments\\%' OR procName LIKE '%\\Downloads\\%' OR procName LIKE '%\\Temporary Internet Files\\Content.Outlook\\%' OR procName LIKE '%\\Local Settings\\Temporary Internet Files\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Software installers downloaded and used by users

**References:**
- https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/
- https://github.com/HackTricks-wiki/hacktricks/blob/e4c7b21b8f36c97c35b7c622732b38a189ce18f7/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md

---

## DLL Load via LSASS

| Field | Value |
|---|---|
| **Sigma ID** | `b3503044-60ce-4bf4-bbcb-e3db98788823` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1547.008 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_lsass_dll_load.yml)**

> Detects a method to load DLL via LSASS process using an undocumented Registry key

```sql
-- ============================================================
-- Title:        DLL Load via LSASS
-- Sigma ID:     b3503044-60ce-4bf4-bbcb-e3db98788823
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1547.008
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-10-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_lsass_dll_load.yml
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
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.xpnsec.com/exploring-mimikatz-part-1/
- https://twitter.com/SBousseaden/status/1183745981189427200

---

## Suspicious Camera and Microphone Access

| Field | Value |
|---|---|
| **Sigma ID** | `62120148-6b7a-42be-8b91-271c04e281a3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1125, T1123 |
| **Author** | Den Iuzvyk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_mic_cam_access.yml)**

> Detects Processes accessing the camera and microphone from suspicious folder

```sql
-- ============================================================
-- Title:        Suspicious Camera and Microphone Access
-- Sigma ID:     62120148-6b7a-42be-8b91-271c04e281a3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1125, T1123
-- Author:       Den Iuzvyk
-- Date:         2020-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_mic_cam_access.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely, there could be conferencing software running from a Temp folder accessing the devices
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
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\NonPackaged%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%microphone%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%webcam%'))
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%:#Windows#Temp#%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%:#$Recycle.bin#%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%:#Temp#%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%:#Users#Public#%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%:#Users#Default#%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%:#Users#Desktop#%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely, there could be conferencing software running from a Temp folder accessing the devices

**References:**
- https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

---

## Registry Tampering by Potentially Suspicious Processes

| Field | Value |
|---|---|
| **Sigma ID** | `7f4c43f9-b1a5-4c7d-b24a-b41bf3a3ebf2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1112, T1059.005 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_process_registry_modification.yml)**

> Detects suspicious registry modifications made by suspicious processes such as script engine processes such as WScript, or CScript etc.
These processes are rarely used for legitimate registry modifications, and their activity may indicate an attempt to modify the registry
without using standard tools like regedit.exe or reg.exe, potentially for evasion and persistence.


```sql
-- ============================================================
-- Title:        Registry Tampering by Potentially Suspicious Processes
-- Sigma ID:     7f4c43f9-b1a5-4c7d-b24a-b41bf3a3ebf2
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence, execution | T1112, T1059.005
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_susp_process_registry_modification.yml
-- Unmapped:     (none)
-- False Pos:    Some legitimate admin or install scripts may use these processes for registry modifications.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\mshta.exe' OR procName LIKE '%\\wscript.exe' OR procName LIKE '%\\cscript.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some legitimate admin or install scripts may use these processes for registry modifications.

**References:**
- https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/
- https://www.linkedin.com/posts/mauricefielenbach_livingofftheland-redteam-persistence-activity-7344801774182051843-TE00/

---
