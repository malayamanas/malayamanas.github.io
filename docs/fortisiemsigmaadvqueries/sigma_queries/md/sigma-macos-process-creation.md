# Sigma → FortiSIEM: Macos Process Creation

> 67 rules · Generated 2026-03-17

## Table of Contents

- [MacOS Scripting Interpreter AppleScript](#macos-scripting-interpreter-applescript)
- [Decode Base64 Encoded Text -MacOs](#decode-base64-encoded-text-macos)
- [Binary Padding - MacOS](#binary-padding-macos)
- [File Time Attribute Change](#file-time-attribute-change)
- [Hidden Flag Set On File/Directory Via Chflags - MacOS](#hidden-flag-set-on-filedirectory-via-chflags-macos)
- [Indicator Removal on Host - Clear Mac System Logs](#indicator-removal-on-host-clear-mac-system-logs)
- [Clipboard Data Collection Via OSAScript](#clipboard-data-collection-via-osascript)
- [Creation Of A Local User Account](#creation-of-a-local-user-account)
- [Hidden User Creation](#hidden-user-creation)
- [Credentials from Password Stores - Keychain](#credentials-from-password-stores-keychain)
- [System Integrity Protection (SIP) Disabled](#system-integrity-protection-sip-disabled)
- [System Integrity Protection (SIP) Enumeration](#system-integrity-protection-sip-enumeration)
- [Disable Security Tools](#disable-security-tools)
- [User Added To Admin Group Via Dscl](#user-added-to-admin-group-via-dscl)
- [User Added To Admin Group Via DseditGroup](#user-added-to-admin-group-via-dseditgroup)
- [Root Account Enable Via Dsenableroot](#root-account-enable-via-dsenableroot)
- [File and Directory Discovery - MacOS](#file-and-directory-discovery-macos)
- [Credentials In Files](#credentials-in-files)
- [GUI Input Capture - macOS](#gui-input-capture-macos)
- [Disk Image Creation Via Hdiutil - MacOS](#disk-image-creation-via-hdiutil-macos)
- [Disk Image Mounting Via Hdiutil - MacOS](#disk-image-mounting-via-hdiutil-macos)
- [Suspicious Installer Package Child Process](#suspicious-installer-package-child-process)
- [System Information Discovery Using Ioreg](#system-information-discovery-using-ioreg)
- [JAMF MDM Potential Suspicious Child Process](#jamf-mdm-potential-suspicious-child-process)
- [JAMF MDM Execution](#jamf-mdm-execution)
- [JXA In-memory Execution Via OSAScript](#jxa-in-memory-execution-via-osascript)
- [Launch Agent/Daemon Execution Via Launchctl](#launch-agentdaemon-execution-via-launchctl)
- [Local System Accounts Discovery - MacOs](#local-system-accounts-discovery-macos)
- [Local Groups Discovery - MacOs](#local-groups-discovery-macos)
- [MacOS Network Service Scanning](#macos-network-service-scanning)
- [Network Sniffing - MacOs](#network-sniffing-macos)
- [File Download Via Nscurl - MacOS](#file-download-via-nscurl-macos)
- [Suspicious Microsoft Office Child Process - MacOS](#suspicious-microsoft-office-child-process-macos)
- [OSACompile Run-Only Execution](#osacompile-run-only-execution)
- [Payload Decoded and Decrypted via Built-in Utilities](#payload-decoded-and-decrypted-via-built-in-utilities)
- [Potential Persistence Via PlistBuddy](#potential-persistence-via-plistbuddy)
- [Remote Access Tool - Potential MeshAgent Execution - MacOS](#remote-access-tool-potential-meshagent-execution-macos)
- [Remote Access Tool - Renamed MeshAgent Execution - MacOS](#remote-access-tool-renamed-meshagent-execution-macos)
- [Remote Access Tool - Team Viewer Session Started On MacOS Host](#remote-access-tool-team-viewer-session-started-on-macos-host)
- [Macos Remote System Discovery](#macos-remote-system-discovery)
- [Scheduled Cron Task/Job - MacOs](#scheduled-cron-taskjob-macos)
- [Screen Capture - macOS](#screen-capture-macos)
- [Security Software Discovery - MacOs](#security-software-discovery-macos)
- [Space After Filename - macOS](#space-after-filename-macos)
- [Split A File Into Pieces](#split-a-file-into-pieces)
- [Suspicious Browser Child Process - MacOS](#suspicious-browser-child-process-macos)
- [Suspicious Execution via macOS Script Editor](#suspicious-execution-via-macos-script-editor)
- [Potential Discovery Activity Using Find - MacOS](#potential-discovery-activity-using-find-macos)
- [Suspicious History File Operations](#suspicious-history-file-operations)
- [Potential In-Memory Download And Compile Of Payloads](#potential-in-memory-download-and-compile-of-payloads)
- [Suspicious MacOS Firmware Activity](#suspicious-macos-firmware-activity)
- [System Network Discovery - macOS](#system-network-discovery-macos)
- [Osacompile Execution By Potentially Suspicious Applet/Osascript](#osacompile-execution-by-potentially-suspicious-appletosascript)
- [System Information Discovery Using sw_vers](#system-information-discovery-using-swvers)
- [User Added To Admin Group Via Sysadminctl](#user-added-to-admin-group-via-sysadminctl)
- [Guest Account Enabled Via Sysadminctl](#guest-account-enabled-via-sysadminctl)
- [System Information Discovery Via Sysctl - MacOS](#system-information-discovery-via-sysctl-macos)
- [System Network Connections Discovery - MacOs](#system-network-connections-discovery-macos)
- [System Information Discovery Using System_Profiler](#system-information-discovery-using-systemprofiler)
- [System Shutdown/Reboot - MacOs](#system-shutdownreboot-macos)
- [Potential Base64 Decoded From Images](#potential-base64-decoded-from-images)
- [Time Machine Backup Deletion Attempt Via Tmutil - MacOS](#time-machine-backup-deletion-attempt-via-tmutil-macos)
- [Time Machine Backup Disabled Via Tmutil - MacOS](#time-machine-backup-disabled-via-tmutil-macos)
- [New File Exclusion Added To Time Machine Via Tmutil - MacOS](#new-file-exclusion-added-to-time-machine-via-tmutil-macos)
- [Potential WizardUpdate Malware Infection](#potential-wizardupdate-malware-infection)
- [Gatekeeper Bypass via Xattr](#gatekeeper-bypass-via-xattr)
- [Potential XCSSET Malware Infection](#potential-xcsset-malware-infection)

## MacOS Scripting Interpreter AppleScript

| Field | Value |
|---|---|
| **Sigma ID** | `1bc2e6c5-0885-472b-bed6-be5ea8eace55` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.002 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_applescript.yml)**

> Detects execution of AppleScript of the macOS scripting language AppleScript.

```sql
-- ============================================================
-- Title:        MacOS Scripting Interpreter AppleScript
-- Sigma ID:     1bc2e6c5-0885-472b-bed6-be5ea8eace55
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.002
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_applescript.yml
-- Unmapped:     (none)
-- False Pos:    Application installers might contain scripts as part of the installation process.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/osascript'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.scpt%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.js%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application installers might contain scripts as part of the installation process.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.002/T1059.002.md
- https://redcanary.com/blog/applescript/

---

## Decode Base64 Encoded Text -MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `719c22d7-c11a-4f2c-93a6-2cfdd5412f68` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_base64_decode.yml)**

> Detects usage of base64 utility to decode arbitrary base64-encoded text

```sql
-- ============================================================
-- Title:        Decode Base64 Encoded Text -MacOs
-- Sigma ID:     719c22d7-c11a-4f2c-93a6-2cfdd5412f68
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_base64_decode.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = '/usr/bin/base64'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-d%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md

---

## Binary Padding - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `95361ce5-c891-4b0a-87ca-e24607884a96` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027.001 |
| **Author** | Igor Fits, Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_binary_padding.yml)**

> Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.

```sql
-- ============================================================
-- Title:        Binary Padding - MacOS
-- Sigma ID:     95361ce5-c891-4b0a-87ca-e24607884a96
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027.001
-- Author:       Igor Fits, Mikhail Larin, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_binary_padding.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate script work
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dd'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%if=/dev/zero%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%if=/dev/random%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%if=/dev/urandom%')))
  OR (procName LIKE '%/truncate'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-s +%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate script work

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.001/T1027.001.md
- https://linux.die.net/man/1/truncate
- https://linux.die.net/man/1/dd

---

## File Time Attribute Change

| Field | Value |
|---|---|
| **Sigma ID** | `88c0f9d8-30a8-4120-bb6b-ebb54abcf2a0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.006 |
| **Author** | Igor Fits, Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_change_file_time_attr.yml)**

> Detect file time attribute change to hide new or changes to existing files

```sql
-- ============================================================
-- Title:        File Time Attribute Change
-- Sigma ID:     88c0f9d8-30a8-4120-bb6b-ebb54abcf2a0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.006
-- Author:       Igor Fits, Mikhail Larin, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_change_file_time_attr.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/touch'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-t%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-acmr%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-d%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-r%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.006/T1070.006.md

---

## Hidden Flag Set On File/Directory Via Chflags - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `3b2c1059-ae5f-40b6-b5d4-6106d3ac20fe` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218, T1564.004, T1552.001, T1105 |
| **Author** | Omar Khaled (@beacon_exe) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_chflags_hidden_flag.yml)**

> Detects the execution of the "chflags" utility with the "hidden" flag, in order to hide files on MacOS.
When a file or directory has this hidden flag set, it becomes invisible to the default file listing commands and in graphical file browsers.


```sql
-- ============================================================
-- Title:        Hidden Flag Set On File/Directory Via Chflags - MacOS
-- Sigma ID:     3b2c1059-ae5f-40b6-b5d4-6106d3ac20fe
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218, T1564.004, T1552.001, T1105
-- Author:       Omar Khaled (@beacon_exe)
-- Date:         2024-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_chflags_hidden_flag.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of chflags by administrators and users.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/chflags'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%hidden %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of chflags by administrators and users.

**References:**
- https://www.sentinelone.com/labs/apt32-multi-stage-macos-trojan-innovates-on-crimeware-scripting-technique/
- https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
- https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf
- https://ss64.com/mac/chflags.html

---

## Indicator Removal on Host - Clear Mac System Logs

| Field | Value |
|---|---|
| **Sigma ID** | `acf61bd8-d814-4272-81f0-a7a269aa69aa` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.002 |
| **Author** | remotephone, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_clear_system_logs.yml)**

> Detects deletion of local audit logs

```sql
-- ============================================================
-- Title:        Indicator Removal on Host - Clear Mac System Logs
-- Sigma ID:     acf61bd8-d814-4272-81f0-a7a269aa69aa
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.002
-- Author:       remotephone, oscd.community
-- Date:         2020-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_clear_system_logs.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/rm' OR procName LIKE '%/unlink' OR procName LIKE '%/shred')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md

---

## Clipboard Data Collection Via OSAScript

| Field | Value |
|---|---|
| **Sigma ID** | `7794fa3c-edea-4cff-bec7-267dd4770fd7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection, execution |
| **MITRE Techniques** | T1115, T1059.002 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_clipboard_data_via_osascript.yml)**

> Detects possible collection of data from the clipboard via execution of the osascript binary

```sql
-- ============================================================
-- Title:        Clipboard Data Collection Via OSAScript
-- Sigma ID:     7794fa3c-edea-4cff-bec7-267dd4770fd7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection, execution | T1115, T1059.002
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-01-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_clipboard_data_via_osascript.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osascript%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%clipboard%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/

---

## Creation Of A Local User Account

| Field | Value |
|---|---|
| **Sigma ID** | `51719bf5-e4fd-4e44-8ba8-b830e7ac0731` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_create_account.yml)**

> Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

```sql
-- ============================================================
-- Title:        Creation Of A Local User Account
-- Sigma ID:     51719bf5-e4fd-4e44-8ba8-b830e7ac0731
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1136.001
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_create_account.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dscl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%create%'))
  OR (procName LIKE '%/sysadminctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%addUser%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.001/T1136.001.md
- https://ss64.com/osx/sysadminctl.html

---

## Hidden User Creation

| Field | Value |
|---|---|
| **Sigma ID** | `b22a5b36-2431-493a-8be1-0bae56c28ef3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.002 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_create_hidden_account.yml)**

> Detects creation of a hidden user account on macOS (UserID < 500) or with IsHidden option

```sql
-- ============================================================
-- Title:        Hidden User Creation
-- Sigma ID:     b22a5b36-2431-493a-8be1-0bae56c28ef3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.002
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_create_hidden_account.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/dscl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%create%'))
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%UniqueID%')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '([0-9]|[1-9][0-9]|[1-4][0-9]{2})'))))
  OR ((procName LIKE '%/dscl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%create%'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IsHidden%')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%true%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%yes%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%1%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.002/T1564.002.md

---

## Credentials from Password Stores - Keychain

| Field | Value |
|---|---|
| **Sigma ID** | `b120b587-a4c2-4b94-875d-99c9807d6955` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555.001 |
| **Author** | Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_creds_from_keychain.yml)**

> Detects passwords dumps from Keychain

```sql
-- ============================================================
-- Title:        Credentials from Password Stores - Keychain
-- Sigma ID:     b120b587-a4c2-4b94-875d-99c9807d6955
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1555.001
-- Author:       Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems)
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_creds_from_keychain.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = '/usr/bin/security'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%find-certificate%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% export %')))
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% dump-keychain %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% login-keychain %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.001/T1555.001.md
- https://gist.github.com/Capybara/6228955

---

## System Integrity Protection (SIP) Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `3603f18a-ec15-43a1-9af2-d196c8a7fec6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1518.001 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_csrutil_disable.yml)**

> Detects the use of csrutil to disable the Configure System Integrity Protection (SIP). This technique is used in post-exploit scenarios.


```sql
-- ============================================================
-- Title:        System Integrity Protection (SIP) Disabled
-- Sigma ID:     3603f18a-ec15-43a1-9af2-d196c8a7fec6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1518.001
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2024-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_csrutil_disable.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/csrutil'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://ss64.com/osx/csrutil.html
- https://objective-see.org/blog/blog_0x6D.html
- https://www.welivesecurity.com/2017/10/20/osx-proton-supply-chain-attack-elmedia/
- https://www.virustotal.com/gui/file/05a2adb266ec6c0ba9ed176d87d8530e71e845348c13caf9f60049760c312cd3/behavior

---

## System Integrity Protection (SIP) Enumeration

| Field | Value |
|---|---|
| **Sigma ID** | `53821412-17b0-4147-ade0-14faae67d54b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1518.001 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_csrutil_status.yml)**

> Detects the use of csrutil to view the Configure System Integrity Protection (SIP) status. This technique is used in post-exploit scenarios.


```sql
-- ============================================================
-- Title:        System Integrity Protection (SIP) Enumeration
-- Sigma ID:     53821412-17b0-4147-ade0-14faae67d54b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1518.001
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2024-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_csrutil_status.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/csrutil'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%status%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://ss64.com/osx/csrutil.html
- https://objective-see.org/blog/blog_0x6D.html
- https://www.welivesecurity.com/2017/10/20/osx-proton-supply-chain-attack-elmedia/
- https://www.virustotal.com/gui/file/05a2adb266ec6c0ba9ed176d87d8530e71e845348c13caf9f60049760c312cd3/behavior

---

## Disable Security Tools

| Field | Value |
|---|---|
| **Sigma ID** | `ff39f1a6-84ac-476f-a1af-37fcdf53d7c0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_disable_security_tools.yml)**

> Detects disabling security tools

```sql
-- ============================================================
-- Title:        Disable Security Tools
-- Sigma ID:     ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_disable_security_tools.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName = '/bin/launchctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%unload%'))
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.objective-see.lulu.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.objective-see.blockblock.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.google.santad.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.carbonblack.defense.daemon.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.carbonblack.daemon.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%at.obdev.littlesnitchd.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.tenablesecurity.nessusagent.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.opendns.osx.RoamingClientConfigUpdater.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.crowdstrike.falcond.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.crowdstrike.userdaemon.plist%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osquery%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%filebeat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%auditbeat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%packetbeat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%td-agent%')))
  OR (procName = '/usr/sbin/spctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

---

## User Added To Admin Group Via Dscl

| Field | Value |
|---|---|
| **Sigma ID** | `b743623c-2776-40e0-87b1-682b975d0ca5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.003 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_dscl_add_user_to_admin_group.yml)**

> Detects attempts to create and add an account to the admin group via "dscl"

```sql
-- ============================================================
-- Title:        User Added To Admin Group Via Dscl
-- Sigma ID:     b743623c-2776-40e0-87b1-682b975d0ca5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.003
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_dscl_add_user_to_admin_group.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dscl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -append %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% /Groups/admin %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% GroupMembership %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-2---create-local-account-with-admin-privileges---macos
- https://ss64.com/osx/dscl.html

---

## User Added To Admin Group Via DseditGroup

| Field | Value |
|---|---|
| **Sigma ID** | `5d0fdb62-f225-42fb-8402-3dfe64da468a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.003 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml)**

> Detects attempts to create and/or add an account to the admin group, thus granting admin privileges.

```sql
-- ============================================================
-- Title:        User Added To Admin Group Via DseditGroup
-- Sigma ID:     5d0fdb62-f225-42fb-8402-3dfe64da468a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.003
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dseditgroup'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -o edit %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -a %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -t user%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%admin%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-5---add-a-newexisting-user-to-the-admin-group-using-dseditgroup-utility---macos
- https://ss64.com/osx/dseditgroup.html

---

## Root Account Enable Via Dsenableroot

| Field | Value |
|---|---|
| **Sigma ID** | `821bcf4d-46c7-4b87-bc57-9509d3ba7c11` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1078.001, T1078.003 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_dsenableroot_enable_root_account.yml)**

> Detects attempts to enable the root account via "dsenableroot"

```sql
-- ============================================================
-- Title:        Root Account Enable Via Dsenableroot
-- Sigma ID:     821bcf4d-46c7-4b87-bc57-9509d3ba7c11
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078, T1078.001, T1078.003
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_dsenableroot_enable_root_account.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/dsenableroot'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1078.003/T1078.003.md
- https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/persistence_enable_root_account.toml
- https://ss64.com/osx/dsenableroot.html

---

## File and Directory Discovery - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `089dbdf6-b960-4bcc-90e3-ffc3480c20f6` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_file_and_directory_discovery.yml)**

> Detects usage of system utilities to discover files and directories

```sql
-- ============================================================
-- Title:        File and Directory Discovery - MacOS
-- Sigma ID:     089dbdf6-b960-4bcc-90e3-ffc3480c20f6
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_file_and_directory_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = '/usr/bin/file'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '(.){200,}')))
  OR procName = '/usr/bin/find'
  OR procName = '/usr/bin/mdfind'
  OR (procName = '/bin/ls'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-R%'))
  OR procName = '/tree'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md

---

## Credentials In Files

| Field | Value |
|---|---|
| **Sigma ID** | `53b1b378-9b06-4992-b972-dde6e423d2b4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1552.001 |
| **Author** | Igor Fits, Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml)**

> Detecting attempts to extract passwords with grep and laZagne

```sql
-- ============================================================
-- Title:        Credentials In Files
-- Sigma ID:     53b1b378-9b06-4992-b972-dde6e423d2b4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1552.001
-- Author:       Igor Fits, Mikhail Larin, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/grep'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%password%'))
  OR indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%laZagne%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md

---

## GUI Input Capture - macOS

| Field | Value |
|---|---|
| **Sigma ID** | `60f1ce20-484e-41bd-85f4-ac4afec2c541` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1056.002 |
| **Author** | remotephone, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_gui_input_capture.yml)**

> Detects attempts to use system dialog prompts to capture user credentials

```sql
-- ============================================================
-- Title:        GUI Input Capture - macOS
-- Sigma ID:     60f1ce20-484e-41bd-85f4-ac4afec2c541
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1056.002
-- Author:       remotephone, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_gui_input_capture.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration tools and activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-e%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%display%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%dialog%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%answer%')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%admin%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%administrator%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%authenticate%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%authentication%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%credentials%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%pass%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%password%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%unlock%'))
  AND procName LIKE '%/osascript')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration tools and activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.002/T1056.002.md
- https://scriptingosx.com/2018/08/user-interaction-from-bash-scripts/

---

## Disk Image Creation Via Hdiutil - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `1cf98dc2-fcb0-47c9-8aea-654c9284d1ae` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **Author** | Omar Khaled (@beacon_exe) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_hdiutil_create.yml)**

> Detects the execution of the hdiutil utility in order to create a disk image.

```sql
-- ============================================================
-- Title:        Disk Image Creation Via Hdiutil - MacOS
-- Sigma ID:     1cf98dc2-fcb0-47c9-8aea-654c9284d1ae
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration
-- Author:       Omar Khaled (@beacon_exe)
-- Date:         2024-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_hdiutil_create.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of hdiutil by administrators and users.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/hdiutil'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%create%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of hdiutil by administrators and users.

**References:**
- https://www.loobins.io/binaries/hdiutil/
- https://www.sentinelone.com/blog/from-the-front-linesunsigned-macos-orat-malware-gambles-for-the-win/
- https://ss64.com/mac/hdiutil.html

---

## Disk Image Mounting Via Hdiutil - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `bf241472-f014-4f01-a869-96f99330ca8c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1566.001, T1560.001 |
| **Author** | Omar Khaled (@beacon_exe) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml)**

> Detects the execution of the hdiutil utility in order to mount disk images.

```sql
-- ============================================================
-- Title:        Disk Image Mounting Via Hdiutil - MacOS
-- Sigma ID:     bf241472-f014-4f01-a869-96f99330ca8c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1566.001, T1560.001
-- Author:       Omar Khaled (@beacon_exe)
-- Date:         2024-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of hdiutil by administrators and users.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/hdiutil'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%attach %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%mount %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of hdiutil by administrators and users.

**References:**
- https://www.loobins.io/binaries/hdiutil/
- https://www.sentinelone.com/blog/from-the-front-linesunsigned-macos-orat-malware-gambles-for-the-win/
- https://ss64.com/mac/hdiutil.html

---

## Suspicious Installer Package Child Process

| Field | Value |
|---|---|
| **Sigma ID** | `e0cfaecd-602d-41af-988d-f6ccebb2af26` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059, T1059.007, T1071, T1071.001 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_installer_susp_child_process.yml)**

> Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters

```sql
-- ============================================================
-- Title:        Suspicious Installer Package Child Process
-- Sigma ID:     e0cfaecd-602d-41af-988d-f6ccebb2af26
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059, T1059.007, T1071, T1071.001
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-02-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_installer_susp_child_process.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software uses the scripts (preinstall, postinstall)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/package\_script\_service' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/installer'))
    AND (procName LIKE '%/sh' OR procName LIKE '%/bash' OR procName LIKE '%/dash' OR procName LIKE '%/python' OR procName LIKE '%/ruby' OR procName LIKE '%/perl' OR procName LIKE '%/php' OR procName LIKE '%/javascript' OR procName LIKE '%/osascript' OR procName LIKE '%/tclsh' OR procName LIKE '%/curl' OR procName LIKE '%/wget')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%preinstall%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%postinstall%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software uses the scripts (preinstall, postinstall)

**References:**
- https://redcanary.com/blog/clipping-silver-sparrows-wings/
- https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/execution_installer_package_spawned_network_event.toml

---

## System Information Discovery Using Ioreg

| Field | Value |
|---|---|
| **Sigma ID** | `2d5e7a8b-f484-4a24-945d-7f0efd52eab0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_ioreg_discovery.yml)**

> Detects the use of "ioreg" which will show I/O Kit registry information.
This process is used for system information discovery.
It has been observed in-the-wild by calling this process directly or using bash and grep to look for specific strings.


```sql
-- ============================================================
-- Title:        System Information Discovery Using Ioreg
-- Sigma ID:     2d5e7a8b-f484-4a24-945d-7f0efd52eab0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_ioreg_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-l%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-c%'))
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%AppleAHCIDiskDriver%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IOPlatformExpertDevice%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%Oracle%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%Parallels%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%USB Vendor Name%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%VirtualBox%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%VMware%'))
  AND (procName LIKE '%/ioreg')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ioreg%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities

**References:**
- https://www.virustotal.com/gui/file/0373d78db6c3c0f6f6dcc409821bf89e1ad8c165d6f95c5c80ecdce2219627d7/behavior
- https://www.virustotal.com/gui/file/4ffdc72d1ff1ee8228e31691020fc275afd1baee5a985403a71ca8c7bd36e2e4/behavior
- https://www.virustotal.com/gui/file/5907d59ec1303cfb5c0a0f4aaca3efc0830707d86c732ba6b9e842b5730b95dc/behavior
- https://www.trendmicro.com/en_ph/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html

---

## JAMF MDM Potential Suspicious Child Process

| Field | Value |
|---|---|
| **Sigma ID** | `2316929c-01aa-438c-970f-099145ab1ee6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_jamf_susp_child.yml)**

> Detects potential suspicious child processes of "jamf". Could be a sign of potential abuse of Jamf as a C2 server as seen by Typhon MythicAgent.

```sql
-- ============================================================
-- Title:        JAMF MDM Potential Suspicious Child Process
-- Sigma ID:     2316929c-01aa-438c-970f-099145ab1ee6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_jamf_susp_child.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate execution of custom scripts or commands by Jamf administrators. Apply additional filters accordingly
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/jamf')
    AND (procName LIKE '%/bash' OR procName LIKE '%/sh'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate execution of custom scripts or commands by Jamf administrators. Apply additional filters accordingly

**References:**
- https://github.com/MythicAgents/typhon/
- https://www.zoocoup.org/casper/jamf_cheatsheet.pdf
- https://docs.jamf.com/10.30.0/jamf-pro/administrator-guide/Components_Installed_on_Managed_Computers.html

---

## JAMF MDM Execution

| Field | Value |
|---|---|
| **Sigma ID** | `be2e3a5c-9cc7-4d02-842a-68e9cb26ec49` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **Author** | Jay Pandit |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_jamf_usage.yml)**

> Detects execution of the "jamf" binary to create user accounts and run commands. For example, the binary can be abused by attackers on the system in order to bypass security controls or remove application control polices.


```sql
-- ============================================================
-- Title:        JAMF MDM Execution
-- Sigma ID:     be2e3a5c-9cc7-4d02-842a-68e9cb26ec49
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution
-- Author:       Jay Pandit
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_jamf_usage.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the JAMF CLI tool by IT support and administrators
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/jamf'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%createAccount%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%manage%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%removeFramework%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%removeMdmProfile%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%resetPassword%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%setComputerName%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the JAMF CLI tool by IT support and administrators

**References:**
- https://github.com/MythicAgents/typhon/
- https://www.zoocoup.org/casper/jamf_cheatsheet.pdf
- https://docs.jamf.com/10.30.0/jamf-pro/administrator-guide/Components_Installed_on_Managed_Computers.html

---

## JXA In-memory Execution Via OSAScript

| Field | Value |
|---|---|
| **Sigma ID** | `f1408a58-0e94-4165-b80a-da9f96cf6fc3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.002, T1059.007 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml)**

> Detects possible malicious execution of JXA in-memory via OSAScript

```sql
-- ============================================================
-- Title:        JXA In-memory Execution Via OSAScript
-- Sigma ID:     f1408a58-0e94-4165-b80a-da9f96cf6fc3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.002, T1059.007
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-01-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -l %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%JavaScript%'))
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.js%'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osascript%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%eval%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%NSData.dataWithContentsOfURL%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/applescript/

---

## Launch Agent/Daemon Execution Via Launchctl

| Field | Value |
|---|---|
| **Sigma ID** | `ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1569.001, T1543.001, T1543.004 |
| **Author** | Pratinav Chandra |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_launchctl_execution.yml)**

> Detects the execution of programs as Launch Agents or Launch Daemons using launchctl on macOS.

```sql
-- ============================================================
-- Title:        Launch Agent/Daemon Execution Via Launchctl
-- Sigma ID:     ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1569.001, T1543.001, T1543.004
-- Author:       Pratinav Chandra
-- Date:         2024-05-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_launchctl_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities is expected to trigger false positives. Investigate the command line being passed to determine if the service or launch agent are suspicious.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/launchctl'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%submit%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%load%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%start%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities is expected to trigger false positives. Investigate the command line being passed to determine if the service or launch agent are suspicious.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1569.001/T1569.001.md
- https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/
- https://www.welivesecurity.com/2020/07/16/mac-cryptocurrency-trading-application-rebranded-bundled-malware/
- https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
- https://www.loobins.io/binaries/launchctl/

---

## Local System Accounts Discovery - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `ddf36b67-e872-4507-ab2e-46bda21b842c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.001 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_local_account.yml)**

> Detects enumeration of local systeam accounts on MacOS

```sql
-- ============================================================
-- Title:        Local System Accounts Discovery - MacOs
-- Sigma ID:     ddf36b67-e872-4507-ab2e-46bda21b842c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1087.001
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_local_account.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dscl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%list%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/users%'))
  OR (procName LIKE '%/dscacheutil'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-q%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%user%'))
  OR indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'x:0:'%')
  OR (procName LIKE '%/cat'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/passwd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/sudoers%')))
  OR procName LIKE '%/id'
  OR (procName LIKE '%/lsof'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-u%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md

---

## Local Groups Discovery - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `89bb1f97-c7b9-40e8-b52b-7d6afbd67276` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | Ömer Günal, Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_local_groups.yml)**

> Detects enumeration of local system groups

```sql
-- ============================================================
-- Title:        Local Groups Discovery - MacOs
-- Sigma ID:     89bb1f97-c7b9-40e8-b52b-7d6afbd67276
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       Ömer Günal, Alejandro Ortuno, oscd.community
-- Date:         2020-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_local_groups.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dscacheutil'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-q%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%group%'))
  OR (procName LIKE '%/cat'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/group%'))
  OR (procName LIKE '%/dscl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-list%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/groups%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md

---

## MacOS Network Service Scanning

| Field | Value |
|---|---|
| **Sigma ID** | `84bae5d4-b518-4ae0-b331-6d4afd34d00f` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1046 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_network_service_scanning.yml)**

> Detects enumeration of local or remote network services.

```sql
-- ============================================================
-- Title:        MacOS Network Service Scanning
-- Sigma ID:     84bae5d4-b518-4ae0-b331-6d4afd34d00f
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1046
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_network_service_scanning.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/nc' OR procName LIKE '%/netcat')
  AND NOT (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%l%')))
  OR (procName LIKE '%/nmap' OR procName LIKE '%/telnet')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md

---

## Network Sniffing - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `adc9bcc4-c39c-4f6b-a711-1884017bf043` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1040 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_network_sniffing.yml)**

> Detects the usage of tooling to sniff network traffic.
An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.


```sql
-- ============================================================
-- Title:        Network Sniffing - MacOs
-- Sigma ID:     adc9bcc4-c39c-4f6b-a711-1884017bf043
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1040
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_network_sniffing.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/tcpdump' OR procName LIKE '%/tshark')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md

---

## File Download Via Nscurl - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `6d8a7cf1-8085-423b-b87d-7e880faabbdf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | Daniel Cortez |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_nscurl_usage.yml)**

> Detects the execution of the nscurl utility in order to download files.

```sql
-- ============================================================
-- Title:        File Download Via Nscurl - MacOS
-- Sigma ID:     6d8a7cf1-8085-423b-b87d-7e880faabbdf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       Daniel Cortez
-- Date:         2024-06-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_nscurl_usage.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of nscurl by administrators and users.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/nscurl'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--download %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--download-directory %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--output %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-dir %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-dl %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-ld%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-o %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of nscurl by administrators and users.

**References:**
- https://www.loobins.io/binaries/nscurl/
- https://www.agnosticdev.com/content/how-diagnose-app-transport-security-issues-using-nscurl-and-openssl
- https://gist.github.com/nasbench/ca6ef95db04ae04ffd1e0b1ce709cadd

---

## Suspicious Microsoft Office Child Process - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `69483748-1525-4a6c-95ca-90dc8d431b68` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1059.002, T1137.002, T1204.002 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml)**

> Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution

```sql
-- ============================================================
-- Title:        Suspicious Microsoft Office Child Process - MacOS
-- Sigma ID:     69483748-1525-4a6c-95ca-90dc8d431b68
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1059.002, T1137.002, T1204.002
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-01-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Microsoft Word%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Microsoft Excel%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Microsoft PowerPoint%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Microsoft OneNote%'))
    AND (procName LIKE '%/bash' OR procName LIKE '%/curl' OR procName LIKE '%/dash' OR procName LIKE '%/fish' OR procName LIKE '%/osacompile' OR procName LIKE '%/osascript' OR procName LIKE '%/sh' OR procName LIKE '%/zsh' OR procName LIKE '%/python' OR procName LIKE '%/python3' OR procName LIKE '%/wget'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/applescript/
- https://objective-see.org/blog/blog_0x4B.html

---

## OSACompile Run-Only Execution

| Field | Value |
|---|---|
| **Sigma ID** | `b9d9b652-d8ed-4697-89a2-a1186ee680ac` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.002 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.yml)**

> Detects potential suspicious run-only executions compiled using OSACompile

```sql
-- ============================================================
-- Title:        OSACompile Run-Only Execution
-- Sigma ID:     b9d9b652-d8ed-4697-89a2-a1186ee680ac
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.002
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-01-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osacompile%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -x %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/applescript/
- https://ss64.com/osx/osacompile.html

---

## Payload Decoded and Decrypted via Built-in Utilities

| Field | Value |
|---|---|
| **Sigma ID** | `234dc5df-40b5-49d1-bf53-0d44ce778eca` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059, T1204, T1140 |
| **Author** | Tim Rauch (rule), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_payload_decoded_and_decrypted.yml)**

> Detects when a built-in utility is used to decode and decrypt a payload after a macOS disk image (DMG) is executed. Malware authors may attempt to evade detection and trick users into executing malicious code by encoding and encrypting their payload and placing it in a disk image file. This behavior is consistent with adware or malware families such as Bundlore and Shlayer.

```sql
-- ============================================================
-- Title:        Payload Decoded and Decrypted via Built-in Utilities
-- Sigma ID:     234dc5df-40b5-49d1-bf53-0d44ce778eca
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059, T1204, T1140
-- Author:       Tim Rauch (rule), Elastic (idea)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_payload_decoded_and_decrypted.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/openssl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Volumes/%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%enc%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-base64%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -d %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-5d42c3d772e04f1e8d0eb60f5233bc79def1ea73105a2d8822f44164f77ef823

---

## Potential Persistence Via PlistBuddy

| Field | Value |
|---|---|
| **Sigma ID** | `65d506d3-fcfe-4071-b4b2-bcefe721bbbb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.001, T1543.004 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_persistence_via_plistbuddy.yml)**

> Detects potential persistence activity using LaunchAgents or LaunchDaemons via the PlistBuddy utility

```sql
-- ============================================================
-- Title:        Potential Persistence Via PlistBuddy
-- Sigma ID:     65d506d3-fcfe-4071-b4b2-bcefe721bbbb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543.001, T1543.004
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-02-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_persistence_via_plistbuddy.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/PlistBuddy'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%RunAtLoad%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%true%')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%LaunchAgents%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%LaunchDaemons%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/clipping-silver-sparrows-wings/
- https://www.manpagez.com/man/8/PlistBuddy/

---

## Remote Access Tool - Potential MeshAgent Execution - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `22c45af6-f590-4d44-bab3-b5b2d2a2b6d9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Norbert Jaśniewicz (AlphaSOC) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_access_tools_meshagent_arguments.yml)**

> Detects potential execution of MeshAgent which is a tool used for remote access.
Historical data shows that threat actors rename MeshAgent binary to evade detection.
Matching command lines with the '--meshServiceName' argument can indicate that the MeshAgent is being used for remote access.


```sql
-- ============================================================
-- Title:        Remote Access Tool - Potential MeshAgent Execution - MacOS
-- Sigma ID:     22c45af6-f590-4d44-bab3-b5b2d2a2b6d9
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1219.002
-- Author:       Norbert Jaśniewicz (AlphaSOC)
-- Date:         2025-05-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_access_tools_meshagent_arguments.yml
-- Unmapped:     (none)
-- False Pos:    Environments that legitimately use MeshAgent
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--meshServiceName%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Environments that legitimately use MeshAgent

**References:**
- https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
- https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
- https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
- https://www.security.com/threat-intelligence/medusa-ransomware-attacks

---

## Remote Access Tool - Renamed MeshAgent Execution - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `bd3b5eaa-439d-4a42-8f35-a49f5c8a2582` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1219.002, T1036.003 |
| **Author** | Norbert Jaśniewicz (AlphaSOC) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml)**

> Detects the execution of a renamed instance of the Remote Monitoring and Management (RMM) tool, MeshAgent.
RMM tools such as MeshAgent are commonly utilized by IT administrators for legitimate remote support and system management.
However, malicious actors may exploit these tools by renaming them to bypass detection mechanisms, enabling unauthorized access and control over compromised systems.


```sql
-- ============================================================
-- Title:        Remote Access Tool - Renamed MeshAgent Execution - MacOS
-- Sigma ID:     bd3b5eaa-439d-4a42-8f35-a49f5c8a2582
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1219.002, T1036.003
-- Author:       Norbert Jaśniewicz (AlphaSOC)
-- Date:         2025-05-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  metrics_string.value[indexOf(metrics_string.name,'originalFileName')] AS originalFileName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--meshServiceName%'))
  OR (indexOf(metrics_string.name, 'originalFileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'originalFileName')] LIKE '%meshagent%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
- https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
- https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
- https://www.security.com/threat-intelligence/medusa-ransomware-attacks

---

## Remote Access Tool - Team Viewer Session Started On MacOS Host

| Field | Value |
|---|---|
| **Sigma ID** | `f459ccb4-9805-41ea-b5b2-55e279e2424a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | Josh Nickels, Qi Nan |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_access_tools_teamviewer_incoming_connection.yml)**

> Detects the command line executed when TeamViewer starts a session started by a remote host.
Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.


```sql
-- ============================================================
-- Title:        Remote Access Tool - Team Viewer Session Started On MacOS Host
-- Sigma ID:     f459ccb4-9805-41ea-b5b2-55e279e2424a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1133
-- Author:       Josh Nickels, Qi Nan
-- Date:         2024-03-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_access_tools_teamviewer_incoming_connection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of TeamViewer
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/TeamViewer\_Service')
    AND procName LIKE '%/TeamViewer\_Desktop'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/TeamViewer\_Desktop --IPCport 5939 --Module 1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of TeamViewer

**References:**
- Internal Research

---

## Macos Remote System Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `10227522-8429-47e6-a301-f2b2d014e7ad` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1018 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_system_discovery.yml)**

> Detects the enumeration of other remote systems.

```sql
-- ============================================================
-- Title:        Macos Remote System Discovery
-- Sigma ID:     10227522-8429-47e6-a301-f2b2d014e7ad
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1018
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_remote_system_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/arp'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-a%'))
  OR (procName LIKE '%/ping'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 10.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 192.168.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.16.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.17.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.18.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.19.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.20.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.21.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.22.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.23.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.24.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.25.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.26.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.27.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.28.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.29.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.30.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 172.31.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 127.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% 169.254.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md

---

## Scheduled Cron Task/Job - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `7c3b43d8-d794-47d2-800a-d277715aa460` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.003 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_schedule_task_job_cron.yml)**

> Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.

```sql
-- ============================================================
-- Title:        Scheduled Cron Task/Job - MacOs
-- Sigma ID:     7c3b43d8-d794-47d2-800a-d277715aa460
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.003
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_schedule_task_job_cron.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/crontab'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md

---

## Screen Capture - macOS

| Field | Value |
|---|---|
| **Sigma ID** | `0877ed01-da46-4c49-8476-d49cdd80dfa7` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | remotephone, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_screencapture.yml)**

> Detects attempts to use screencapture to collect macOS screenshots

```sql
-- ============================================================
-- Title:        Screen Capture - macOS
-- Sigma ID:     0877ed01-da46-4c49-8476-d49cdd80dfa7
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       remotephone, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_screencapture.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate user activity taking screenshots
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName = '/usr/sbin/screencapture'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity taking screenshots

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md
- https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/lib/modules/python/collection/osx/screenshot.py

---

## Security Software Discovery - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `0ed75b9c-c73b-424d-9e7d-496cd565fbe0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1518.001 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_security_software_discovery.yml)**

> Detects usage of system utilities (only grep for now) to discover security software discovery

```sql
-- ============================================================
-- Title:        Security Software Discovery - MacOs
-- Sigma ID:     0ed75b9c-c73b-424d-9e7d-496cd565fbe0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1518.001
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_security_software_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName = '/usr/bin/grep'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md

---

## Space After Filename - macOS

| Field | Value |
|---|---|
| **Sigma ID** | `b6e2a2e3-2d30-43b1-a4ea-071e36595690` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1036.006 |
| **Author** | remotephone |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_space_after_filename.yml)**

> Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.

```sql
-- ============================================================
-- Title:        Space After Filename - macOS
-- Sigma ID:     b6e2a2e3-2d30-43b1-a4ea-071e36595690
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1036.006
-- Author:       remotephone
-- Date:         2021-11-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_space_after_filename.yml
-- Unmapped:     (none)
-- False Pos:    Mistyped commands or legitimate binaries named to match the pattern
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% ')
  OR procName LIKE '% '
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Mistyped commands or legitimate binaries named to match the pattern

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.006/T1036.006.md

---

## Split A File Into Pieces

| Field | Value |
|---|---|
| **Sigma ID** | `7f2bb9d5-6395-4de5-969c-70c11fbe6b12` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1030 |
| **Author** | Igor Fits, Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml)**

> Detection use of the command "split" to split files into parts and possible transfer.

```sql
-- ============================================================
-- Title:        Split A File Into Pieces
-- Sigma ID:     7f2bb9d5-6395-4de5-969c-70c11fbe6b12
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1030
-- Author:       Igor Fits, Mikhail Larin, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/split'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1030/T1030.md

---

## Suspicious Browser Child Process - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `0250638a-2b28-4541-86fc-ea4c558fa0c6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1189, T1203, T1059 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_browser_child_process.yml)**

> Detects suspicious child processes spawned from browsers. This could be a result of a potential web browser exploitation.

```sql
-- ============================================================
-- Title:        Suspicious Browser Child Process - MacOS
-- Sigma ID:     0250638a-2b28-4541-86fc-ea4c558fa0c6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1189, T1203, T1059
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-04-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_browser_child_process.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate browser install, update and recovery scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%com.apple.WebKit.WebContent%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%firefox%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Google Chrome Helper%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Google Chrome%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Microsoft Edge%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Opera%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Safari%' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%Tor Browser%'))
    AND (procName LIKE '%/bash' OR procName LIKE '%/curl' OR procName LIKE '%/dash' OR procName LIKE '%/ksh' OR procName LIKE '%/osascript' OR procName LIKE '%/perl' OR procName LIKE '%/php' OR procName LIKE '%/pwsh' OR procName LIKE '%/python' OR procName LIKE '%/sh' OR procName LIKE '%/tcsh' OR procName LIKE '%/wget' OR procName LIKE '%/zsh'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate browser install, update and recovery scripts

**References:**
- https://fr.slideshare.net/codeblue_jp/cb19-recent-apt-attack-on-crypto-exchange-employees-by-heungsoo-kang
- https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/execution_initial_access_suspicious_browser_childproc.toml

---

## Suspicious Execution via macOS Script Editor

| Field | Value |
|---|---|
| **Sigma ID** | `6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1566, T1566.002, T1059, T1059.002, T1204, T1204.001, T1553 |
| **Author** | Tim Rauch (rule), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml)**

> Detects when the macOS Script Editor utility spawns an unusual child process.

```sql
-- ============================================================
-- Title:        Suspicious Execution via macOS Script Editor
-- Sigma ID:     6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1566, T1566.002, T1059, T1059.002, T1204, T1204.001, T1553
-- Author:       Tim Rauch (rule), Elastic (idea)
-- Date:         2022-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((procName LIKE '%/curl' OR procName LIKE '%/bash' OR procName LIKE '%/sh' OR procName LIKE '%/zsh' OR procName LIKE '%/dash' OR procName LIKE '%/fish' OR procName LIKE '%/osascript' OR procName LIKE '%/mktemp' OR procName LIKE '%/chmod' OR procName LIKE '%/php' OR procName LIKE '%/nohup' OR procName LIKE '%/openssl' OR procName LIKE '%/plutil' OR procName LIKE '%/PlistBuddy' OR procName LIKE '%/xattr' OR procName LIKE '%/sqlite' OR procName LIKE '%/funzip' OR procName LIKE '%/popen'))
  OR ((procName LIKE '%python%' OR procName LIKE '%perl%'))
  AND indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/Script Editor'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-7f541fbc4a4a28a92970e8bf53effea5bd934604429112c920affb457f5b2685
- https://wojciechregula.blog/post/macos-red-teaming-initial-access-via-applescript-url/

---

## Potential Discovery Activity Using Find - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `85de3a19-b675-4a51-bfc6-b11a5186c971` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_find_execution.yml)**

> Detects usage of "find" binary in a suspicious manner to perform discovery

```sql
-- ============================================================
-- Title:        Potential Discovery Activity Using Find - MacOS
-- Sigma ID:     85de3a19-b675-4a51-bfc6-b11a5186c971
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_find_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/find'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -4000%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -2000%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm 0777%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -222%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -o w%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -o x%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -u=s%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-perm -g=s%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes

---

## Suspicious History File Operations

| Field | Value |
|---|---|
| **Sigma ID** | `508a9374-ad52-4789-b568-fc358def2c65` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552.003 |
| **Author** | Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_histfile_operations.yml)**

> Detects commandline operations on shell history files

```sql
-- ============================================================
-- Title:        Suspicious History File Operations
-- Sigma ID:     508a9374-ad52-4789-b568-fc358def2c65
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552.003
-- Author:       Mikhail Larin, oscd.community
-- Date:         2020-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_histfile_operations.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activity; Legitimate software, cleaning hist file
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.bash\_history%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.zsh\_history%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.zhistory%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.history%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.sh\_history%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%fish\_history%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity; Legitimate software, cleaning hist file

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md

---

## Potential In-Memory Download And Compile Of Payloads

| Field | Value |
|---|---|
| **Sigma ID** | `13db8d2e-7723-4c2c-93c1-a4d36994f7ef` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.007, T1105 |
| **Author** | Sohan G (D4rkCiph3r), Red Canary (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_in_memory_download_and_compile.yml)**

> Detects potential in-memory downloading and compiling of applets using curl and osacompile as seen used by XCSSET malware

```sql
-- ============================================================
-- Title:        Potential In-Memory Download And Compile Of Payloads
-- Sigma ID:     13db8d2e-7723-4c2c-93c1-a4d36994f7ef
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.007, T1105
-- Author:       Sohan G (D4rkCiph3r), Red Canary (idea)
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_in_memory_download_and_compile.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osacompile%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%curl%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/mac-application-bundles/

---

## Suspicious MacOS Firmware Activity

| Field | Value |
|---|---|
| **Sigma ID** | `7ed2c9f7-c59d-4c82-a7e2-f859aa676099` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_macos_firmware_activity.yml)**

> Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.

```sql
-- ============================================================
-- Title:        Suspicious MacOS Firmware Activity
-- Sigma ID:     7ed2c9f7-c59d-4c82-a7e2-f859aa676099
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_macos_firmware_activity.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = '/usr/sbin/firmwarepasswd'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%setpasswd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%full%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%delete%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%check%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/usnistgov/macos_security/blob/932a51f3e819dd3e02ebfcf3ef433cfffafbe28b/rules/os/os_firmware_password_require.yaml
- https://www.manpagez.com/man/8/firmwarepasswd/
- https://support.apple.com/guide/security/firmware-password-protection-sec28382c9ca/web

---

## System Network Discovery - macOS

| Field | Value |
|---|---|
| **Sigma ID** | `58800443-f9fc-4d55-ae0c-98a3966dfb97` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1016 |
| **Author** | remotephone, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_system_network_discovery.yml)**

> Detects enumeration of local network configuration

```sql
-- ============================================================
-- Title:        System Network Discovery - macOS
-- Sigma ID:     58800443-f9fc-4d55-ae0c-98a3966dfb97
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1016
-- Author:       remotephone, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_susp_system_network_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md

---

## Osacompile Execution By Potentially Suspicious Applet/Osascript

| Field | Value |
|---|---|
| **Sigma ID** | `a753a6af-3126-426d-8bd0-26ebbcb92254` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.002 |
| **Author** | Sohan G (D4rkCiph3r), Red Canary (Idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_suspicious_applet_behaviour.yml)**

> Detects potential suspicious applet or osascript executing "osacompile".

```sql
-- ============================================================
-- Title:        Osacompile Execution By Potentially Suspicious Applet/Osascript
-- Sigma ID:     a753a6af-3126-426d-8bd0-26ebbcb92254
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.002
-- Author:       Sohan G (D4rkCiph3r), Red Canary (Idea)
-- Date:         2023-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_suspicious_applet_behaviour.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/applet' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/osascript'))
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osacompile%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/mac-application-bundles/

---

## System Information Discovery Using sw_vers

| Field | Value |
|---|---|
| **Sigma ID** | `5de06a6f-673a-4fc0-8d48-bcfe3837b033` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_swvers_discovery.yml)**

> Detects the use of "sw_vers" for system information discovery

```sql
-- ============================================================
-- Title:        System Information Discovery Using sw_vers
-- Sigma ID:     5de06a6f-673a-4fc0-8d48-bcfe3837b033
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_swvers_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sw\_vers'
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-buildVersion%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-productName%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-productVersion%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities

**References:**
- https://www.virustotal.com/gui/file/d3fa64f63563fe958b75238742d1e473800cb5f49f5cb79d38d4aa3c93709026/behavior
- https://www.virustotal.com/gui/file/03b71eaceadea05bc0eea5cddecaa05f245126d6b16cfcd0f3ba0442ac58dab3/behavior
- https://ss64.com/osx/sw_vers.html

---

## User Added To Admin Group Via Sysadminctl

| Field | Value |
|---|---|
| **Sigma ID** | `652c098d-dc11-4ba6-8566-c20e89042f2b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.003 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysadminctl_add_user_to_admin_group.yml)**

> Detects attempts to create and add an account to the admin group via "sysadminctl"

```sql
-- ============================================================
-- Title:        User Added To Admin Group Via Sysadminctl
-- Sigma ID:     652c098d-dc11-4ba6-8566-c20e89042f2b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.003
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysadminctl_add_user_to_admin_group.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sysadminctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -addUser %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -admin %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-3---create-local-account-with-admin-privileges-using-sysadminctl-utility---macos
- https://ss64.com/osx/sysadminctl.html

---

## Guest Account Enabled Via Sysadminctl

| Field | Value |
|---|---|
| **Sigma ID** | `d7329412-13bd-44ba-a072-3387f804a106` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1078.001 |
| **Author** | Sohan G (D4rkCiph3r) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysadminctl_enable_guest_account.yml)**

> Detects attempts to enable the guest account using the sysadminctl utility

```sql
-- ============================================================
-- Title:        Guest Account Enabled Via Sysadminctl
-- Sigma ID:     d7329412-13bd-44ba-a072-3387f804a106
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078, T1078.001
-- Author:       Sohan G (D4rkCiph3r)
-- Date:         2023-02-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysadminctl_enable_guest_account.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sysadminctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -guestAccount%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% on%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://ss64.com/osx/sysadminctl.html

---

## System Information Discovery Via Sysctl - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `6ff08e55-ea53-4f27-94a1-eff92e6d9d5c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1497.001, T1082 |
| **Author** | Pratinav Chandra |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysctl_discovery.yml)**

> Detects the execution of "sysctl" with specific arguments that have been used by threat actors and malware. It provides system hardware information.
This process is primarily used to detect and avoid virtualization and analysis environments.


```sql
-- ============================================================
-- Title:        System Information Discovery Via Sysctl - MacOS
-- Sigma ID:     6ff08e55-ea53-4f27-94a1-eff92e6d9d5c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1497.001, T1082
-- Author:       Pratinav Chandra
-- Date:         2024-05-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_sysctl_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%hw.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%kern.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%machdep.%'))
  AND (procName LIKE '%/sysctl')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sysctl%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities

**References:**
- https://www.loobins.io/binaries/sysctl/#
- https://evasions.checkpoint.com/techniques/macos.html
- https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
- https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/
- https://objective-see.org/blog/blog_0x1E.html
- https://www.virustotal.com/gui/file/1c547a064494a35d6b5e6b459de183ab2720a22725e082bed6f6629211f7abc1/behavior
- https://www.virustotal.com/gui/file/b4b1fc65f87b3dcfa35e2dbe8e0a34ad9d8a400bec332025c0a2e200671038aa/behavior

---

## System Network Connections Discovery - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `9a7a0393-2144-4626-9bf1-7c2f5a7321db` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1049 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_network_connections_discovery.yml)**

> Detects usage of system utilities to discover system network connections

```sql
-- ============================================================
-- Title:        System Network Connections Discovery - MacOs
-- Sigma ID:     9a7a0393-2144-4626-9bf1-7c2f5a7321db
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1049
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_network_connections_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/who' OR procName LIKE '%/w' OR procName LIKE '%/last' OR procName LIKE '%/lsof' OR procName LIKE '%/netstat')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md

---

## System Information Discovery Using System_Profiler

| Field | Value |
|---|---|
| **Sigma ID** | `4809c683-059b-4935-879d-36835986f8cf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082, T1497.001 |
| **Author** | Stephen Lincoln `@slincoln_aiq` (AttackIQ) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_profiler_discovery.yml)**

> Detects the execution of "system_profiler" with specific "Data Types" that have been seen being used by threat actors and malware. It provides system hardware and software configuration information.
This process is primarily used for system information discovery. However, "system_profiler" can also be used to determine if virtualization software is being run for defense evasion purposes.


```sql
-- ============================================================
-- Title:        System Information Discovery Using System_Profiler
-- Sigma ID:     4809c683-059b-4935-879d-36835986f8cf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1082, T1497.001
-- Author:       Stephen Lincoln `@slincoln_aiq` (AttackIQ)
-- Date:         2024-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_profiler_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%SPApplicationsDataType%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%SPHardwareDataType%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%SPNetworkDataType%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%SPUSBDataType%'))
  AND (procName LIKE '%/system\_profiler')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%system\_profiler%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities

**References:**
- https://www.trendmicro.com/en_za/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
- https://www.sentinelone.com/wp-content/uploads/pdf-gen/1630910064/20-common-tools-techniques-used-by-macos-threat-actors-malware.pdf
- https://ss64.com/mac/system_profiler.html
- https://objective-see.org/blog/blog_0x62.html
- https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
- https://gist.github.com/nasbench/9a1ba4bc7094ea1b47bc42bf172961af

---

## System Shutdown/Reboot - MacOs

| Field | Value |
|---|---|
| **Sigma ID** | `40b1fbe2-18ea-4ee7-be47-0294285811de` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1529 |
| **Author** | Igor Fits, Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_shutdown_reboot.yml)**

> Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.

```sql
-- ============================================================
-- Title:        System Shutdown/Reboot - MacOs
-- Sigma ID:     40b1fbe2-18ea-4ee7-be47-0294285811de
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1529
-- Author:       Igor Fits, Mikhail Larin, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_shutdown_reboot.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/shutdown' OR procName LIKE '%/reboot' OR procName LIKE '%/halt')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md

---

## Potential Base64 Decoded From Images

| Field | Value |
|---|---|
| **Sigma ID** | `09a910bf-f71f-4737-9c40-88880ba5913d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1140 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tail_base64_decode_from_image.yml)**

> Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.


```sql
-- ============================================================
-- Title:        Potential Base64 Decoded From Images
-- Sigma ID:     09a910bf-f71f-4737-9c40-88880ba5913d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1140
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tail_base64_decode_from_image.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%base64%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-d%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%>%')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.avif%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.gif%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.jfif%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.jpeg%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.jpg%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.pjp%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.pjpeg%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.png%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.svg%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.webp%'))
  AND procName LIKE '%/bash'
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tail%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-c%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.virustotal.com/gui/file/16bafdf741e7a13137c489f3c8db1334f171c7cb13b62617d691b0a64783cc48/behavior
- https://www.virustotal.com/gui/file/483fafc64a2b84197e1ef6a3f51e443f84dc5742602e08b9e8ec6ad690b34ed0/behavior

---

## Time Machine Backup Deletion Attempt Via Tmutil - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `452df256-da78-427a-866f-49fa04417d74` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | Pratinav Chandra |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tmutil_delete_backup.yml)**

> Detects deletion attempts of MacOS Time Machine backups via the native backup utility "tmutil".
An adversary may perform this action before launching a ransonware attack to prevent the victim from restoring their files.


```sql
-- ============================================================
-- Title:        Time Machine Backup Deletion Attempt Via Tmutil - MacOS
-- Sigma ID:     452df256-da78-427a-866f-49fa04417d74
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       Pratinav Chandra
-- Date:         2024-05-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tmutil_delete_backup.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%delete%')
  AND (procName LIKE '%/tmutil')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tmutil%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-12---disable-time-machine
- https://www.loobins.io/binaries/tmutil/

---

## Time Machine Backup Disabled Via Tmutil - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `2c95fa8a-8b8d-4787-afce-7117ceb8e3da` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | Pratinav Chandra |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tmutil_disable_backup.yml)**

> Detects disabling of Time Machine (Apple's automated backup utility software) via the native macOS backup utility "tmutil".
An attacker can use this to prevent backups from occurring.


```sql
-- ============================================================
-- Title:        Time Machine Backup Disabled Via Tmutil - MacOS
-- Sigma ID:     2c95fa8a-8b8d-4787-afce-7117ceb8e3da
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       Pratinav Chandra
-- Date:         2024-05-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tmutil_disable_backup.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%')
  AND (procName LIKE '%/tmutil')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tmutil%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-12---disable-time-machine
- https://www.loobins.io/binaries/tmutil/

---

## New File Exclusion Added To Time Machine Via Tmutil - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `9acf45ed-3a26-4062-bf08-56857613eb52` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | Pratinav Chandra |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tmutil_exclude_file_from_backup.yml)**

> Detects the addition of a new file or path exclusion to MacOS Time Machine via the "tmutil" utility.
An adversary could exclude a path from Time Machine backups to prevent certain files from being backed up.


```sql
-- ============================================================
-- Title:        New File Exclusion Added To Time Machine Via Tmutil - MacOS
-- Sigma ID:     9acf45ed-3a26-4062-bf08-56857613eb52
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       Pratinav Chandra
-- Date:         2024-05-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_tmutil_exclude_file_from_backup.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%addexclusion%')
  AND (procName LIKE '%/tmutil')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tmutil%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-12---disable-time-machine
- https://www.loobins.io/binaries/tmutil/

---

## Potential WizardUpdate Malware Infection

| Field | Value |
|---|---|
| **Sigma ID** | `f68c4a4f-19ef-4817-952c-50dce331f4b0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Tim Rauch (rule), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_wizardupdate_malware_infection.yml)**

> Detects the execution traces of the WizardUpdate malware. WizardUpdate is a macOS trojan that attempts to infiltrate macOS machines to steal data and it is associated with other types of malicious payloads, increasing the chances of multiple infections on a device.

```sql
-- ============================================================
-- Title:        Potential WizardUpdate Malware Infection
-- Sigma ID:     f68c4a4f-19ef-4817-952c-50dce331f4b0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Tim Rauch (rule), Elastic (idea)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_wizardupdate_malware_infection.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sh'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%=$(curl %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%eval%'))
  OR (procName LIKE '%/curl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%\_intermediate\_agent\_%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-c68a1fcbf7a3f80c87225d7fdc031f691e9f3b6a14a36754be00762bfe6eae97
- https://malpedia.caad.fkie.fraunhofer.de/details/osx.xcsset
- https://www.microsoft.com/security/blog/2022/02/02/the-evolution-of-a-mac-trojan-updateagents-progression/

---

## Gatekeeper Bypass via Xattr

| Field | Value |
|---|---|
| **Sigma ID** | `f5141b6d-9f42-41c6-a7bf-2a780678b29b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1553.001 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_xattr_gatekeeper_bypass.yml)**

> Detects macOS Gatekeeper bypass via xattr utility

```sql
-- ============================================================
-- Title:        Gatekeeper Bypass via Xattr
-- Sigma ID:     f5141b6d-9f42-41c6-a7bf-2a780678b29b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1553.001
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_xattr_gatekeeper_bypass.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/xattr'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-d%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%com.apple.quarantine%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/1fed40dc7e48f16ed44dcdd9c73b9222a70cca85/atomics/T1553.001/T1553.001.md
- https://www.loobins.io/binaries/xattr/

---

## Potential XCSSET Malware Infection

| Field | Value |
|---|---|
| **Sigma ID** | `47d65ac0-c06f-4ba2-a2e3-d263139d0f51` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Tim Rauch (rule), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_xcsset_malware_infection.yml)**

> Identifies the execution traces of the XCSSET malware. XCSSET is a macOS trojan that primarily spreads via Xcode projects and maliciously modifies applications. Infected users are also vulnerable to having their credentials, accounts, and other vital data stolen.

```sql
-- ============================================================
-- Title:        Potential XCSSET Malware Infection
-- Sigma ID:     47d65ac0-c06f-4ba2-a2e3-d263139d0f51
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Tim Rauch (rule), Elastic (idea)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_xcsset_malware_infection.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('macOS-Exec-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/bash')
    AND procName LIKE '%/curl'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/sys/log.php%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/sys/prepod.php%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/sys/bin/Pods%')))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%https://%'))
  OR (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/bash')
    AND procName LIKE '%/osacompile'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Users/%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Library/Group Containers/%'))
  OR (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/bash')
    AND procName LIKE '%/plutil'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%LSUIElement%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Users/%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Library/Group Containers/%'))
  OR (procName LIKE '%/zip'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-r%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Users/%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/Library/Group Containers/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-f5deb07688e1a8dec9530bc3071967b2da5c16b482e671812b864c37beb28f08
- https://malpedia.caad.fkie.fraunhofer.de/details/osx.xcsset

---
