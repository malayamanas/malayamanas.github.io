# Sigma → FortiSIEM: Macos File Event

> 2 rules · Generated 2026-03-17

## Table of Contents

- [MacOS Emond Launch Daemon](#macos-emond-launch-daemon)
- [Startup Item File Created - MacOS](#startup-item-file-created-macos)

## MacOS Emond Launch Daemon

| Field | Value |
|---|---|
| **Sigma ID** | `23c43900-e732-45a4-8354-63e4a6c187ce` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.014 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/file_event/file_event_macos_emond_launch_daemon.yml)**

> Detects additions to the Emond Launch Daemon that adversaries may use to gain persistence and elevate privileges.

```sql
-- ============================================================
-- Title:        MacOS Emond Launch Daemon
-- Sigma ID:     23c43900-e732-45a4-8354-63e4a6c187ce
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.014
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/file_event/file_event_macos_emond_launch_daemon.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================
-- UNMAPPED_LOGSOURCE: macos/file_event

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/etc/emond.d/rules/%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.plist'))
  OR indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/private/var/db/emondClients/%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.014/T1546.014.md
- https://posts.specterops.io/leveraging-emond-on-macos-for-persistence-a040a2785124

---

## Startup Item File Created - MacOS

| Field | Value |
|---|---|
| **Sigma ID** | `dfe8b941-4e54-4242-b674-6b613d521962` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1037.005 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/macos/file_event/file_event_macos_susp_startup_item_created.yml)**

> Detects the creation of a startup item plist file, that automatically get executed at boot initialization to establish persistence.
Adversaries may use startup items automatically executed at boot initialization to establish persistence.
Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.


```sql
-- ============================================================
-- Title:        Startup Item File Created - MacOS
-- Sigma ID:     dfe8b941-4e54-4242-b674-6b613d521962
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1037.005
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/macos/file_event/file_event_macos_susp_startup_item_created.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================
-- UNMAPPED_LOGSOURCE: macos/file_event

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/Library/StartupItems/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/System/Library/StartupItems%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.plist'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.005/T1037.005.md
- https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/StartupItems.html

---
