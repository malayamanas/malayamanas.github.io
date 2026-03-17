# Sigma → FortiSIEM: Linux File Event

> 8 rules · Generated 2026-03-17

## Table of Contents

- [Linux Doas Conf File Creation](#linux-doas-conf-file-creation)
- [Persistence Via Cron Files](#persistence-via-cron-files)
- [Persistence Via Sudoers Files](#persistence-via-sudoers-files)
- [Suspicious Filename with Embedded Base64 Commands](#suspicious-filename-with-embedded-base64-commands)
- [Potentially Suspicious Shell Script Creation in Profile Folder](#potentially-suspicious-shell-script-creation-in-profile-folder)
- [Triple Cross eBPF Rootkit Default LockFile](#triple-cross-ebpf-rootkit-default-lockfile)
- [Triple Cross eBPF Rootkit Default Persistence](#triple-cross-ebpf-rootkit-default-persistence)
- [Wget Creating Files in Tmp Directory](#wget-creating-files-in-tmp-directory)

## Linux Doas Conf File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `00eee2a5-fdb0-4746-a21d-e43fbdea5681` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548 |
| **Author** | Sittikorn S, Teoderick Contreras |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_doas_conf_creation.yml)**

> Detects the creation of doas.conf file in linux host platform.

```sql
-- ============================================================
-- Title:        Linux Doas Conf File Creation
-- Sigma ID:     00eee2a5-fdb0-4746-a21d-e43fbdea5681
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1548
-- Author:       Sittikorn S, Teoderick Contreras
-- Date:         2022-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_doas_conf_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/etc/doas.conf')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://research.splunk.com/endpoint/linux_doas_conf_file_creation/
- https://www.makeuseof.com/how-to-install-and-use-doas/

---

## Persistence Via Cron Files

| Field | Value |
|---|---|
| **Sigma ID** | `6c4e2f43-d94d-4ead-b64d-97e53fa2bd05` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.003 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_persistence_cron_files.yml)**

> Detects creation of cron file or files in Cron directories which could indicates potential persistence.

```sql
-- ============================================================
-- Title:        Persistence Via Cron Files
-- Sigma ID:     6c4e2f43-d94d-4ead-b64d-97e53fa2bd05
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.003
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_persistence_cron_files.yml
-- Unmapped:     (none)
-- False Pos:    Any legitimate cron file.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/etc/cron.d/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/etc/cron.daily/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/etc/cron.hourly/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/etc/cron.monthly/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/etc/cron.weekly/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/var/spool/cron/crontabs/%'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/etc/cron.allow%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/etc/cron.deny%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/etc/crontab%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Any legitimate cron file.

**References:**
- https://github.com/microsoft/MSTIC-Sysmon/blob/f1477c0512b0747c1455283069c21faec758e29d/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml

---

## Persistence Via Sudoers Files

| Field | Value |
|---|---|
| **Sigma ID** | `ddb26b76-4447-4807-871f-1b035b2bfa5d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml)**

> Detects creation of sudoers file or files in "sudoers.d" directory which can be used a potential method to persiste privileges for a specific user.

```sql
-- ============================================================
-- Title:        Persistence Via Sudoers Files
-- Sigma ID:     ddb26b76-4447-4807-871f-1b035b2bfa5d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_persistence_sudoers_files.yml
-- Unmapped:     (none)
-- False Pos:    Creation of legitimate files in sudoers.d folder part of administrator work
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/etc/sudoers.d/%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Creation of legitimate files in sudoers.d folder part of administrator work

**References:**
- https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh

---

## Suspicious Filename with Embedded Base64 Commands

| Field | Value |
|---|---|
| **Sigma ID** | `179b3686-6271-4d87-807d-17d843a8af73` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004, T1027 |
| **Author** | @kostastsale |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_susp_filename_with_embedded_base64_command.yml)**

> Detects files with specially crafted filenames that embed Base64-encoded bash payloads designed to execute when processed by shell scripts.
These filenames exploit shell interpretation quirks to trigger hidden commands, a technique observed in VShell malware campaigns.


```sql
-- ============================================================
-- Title:        Suspicious Filename with Embedded Base64 Commands
-- Sigma ID:     179b3686-6271-4d87-807d-17d843a8af73
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1059.004, T1027
-- Author:       @kostastsale
-- Date:         2025-11-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_susp_filename_with_embedded_base64_command.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate files with similar naming patterns (very unlikely).
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%{echo%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%{base64,-d}%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate files with similar naming patterns (very unlikely).

**References:**
- https://www.trellix.com/blogs/research/the-silent-fileless-threat-of-vshell/

---

## Potentially Suspicious Shell Script Creation in Profile Folder

| Field | Value |
|---|---|
| **Sigma ID** | `13f08f54-e705-4498-91fd-cce9d9cee9f1` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_susp_shell_script_under_profile_directory.yml)**

> Detects the creation of shell scripts under the "profile.d" path.

```sql
-- ============================================================
-- Title:        Potentially Suspicious Shell Script Creation in Profile Folder
-- Sigma ID:     13f08f54-e705-4498-91fd-cce9d9cee9f1
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_susp_shell_script_under_profile_directory.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate shell scripts in the "profile.d" directory could be common in your environment. Apply additional filter accordingly via "image", by adding specific filenames you "trust" or by correlating it with other events.; Regular file creation during system update or software installation by the package manager
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%/etc/profile.d/%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.csh' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sh')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate shell scripts in the "profile.d" directory could be common in your environment. Apply additional filter accordingly via "image", by adding specific filenames you "trust" or by correlating it with other events.; Regular file creation during system update or software installation by the package manager

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Triple Cross eBPF Rootkit Default LockFile

| Field | Value |
|---|---|
| **Sigma ID** | `c0239255-822c-4630-b7f1-35362bcb8f44` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_lock_file.yml)**

> Detects the creation of the file "rootlog" which is used by the TripleCross rootkit as a way to check if the backdoor is already running.

```sql
-- ============================================================
-- Title:        Triple Cross eBPF Rootkit Default LockFile
-- Sigma ID:     c0239255-822c-4630-b7f1-35362bcb8f44
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_lock_file.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = '/tmp/rootlog')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/src/helpers/execve_hijack.c#L33

---

## Triple Cross eBPF Rootkit Default Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `1a2ea919-d11d-4d1e-8535-06cda13be20f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.yml)**

> Detects the creation of "ebpfbackdoor" files in both "cron.d" and "sudoers.d" directories. Which both are related to the TripleCross persistence method

```sql
-- ============================================================
-- Title:        Triple Cross eBPF Rootkit Default Persistence
-- Sigma ID:     1a2ea919-d11d-4d1e-8535-06cda13be20f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ebpfbackdoor')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/h3xduck/TripleCross/blob/12629558b8b0a27a5488a0b98f1ea7042e76f8ab/apps/deployer.sh

---

## Wget Creating Files in Tmp Directory

| Field | Value |
|---|---|
| **Sigma ID** | `35a05c60-9012-49b6-a11f-6bab741c9f74` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.yml)**

> Detects the use of wget to download content in a temporary directory such as "/tmp" or "/var/tmp"

```sql
-- ============================================================
-- Title:        Wget Creating Files in Tmp Directory
-- Sigma ID:     35a05c60-9012-49b6-a11f-6bab741c9f74
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate downloads of files in the tmp folder.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_FILE_CREATE')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/wget'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/tmp/%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '/var/tmp/%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate downloads of files in the tmp folder.

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---
