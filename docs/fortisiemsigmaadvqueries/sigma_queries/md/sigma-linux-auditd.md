# Sigma → FortiSIEM: Linux Auditd

> 53 rules · Generated 2026-03-17

## Table of Contents

- [Binary Padding - Linux](#binary-padding-linux)
- [Bpfdoor TCP Ports Redirect](#bpfdoor-tcp-ports-redirect)
- [Linux Capabilities Discovery](#linux-capabilities-discovery)
- [File Time Attribute Change - Linux](#file-time-attribute-change-linux)
- [Remove Immutable File Attribute - Auditd](#remove-immutable-file-attribute-auditd)
- [Clipboard Collection with Xclip Tool - Auditd](#clipboard-collection-with-xclip-tool-auditd)
- [Clipboard Collection of Image Data with Xclip Tool](#clipboard-collection-of-image-data-with-xclip-tool)
- [Possible Coin Miner CPU Priority Param](#possible-coin-miner-cpu-priority-param)
- [Data Compressed](#data-compressed)
- [Data Exfiltration with Wget](#data-exfiltration-with-wget)
- [Overwriting the File with Dev Zero or Null](#overwriting-the-file-with-dev-zero-or-null)
- [File or Folder Permissions Change](#file-or-folder-permissions-change)
- [Credentials In Files - Linux](#credentials-in-files-linux)
- [Hidden Files and Directories](#hidden-files-and-directories)
- [Steganography Hide Zip Information in Picture File](#steganography-hide-zip-information-in-picture-file)
- [Masquerading as Linux Crond Process](#masquerading-as-linux-crond-process)
- [Modify System Firewall](#modify-system-firewall)
- [Network Sniffing - Linux](#network-sniffing-linux)
- [Screen Capture with Import Tool](#screen-capture-with-import-tool)
- [Screen Capture with Xwd](#screen-capture-with-xwd)
- [Steganography Hide Files with Steghide](#steganography-hide-files-with-steghide)
- [Steganography Extract Files with Steghide](#steganography-extract-files-with-steghide)
- [Suspicious Commands Linux](#suspicious-commands-linux)
- [Suspicious History File Operations - Linux](#suspicious-history-file-operations-linux)
- [Service Reload or Start - Linux](#service-reload-or-start-linux)
- [System Shutdown/Reboot - Linux](#system-shutdownreboot-linux)
- [Steganography Unzip Hidden Information From Picture File](#steganography-unzip-hidden-information-from-picture-file)
- [System Owner or User Discovery - Linux](#system-owner-or-user-discovery-linux)
- [Audio Capture](#audio-capture)
- [ASLR Disabled Via Sysctl or Direct Syscall - Linux](#aslr-disabled-via-sysctl-or-direct-syscall-linux)
- [Linux Keylogging with Pam.d](#linux-keylogging-with-pamd)
- [Password Policy Discovery - Linux](#password-policy-discovery-linux)
- [Suspicious C2 Activities](#suspicious-c2-activities)
- [System Information Discovery - Auditd](#system-information-discovery-auditd)
- [Auditing Configuration Changes on Linux Host](#auditing-configuration-changes-on-linux-host)
- [BPFDoor Abnormal Process ID or Lock File Accessed](#bpfdoor-abnormal-process-id-or-lock-file-accessed)
- [Use Of Hidden Paths Or Files](#use-of-hidden-paths-or-files)
- [Modification of ld.so.preload](#modification-of-ldsopreload)
- [Logging Configuration Changes on Linux Host](#logging-configuration-changes-on-linux-host)
- [Potential Abuse of Linux Magic System Request Key](#potential-abuse-of-linux-magic-system-request-key)
- [System and Hardware Information Discovery](#system-and-hardware-information-discovery)
- [Systemd Service Creation](#systemd-service-creation)
- [Unix Shell Configuration Modification](#unix-shell-configuration-modification)
- [Disable System Firewall](#disable-system-firewall)
- [Clear or Disable Kernel Ring Buffer Logs via Syslog Syscall](#clear-or-disable-kernel-ring-buffer-logs-via-syslog-syscall)
- [Creation Of An User Account](#creation-of-an-user-account)
- [Loading of Kernel Module via Insmod](#loading-of-kernel-module-via-insmod)
- [Linux Network Service Scanning - Auditd](#linux-network-service-scanning-auditd)
- [Split A File Into Pieces - Linux](#split-a-file-into-pieces-linux)
- [System Info Discovery via Sysinfo Syscall](#system-info-discovery-via-sysinfo-syscall)
- [Program Executions in Suspicious Folders](#program-executions-in-suspicious-folders)
- [Special File Creation via Mknod Syscall](#special-file-creation-via-mknod-syscall)
- [Webshell Remote Command Execution](#webshell-remote-command-execution)

## Binary Padding - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `c52a914f-3d8b-4b2a-bb75-b3991e75f8ba` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027.001 |
| **Author** | Igor Fits, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_binary_padding.yml)**

> Adversaries may use binary padding to add junk data and change the on-disk representation of malware.
This rule detect using dd and truncate to add a junk data to file.


```sql
-- ============================================================
-- Title:        Binary Padding - Linux
-- Sigma ID:     c52a914f-3d8b-4b2a-bb75-b3991e75f8ba
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027.001
-- Author:       Igor Fits, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_binary_padding.yml
-- Unmapped:     type, 
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
  AND (rawEventMsg LIKE '%truncate%' OR rawEventMsg LIKE '%-s%'))
  OR ((rawEventMsg LIKE '%dd%' OR rawEventMsg LIKE '%if=%')
  AND NOT (rawEventMsg LIKE '%of=%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.001/T1027.001.md

---

## Bpfdoor TCP Ports Redirect

| Field | Value |
|---|---|
| **Sigma ID** | `70b4156e-50fc-4523-aa50-c9dddf1993fc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Rafal Piasecki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_bpfdoor_port_redirect.yml)**

> All TCP traffic on particular port from attacker is routed to different port. ex. '/sbin/iptables -t nat -D PREROUTING -p tcp -s 192.168.1.1 --dport 22 -j REDIRECT --to-ports 42392'
The traffic looks like encrypted SSH communications going to TCP port 22, but in reality is being directed to the shell port once it hits the iptables rule for the attacker host only.


```sql
-- ============================================================
-- Title:        Bpfdoor TCP Ports Redirect
-- Sigma ID:     70b4156e-50fc-4523-aa50-c9dddf1993fc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Rafal Piasecki
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_bpfdoor_port_redirect.yml
-- Unmapped:     type, a0, a1, a2
-- False Pos:    Legitimate ports redirect
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'EXECVE'
    AND rawEventMsg LIKE '%iptables'
    AND rawEventMsg = '-t'
    AND rawEventMsg = 'nat')
  AND rawEventMsg LIKE '%--to-ports 42%' OR rawEventMsg LIKE '%--to-ports 43%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate ports redirect

**References:**
- https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
- https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor

---

## Linux Capabilities Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `fe10751f-1995-40a5-aaa2-c97ccb4123fe` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083, T1548 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_capabilities_discovery.yml)**

> Detects attempts to discover the files with setuid/setgid capability on them. That would allow adversary to escalate their privileges.

```sql
-- ============================================================
-- Title:        Linux Capabilities Discovery
-- Sigma ID:     fe10751f-1995-40a5-aaa2-c97ccb4123fe
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1083, T1548
-- Author:       Pawel Mazur
-- Date:         2021-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_capabilities_discovery.yml
-- Unmapped:     type, a0, a1, a2
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'getcap'
    AND rawEventMsg = '-r'
    AND rawEventMsg = '/')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://man7.org/linux/man-pages/man8/getcap.8.html
- https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
- https://mn3m.info/posts/suid-vs-capabilities/
- https://int0x33.medium.com/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099

---

## File Time Attribute Change - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.006 |
| **Author** | Igor Fits, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_change_file_time_attr.yml)**

> Detect file time attribute change to hide new or changes to existing files.

```sql
-- ============================================================
-- Title:        File Time Attribute Change - Linux
-- Sigma ID:     b3cec4e7-6901-4b0d-a02d-8ab2d8eb818b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.006
-- Author:       Igor Fits, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_change_file_time_attr.yml
-- Unmapped:     type
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
  AND rawEventMsg LIKE '%touch%'
  AND rawEventMsg LIKE '%-t%' OR rawEventMsg LIKE '%-acmr%' OR rawEventMsg LIKE '%-d%' OR rawEventMsg LIKE '%-r%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.006/T1070.006.md

---

## Remove Immutable File Attribute - Auditd

| Field | Value |
|---|---|
| **Sigma ID** | `a5b977d6-8a81-4475-91b9-49dbfcd941f7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1222.002 |
| **Author** | Jakob Weinzettl, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_chattr_immutable_removal.yml)**

> Detects removing immutable file attribute.

```sql
-- ============================================================
-- Title:        Remove Immutable File Attribute - Auditd
-- Sigma ID:     a5b977d6-8a81-4475-91b9-49dbfcd941f7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1222.002
-- Author:       Jakob Weinzettl, oscd.community
-- Date:         2019-09-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_chattr_immutable_removal.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Administrator interacting with immutable files (e.g. for instance backups).
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg LIKE '%chattr%'
    AND rawEventMsg LIKE '%-i%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator interacting with immutable files (e.g. for instance backups).

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md

---

## Clipboard Collection with Xclip Tool - Auditd

| Field | Value |
|---|---|
| **Sigma ID** | `214e7e6c-f21b-47ff-bb6f-551b2d143fcf` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1115 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_clipboard_collection.yml)**

> Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool.
Xclip has to be installed.
Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.


```sql
-- ============================================================
-- Title:        Clipboard Collection with Xclip Tool - Auditd
-- Sigma ID:     214e7e6c-f21b-47ff-bb6f-551b2d143fcf
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1115
-- Author:       Pawel Mazur
-- Date:         2021-09-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_clipboard_collection.yml
-- Unmapped:     type, a0, a1, a2, a3
-- False Pos:    Legitimate usage of xclip tools
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: a3

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'xclip'
    AND rawEventMsg IN ('-selection', '-sel')
    AND rawEventMsg IN ('clipboard', 'clip')
    AND rawEventMsg = '-o')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of xclip tools

**References:**
- https://linux.die.net/man/1/xclip
- https://www.cyberciti.biz/faq/xclip-linux-insert-files-command-output-intoclipboard/

---

## Clipboard Collection of Image Data with Xclip Tool

| Field | Value |
|---|---|
| **Sigma ID** | `f200dc3f-b219-425d-a17e-c38467364816` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1115 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_clipboard_image_collection.yml)**

> Detects attempts to collect image data stored in the clipboard from users with the usage of xclip tool.
Xclip has to be installed.
Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.


```sql
-- ============================================================
-- Title:        Clipboard Collection of Image Data with Xclip Tool
-- Sigma ID:     f200dc3f-b219-425d-a17e-c38467364816
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1115
-- Author:       Pawel Mazur
-- Date:         2021-10-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_clipboard_image_collection.yml
-- Unmapped:     type, a0, a1, a2, a3, a4, a5
-- False Pos:    Legitimate usage of xclip tools
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: a3
-- UNMAPPED_FIELD: a4
-- UNMAPPED_FIELD: a5

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'xclip'
    AND rawEventMsg IN ('-selection', '-sel')
    AND rawEventMsg IN ('clipboard', 'clip')
    AND rawEventMsg = '-t'
    AND rawEventMsg LIKE 'image/%'
    AND rawEventMsg = '-o')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of xclip tools

**References:**
- https://linux.die.net/man/1/xclip

---

## Possible Coin Miner CPU Priority Param

| Field | Value |
|---|---|
| **Sigma ID** | `071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1068 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_coinminer.yml)**

> Detects command line parameter very often used with coin miners

```sql
-- ============================================================
-- Title:        Possible Coin Miner CPU Priority Param
-- Sigma ID:     071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1068
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_coinminer.yml
-- Unmapped:     a1, a2, a3, a4, a5, a6, a7
-- False Pos:    Other tools that use a --cpu-priority flag
-- ============================================================
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: a3
-- UNMAPPED_FIELD: a4
-- UNMAPPED_FIELD: a5
-- UNMAPPED_FIELD: a6
-- UNMAPPED_FIELD: a7

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '--cpu-priority%'
  OR rawEventMsg LIKE '--cpu-priority%'
  OR rawEventMsg LIKE '--cpu-priority%'
  OR rawEventMsg LIKE '--cpu-priority%'
  OR rawEventMsg LIKE '--cpu-priority%'
  OR rawEventMsg LIKE '--cpu-priority%'
  OR rawEventMsg LIKE '--cpu-priority%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other tools that use a --cpu-priority flag

**References:**
- https://xmrig.com/docs/miner/command-line-options

---

## Data Compressed

| Field | Value |
|---|---|
| **Sigma ID** | `a3b5e3e9-1b49-4119-8b8e-0344a01f21ee` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration, collection |
| **MITRE Techniques** | T1560.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_data_compressed.yml)**

> An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.

```sql
-- ============================================================
-- Title:        Data Compressed
-- Sigma ID:     a3b5e3e9-1b49-4119-8b8e-0344a01f21ee
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration, collection | T1560.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2019-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_data_compressed.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Legitimate use of archiving tools by legitimate user.
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'execve'
    AND rawEventMsg = 'zip')
  OR (rawEventMsg = 'execve'
    AND rawEventMsg = 'gzip'
    AND rawEventMsg = '-k')
  OR (rawEventMsg = 'execve'
    AND rawEventMsg = 'tar'
    AND rawEventMsg LIKE '%-c%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of archiving tools by legitimate user.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/a78b9ed805ab9ea2e422e1aa7741e9407d82d7b1/atomics/T1560.001/T1560.001.md

---

## Data Exfiltration with Wget

| Field | Value |
|---|---|
| **Sigma ID** | `cb39d16b-b3b6-4a7a-8222-1cf24b686ffc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048.003 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_data_exfil_wget.yml)**

> Detects attempts to post the file with the usage of wget utility.
The adversary can bypass the permission restriction with the misconfigured sudo permission for wget utility which could allow them to read files like /etc/shadow.


```sql
-- ============================================================
-- Title:        Data Exfiltration with Wget
-- Sigma ID:     cb39d16b-b3b6-4a7a-8222-1cf24b686ffc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1048.003
-- Author:       Pawel Mazur
-- Date:         2021-11-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_data_exfil_wget.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Legitimate usage of wget utility to post a file
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'wget'
    AND rawEventMsg LIKE '--post-file=%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of wget utility to post a file

**References:**
- https://linux.die.net/man/1/wget
- https://gtfobins.github.io/gtfobins/wget/

---

## Overwriting the File with Dev Zero or Null

| Field | Value |
|---|---|
| **Sigma ID** | `37222991-11e9-4b6d-8bdf-60fbe48f753e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485 |
| **Author** | Jakob Weinzettl, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_dd_delete_file.yml)**

> Detects overwriting (effectively wiping/deleting) of a file.

```sql
-- ============================================================
-- Title:        Overwriting the File with Dev Zero or Null
-- Sigma ID:     37222991-11e9-4b6d-8bdf-60fbe48f753e
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        impact | T1485
-- Author:       Jakob Weinzettl, oscd.community
-- Date:         2019-10-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_dd_delete_file.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Appending null bytes to files.; Legitimate overwrite of files.
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg LIKE '%dd%'
    AND (rawEventMsg LIKE '%if=/dev/null%' OR rawEventMsg LIKE '%if=/dev/zero%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Appending null bytes to files.; Legitimate overwrite of files.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md

---

## File or Folder Permissions Change

| Field | Value |
|---|---|
| **Sigma ID** | `74c01ace-0152-4094-8ae2-6fd776dd43e5` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1222.002 |
| **Author** | Jakob Weinzettl, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_file_or_folder_permissions.yml)**

> Detects file and folder permission changes.

```sql
-- ============================================================
-- Title:        File or Folder Permissions Change
-- Sigma ID:     74c01ace-0152-4094-8ae2-6fd776dd43e5
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1222.002
-- Author:       Jakob Weinzettl, oscd.community
-- Date:         2019-09-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_file_or_folder_permissions.yml
-- Unmapped:     type, a0
-- False Pos:    User interacting with files permissions (normal/daily behaviour).
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND (rawEventMsg LIKE '%chmod%' OR rawEventMsg LIKE '%chown%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User interacting with files permissions (normal/daily behaviour).

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md

---

## Credentials In Files - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `df3fcaea-2715-4214-99c5-0056ea59eb35` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1552.001 |
| **Author** | Igor Fits, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_find_cred_in_files.yml)**

> Detecting attempts to extract passwords with grep

```sql
-- ============================================================
-- Title:        Credentials In Files - Linux
-- Sigma ID:     df3fcaea-2715-4214-99c5-0056ea59eb35
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1552.001
-- Author:       Igor Fits, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_find_cred_in_files.yml
-- Unmapped:     type, 
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
  AND (rawEventMsg LIKE '%grep%' OR rawEventMsg LIKE '%password%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md

---

## Hidden Files and Directories

| Field | Value |
|---|---|
| **Sigma ID** | `d08722cd-3d09-449a-80b4-83ea2d9d4616` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1564.001 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_hidden_files_directories.yml)**

> Detects adversary creating hidden file or directory, by detecting directories or files with . as the first character

```sql
-- ============================================================
-- Title:        Hidden Files and Directories
-- Sigma ID:     d08722cd-3d09-449a-80b4-83ea2d9d4616
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1564.001
-- Author:       Pawel Mazur
-- Date:         2021-09-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_hidden_files_directories.yml
-- Unmapped:     a1, a2, type, a0
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((match(rawEventMsg, '(^|\/)\.[^.\/]'))
  OR (match(rawEventMsg, '(^|\/)\.[^.\/]'))
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg IN ('mkdir', 'nano', 'touch', 'vi', 'vim')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md

---

## Steganography Hide Zip Information in Picture File

| Field | Value |
|---|---|
| **Sigma ID** | `45810b50-7edc-42ca-813b-bdac02fb946b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027.003 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_hidden_zip_files_steganography.yml)**

> Detects appending of zip file to image

```sql
-- ============================================================
-- Title:        Steganography Hide Zip Information in Picture File
-- Sigma ID:     45810b50-7edc-42ca-813b-bdac02fb946b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027.003
-- Author:       Pawel Mazur
-- Date:         2021-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_hidden_zip_files_steganography.yml
-- Unmapped:     type, a0, a1, a2
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'cat')
  AND (rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.png')
  AND rawEventMsg LIKE '%.zip')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://zerotoroot.me/steganography-hiding-a-zip-in-a-jpeg-file/

---

## Masquerading as Linux Crond Process

| Field | Value |
|---|---|
| **Sigma ID** | `9d4548fa-bba0-4e88-bd66-5d5bf516cda0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.003 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_masquerading_crond.yml)**

> Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation.
Several different variations of this technique have been observed.


```sql
-- ============================================================
-- Title:        Masquerading as Linux Crond Process
-- Sigma ID:     9d4548fa-bba0-4e88-bd66-5d5bf516cda0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.003
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2019-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_masquerading_crond.yml
-- Unmapped:     type, a0, a1, a2
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'execve'
    AND rawEventMsg = 'cp'
    AND rawEventMsg = '/bin/sh'
    AND rawEventMsg LIKE '%/crond')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/8a82e9b66a5b4f4bc5b91089e9f24e0544f20ad7/atomics/T1036.003/T1036.003.md#atomic-test-2---masquerading-as-linux-crond-process

---

## Modify System Firewall

| Field | Value |
|---|---|
| **Sigma ID** | `323ff3f5-0013-4847-bbd4-250b5edb62cc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | IAI |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_modify_system_firewall.yml)**

> Detects the removal of system firewall rules. Adversaries may only delete or modify a specific system firewall rule to bypass controls limiting network usage or access.
Detection rules that match only on the disabling of firewalls will miss this.


```sql
-- ============================================================
-- Title:        Modify System Firewall
-- Sigma ID:     323ff3f5-0013-4847-bbd4-250b5edb62cc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       IAI
-- Date:         2023-03-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_modify_system_firewall.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Legitimate admin activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'iptables'
    AND rawEventMsg LIKE '%DROP%')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'firewall-cmd'
    AND rawEventMsg LIKE '%remove%')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'ufw'
    AND rawEventMsg LIKE '%delete%')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'nft'
    AND (rawEventMsg LIKE '%delete%' OR rawEventMsg LIKE '%flush%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin activity

**References:**
- https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html
- https://blog.aquasec.com/container-security-tnt-container-attack
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-nftables_configuring-and-managing-networking

---

## Network Sniffing - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `f4d3748a-65d1-4806-bd23-e25728081d01` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1040 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_network_sniffing.yml)**

> Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.


```sql
-- ============================================================
-- Title:        Network Sniffing - Linux
-- Sigma ID:     f4d3748a-65d1-4806-bd23-e25728081d01
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1040
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2019-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_network_sniffing.yml
-- Unmapped:     type, a0, a1, a3
-- False Pos:    Legitimate administrator or user uses network sniffing tool for legitimate reasons.
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a3

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'execve'
    AND rawEventMsg = 'tcpdump'
    AND rawEventMsg = '-c'
    AND rawEventMsg LIKE '%-i%')
  OR (rawEventMsg = 'execve'
    AND rawEventMsg = 'tshark'
    AND rawEventMsg = '-c'
    AND rawEventMsg = '-i')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator or user uses network sniffing tool for legitimate reasons.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md

---

## Screen Capture with Import Tool

| Field | Value |
|---|---|
| **Sigma ID** | `dbe4b9c5-c254-4258-9688-d6af0b7967fd` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_screencapture_import.yml)**

> Detects adversary creating screen capture of a desktop with Import Tool.
Highly recommended using rule on servers, due to high usage of screenshot utilities on user workstations.
ImageMagick must be installed.


```sql
-- ============================================================
-- Title:        Screen Capture with Import Tool
-- Sigma ID:     dbe4b9c5-c254-4258-9688-d6af0b7967fd
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       Pawel Mazur
-- Date:         2021-09-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_screencapture_import.yml
-- Unmapped:     type, a0, a1, a2, a3
-- False Pos:    Legitimate use of screenshot utility
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: a3

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'import')
  AND (rawEventMsg = '-window'
    AND rawEventMsg = 'root'
    AND (rawEventMsg LIKE '%.png' OR rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.jpeg')))
  OR (rawEventMsg LIKE '%.png' OR rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.jpeg')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of screenshot utility

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md
- https://linux.die.net/man/1/import
- https://imagemagick.org/

---

## Screen Capture with Xwd

| Field | Value |
|---|---|
| **Sigma ID** | `e2f17c5d-b02a-442b-9052-6eb89c9fec9c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_screencaputre_xwd.yml)**

> Detects adversary creating screen capture of a full with xwd. Highly recommended using rule on servers, due high usage of screenshot utilities on user workstations

```sql
-- ============================================================
-- Title:        Screen Capture with Xwd
-- Sigma ID:     e2f17c5d-b02a-442b-9052-6eb89c9fec9c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       Pawel Mazur
-- Date:         2021-09-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_screencaputre_xwd.yml
-- Unmapped:     type, a0
-- False Pos:    Legitimate use of screenshot utility
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'xwd')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of screenshot utility

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md#atomic-test-3---x-windows-capture
- https://linux.die.net/man/1/xwd

---

## Steganography Hide Files with Steghide

| Field | Value |
|---|---|
| **Sigma ID** | `ce446a9e-30b9-4483-8e38-d2c9ad0a2280` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027.003 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_steghide_embed_steganography.yml)**

> Detects embedding of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.

```sql
-- ============================================================
-- Title:        Steganography Hide Files with Steghide
-- Sigma ID:     ce446a9e-30b9-4483-8e38-d2c9ad0a2280
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027.003
-- Author:       Pawel Mazur
-- Date:         2021-09-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_steghide_embed_steganography.yml
-- Unmapped:     type, a0, a1, a2, a4
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: a4

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'steghide'
    AND rawEventMsg = 'embed'
    AND rawEventMsg IN ('-cf', '-ef')
    AND rawEventMsg IN ('-cf', '-ef'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://vitux.com/how-to-hide-confidential-files-in-images-on-debian-using-steganography/

---

## Steganography Extract Files with Steghide

| Field | Value |
|---|---|
| **Sigma ID** | `a5a827d9-1bbe-4952-9293-c59d897eb41b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027.003 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_steghide_extract_steganography.yml)**

> Detects extraction of files with usage of steghide binary, the adversaries may use this technique to prevent the detection of hidden information.

```sql
-- ============================================================
-- Title:        Steganography Extract Files with Steghide
-- Sigma ID:     a5a827d9-1bbe-4952-9293-c59d897eb41b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027.003
-- Author:       Pawel Mazur
-- Date:         2021-09-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_steghide_extract_steganography.yml
-- Unmapped:     type, a0, a1, a2, a3
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: a3

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'steghide'
    AND rawEventMsg = 'extract'
    AND rawEventMsg = '-sf'
    AND (rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.png'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://vitux.com/how-to-hide-confidential-files-in-images-on-debian-using-steganography/

---

## Suspicious Commands Linux

| Field | Value |
|---|---|
| **Sigma ID** | `1543ae20-cbdf-4ec1-8d12-7664d667a825` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_susp_cmds.yml)**

> Detects relevant commands often related to malware or hacking activity

```sql
-- ============================================================
-- Title:        Suspicious Commands Linux
-- Sigma ID:     1543ae20-cbdf-4ec1-8d12-7664d667a825
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-12-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_susp_cmds.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Admin activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'chmod'
    AND rawEventMsg = '777')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'chmod'
    AND rawEventMsg = 'u+s')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'cp'
    AND rawEventMsg = '/bin/ksh')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'cp'
    AND rawEventMsg = '/bin/sh')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin activity

**References:**
- Internal Research - mostly derived from exploit code including code in MSF

---

## Suspicious History File Operations - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `eae8ce9f-bde9-47a6-8e79-f20d18419910` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552.003 |
| **Author** | Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_susp_histfile_operations.yml)**

> Detects commandline operations on shell history files

```sql
-- ============================================================
-- Title:        Suspicious History File Operations - Linux
-- Sigma ID:     eae8ce9f-bde9-47a6-8e79-f20d18419910
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552.003
-- Author:       Mikhail Larin, oscd.community
-- Date:         2020-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_susp_histfile_operations.yml
-- Unmapped:     type
-- False Pos:    Legitimate administrative activity; Legitimate software, cleaning hist file
-- ============================================================
-- UNMAPPED_FIELD: type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
  AND rawEventMsg LIKE '%.bash\_history%' OR rawEventMsg LIKE '%.zsh\_history%' OR rawEventMsg LIKE '%.zhistory%' OR rawEventMsg LIKE '%.history%' OR rawEventMsg LIKE '%.sh\_history%' OR rawEventMsg LIKE '%fish\_history%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity; Legitimate software, cleaning hist file

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md

---

## Service Reload or Start - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `2625cc59-0634-40d0-821e-cb67382a3dd7` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.002 |
| **Author** | Jakob Weinzettl, oscd.community, CheraghiMilad |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_susp_service_reload_or_restart.yml)**

> Detects the start, reload or restart of a service.

```sql
-- ============================================================
-- Title:        Service Reload or Start - Linux
-- Sigma ID:     2625cc59-0634-40d0-821e-cb67382a3dd7
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1543.002
-- Author:       Jakob Weinzettl, oscd.community, CheraghiMilad
-- Date:         2019-09-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_susp_service_reload_or_restart.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Installation of legitimate service.; Legitimate reconfiguration of service.; Command line contains daemon-reload.
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND (rawEventMsg LIKE '%systemctl%' OR rawEventMsg LIKE '%service%')
    AND (rawEventMsg LIKE '%reload%' OR rawEventMsg LIKE '%start%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Installation of legitimate service.; Legitimate reconfiguration of service.; Command line contains daemon-reload.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.002/T1543.002.md

---

## System Shutdown/Reboot - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1529 |
| **Author** | Igor Fits, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_system_shutdown_reboot.yml)**

> Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.

```sql
-- ============================================================
-- Title:        System Shutdown/Reboot - Linux
-- Sigma ID:     4cb57c2f-1f29-41f8-893d-8bed8e1c1d2f
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1529
-- Author:       Igor Fits, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_system_shutdown_reboot.yml
-- Unmapped:     type
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
  AND rawEventMsg LIKE '%shutdown%' OR rawEventMsg LIKE '%reboot%' OR rawEventMsg LIKE '%halt%' OR rawEventMsg LIKE '%poweroff%')
  OR (rawEventMsg LIKE '%init%' OR rawEventMsg LIKE '%telinit%'
  AND rawEventMsg LIKE '%0%' OR rawEventMsg LIKE '%6%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md

---

## Steganography Unzip Hidden Information From Picture File

| Field | Value |
|---|---|
| **Sigma ID** | `edd595d7-7895-4fa7-acb3-85a18a8772ca` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027.003 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_unzip_hidden_zip_files_steganography.yml)**

> Detects extracting of zip file from image file

```sql
-- ============================================================
-- Title:        Steganography Unzip Hidden Information From Picture File
-- Sigma ID:     edd595d7-7895-4fa7-acb3-85a18a8772ca
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027.003
-- Author:       Pawel Mazur
-- Date:         2021-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_unzip_hidden_zip_files_steganography.yml
-- Unmapped:     type, a0, a1
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'unzip')
  AND (rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.png'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://zerotoroot.me/steganography-hiding-a-zip-in-a-jpeg-file/

---

## System Owner or User Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `9a0d8ca0-2385-4020-b6c6-cb6153ca56f3` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_user_discovery.yml)**

> Detects the execution of host or user discovery utilities such as "whoami", "hostname", "id", etc.
Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.


```sql
-- ============================================================
-- Title:        System Owner or User Discovery - Linux
-- Sigma ID:     9a0d8ca0-2385-4020-b6c6-cb6153ca56f3
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2019-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/execve/lnx_auditd_user_discovery.yml
-- Unmapped:     type, a0
-- False Pos:    Admin activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg IN ('hostname', 'id', 'last', 'uname', 'users', 'w', 'who', 'whoami'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md

---

## Audio Capture

| Field | Value |
|---|---|
| **Sigma ID** | `a7af2487-9c2f-42e4-9bb9-ff961f0561d5` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1123 |
| **Author** | Pawel Mazur, Milad Cheraghi |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_audio_capture.yml)**

> Detects attempts to record audio using the arecord and ecasound utilities.

```sql
-- ============================================================
-- Title:        Audio Capture
-- Sigma ID:     a7af2487-9c2f-42e4-9bb9-ff961f0561d5
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1123
-- Author:       Pawel Mazur, Milad Cheraghi
-- Date:         2021-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_audio_capture.yml
-- Unmapped:     type, a0, a1, a2, exe, SYSCALL
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2
-- UNMAPPED_FIELD: exe
-- UNMAPPED_FIELD: SYSCALL

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'arecord'
    AND rawEventMsg = '-vv'
    AND rawEventMsg = '-fdat')
  OR (rawEventMsg = 'SYSCALL'
    AND rawEventMsg LIKE '%/ecasound'
    AND rawEventMsg = 'memfd_create')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://linux.die.net/man/1/arecord
- https://linuxconfig.org/how-to-test-microphone-with-audio-linux-sound-architecture-alsa
- https://manpages.debian.org/unstable/ecasound/ecasound.1.en.html
- https://ecasound.seul.org/ecasound/Documentation/examples.html#fconversions

---

## ASLR Disabled Via Sysctl or Direct Syscall - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `e497a24e-9345-4a62-9803-b06d7d7cb132` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001, T1055.009 |
| **Author** | Milad Cheraghi |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_disable_aslr_protection.yml)**

> Detects actions that disable Address Space Layout Randomization (ASLR) in Linux, including:
  - Use of the `personality` syscall with the ADDR_NO_RANDOMIZE flag (0x0040000)
  - Modification of the /proc/sys/kernel/randomize_va_space file
  - Execution of the `sysctl` command to set `kernel.randomize_va_space=0`
Disabling ASLR is often used by attackers during exploit development or to bypass memory protection mechanisms.
A successful use of these methods can reduce the effectiveness of ASLR and make memory corruption attacks more reliable.


```sql
-- ============================================================
-- Title:        ASLR Disabled Via Sysctl or Direct Syscall - Linux
-- Sigma ID:     e497a24e-9345-4a62-9803-b06d7d7cb132
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001, T1055.009
-- Author:       Milad Cheraghi
-- Date:         2025-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_disable_aslr_protection.yml
-- Unmapped:     type, SYSCALL, a0, a1, a2
-- False Pos:    Debugging or legitimate software testing
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: SYSCALL
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: a2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg = 'personality'
    AND rawEventMsg = '40000')
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'sysctl'
    AND rawEventMsg = '-w'
    AND rawEventMsg = 'kernel.randomize_va_space=0')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Debugging or legitimate software testing

**References:**
- https://github.com/CheraghiMilad/bypass-Neo23x0-auditd-config/blob/f1c478a37911a5447d5ffcd580f22b167bf3df14/personality-syscall/README.md
- https://man7.org/linux/man-pages/man2/personality.2.html
- https://manual.cs50.io/2/personality
- https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/

---

## Linux Keylogging with Pam.d

| Field | Value |
|---|---|
| **Sigma ID** | `49aae26c-450e-448b-911d-b3c13d178dfc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1003, T1056.001 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_keylogging_with_pam_d.yml)**

> Detect attempt to enable auditing of TTY input

```sql
-- ============================================================
-- Title:        Linux Keylogging with Pam.d
-- Sigma ID:     49aae26c-450e-448b-911d-b3c13d178dfc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1003, T1056.001
-- Author:       Pawel Mazur
-- Date:         2021-05-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_keylogging_with_pam_d.yml
-- Unmapped:     type, name
-- False Pos:    Administrative work
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/etc/pam.d/system-auth', '/etc/pam.d/password-auth'))
  OR rawEventMsg IN ('TTY', 'USER_TTY')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative work

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.001/T1056.001.md
- https://linux.die.net/man/8/pam_tty_audit
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-configuring_pam_for_auditing
- https://access.redhat.com/articles/4409591#audit-record-types-2

---

## Password Policy Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `ca94a6db-8106-4737-9ed2-3e3bb826af0a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1201 |
| **Author** | Ömer Günal, oscd.community, Pawel Mazur |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_password_policy_discovery.yml)**

> Detects password policy discovery commands

```sql
-- ============================================================
-- Title:        Password Policy Discovery - Linux
-- Sigma ID:     ca94a6db-8106-4737-9ed2-3e3bb826af0a
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        discovery | T1201
-- Author:       Ömer Günal, oscd.community, Pawel Mazur
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_password_policy_discovery.yml
-- Unmapped:     type, a0, a1, name
-- False Pos:    Legitimate administration activities
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'chage'
    AND rawEventMsg IN ('--list', '-l'))
  OR (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/etc/login.defs', '/etc/pam.d/auth', '/etc/pam.d/common-account', '/etc/pam.d/common-auth', '/etc/pam.d/common-password', '/etc/pam.d/system-auth', '/etc/security/pwquality.conf'))
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'passwd'
    AND rawEventMsg IN ('-S', '--status'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1201/T1201.md
- https://linux.die.net/man/1/chage
- https://man7.org/linux/man-pages/man1/passwd.1.html
- https://superuser.com/questions/150675/how-to-display-password-policy-information-for-a-user-ubuntu

---

## Suspicious C2 Activities

| Field | Value |
|---|---|
| **Sigma ID** | `f7158a64-6204-4d6d-868a-6e6378b467e0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Marie Euler |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_susp_c2_commands.yml)**

> Detects suspicious activities as declared by Florian Roth in its 'Best Practice Auditd Configuration'.
This includes the detection of the following commands; wget, curl, base64, nc, netcat, ncat, ssh, socat, wireshark, rawshark, rdesktop, nmap.
These commands match a few techniques from the tactics "Command and Control", including not exhaustively the following; Application Layer Protocol (T1071), Non-Application Layer Protocol (T1095), Data Encoding (T1132)


```sql
-- ============================================================
-- Title:        Suspicious C2 Activities
-- Sigma ID:     f7158a64-6204-4d6d-868a-6e6378b467e0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Marie Euler
-- Date:         2020-05-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_susp_c2_commands.yml
-- Unmapped:     key
-- False Pos:    Admin or User activity
-- ============================================================
-- UNMAPPED_FIELD: key

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'susp_activity'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin or User activity

**References:**
- https://github.com/Neo23x0/auditd

---

## System Information Discovery - Auditd

| Field | Value |
|---|---|
| **Sigma ID** | `f34047d9-20d3-4e8b-8672-0a35cc50dc71` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_system_info_discovery.yml)**

> Detects System Information Discovery commands

```sql
-- ============================================================
-- Title:        System Information Discovery - Auditd
-- Sigma ID:     f34047d9-20d3-4e8b-8672-0a35cc50dc71
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Pawel Mazur
-- Date:         2021-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/lnx_auditd_system_info_discovery.yml
-- Unmapped:     type, name, a0, a1
-- False Pos:    Likely
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name
-- UNMAPPED_FIELD: a0
-- UNMAPPED_FIELD: a1

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/etc/lsb-release', '/etc/redhat-release', '/etc/issue'))
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg IN ('uname', 'uptime', 'lsmod', 'hostname', 'env'))
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'grep'
    AND (rawEventMsg LIKE '%vbox%' OR rawEventMsg LIKE '%vm%' OR rawEventMsg LIKE '%xen%' OR rawEventMsg LIKE '%virtio%' OR rawEventMsg LIKE '%hv%'))
  OR (rawEventMsg = 'EXECVE'
    AND rawEventMsg = 'kmod'
    AND rawEventMsg = 'list')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f296668303c29d3f4c07e42bdd2b28d8dd6625f9/atomics/T1082/T1082.md

---

## Auditing Configuration Changes on Linux Host

| Field | Value |
|---|---|
| **Sigma ID** | `977ef627-4539-4875-adf4-ed8f780c4922` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.006 |
| **Author** | Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_auditing_config_change.yml)**

> Detect changes in auditd configuration files

```sql
-- ============================================================
-- Title:        Auditing Configuration Changes on Linux Host
-- Sigma ID:     977ef627-4539-4875-adf4-ed8f780c4922
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.006
-- Author:       Mikhail Larin, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_auditing_config_change.yml
-- Unmapped:     type, name
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/etc/audit/*', '/etc/libaudit.conf', '/etc/audisp/*'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://github.com/Neo23x0/auditd/blob/master/audit.rules
- Self Experience

---

## BPFDoor Abnormal Process ID or Lock File Accessed

| Field | Value |
|---|---|
| **Sigma ID** | `808146b2-9332-4d78-9416-d7e47012d83d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1106, T1059 |
| **Author** | Rafal Piasecki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_bpfdoor_file_accessed.yml)**

> detects BPFDoor .lock and .pid files access in temporary file storage facility

```sql
-- ============================================================
-- Title:        BPFDoor Abnormal Process ID or Lock File Accessed
-- Sigma ID:     808146b2-9332-4d78-9416-d7e47012d83d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1106, T1059
-- Author:       Rafal Piasecki
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_bpfdoor_file_accessed.yml
-- Unmapped:     type, name
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/var/run/haldrund.pid', '/var/run/xinetd.lock', '/var/run/kdevrund.pid'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
- https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor

---

## Use Of Hidden Paths Or Files

| Field | Value |
|---|---|
| **Sigma ID** | `9e1bef8d-0fff-46f6-8465-9aa54e128c1e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | David Burkett, @signalblur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_hidden_binary_execution.yml)**

> Detects calls to hidden files or files located in hidden directories in NIX systems.

```sql
-- ============================================================
-- Title:        Use Of Hidden Paths Or Files
-- Sigma ID:     9e1bef8d-0fff-46f6-8465-9aa54e128c1e
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       David Burkett, @signalblur
-- Date:         2022-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_hidden_binary_execution.yml
-- Unmapped:     type, name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'PATH'
    AND rawEventMsg LIKE '%/.%')
  AND NOT ((rawEventMsg LIKE '%/.cache/%' OR rawEventMsg LIKE '%/.config/%' OR rawEventMsg LIKE '%/.pyenv/%' OR rawEventMsg LIKE '%/.rustup/toolchains%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md

---

## Modification of ld.so.preload

| Field | Value |
|---|---|
| **Sigma ID** | `4b3cb710-5e83-4715-8c45-8b2b5b3e5751` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.006 |
| **Author** | E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_ld_so_preload_mod.yml)**

> Identifies modification of ld.so.preload for shared object injection. This technique is used by attackers to load arbitrary code into processes.

```sql
-- ============================================================
-- Title:        Modification of ld.so.preload
-- Sigma ID:     4b3cb710-5e83-4715-8c45-8b2b5b3e5751
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.006
-- Author:       E.M. Anhaus (originally from Atomic Blue Detections, Tony Lambert), oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_ld_so_preload_mod.yml
-- Unmapped:     type, name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg = '/etc/ld.so.preload')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.006/T1574.006.md
- https://eqllib.readthedocs.io/en/latest/analytics/fd9b987a-1101-4ed3-bda6-a70300eaf57e.html

---

## Logging Configuration Changes on Linux Host

| Field | Value |
|---|---|
| **Sigma ID** | `c830f15d-6f6e-430f-8074-6f73d6807841` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.006 |
| **Author** | Mikhail Larin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_logging_config_change.yml)**

> Detect changes of syslog daemons configuration files

```sql
-- ============================================================
-- Title:        Logging Configuration Changes on Linux Host
-- Sigma ID:     c830f15d-6f6e-430f-8074-6f73d6807841
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.006
-- Author:       Mikhail Larin, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_logging_config_change.yml
-- Unmapped:     type, name
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/etc/syslog.conf', '/etc/rsyslog.conf', '/etc/syslog-ng/syslog-ng.conf'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- self experience

---

## Potential Abuse of Linux Magic System Request Key

| Field | Value |
|---|---|
| **Sigma ID** | `ea61bb82-a5e0-42e6-8537-91d29500f1b9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, impact |
| **MITRE Techniques** | T1059.004, T1529, T1489, T1499 |
| **Author** | Milad Cheraghi |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_magic_system_request_key.yml)**

> Detects the potential abuse of the Linux Magic SysRq (System Request) key by adversaries with root or sufficient privileges
to silently manipulate or destabilize a system. By writing to /proc/sysrq-trigger, they can crash the system, kill processes,
or disrupt forensic analysis—all while bypassing standard logging. Though intended for recovery and debugging, SysRq can be
misused as a stealthy post-exploitation tool. It is controlled via /proc/sys/kernel/sysrq or permanently through /etc/sysctl.conf.


```sql
-- ============================================================
-- Title:        Potential Abuse of Linux Magic System Request Key
-- Sigma ID:     ea61bb82-a5e0-42e6-8537-91d29500f1b9
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution, impact | T1059.004, T1529, T1489, T1499
-- Author:       Milad Cheraghi
-- Date:         2025-05-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_magic_system_request_key.yml
-- Unmapped:     type, name
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND (rawEventMsg LIKE '%/sysrq' OR rawEventMsg LIKE '%/sysctl.conf' OR rawEventMsg LIKE '%/sysrq-trigger'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://www.kernel.org/doc/html/v4.10/_sources/admin-guide/sysrq.txt
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/reference_guide/s3-proc-sys-kernel
- https://www.splunk.com/en_us/blog/security/threat-update-awfulshred-script-wiper.html

---

## System and Hardware Information Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `1f358e2e-cb63-43c3-b575-dfb072a6814f` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Ömer Günal, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_system_info_discovery2.yml)**

> Detects system information discovery commands

```sql
-- ============================================================
-- Title:        System and Hardware Information Discovery
-- Sigma ID:     1f358e2e-cb63-43c3-b575-dfb072a6814f
-- Level:        informational  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        discovery | T1082
-- Author:       Ömer Günal, oscd.community
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_system_info_discovery2.yml
-- Unmapped:     type, name
-- False Pos:    Legitimate administration activities
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/sys/class/dmi/id/bios_version', '/sys/class/dmi/id/product_name', '/sys/class/dmi/id/chassis_vendor', '/proc/scsi/scsi', '/proc/ide/hd0/model', '/proc/version', '/etc/*version', '/etc/*release', '/etc/issue'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-4---linux-vm-check-via-hardware

---

## Systemd Service Creation

| Field | Value |
|---|---|
| **Sigma ID** | `1bac86ba-41aa-4f62-9d6b-405eac99b485` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.002 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml)**

> Detects a creation of systemd services which could be used by adversaries to execute malicious code.

```sql
-- ============================================================
-- Title:        Systemd Service Creation
-- Sigma ID:     1bac86ba-41aa-4f62-9d6b-405eac99b485
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1543.002
-- Author:       Pawel Mazur
-- Date:         2022-02-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml
-- Unmapped:     type, nametype
-- False Pos:    Admin work like legit service installs.
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: nametype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg = 'CREATE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin work like legit service installs.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.002/T1543.002.md

---

## Unix Shell Configuration Modification

| Field | Value |
|---|---|
| **Sigma ID** | `a94cdd87-6c54-4678-a6cc-2814ffe5a13d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.004 |
| **Author** | Peter Matkovski, IAI |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_unix_shell_configuration_modification.yml)**

> Detect unix shell configuration modification. Adversaries may establish persistence through executing malicious commands triggered when a new shell is opened.

```sql
-- ============================================================
-- Title:        Unix Shell Configuration Modification
-- Sigma ID:     a94cdd87-6c54-4678-a6cc-2814ffe5a13d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.004
-- Author:       Peter Matkovski, IAI
-- Date:         2023-03-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/path/lnx_auditd_unix_shell_configuration_modification.yml
-- Unmapped:     type, name
-- False Pos:    Admin or User activity are expected to generate some false positives
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'PATH'
    AND rawEventMsg IN ('/etc/shells', '/etc/profile', '/etc/profile.d/*', '/etc/bash.bashrc', '/etc/bashrc', '/etc/zsh/zprofile', '/etc/zsh/zshrc', '/etc/zsh/zlogin', '/etc/zsh/zlogout', '/etc/csh.cshrc', '/etc/csh.login', '/root/.bashrc', '/root/.bash_profile', '/root/.profile', '/root/.zshrc', '/root/.zprofile', '/home/*/.bashrc', '/home/*/.zshrc', '/home/*/.bash_profile', '/home/*/.zprofile', '/home/*/.profile', '/home/*/.bash_login', '/home/*/.bash_logout', '/home/*/.zlogin', '/home/*/.zlogout'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin or User activity are expected to generate some false positives

**References:**
- https://objective-see.org/blog/blog_0x68.html
- https://web.archive.org/web/20221204161143/https://www.glitch-cat.com/p/green-lambert-and-attack
- https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat

---

## Disable System Firewall

| Field | Value |
|---|---|
| **Sigma ID** | `53059bc0-1472-438b-956a-7508a94a91f0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/service_stop/lnx_auditd_disable_system_firewall.yml)**

> Detects disabling of system firewalls which could be used by adversaries to bypass controls that limit usage of the network.

```sql
-- ============================================================
-- Title:        Disable System Firewall
-- Sigma ID:     53059bc0-1472-438b-956a-7508a94a91f0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Pawel Mazur
-- Date:         2022-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/service_stop/lnx_auditd_disable_system_firewall.yml
-- Unmapped:     type, unit
-- False Pos:    Admin activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: unit

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SERVICE_STOP'
    AND rawEventMsg IN ('firewalld', 'iptables', 'ufw'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
- https://firewalld.org/documentation/man-pages/firewall-cmd.html

---

## Clear or Disable Kernel Ring Buffer Logs via Syslog Syscall

| Field | Value |
|---|---|
| **Sigma ID** | `eca5e022-d368-4043-98e5-9736fb01f72f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.002 |
| **Author** | Milad Cheraghi |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_clean_disable_dmesg_logs_via_syslog.yml)**

> Detects the use of the `syslog` syscall with action code 5 (SYSLOG_ACTION_CLEAR),
(4 is SYSLOG_ACTION_READ_CLEAR and 6 is SYSLOG_ACTION_CONSOLE_OFF) which clears the kernel
ring buffer (dmesg logs). This can be used by attackers to hide traces after exploitation
or privilege escalation. A common technique is running `dmesg -c`, which triggers this syscall internally.


```sql
-- ============================================================
-- Title:        Clear or Disable Kernel Ring Buffer Logs via Syslog Syscall
-- Sigma ID:     eca5e022-d368-4043-98e5-9736fb01f72f
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1070.002
-- Author:       Milad Cheraghi
-- Date:         2025-05-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_clean_disable_dmesg_logs_via_syslog.yml
-- Unmapped:     type, SYSCALL, a0
-- False Pos:    System administrators or scripts that intentionally clear logs; Debugging scripts
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: SYSCALL
-- UNMAPPED_FIELD: a0

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg = 'syslog'
    AND rawEventMsg IN ('4', '5', '6'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System administrators or scripts that intentionally clear logs; Debugging scripts

**References:**
- https://man7.org/linux/man-pages/man2/syslog.2.html
- https://man7.org/linux/man-pages/man1/dmesg.1.html

---

## Creation Of An User Account

| Field | Value |
|---|---|
| **Sigma ID** | `759d0d51-bc99-4b5e-9add-8f5b2c8e7512` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Marie Euler, Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_create_account.yml)**

> Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

```sql
-- ============================================================
-- Title:        Creation Of An User Account
-- Sigma ID:     759d0d51-bc99-4b5e-9add-8f5b2c8e7512
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1136.001
-- Author:       Marie Euler, Pawel Mazur
-- Date:         2020-05-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_create_account.yml
-- Unmapped:     type, exe
-- False Pos:    Admin activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: exe

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'ADD_USER'
  OR (rawEventMsg = 'SYSCALL'
    AND rawEventMsg LIKE '%/useradd')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin activity

**References:**
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files
- https://access.redhat.com/articles/4409591#audit-record-types-2
- https://www.youtube.com/watch?v=VmvY5SQm5-Y&ab_channel=M45C07

---

## Loading of Kernel Module via Insmod

| Field | Value |
|---|---|
| **Sigma ID** | `106d7cbd-80ff-4985-b682-a7043e5acb72` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.006 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_load_module_insmod.yml)**

> Detects loading of kernel modules with insmod command.
Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand.
Adversaries may use LKMs to obtain persistence within the system or elevate the privileges.


```sql
-- ============================================================
-- Title:        Loading of Kernel Module via Insmod
-- Sigma ID:     106d7cbd-80ff-4985-b682-a7043e5acb72
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.006
-- Author:       Pawel Mazur
-- Date:         2021-11-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_load_module_insmod.yml
-- Unmapped:     type, comm, exe
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: comm
-- UNMAPPED_FIELD: exe

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg = 'insmod'
    AND rawEventMsg = '/usr/bin/kmod')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.006/T1547.006.md
- https://linux.die.net/man/8/insmod
- https://man7.org/linux/man-pages/man8/kmod.8.html

---

## Linux Network Service Scanning - Auditd

| Field | Value |
|---|---|
| **Sigma ID** | `3761e026-f259-44e6-8826-719ed8079408` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1046 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_network_service_scanning.yml)**

> Detects enumeration of local or remote network services.

```sql
-- ============================================================
-- Title:        Linux Network Service Scanning - Auditd
-- Sigma ID:     3761e026-f259-44e6-8826-719ed8079408
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1046
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_network_service_scanning.yml
-- Unmapped:     type, exe, key
-- False Pos:    Legitimate administration activities
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: exe
-- UNMAPPED_FIELD: key

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND (rawEventMsg LIKE '%/telnet' OR rawEventMsg LIKE '%/nmap' OR rawEventMsg LIKE '%/netcat' OR rawEventMsg LIKE '%/nc' OR rawEventMsg LIKE '%/ncat' OR rawEventMsg LIKE '%/nc.openbsd')
    AND rawEventMsg = 'network_connect_4')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md

---

## Split A File Into Pieces - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `2dad0cba-c62a-4a4f-949f-5f6ecd619769` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1030 |
| **Author** | Igor Fits, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_split_file_into_pieces.yml)**

> Detection use of the command "split" to split files into parts and possible transfer.

```sql
-- ============================================================
-- Title:        Split A File Into Pieces - Linux
-- Sigma ID:     2dad0cba-c62a-4a4f-949f-5f6ecd619769
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1030
-- Author:       Igor Fits, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_split_file_into_pieces.yml
-- Unmapped:     type, comm
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: comm

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg = 'split')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1030/T1030.md

---

## System Info Discovery via Sysinfo Syscall

| Field | Value |
|---|---|
| **Sigma ID** | `b207d563-a1d9-4275-b349-77d1eb55aa6d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1057, T1082 |
| **Author** | Milad Cheraghi |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_susp_discovery_sysinfo_syscall.yml)**

> Detects use of the sysinfo system call in Linux, which provides a snapshot of key system statistics such as uptime, load averages, memory usage, and the number of running processes.
Malware or reconnaissance tools might leverage sysinfo to fingerprint the system - gathering data to determine if it's a viable target.


```sql
-- ============================================================
-- Title:        System Info Discovery via Sysinfo Syscall
-- Sigma ID:     b207d563-a1d9-4275-b349-77d1eb55aa6d
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        discovery | T1057, T1082
-- Author:       Milad Cheraghi
-- Date:         2025-05-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_susp_discovery_sysinfo_syscall.yml
-- Unmapped:     type, SYSCALL
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: SYSCALL

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg = 'sysinfo')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://github.com/CheraghiMilad/bypass-Neo23x0-auditd-config/blob/f1c478a37911a5447d5ffcd580f22b167bf3df14/sysinfo-syscall/README.md
- https://man7.org/linux/man-pages/man2/sysinfo.2.html

---

## Program Executions in Suspicious Folders

| Field | Value |
|---|---|
| **Sigma ID** | `a39d7fa7-3fbd-4dc2-97e1-d87f546b1bbc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1587, T1584 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_susp_exe_folders.yml)**

> Detects program executions in suspicious non-program folders related to malware or hacking activity

```sql
-- ============================================================
-- Title:        Program Executions in Suspicious Folders
-- Sigma ID:     a39d7fa7-3fbd-4dc2-97e1-d87f546b1bbc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1587, T1584
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_susp_exe_folders.yml
-- Unmapped:     type, exe
-- False Pos:    Admin activity (especially in /tmp folders); Crazy web applications
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: exe

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND (rawEventMsg LIKE '/tmp/%' OR rawEventMsg LIKE '/var/www/%' OR rawEventMsg LIKE '/home/*/public\_html/%' OR rawEventMsg LIKE '/usr/local/apache2/%' OR rawEventMsg LIKE '/usr/local/httpd/%' OR rawEventMsg LIKE '/var/apache/%' OR rawEventMsg LIKE '/srv/www/%' OR rawEventMsg LIKE '/home/httpd/html/%' OR rawEventMsg LIKE '/srv/http/%' OR rawEventMsg LIKE '/usr/share/nginx/html/%' OR rawEventMsg LIKE '/var/lib/pgsql/data/%' OR rawEventMsg LIKE '/usr/local/mysql/data/%' OR rawEventMsg LIKE '/var/lib/mysql/%' OR rawEventMsg LIKE '/var/vsftpd/%' OR rawEventMsg LIKE '/etc/bind/%' OR rawEventMsg LIKE '/var/named/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin activity (especially in /tmp folders); Crazy web applications

**References:**
- Internal Research

---

## Special File Creation via Mknod Syscall

| Field | Value |
|---|---|
| **Sigma ID** | `710bdbce-495d-491d-9a8f-7d0d88d2b41e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | Milad Cheraghi |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_susp_special_file_creation_via_mknod_syscall.yml)**

> Detects usage of the `mknod` syscall to create special files (e.g., character or block devices).
Attackers or malware might use `mknod` to create fake devices, interact with kernel interfaces,
or establish covert channels in Linux systems.
Monitoring the use of `mknod` is important because this syscall is rarely used by legitimate applications,
and it can be abused to bypass file system restrictions or create backdoors.


```sql
-- ============================================================
-- Title:        Special File Creation via Mknod Syscall
-- Sigma ID:     710bdbce-495d-491d-9a8f-7d0d88d2b41e
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        persistence | T1543.003
-- Author:       Milad Cheraghi
-- Date:         2025-05-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_susp_special_file_creation_via_mknod_syscall.yml
-- Unmapped:     type, SYSCALL
-- False Pos:    Device creation by legitimate scripts or init systems (udevadm, MAKEDEV); Container runtimes or security tools during initialization
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: SYSCALL

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg = 'mknod')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Device creation by legitimate scripts or init systems (udevadm, MAKEDEV); Container runtimes or security tools during initialization

**References:**
- https://man7.org/linux/man-pages/man2/mknod.2.html
- https://hopeness.medium.com/master-the-linux-mknod-command-a-comprehensive-guide-1c150a546aa8

---

## Webshell Remote Command Execution

| Field | Value |
|---|---|
| **Sigma ID** | `c0d3734d-330f-4a03-aae2-65dacc6a8222` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Ilyas Ochkov, Beyu Denis, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_web_rce.yml)**

> Detects possible command execution by web application/web shell

```sql
-- ============================================================
-- Title:        Webshell Remote Command Execution
-- Sigma ID:     c0d3734d-330f-4a03-aae2-65dacc6a8222
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Ilyas Ochkov, Beyu Denis, oscd.community
-- Date:         2019-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/auditd/syscall/lnx_auditd_web_rce.yml
-- Unmapped:     type, SYSCALL, euid
-- False Pos:    Admin activity; Crazy web applications
-- ============================================================
-- UNMAPPED_FIELD: type
-- UNMAPPED_FIELD: SYSCALL
-- UNMAPPED_FIELD: euid

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Linux-Audit-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SYSCALL'
    AND rawEventMsg IN ('execve', 'execveat')
    AND rawEventMsg = '33')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin activity; Crazy web applications

**References:**
- Personal Experience of the Author
- https://www.vaadata.com/blog/what-is-command-injection-exploitations-and-security-best-practices/

---
