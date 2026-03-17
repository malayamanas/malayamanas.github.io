# Sigma → FortiSIEM: Linux Process Creation

> 119 rules · Generated 2026-03-17

## Table of Contents

- [Shell Invocation via Apt - Linux](#shell-invocation-via-apt-linux)
- [Scheduled Task/Job At](#scheduled-taskjob-at)
- [Audit Rules Deleted Via Auditctl](#audit-rules-deleted-via-auditctl)
- [Kaspersky Endpoint Security Stopped Via CommandLine - Linux](#kaspersky-endpoint-security-stopped-via-commandline-linux)
- [Suspicious Invocation of Shell via AWK - Linux](#suspicious-invocation-of-shell-via-awk-linux)
- [Decode Base64 Encoded Text](#decode-base64-encoded-text)
- [Linux Base64 Encoded Pipe to Shell](#linux-base64-encoded-pipe-to-shell)
- [Linux Base64 Encoded Shebang In CLI](#linux-base64-encoded-shebang-in-cli)
- [Bash Interactive Shell](#bash-interactive-shell)
- [Enable BPF Kprobes Tracing](#enable-bpf-kprobes-tracing)
- [BPFtrace Unsafe Option Usage](#bpftrace-unsafe-option-usage)
- [Linux Setgid Capability Set on a Binary via Setcap Utility](#linux-setgid-capability-set-on-a-binary-via-setcap-utility)
- [Linux Setuid Capability Set on a Binary via Setcap Utility](#linux-setuid-capability-set-on-a-binary-via-setcap-utility)
- [Capabilities Discovery - Linux](#capabilities-discovery-linux)
- [Capsh Shell Invocation - Linux](#capsh-shell-invocation-linux)
- [Remove Immutable File Attribute](#remove-immutable-file-attribute)
- [Linux Sudo Chroot Execution](#linux-sudo-chroot-execution)
- [Clear Linux Logs](#clear-linux-logs)
- [Syslog Clearing or Removal Via System Utilities](#syslog-clearing-or-removal-via-system-utilities)
- [Clipboard Collection with Xclip Tool](#clipboard-collection-with-xclip-tool)
- [Copy Passwd Or Shadow From TMP Path](#copy-passwd-or-shadow-from-tmp-path)
- [Crontab Enumeration](#crontab-enumeration)
- [Remove Scheduled Cron Task/Job](#remove-scheduled-cron-taskjob)
- [Linux Crypto Mining Indicators](#linux-crypto-mining-indicators)
- [Curl Usage on Linux](#curl-usage-on-linux)
- [Suspicious Download and Execute Pattern via Curl/Wget](#suspicious-download-and-execute-pattern-via-curlwget)
- [DD File Overwrite](#dd-file-overwrite)
- [Potential Linux Process Code Injection Via DD Utility](#potential-linux-process-code-injection-via-dd-utility)
- [Ufw Force Stop Using Ufw-Init](#ufw-force-stop-using-ufw-init)
- [Linux Doas Tool Execution](#linux-doas-tool-execution)
- [Shell Invocation via Env Command - Linux](#shell-invocation-via-env-command-linux)
- [ESXi Network Configuration Discovery Via ESXCLI](#esxi-network-configuration-discovery-via-esxcli)
- [ESXi Admin Permission Assigned To Account Via ESXCLI](#esxi-admin-permission-assigned-to-account-via-esxcli)
- [ESXi Storage Information Discovery Via ESXCLI](#esxi-storage-information-discovery-via-esxcli)
- [ESXi Syslog Configuration Change Via ESXCLI](#esxi-syslog-configuration-change-via-esxcli)
- [ESXi System Information Discovery Via ESXCLI](#esxi-system-information-discovery-via-esxcli)
- [ESXi Account Creation Via ESXCLI](#esxi-account-creation-via-esxcli)
- [ESXi VM List Discovery Via ESXCLI](#esxi-vm-list-discovery-via-esxcli)
- [ESXi VM Kill Via ESXCLI](#esxi-vm-kill-via-esxcli)
- [ESXi VSAN Information Discovery Via ESXCLI](#esxi-vsan-information-discovery-via-esxcli)
- [File and Directory Discovery - Linux](#file-and-directory-discovery-linux)
- [File Deletion](#file-deletion)
- [Shell Execution via Find - Linux](#shell-execution-via-find-linux)
- [Shell Execution via Flock - Linux](#shell-execution-via-flock-linux)
- [Shell Execution GCC  - Linux](#shell-execution-gcc-linux)
- [Shell Execution via Git - Linux](#shell-execution-via-git-linux)
- [OS Architecture Discovery Via Grep](#os-architecture-discovery-via-grep)
- [Group Has Been Deleted Via Groupdel](#group-has-been-deleted-via-groupdel)
- [Install Root Certificate](#install-root-certificate)
- [Suspicious Package Installed - Linux](#suspicious-package-installed-linux)
- [Flush Iptables Ufw Chain](#flush-iptables-ufw-chain)
- [Local System Accounts Discovery - Linux](#local-system-accounts-discovery-linux)
- [Local Groups Discovery - Linux](#local-groups-discovery-linux)
- [Potential GobRAT File Discovery Via Grep](#potential-gobrat-file-discovery-via-grep)
- [Named Pipe Created Via Mkfifo](#named-pipe-created-via-mkfifo)
- [Potentially Suspicious Named Pipe Created Via Mkfifo](#potentially-suspicious-named-pipe-created-via-mkfifo)
- [Mount Execution With Hidepid Parameter](#mount-execution-with-hidepid-parameter)
- [Potential Netcat Reverse Shell Execution](#potential-netcat-reverse-shell-execution)
- [Shell Execution via Nice - Linux](#shell-execution-via-nice-linux)
- [Nohup Execution](#nohup-execution)
- [Suspicious Nohup Execution](#suspicious-nohup-execution)
- [OMIGOD SCX RunAsProvider ExecuteScript](#omigod-scx-runasprovider-executescript)
- [OMIGOD SCX RunAsProvider ExecuteShellCommand](#omigod-scx-runasprovider-executeshellcommand)
- [Potential Perl Reverse Shell Execution](#potential-perl-reverse-shell-execution)
- [Potential PHP Reverse Shell](#potential-php-reverse-shell)
- [Pnscan Binary Data Transmission Activity](#pnscan-binary-data-transmission-activity)
- [Connection Proxy](#connection-proxy)
- [PUA - TruffleHog Execution - Linux](#pua-trufflehog-execution-linux)
- [Python WebServer Execution - Linux](#python-webserver-execution-linux)
- [Python Spawning Pretty TTY Via PTY Module](#python-spawning-pretty-tty-via-pty-module)
- [Python Reverse Shell Execution Via PTY And Socket Modules](#python-reverse-shell-execution-via-pty-and-socket-modules)
- [Inline Python Execution - Spawn Shell Via OS System Library](#inline-python-execution-spawn-shell-via-os-system-library)
- [Remote Access Tool - Team Viewer Session Started On Linux Host](#remote-access-tool-team-viewer-session-started-on-linux-host)
- [Linux Remote System Discovery](#linux-remote-system-discovery)
- [Linux Package Uninstall](#linux-package-uninstall)
- [Shell Execution via Rsync - Linux](#shell-execution-via-rsync-linux)
- [Suspicious Invocation of Shell via Rsync](#suspicious-invocation-of-shell-via-rsync)
- [Potential Ruby Reverse Shell](#potential-ruby-reverse-shell)
- [Scheduled Cron Task/Job - Linux](#scheduled-cron-taskjob-linux)
- [Security Software Discovery - Linux](#security-software-discovery-linux)
- [Disabling Security Tools](#disabling-security-tools)
- [Disable Or Stop Services](#disable-or-stop-services)
- [Setuid and Setgid](#setuid-and-setgid)
- [Shell Invocation Via Ssh - Linux](#shell-invocation-via-ssh-linux)
- [Potential Linux Amazon SSM Agent Hijacking](#potential-linux-amazon-ssm-agent-hijacking)
- [Chmod Suspicious Directory](#chmod-suspicious-directory)
- [Container Residence Discovery Via Proc Virtual FS](#container-residence-discovery-via-proc-virtual-fs)
- [Suspicious Curl File Upload - Linux](#suspicious-curl-file-upload-linux)
- [Suspicious Curl Change User Agents - Linux](#suspicious-curl-change-user-agents-linux)
- [Docker Container Discovery Via Dockerenv Listing](#docker-container-discovery-via-dockerenv-listing)
- [Potentially Suspicious Execution From Tmp Folder](#potentially-suspicious-execution-from-tmp-folder)
- [Potential Discovery Activity Using Find - Linux](#potential-discovery-activity-using-find-linux)
- [Suspicious Git Clone - Linux](#suspicious-git-clone-linux)
- [History File Deletion](#history-file-deletion)
- [Print History File Contents](#print-history-file-contents)
- [Linux HackTool Execution](#linux-hacktool-execution)
- [Potential Container Discovery Via Inodes Listing](#potential-container-discovery-via-inodes-listing)
- [Interactive Bash Suspicious Children](#interactive-bash-suspicious-children)
- [Suspicious Java Children Processes](#suspicious-java-children-processes)
- [Linux Network Service Scanning Tools Execution](#linux-network-service-scanning-tools-execution)
- [Linux Shell Pipe to Shell](#linux-shell-pipe-to-shell)
- [Access of Sudoers File Content](#access-of-sudoers-file-content)
- [Linux Recon Indicators](#linux-recon-indicators)
- [Potential Suspicious Change To Sensitive/Critical Files](#potential-suspicious-change-to-sensitivecritical-files)
- [Shell Execution Of Process Located In Tmp Directory](#shell-execution-of-process-located-in-tmp-directory)
- [Execution Of Script Located In Potentially Suspicious Directory](#execution-of-script-located-in-potentially-suspicious-directory)
- [System Information Discovery](#system-information-discovery)
- [System Network Connections Discovery - Linux](#system-network-connections-discovery-linux)
- [System Network Discovery - Linux](#system-network-discovery-linux)
- [Mask System Power Settings Via Systemctl](#mask-system-power-settings-via-systemctl)
- [Touch Suspicious Service File](#touch-suspicious-service-file)
- [Triple Cross eBPF Rootkit Execve Hijack](#triple-cross-ebpf-rootkit-execve-hijack)
- [Triple Cross eBPF Rootkit Install Commands](#triple-cross-ebpf-rootkit-install-commands)
- [User Has Been Deleted Via Userdel](#user-has-been-deleted-via-userdel)
- [User Added To Root/Sudoers Group Using Usermod](#user-added-to-rootsudoers-group-using-usermod)
- [Vim GTFOBin Abuse - Linux](#vim-gtfobin-abuse-linux)
- [Linux Webshell Indicators](#linux-webshell-indicators)
- [Download File To Potentially Suspicious Directory Via Wget](#download-file-to-potentially-suspicious-directory-via-wget)
- [Potential Xterm Reverse Shell](#potential-xterm-reverse-shell)

## Shell Invocation via Apt - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `bb382fd5-b454-47ea-a264-1828e4c766d6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_apt_shell_execution.yml)**

> Detects the use of the "apt" and "apt-get" commands to execute a shell or proxy commands.
Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Invocation via Apt - Linux
-- Sigma ID:     bb382fd5-b454-47ea-a264-1828e4c766d6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_apt_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/apt' OR procName LIKE '%/apt-get')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%APT::Update::Pre-Invoke::=%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/apt/
- https://gtfobins.github.io/gtfobins/apt-get/

---

## Scheduled Task/Job At

| Field | Value |
|---|---|
| **Sigma ID** | `d2d642d7-b393-43fe-bae4-e81ed5915c4b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.002 |
| **Author** | Ömer Günal, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_at_command.yml)**

> Detects the use of at/atd which are utilities that are used to schedule tasks.
They are often abused by adversaries to maintain persistence or to perform task scheduling for initial or recurring execution of malicious code


```sql
-- ============================================================
-- Title:        Scheduled Task/Job At
-- Sigma ID:     d2d642d7-b393-43fe-bae4-e81ed5915c4b
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        execution, persistence | T1053.002
-- Author:       Ömer Günal, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_at_command.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/at' OR procName LIKE '%/atd')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.002/T1053.002.md

---

## Audit Rules Deleted Via Auditctl

| Field | Value |
|---|---|
| **Sigma ID** | `bed26dea-4525-47f4-b24a-76e30e44ffb0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.012 |
| **Author** | Mohamed LAKRI |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_auditctl_clear_rules.yml)**

> Detects the execution of 'auditctl' with the '-D' command line parameter, which deletes all configured audit rules and watches on Linux systems.
This technique is commonly used by attackers to disable audit logging and cover their tracks by removing monitoring capabilities.
Removal of audit rules can significantly impair detection of malicious activities on the affected system.


```sql
-- ============================================================
-- Title:        Audit Rules Deleted Via Auditctl
-- Sigma ID:     bed26dea-4525-47f4-b24a-76e30e44ffb0
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.012
-- Author:       Mohamed LAKRI
-- Date:         2025-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_auditctl_clear_rules.yml
-- Unmapped:     (none)
-- False Pos:    An administrator troubleshooting. Investigate all attempts.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/auditctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '-D')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** An administrator troubleshooting. Investigate all attempts.

**References:**
- https://www.atomicredteam.io/atomic-red-team/atomics/T1562.012
- https://linux.die.net/man/8/auditct

---

## Kaspersky Endpoint Security Stopped Via CommandLine - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `36388120-b3f1-4ce9-b50b-280d9a7f4c04` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1562.001 |
| **Author** | Milad Cheraghi |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_av_kaspersky_av_disabled.yml)**

> Detects execution of the Kaspersky init.d stop script on Linux systems either directly or via systemctl.
This activity may indicate a manual interruption of the antivirus service by an administrator, or it could be a sign of potential tampering or evasion attempts by malicious actors.


```sql
-- ============================================================
-- Title:        Kaspersky Endpoint Security Stopped Via CommandLine - Linux
-- Sigma ID:     36388120-b3f1-4ce9-b50b-280d9a7f4c04
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1562.001
-- Author:       Milad Cheraghi
-- Date:         2025-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_av_kaspersky_av_disabled.yml
-- Unmapped:     (none)
-- False Pos:    System administrator manually stopping Kaspersky services
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/systemctl' OR procName LIKE '%/bash' OR procName LIKE '%/sh')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%kesl%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System administrator manually stopping Kaspersky services

**References:**
- https://support.kaspersky.com/KES4Linux/12.0.0/en-US/197929.htm

---

## Suspicious Invocation of Shell via AWK - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `8c1a5675-cb85-452f-a298-b01b22a51856` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_awk_shell_spawn.yml)**

> Detects the execution of "awk" or it's sibling commands, to invoke a shell using the system() function.
This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.


```sql
-- ============================================================
-- Title:        Suspicious Invocation of Shell via AWK - Linux
-- Sigma ID:     8c1a5675-cb85-452f-a298-b01b22a51856
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_awk_shell_spawn.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%'))
  AND ((procName LIKE '%/awk' OR procName LIKE '%/gawk' OR procName LIKE '%/mawk' OR procName LIKE '%/nawk')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%BEGIN {system%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/awk/#shell
- https://gtfobins.github.io/gtfobins/gawk/#shell
- https://gtfobins.github.io/gtfobins/nawk/#shell
- https://gtfobins.github.io/gtfobins/mawk/#shell

---

## Decode Base64 Encoded Text

| Field | Value |
|---|---|
| **Sigma ID** | `e2072cab-8c9a-459b-b63c-40ae79e27031` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_base64_decode.yml)**

> Detects usage of base64 utility to decode arbitrary base64-encoded text

```sql
-- ============================================================
-- Title:        Decode Base64 Encoded Text
-- Sigma ID:     e2072cab-8c9a-459b-b63c-40ae79e27031
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_base64_decode.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/base64'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-d%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md

---

## Linux Base64 Encoded Pipe to Shell

| Field | Value |
|---|---|
| **Sigma ID** | `ba592c6d-6888-43c3-b8c6-689b8fe47337` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1140 |
| **Author** | pH-T (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml)**

> Detects suspicious process command line that uses base64 encoded input for execution with a shell

```sql
-- ============================================================
-- Title:        Linux Base64 Encoded Pipe to Shell
-- Sigma ID:     ba592c6d-6888-43c3-b8c6-689b8fe47337
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1140
-- Author:       pH-T (Nextron Systems)
-- Date:         2022-07-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%base64 %')
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| bash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| sh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%|bash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%|sh %')))
  OR ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% |sh' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| bash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| sh' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%|bash'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/arget13/DDexec
- https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally

---

## Linux Base64 Encoded Shebang In CLI

| Field | Value |
|---|---|
| **Sigma ID** | `fe2f9663-41cb-47e2-b954-8a228f3b9dff` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1140 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml)**

> Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded

```sql
-- ============================================================
-- Title:        Linux Base64 Encoded Shebang In CLI
-- Sigma ID:     fe2f9663-41cb-47e2-b954-8a228f3b9dff
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1140
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IyEvYmluL2Jhc2%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IyEvYmluL2Rhc2%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IyEvYmluL3pza%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IyEvYmluL2Zpc2%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%IyEvYmluL3No%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
- https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

---

## Bash Interactive Shell

| Field | Value |
|---|---|
| **Sigma ID** | `6104e693-a7d6-4891-86cb-49a258523559` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **Author** | @d4ns4n_ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml)**

> Detects execution of the bash shell with the interactive flag "-i".

```sql
-- ============================================================
-- Title:        Bash Interactive Shell
-- Sigma ID:     6104e693-a7d6-4891-86cb-49a258523559
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution
-- Author:       @d4ns4n_
-- Date:         2023-04-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/bash'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -i %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/
- https://linux.die.net/man/1/bash

---

## Enable BPF Kprobes Tracing

| Field | Value |
|---|---|
| **Sigma ID** | `7692f583-bd30-4008-8615-75dab3f08a99` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.yml)**

> Detects common command used to enable bpf kprobes tracing

```sql
-- ============================================================
-- Title:        Enable BPF Kprobes Tracing
-- Sigma ID:     7692f583-bd30-4008-8615-75dab3f08a99
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%echo 1 >%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/sys/kernel/debug/tracing/events/kprobes/%')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/myprobe/enable%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/myretprobe/enable%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
- https://bpftrace.org/
- https://www.kernel.org/doc/html/v5.0/trace/kprobetrace.html

---

## BPFtrace Unsafe Option Usage

| Field | Value |
|---|---|
| **Sigma ID** | `f8341cb2-ee25-43fa-a975-d8a5a9714b39` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Andreas Hunkeler (@Karneades) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.yml)**

> Detects the usage of the unsafe bpftrace option

```sql
-- ============================================================
-- Title:        BPFtrace Unsafe Option Usage
-- Sigma ID:     f8341cb2-ee25-43fa-a975-d8a5a9714b39
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Andreas Hunkeler (@Karneades)
-- Date:         2022-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of the unsafe option
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%bpftrace'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--unsafe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the unsafe option

**References:**
- https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
- https://bpftrace.org/

---

## Linux Setgid Capability Set on a Binary via Setcap Utility

| Field | Value |
|---|---|
| **Sigma ID** | `3a716279-c18c-4488-83be-f9ececbfb9fc` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548, T1554 |
| **Author** | Luc Génaux |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_cap_setgid.yml)**

> Detects the use of the 'setcap' utility to set the 'setgid' capability (cap_setgid) on a binary file.
This capability allows a non privileged process to make arbitrary manipulations of group IDs (GIDs), including setting its current GID to a value that would otherwise be restricted (i.e. GID 0, the root group).
This behavior can be used by adversaries to backdoor a binary in order to escalate privileges again in the future if needed.


```sql
-- ============================================================
-- Title:        Linux Setgid Capability Set on a Binary via Setcap Utility
-- Sigma ID:     3a716279-c18c-4488-83be-f9ececbfb9fc
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        persistence | T1548, T1554
-- Author:       Luc Génaux
-- Date:         2026-01-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_cap_setgid.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/setcap'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cap\_setgid%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://man7.org/linux/man-pages/man8/setcap.8.html
- https://dfir.ch/posts/linux_capabilities/
- https://juggernaut-sec.com/capabilities/#cap_setgid

---

## Linux Setuid Capability Set on a Binary via Setcap Utility

| Field | Value |
|---|---|
| **Sigma ID** | `ed447910-bc30-4575-a598-3a2e49516a7a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548, T1554 |
| **Author** | Luc Génaux |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_cap_setuid.yml)**

> Detects the use of the 'setcap' utility to set the 'setuid' capability (cap_setuid) on a binary file.
This capability allows a non privileged process to make arbitrary manipulations of user IDs (UIDs), including setting its current UID to a value that would otherwise be restricted (i.e. UID 0, the root user).
This behavior can be used by adversaries to backdoor a binary in order to escalate privileges again in the future if needed.


```sql
-- ============================================================
-- Title:        Linux Setuid Capability Set on a Binary via Setcap Utility
-- Sigma ID:     ed447910-bc30-4575-a598-3a2e49516a7a
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        persistence | T1548, T1554
-- Author:       Luc Génaux
-- Date:         2026-01-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_cap_setuid.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/setcap'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cap\_setuid%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://man7.org/linux/man-pages/man8/setcap.8.html
- https://dfir.ch/posts/linux_capabilities/
- https://juggernaut-sec.com/capabilities/#cap_setuid

---

## Capabilities Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `d8d97d51-122d-4cdd-9e2f-01b4b4933530` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_capa_discovery.yml)**

> Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.

```sql
-- ============================================================
-- Title:        Capabilities Discovery - Linux
-- Sigma ID:     d8d97d51-122d-4cdd-9e2f-01b4b4933530
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_capa_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/getcap'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -r %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
- https://github.com/carlospolop/PEASS-ng
- https://github.com/diego-treitos/linux-smart-enumeration

---

## Capsh Shell Invocation - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `db1ac3be-f606-4e3a-89e0-9607cbe6b98a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_capsh_shell_invocation.yml)**

> Detects the use of the "capsh" utility to invoke a shell.


```sql
-- ============================================================
-- Title:        Capsh Shell Invocation - Linux
-- Sigma ID:     db1ac3be-f606-4e3a-89e0-9607cbe6b98a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_capsh_shell_invocation.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/capsh'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/capsh/#shell
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## Remove Immutable File Attribute

| Field | Value |
|---|---|
| **Sigma ID** | `34979410-e4b5-4e5d-8cfb-389fdff05c12` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1222.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml)**

> Detects usage of the 'chattr' utility to remove immutable file attribute.

```sql
-- ============================================================
-- Title:        Remove Immutable File Attribute
-- Sigma ID:     34979410-e4b5-4e5d-8cfb-389fdff05c12
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1222.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml
-- Unmapped:     (none)
-- False Pos:    Administrator interacting with immutable files (e.g. for instance backups).
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/chattr'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -i %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator interacting with immutable files (e.g. for instance backups).

**References:**
- https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html

---

## Linux Sudo Chroot Execution

| Field | Value |
|---|---|
| **Sigma ID** | `f2bed782-994e-4f40-9cd5-518198cb3fba` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1068 |
| **Author** | Swachchhanda Shrawn Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_chroot_execution.yml)**

> Detects the execution of 'sudo' command with '--chroot' option, which is used to change the root directory for command execution.
Attackers may use this technique to evade detection and execute commands in a modified environment.
This can be part of a privilege escalation strategy, as it allows the execution of commands with elevated privileges in a controlled environment as seen in CVE-2025-32463.
While investigating, look out for unusual or unexpected use of 'sudo --chroot' in conjunction with other commands or scripts such as execution from temporary directories or unusual user accounts.


```sql
-- ============================================================
-- Title:        Linux Sudo Chroot Execution
-- Sigma ID:     f2bed782-994e-4f40-9cd5-518198cb3fba
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        T1068
-- Author:       Swachchhanda Shrawn Poudel (Nextron Systems)
-- Date:         2025-10-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_chroot_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative tasks or scripts that use 'sudo --chroot' for containerization, testing, or system management.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sudo'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --chroot %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sudo -R %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative tasks or scripts that use 'sudo --chroot' for containerization, testing, or system management.

**References:**
- https://github.com/kh4sh3i/CVE-2025-32463/blob/81bb430f84fa2089224733c3ed4bfa434c197ad4/exploit.sh

---

## Clear Linux Logs

| Field | Value |
|---|---|
| **Sigma ID** | `80915f59-9b56-4616-9de0-fd0dea6c12fe` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.002 |
| **Author** | Ömer Günal, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_clear_logs.yml)**

> Detects attempts to clear logs on the system. Adversaries may clear system logs to hide evidence of an intrusion

```sql
-- ============================================================
-- Title:        Clear Linux Logs
-- Sigma ID:     80915f59-9b56-4616-9de0-fd0dea6c12fe
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1070.002
-- Author:       Ömer Günal, oscd.community
-- Date:         2020-10-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_clear_logs.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/rm' OR procName LIKE '%/shred' OR procName LIKE '%/unlink')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/var/log%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/var/spool/mail%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md

---

## Syslog Clearing or Removal Via System Utilities

| Field | Value |
|---|---|
| **Sigma ID** | `3fcc9b35-39e4-44c0-a2ad-9e82b6902b31` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.002 |
| **Author** | Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_clear_syslog.yml)**

> Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks


```sql
-- ============================================================
-- Title:        Syslog Clearing or Removal Via System Utilities
-- Sigma ID:     3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.002
-- Author:       Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_clear_syslog.yml
-- Unmapped:     (none)
-- False Pos:    Log rotation.; Maintenance.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/var/log/syslog%')
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%journalctl --vacuum%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%journalctl --rotate%'))
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% > /var/log/syslog%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% >/var/log/syslog%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% >| /var/log/syslog%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%: > /var/log/syslog%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%:> /var/log/syslog%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%:>/var/log/syslog%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%>|/var/log/syslog%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Log rotation.; Maintenance.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
- https://www.virustotal.com/gui/file/54d60fd58d7fa3475fa123985bfc1594df26da25c1f5fbc7dfdba15876dd8ac5/behavior

---

## Clipboard Collection with Xclip Tool

| Field | Value |
|---|---|
| **Sigma ID** | `ec127035-a636-4b9a-8555-0efd4e59f316` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1115 |
| **Author** | Pawel Mazur, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_clipboard_collection.yml)**

> Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed.
Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.


```sql
-- ============================================================
-- Title:        Clipboard Collection with Xclip Tool
-- Sigma ID:     ec127035-a636-4b9a-8555-0efd4e59f316
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1115
-- Author:       Pawel Mazur, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_clipboard_collection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of xclip tools.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%xclip%'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-sel%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%clip%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-o%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of xclip tools.

**References:**
- https://www.packetlabs.net/posts/clipboard-data-security/

---

## Copy Passwd Or Shadow From TMP Path

| Field | Value |
|---|---|
| **Sigma ID** | `fa4aaed5-4fe0-498d-bbc0-08e3346387ba` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1552.001 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml)**

> Detects when the file "passwd" or "shadow" is copied from tmp path

```sql
-- ============================================================
-- Title:        Copy Passwd Or Shadow From TMP Path
-- Sigma ID:     fa4aaed5-4fe0-498d-bbc0-08e3346387ba
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1552.001
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-01-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%passwd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%shadow%'))
  AND procName LIKE '%/cp'
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.blackberry.com/
- https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144

---

## Crontab Enumeration

| Field | Value |
|---|---|
| **Sigma ID** | `403ed92c-b7ec-4edd-9947-5b535ee12d46` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1007 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_crontab_enumeration.yml)**

> Detects usage of crontab to list the tasks of the user

```sql
-- ============================================================
-- Title:        Crontab Enumeration
-- Sigma ID:     403ed92c-b7ec-4edd-9947-5b535ee12d46
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1007
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_crontab_enumeration.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of crontab
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/crontab'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -l%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of crontab

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Remove Scheduled Cron Task/Job

| Field | Value |
|---|---|
| **Sigma ID** | `c2e234de-03a3-41e1-b39a-1e56dc17ba67` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_crontab_removal.yml)**

> Detects usage of the 'crontab' utility to remove the current crontab.
This is a common occurrence where cryptocurrency miners compete against each other by removing traces of other miners to hijack the maximum amount of resources possible


```sql
-- ============================================================
-- Title:        Remove Scheduled Cron Task/Job
-- Sigma ID:     c2e234de-03a3-41e1-b39a-1e56dc17ba67
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_crontab_removal.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%crontab'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -r%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html

---

## Linux Crypto Mining Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `9069ea3c-b213-4c52-be13-86506a227ab1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1496 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_crypto_mining.yml)**

> Detects command line parameters or strings often used by crypto miners

```sql
-- ============================================================
-- Title:        Linux Crypto Mining Indicators
-- Sigma ID:     9069ea3c-b213-4c52-be13-86506a227ab1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1496
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_crypto_mining.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of crypto miners
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --cpu-priority=%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--donate-level=0%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -o pool.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --nicehash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --algo=rx/0 %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stratum+tcp://%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stratum+udp://%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sh -c /sbin/modprobe msr allow\_writes=on%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%LS1kb25hdGUtbGV2ZWw9%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%0tZG9uYXRlLWxldmVsP%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tLWRvbmF0ZS1sZXZlbD%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%c3RyYXR1bSt0Y3A6Ly%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%N0cmF0dW0rdGNwOi8v%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zdHJhdHVtK3RjcDovL%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%c3RyYXR1bSt1ZHA6Ly%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%N0cmF0dW0rdWRwOi8v%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zdHJhdHVtK3VkcDovL%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of crypto miners

**References:**
- https://www.poolwatch.io/coin/monero

---

## Curl Usage on Linux

| Field | Value |
|---|---|
| **Sigma ID** | `ea34fb97-e2c4-4afb-810f-785e4459b194` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1105 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_curl_usage.yml)**

> Detects a curl process start on linux, which indicates a file download from a remote location or a simple web request to a remote server

```sql
-- ============================================================
-- Title:        Curl Usage on Linux
-- Sigma ID:     ea34fb97-e2c4-4afb-810f-785e4459b194
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1105
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_curl_usage.yml
-- Unmapped:     (none)
-- False Pos:    Scripts created by developers and admins; Administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/curl'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Scripts created by developers and admins; Administrative activity

**References:**
- https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html

---

## Suspicious Download and Execute Pattern via Curl/Wget

| Field | Value |
|---|---|
| **Sigma ID** | `a2d9e2f3-0f43-4c7a-bcd9-9acfc0d723aa` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004, T1203 |
| **Author** | Aayush Gupta |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_curl_wget_exec_tmp.yml)**

> Detects suspicious use of command-line tools such as curl or wget to download remote
content - particularly scripts - into temporary directories (e.g., /dev/shm, /tmp), followed by
immediate execution, indicating potential malicious activity. This pattern is commonly used
by malicious scripts, stagers, or downloaders in fileless or multi-stage Linux attacks.


```sql
-- ============================================================
-- Title:        Suspicious Download and Execute Pattern via Curl/Wget
-- Sigma ID:     a2d9e2f3-0f43-4c7a-bcd9-9acfc0d723aa
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1059.004, T1203
-- Author:       Aayush Gupta
-- Date:         2025-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_curl_wget_exec_tmp.yml
-- Unmapped:     (none)
-- False Pos:    System update scripts using temporary files; Installer scripts or automated provisioning tools
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/curl%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/wget%'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sh -c%')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/dev/shm/%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System update scripts using temporary files; Installer scripts or automated provisioning tools

**References:**
- https://gtfobins.github.io/gtfobins/wget/
- https://gtfobins.github.io/gtfobins/curl/

---

## DD File Overwrite

| Field | Value |
|---|---|
| **Sigma ID** | `2953194b-e33c-4859-b9e8-05948c167447` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml)**

> Detects potential overwriting and deletion of a file using DD.

```sql
-- ============================================================
-- Title:        DD File Overwrite
-- Sigma ID:     2953194b-e33c-4859-b9e8-05948c167447
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1485
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml
-- Unmapped:     (none)
-- False Pos:    Any user deleting files that way.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName IN ('/bin/dd', '/usr/bin/dd')
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%of=%')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%if=/dev/zero%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%if=/dev/null%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Any user deleting files that way.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd

---

## Potential Linux Process Code Injection Via DD Utility

| Field | Value |
|---|---|
| **Sigma ID** | `4cad6c64-d6df-42d6-8dae-eb78defdc415` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1055.009 |
| **Author** | Joseph Kamau |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_dd_process_injection.yml)**

> Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.

```sql
-- ============================================================
-- Title:        Potential Linux Process Code Injection Via DD Utility
-- Sigma ID:     4cad6c64-d6df-42d6-8dae-eb78defdc415
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1055.009
-- Author:       Joseph Kamau
-- Date:         2023-12-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_dd_process_injection.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/dd'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%of=%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/proc/%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/mem%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.aon.com/cyber-solutions/aon_cyber_labs/linux-based-inter-process-code-injection-without-ptrace2/
- https://github.com/AonCyberLabs/Cexigua/blob/34d338620afae4c6335ba8d8d499e1d7d3d5d7b5/overwrite.sh

---

## Ufw Force Stop Using Ufw-Init

| Field | Value |
|---|---|
| **Sigma ID** | `84c9e83c-599a-458a-a0cb-0ecce44e807a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_disable_ufw.yml)**

> Detects attempts to force stop the ufw using ufw-init

```sql
-- ============================================================
-- Title:        Ufw Force Stop Using Ufw-Init
-- Sigma ID:     84c9e83c-599a-458a-a0cb-0ecce44e807a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-01-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_disable_ufw.yml
-- Unmapped:     (none)
-- False Pos:    Network administrators
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-ufw-init%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%force-stop%')
  OR indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ufw%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Network administrators

**References:**
- https://blogs.blackberry.com/
- https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144

---

## Linux Doas Tool Execution

| Field | Value |
|---|---|
| **Sigma ID** | `067d8238-7127-451c-a9ec-fa78045b618b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1548 |
| **Author** | Sittikorn S, Teoderick Contreras |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_doas_execution.yml)**

> Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.

```sql
-- ============================================================
-- Title:        Linux Doas Tool Execution
-- Sigma ID:     067d8238-7127-451c-a9ec-fa78045b618b
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        T1548
-- Author:       Sittikorn S, Teoderick Contreras
-- Date:         2022-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_doas_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/doas'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://research.splunk.com/endpoint/linux_doas_tool_execution/
- https://www.makeuseof.com/how-to-install-and-use-doas/

---

## Shell Invocation via Env Command - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `bed978f8-7f3a-432b-82c5-9286a9b3031a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_env_shell_invocation.yml)**

> Detects the use of the env command to invoke a shell. This may indicate an attempt to bypass restricted environments, escalate privileges, or execute arbitrary commands.


```sql
-- ============================================================
-- Title:        Shell Invocation via Env Command - Linux
-- Sigma ID:     bed978f8-7f3a-432b-82c5-9286a9b3031a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_env_shell_invocation.yml
-- Unmapped:     (none)
-- False Pos:    Github operations such as ghe-backup
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/env'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Github operations such as ghe-backup

**References:**
- https://gtfobins.github.io/gtfobins/env/#shell
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## ESXi Network Configuration Discovery Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `33e814e0-1f00-4e43-9c34-31fb7ae2b174` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1033, T1007, T1059.012 |
| **Author** | Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_network_discovery.yml)**

> Detects execution of the "esxcli" command with the "network" flag in order to retrieve information about the network configuration.

```sql
-- ============================================================
-- Title:        ESXi Network Configuration Discovery Via ESXCLI
-- Sigma ID:     33e814e0-1f00-4e43-9c34-31fb7ae2b174
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery, execution | T1033, T1007, T1059.012
-- Author:       Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_network_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% get%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% list%'))
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%network%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_network.html

---

## ESXi Admin Permission Assigned To Account Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `9691f58d-92c1-4416-8bf3-2edd753ec9cf` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1059.012, T1098 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_permission_change_admin.yml)**

> Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.

```sql
-- ============================================================
-- Title:        ESXi Admin Permission Assigned To Account Via ESXCLI
-- Sigma ID:     9691f58d-92c1-4416-8bf3-2edd753ec9cf
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1059.012, T1098
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_permission_change_admin.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%system%')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% permission %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% set%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%Admin%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html

---

## ESXi Storage Information Discovery Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `f41dada5-3f56-4232-8503-3fb7f9cf2d60` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1033, T1007, T1059.012 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_storage_discovery.yml)**

> Detects execution of the "esxcli" command with the "storage" flag in order to retrieve information about the storage status and other related information. Seen used by malware such as DarkSide and LockBit.

```sql
-- ============================================================
-- Title:        ESXi Storage Information Discovery Via ESXCLI
-- Sigma ID:     f41dada5-3f56-4232-8503-3fb7f9cf2d60
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery, execution | T1033, T1007, T1059.012
-- Author:       Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_storage_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% get%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% list%'))
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%storage%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.trendmicro.com/en_us/research/21/e/darkside-linux-vms-targeted.html
- https://www.trendmicro.com/en_us/research/22/a/analysis-and-Impact-of-lockbit-ransomwares-first-linux-and-vmware-esxi-variant.html
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_storage.html

---

## ESXi Syslog Configuration Change Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `38eb1dbb-011f-40b1-a126-cf03a0210563` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1562.001, T1562.003, T1059.012 |
| **Author** | Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_syslog_config_change.yml)**

> Detects changes to the ESXi syslog configuration via "esxcli"

```sql
-- ============================================================
-- Title:        ESXi Syslog Configuration Change Via ESXCLI
-- Sigma ID:     38eb1dbb-011f-40b1-a126-cf03a0210563
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1562.001, T1562.003, T1059.012
-- Author:       Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_syslog_config_change.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%system%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%syslog%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%config%')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% set%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities

**References:**
- https://support.solarwinds.com/SuccessCenter/s/article/Configure-ESXi-Syslog-to-LEM?language=en_US
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html

---

## ESXi System Information Discovery Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `e80273e1-9faf-40bc-bd85-dbaff104c4e9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1033, T1007, T1059.012 |
| **Author** | Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_system_discovery.yml)**

> Detects execution of the "esxcli" command with the "system" flag in order to retrieve information about the different component of the system. Such as accounts, modules, NTP, etc.

```sql
-- ============================================================
-- Title:        ESXi System Information Discovery Via ESXCLI
-- Sigma ID:     e80273e1-9faf-40bc-bd85-dbaff104c4e9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery, execution | T1033, T1007, T1059.012
-- Author:       Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_system_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% get%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% list%'))
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%system%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html

---

## ESXi Account Creation Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1136, T1059.012 |
| **Author** | Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_user_account_creation.yml)**

> Detects user account creation on ESXi system via esxcli

```sql
-- ============================================================
-- Title:        ESXi Account Creation Via ESXCLI
-- Sigma ID:     b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution | T1136, T1059.012
-- Author:       Cedric Maurugeon
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_user_account_creation.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%system %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%account %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%add %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html

---

## ESXi VM List Discovery Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `5f1573a7-363b-4114-9208-ad7a61de46eb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1033, T1007, T1059.012 |
| **Author** | Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_vm_discovery.yml)**

> Detects execution of the "esxcli" command with the "vm" flag in order to retrieve information about the installed VMs.

```sql
-- ============================================================
-- Title:        ESXi VM List Discovery Via ESXCLI
-- Sigma ID:     5f1573a7-363b-4114-9208-ad7a61de46eb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery, execution | T1033, T1007, T1059.012
-- Author:       Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_vm_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%vm process%')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% list'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vm.html
- https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/
- https://www.trendmicro.com/en_us/research/22/e/new-linux-based-ransomware-cheerscrypt-targets-exsi-devices.html

---

## ESXi VM Kill Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `2992ac4d-31e9-4325-99f2-b18a73221bb2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, impact |
| **MITRE Techniques** | T1059.012, T1529 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_vm_kill.yml)**

> Detects execution of the "esxcli" command with the "vm" and "kill" flag in order to kill/shutdown a specific VM.

```sql
-- ============================================================
-- Title:        ESXi VM Kill Via ESXCLI
-- Sigma ID:     2992ac4d-31e9-4325-99f2-b18a73221bb2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, impact | T1059.012, T1529
-- Author:       Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_vm_kill.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%vm process%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%kill%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vm.html
- https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/
- https://www.trendmicro.com/en_us/research/22/e/new-linux-based-ransomware-cheerscrypt-targets-exsi-devices.html

---

## ESXi VSAN Information Discovery Via ESXCLI

| Field | Value |
|---|---|
| **Sigma ID** | `d54c2f06-aca9-4e2b-81c9-5317858f4b79` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1033, T1007, T1059.012 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_vsan_discovery.yml)**

> Detects execution of the "esxcli" command with the "vsan" flag in order to retrieve information about virtual storage. Seen used by malware such as DarkSide.

```sql
-- ============================================================
-- Title:        ESXi VSAN Information Discovery Via ESXCLI
-- Sigma ID:     d54c2f06-aca9-4e2b-81c9-5317858f4b79
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery, execution | T1033, T1007, T1059.012
-- Author:       Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
-- Date:         2023-09-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_esxcli_vsan_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% get%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% list%'))
  AND (procName LIKE '%/esxcli'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%vsan%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.trendmicro.com/en_us/research/21/e/darkside-linux-vms-targeted.html
- https://www.trendmicro.com/en_us/research/22/a/analysis-and-Impact-of-lockbit-ransomwares-first-linux-and-vmware-esxi-variant.html
- https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vsan.html

---

## File and Directory Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Daniil Yugoslavskiy, oscd.community, CheraghiMilad |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_file_and_directory_discovery.yml)**

> Detects usage of system utilities such as "find", "tree", "findmnt", etc, to discover files, directories and network shares.


```sql
-- ============================================================
-- Title:        File and Directory Discovery - Linux
-- Sigma ID:     d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Daniil Yugoslavskiy, oscd.community, CheraghiMilad
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_file_and_directory_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/file'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '(.){200,}')))
  OR procName LIKE '%/find'
  OR procName LIKE '%/findmnt'
  OR procName LIKE '%/mlocate'
  OR (procName LIKE '%/ls'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-R%'))
  OR procName LIKE '%/tree'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md

---

## File Deletion

| Field | Value |
|---|---|
| **Sigma ID** | `30aed7b6-d2c1-4eaf-9382-b6bc43e50c57` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.004 |
| **Author** | Ömer Günal, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_file_deletion.yml)**

> Detects file deletion using "rm", "shred" or "unlink" commands which are used often by adversaries to delete files left behind by the actions of their intrusion activity

```sql
-- ============================================================
-- Title:        File Deletion
-- Sigma ID:     30aed7b6-d2c1-4eaf-9382-b6bc43e50c57
-- Level:        informational  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1070.004
-- Author:       Ömer Günal, oscd.community
-- Date:         2020-10-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_file_deletion.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/rm' OR procName LIKE '%/shred' OR procName LIKE '%/unlink')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md

---

## Shell Execution via Find - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `6adfbf8f-52be-4444-9bac-81b539624146` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_find_shell_execution.yml)**

> Detects the use of the find command to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or exploitation attempt.


```sql
-- ============================================================
-- Title:        Shell Execution via Find - Linux
-- Sigma ID:     6adfbf8f-52be-4444-9bac-81b539624146
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_find_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%'))
  AND (procName LIKE '%/find'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% . %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-exec%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/find/#shell
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## Shell Execution via Flock - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `4b09c71e-4269-4111-9cdd-107d8867f0cc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_flock_shell_execution.yml)**

> Detects the use of the "flock" command to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Execution via Flock - Linux
-- Sigma ID:     4b09c71e-4269-4111-9cdd-107d8867f0cc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_flock_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%'))
  AND (procName LIKE '%/flock'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -u %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/flock/#shell
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## Shell Execution GCC  - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `9b5de532-a757-4d70-946c-1f3e44f48b4d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.yml)**

> Detects the use of the "gcc" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Execution GCC  - Linux
-- Sigma ID:     9b5de532-a757-4d70-946c-1f3e44f48b4d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash,-s%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash,-s%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish,-s%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh,-s%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh,-s%'))
  AND ((procName LIKE '%/c89' OR procName LIKE '%/c99' OR procName LIKE '%/gcc')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-wrapper%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/gcc/#shell
- https://gtfobins.github.io/gtfobins/c89/#shell
- https://gtfobins.github.io/gtfobins/c99/#shell
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## Shell Execution via Git - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `47b3bbd4-1bf7-48cc-84ab-995362aaa75a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_git_shell_execution.yml)**

> Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Execution via Git - Linux
-- Sigma ID:     47b3bbd4-1bf7-48cc-84ab-995362aaa75a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_git_shell_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'parentProcName')] AS parentImage,
  metrics_string.value[indexOf(metrics_string.name,'parentCommand')] AS parentCommandLine,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/git')
    AND indexOf(metrics_string.name, 'parentCommand') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentCommand')] LIKE '% -p %' AND metrics_string.value[indexOf(metrics_string.name,'parentCommand')] LIKE '%help%')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%bash 0<&1%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%dash 0<&1%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sh 0<&1%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/git/#shell

---

## OS Architecture Discovery Via Grep

| Field | Value |
|---|---|
| **Sigma ID** | `d27ab432-2199-483f-a297-03633c05bae6` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_grep_os_arch_discovery.yml)**

> Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of "uname" or "cat /proc/cpuinfo"


```sql
-- ============================================================
-- Title:        OS Architecture Discovery Via Grep
-- Sigma ID:     d27ab432-2199-483f-a297-03633c05bae6
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_grep_os_arch_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%aarch64' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%arm' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%i386' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%i686' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%mips' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%x86\_64'))
  AND procName LIKE '%/grep')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Group Has Been Deleted Via Groupdel

| Field | Value |
|---|---|
| **Sigma ID** | `8a46f16c-8c4c-82d1-b121-0fdd3ba70a84` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | Tuan Le (NCSGroup) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_groupdel.yml)**

> Detects execution of the "groupdel" binary. Which is used to delete a group. This is sometimes abused by threat actors in order to cover their tracks

```sql
-- ============================================================
-- Title:        Group Has Been Deleted Via Groupdel
-- Sigma ID:     8a46f16c-8c4c-82d1-b121-0fdd3ba70a84
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       Tuan Le (NCSGroup)
-- Date:         2022-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_groupdel.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/groupdel'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activities

**References:**
- https://linuxize.com/post/how-to-delete-group-in-linux/
- https://www.cyberciti.biz/faq/linux-remove-user-command/
- https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
- https://linux.die.net/man/8/groupdel

---

## Install Root Certificate

| Field | Value |
|---|---|
| **Sigma ID** | `78a80655-a51e-4669-bc6b-e9d206a462ee` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1553.004 |
| **Author** | Ömer Günal, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_install_root_certificate.yml)**

> Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s

```sql
-- ============================================================
-- Title:        Install Root Certificate
-- Sigma ID:     78a80655-a51e-4669-bc6b-e9d206a462ee
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1553.004
-- Author:       Ömer Günal, oscd.community
-- Date:         2020-10-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_install_root_certificate.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/update-ca-certificates' OR procName LIKE '%/update-ca-trust')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md

---

## Suspicious Package Installed - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `700fb7e8-2981-401c-8430-be58e189e741` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1553.004 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_install_suspicious_packages.yml)**

> Detects installation of suspicious packages using system installation utilities

```sql
-- ============================================================
-- Title:        Suspicious Package Installed - Linux
-- Sigma ID:     700fb7e8-2981-401c-8430-be58e189e741
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1553.004
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_install_suspicious_packages.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%nmap%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% nc%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%netcat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%wireshark%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tshark%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%openconnect%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%proxychains%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%socat%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt

---

## Flush Iptables Ufw Chain

| Field | Value |
|---|---|
| **Sigma ID** | `3be619f4-d9ec-4ea8-a173-18fdd01996ab` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_iptables_flush_ufw.yml)**

> Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic

```sql
-- ============================================================
-- Title:        Flush Iptables Ufw Chain
-- Sigma ID:     3be619f4-d9ec-4ea8-a173-18fdd01996ab
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-01-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_iptables_flush_ufw.yml
-- Unmapped:     (none)
-- False Pos:    Network administrators
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/iptables' OR procName LIKE '%/xtables-legacy-multi' OR procName LIKE '%/iptables-legacy-multi' OR procName LIKE '%/ip6tables' OR procName LIKE '%/ip6tables-legacy-multi')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-F%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-Z%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-X%'))
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ufw-logging-deny%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ufw-logging-allow%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ufw6-logging-deny%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ufw6-logging-allow%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Network administrators

**References:**
- https://blogs.blackberry.com/
- https://www.cyberciti.biz/tips/linux-iptables-how-to-flush-all-rules.html
- https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144

---

## Local System Accounts Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `b45e3d6f-42c6-47d8-a478-df6bd6cf534c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.001 |
| **Author** | Alejandro Ortuno, oscd.community, CheraghiMilad |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_local_account.yml)**

> Detects enumeration of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

```sql
-- ============================================================
-- Title:        Local System Accounts Discovery - Linux
-- Sigma ID:     b45e3d6f-42c6-47d8-a478-df6bd6cf534c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1087.001
-- Author:       Alejandro Ortuno, oscd.community, CheraghiMilad
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_local_account.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/lastlog'
  OR indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'x:0:'%')
  OR ((procName LIKE '%/cat' OR procName LIKE '%/ed' OR procName LIKE '%/head' OR procName LIKE '%/more' OR procName LIKE '%/nano' OR procName LIKE '%/tail' OR procName LIKE '%/vi' OR procName LIKE '%/vim' OR procName LIKE '%/less' OR procName LIKE '%/emacs' OR procName LIKE '%/sqlite3' OR procName LIKE '%/makemap')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/passwd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/shadow%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/sudoers%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/spwd.db%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/pwd.db%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/master.passwd%')))
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
- https://my.f5.com/manage/s/article/K589
- https://man.freebsd.org/cgi/man.cgi?pwd_mkdb

---

## Local Groups Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `676381a6-15ca-4d73-a9c8-6a22e970b90d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.001 |
| **Author** | Ömer Günal, Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_local_groups.yml)**

> Detects enumeration of local system groups. Adversaries may attempt to find local system groups and permission settings

```sql
-- ============================================================
-- Title:        Local Groups Discovery - Linux
-- Sigma ID:     676381a6-15ca-4d73-a9c8-6a22e970b90d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.001
-- Author:       Ömer Günal, Alejandro Ortuno, oscd.community
-- Date:         2020-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_local_groups.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/groups'
  OR ((procName LIKE '%/cat' OR procName LIKE '%/ed' OR procName LIKE '%/head' OR procName LIKE '%/less' OR procName LIKE '%/more' OR procName LIKE '%/nano' OR procName LIKE '%/tail' OR procName LIKE '%/vi' OR procName LIKE '%/vim')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/group%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.001/T1069.001.md

---

## Potential GobRAT File Discovery Via Grep

| Field | Value |
|---|---|
| **Sigma ID** | `e34cfa0c-0a50-4210-9cb3-5632d08eb041` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_malware_gobrat_grep_payload_discovery.yml)**

> Detects the use of grep to discover specific files created by the GobRAT malware

```sql
-- ============================================================
-- Title:        Potential GobRAT File Discovery Via Grep
-- Sigma ID:     e34cfa0c-0a50-4210-9cb3-5632d08eb041
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_malware_gobrat_grep_payload_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/grep'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%apached%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%frpc%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sshd.sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zone.arm%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Named Pipe Created Via Mkfifo

| Field | Value |
|---|---|
| **Sigma ID** | `9d779ce8-5256-4b13-8b6f-b91c602b43f4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation.yml)**

> Detects the creation of a new named pipe using the "mkfifo" utility

```sql
-- ============================================================
-- Title:        Named Pipe Created Via Mkfifo
-- Sigma ID:     9d779ce8-5256-4b13-8b6f-b91c602b43f4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/mkfifo'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk
- https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally

---

## Potentially Suspicious Named Pipe Created Via Mkfifo

| Field | Value |
|---|---|
| **Sigma ID** | `999c3b12-0a8c-40b6-8e13-dd7d62b75c7a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation_susp_location.yml)**

> Detects the creation of a new named pipe using the "mkfifo" utility in a potentially suspicious location

```sql
-- ============================================================
-- Title:        Potentially Suspicious Named Pipe Created Via Mkfifo
-- Sigma ID:     999c3b12-0a8c-40b6-8e13-dd7d62b75c7a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation_susp_location.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/mkfifo'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% /tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk
- https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally

---

## Mount Execution With Hidepid Parameter

| Field | Value |
|---|---|
| **Sigma ID** | `ec52985a-d024-41e3-8ff6-14169039a0b3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_mount_hidepid.yml)**

> Detects execution of the "mount" command with "hidepid" parameter to make invisible processes to other users from the system

```sql
-- ============================================================
-- Title:        Mount Execution With Hidepid Parameter
-- Sigma ID:     ec52985a-d024-41e3-8ff6-14169039a0b3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_mount_hidepid.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/mount'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%hidepid=2%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -o %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.blackberry.com/
- https://www.cyberciti.biz/faq/linux-hide-processes-from-other-users/
- https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144

---

## Potential Netcat Reverse Shell Execution

| Field | Value |
|---|---|
| **Sigma ID** | `7f734ed0-4f47-46c0-837f-6ee62505abd9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml)**

> Detects execution of netcat with the "-e" flag followed by common shells. This could be a sign of a potential reverse shell setup.

```sql
-- ============================================================
-- Title:        Potential Netcat Reverse Shell Execution
-- Sigma ID:     7f734ed0-4f47-46c0-837f-6ee62505abd9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -c %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %'))
  AND (procName LIKE '%/nc' OR procName LIKE '%/ncat')
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% ash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% bsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% csh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% ksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% pdksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% tcsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/ash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/csh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/ksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/pdksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/tcsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSbash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSbsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFScsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSpdksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFStcsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%$IFSzsh%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/
- https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
- https://www.infosecademy.com/netcat-reverse-shells/
- https://man7.org/linux/man-pages/man1/ncat.1.html

---

## Shell Execution via Nice - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `093d68c7-762a-42f4-9f46-95e79142571a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_nice_shell_execution.yml)**

> Detects the use of the "nice" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Execution via Nice - Linux
-- Sigma ID:     093d68c7-762a-42f4-9f46-95e79142571a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_nice_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/nice'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/nice/#shell
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## Nohup Execution

| Field | Value |
|---|---|
| **Sigma ID** | `e4ffe466-6ff8-48d4-94bd-e32d1a6061e2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Christopher Peacock @SecurePeacock, SCYTHE @scythe_io |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_nohup.yml)**

> Detects usage of nohup which could be leveraged by an attacker to keep a process running or break out from restricted environments

```sql
-- ============================================================
-- Title:        Nohup Execution
-- Sigma ID:     e4ffe466-6ff8-48d4-94bd-e32d1a6061e2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
-- Date:         2022-06-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_nohup.yml
-- Unmapped:     (none)
-- False Pos:    Administrators or installed processes that leverage nohup
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/nohup'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators or installed processes that leverage nohup

**References:**
- https://gtfobins.github.io/gtfobins/nohup/
- https://en.wikipedia.org/wiki/Nohup
- https://www.computerhope.com/unix/unohup.htm

---

## Suspicious Nohup Execution

| Field | Value |
|---|---|
| **Sigma ID** | `457df417-8b9d-4912-85f3-9dbda39c3645` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_nohup_susp_execution.yml)**

> Detects execution of binaries located in potentially suspicious locations via "nohup"

```sql
-- ============================================================
-- Title:        Suspicious Nohup Execution
-- Sigma ID:     457df417-8b9d-4912-85f3-9dbda39c3645
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_nohup_susp_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/nohup'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## OMIGOD SCX RunAsProvider ExecuteScript

| Field | Value |
|---|---|
| **Sigma ID** | `6eea1bf6-f8d2-488a-a742-e6ef6c1b67db` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1068, T1190, T1203 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml)**

> Rule to detect the use of the SCX RunAsProvider ExecuteScript to execute any UNIX/Linux script using the /bin/sh shell.
Script being executed gets created as a temp file in /tmp folder with a scx* prefix.
Then it is invoked from the following directory /etc/opt/microsoft/scx/conf/tmpdir/.
The file in that directory has the same prefix scx*. SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including
Microsoft Operations Manager, Microsoft Azure, and Microsoft Operations Management Suite.


```sql
-- ============================================================
-- Title:        OMIGOD SCX RunAsProvider ExecuteScript
-- Sigma ID:     6eea1bf6-f8d2-488a-a742-e6ef6c1b67db
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1068, T1190, T1203
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml
-- Unmapped:     LogonId
-- False Pos:    Legitimate use of SCX RunAsProvider ExecuteScript.
-- ============================================================
-- UNMAPPED_FIELD: LogonId

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'currentDirectory')] AS currentDirectory,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (user = 'root'
    AND rawEventMsg = '0'
    AND indexOf(metrics_string.name, 'currentDirectory') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'currentDirectory')] = '/var/opt/microsoft/scx/tmp')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/opt/microsoft/scx/conf/tmpdir/scx%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of SCX RunAsProvider ExecuteScript.

**References:**
- https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
- https://github.com/Azure/Azure-Sentinel/pull/3059

---

## OMIGOD SCX RunAsProvider ExecuteShellCommand

| Field | Value |
|---|---|
| **Sigma ID** | `21541900-27a9-4454-9c4c-3f0a4240344a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1068, T1190, T1203 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml)**

> Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including
Microsoft Operations Manager, Microsoft Azure, and Microsoft Operations Management Suite.


```sql
-- ============================================================
-- Title:        OMIGOD SCX RunAsProvider ExecuteShellCommand
-- Sigma ID:     21541900-27a9-4454-9c4c-3f0a4240344a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1068, T1190, T1203
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml
-- Unmapped:     LogonId
-- False Pos:    Legitimate use of SCX RunAsProvider Invoke_ExecuteShellCommand.
-- ============================================================
-- UNMAPPED_FIELD: LogonId

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'currentDirectory')] AS currentDirectory,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (user = 'root'
    AND rawEventMsg = '0'
    AND indexOf(metrics_string.name, 'currentDirectory') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'currentDirectory')] = '/var/opt/microsoft/scx/tmp')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of SCX RunAsProvider Invoke_ExecuteShellCommand.

**References:**
- https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
- https://github.com/Azure/Azure-Sentinel/pull/3059

---

## Potential Perl Reverse Shell Execution

| Field | Value |
|---|---|
| **Sigma ID** | `259df6bc-003f-4306-9f54-4ff1a08fa38e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml)**

> Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity

```sql
-- ============================================================
-- Title:        Potential Perl Reverse Shell Execution
-- Sigma ID:     259df6bc-003f-4306-9f54-4ff1a08fa38e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%fdopen(%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%::Socket::INET%'))
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%Socket%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%connect%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%open%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%exec%'))
  AND (procName LIKE '%/perl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/

---

## Potential PHP Reverse Shell

| Field | Value |
|---|---|
| **Sigma ID** | `c6714a24-d7d5-4283-a36b-3ffd091d5f7e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | @d4ns4n_ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml)**

> Detects usage of the PHP CLI with the "-r" flag which allows it to run inline PHP code. The rule looks for calls to the "fsockopen" function which allows the creation of sockets.
Attackers often leverage this in combination with functions such as "exec" or "fopen" to initiate a reverse shell connection.


```sql
-- ============================================================
-- Title:        Potential PHP Reverse Shell
-- Sigma ID:     c6714a24-d7d5-4283-a36b-3ffd091d5f7e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       @d4ns4n_
-- Date:         2023-04-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/php%'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -r %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%fsockopen%')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%bsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%csh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%pdksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%tcsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zsh%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/

---

## Pnscan Binary Data Transmission Activity

| Field | Value |
|---|---|
| **Sigma ID** | `97de11cd-4b67-4abf-9a8b-1020e670aa9e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1046 |
| **Author** | David Burkett (@signalblur) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_pnscan_binary_cli_pattern.yml)**

> Detects command line patterns associated with the use of Pnscan for sending and receiving binary data across the network.
This behavior has been identified in a Linux malware campaign targeting Docker, Apache Hadoop, Redis, and Confluence and was previously used by the threat actor known as TeamTNT


```sql
-- ============================================================
-- Title:        Pnscan Binary Data Transmission Activity
-- Sigma ID:     97de11cd-4b67-4abf-9a8b-1020e670aa9e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1046
-- Author:       David Burkett (@signalblur)
-- Date:         2024-04-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_pnscan_binary_cli_pattern.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '-(W|R)\s?(\s|"|')([0-9a-fA-F]{2}\s?){2,20}(\s|"|')'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cadosecurity.com/blog/spinning-yarn-a-new-linux-malware-campaign-targets-docker-apache-hadoop-redis-and-confluence
- https://intezer.com/wp-content/uploads/2021/09/TeamTNT-Cryptomining-Explosion.pdf
- https://regex101.com/r/RugQYK/1
- https://www.virustotal.com/gui/file/beddf70a7bab805f0c0b69ac0989db6755949f9f68525c08cb874988353f78a9/content

---

## Connection Proxy

| Field | Value |
|---|---|
| **Sigma ID** | `72f4ab3f-787d-495d-a55d-68c2ff46cf4c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1090 |
| **Author** | Ömer Günal |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_proxy_connection.yml)**

> Detects setting proxy configuration

```sql
-- ============================================================
-- Title:        Connection Proxy
-- Sigma ID:     72f4ab3f-787d-495d-a55d-68c2ff46cf4c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1090
-- Author:       Ömer Günal
-- Date:         2020-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_proxy_connection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%http\_proxy=%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%https\_proxy=%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

---

## PUA - TruffleHog Execution - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `d7a650c4-226c-451e-948f-cc490db506aa` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083, T1552.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_pua_trufflehog.yml)**

> Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously.
While it is a legitimate tool, intended for use in CI pipelines and security assessments,
It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information.


```sql
-- ============================================================
-- Title:        PUA - TruffleHog Execution - Linux
-- Sigma ID:     d7a650c4-226c-451e-948f-cc490db506aa
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        discovery | T1083, T1552.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-09-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_pua_trufflehog.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of TruffleHog by security teams or developers.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/trufflehog'
  OR ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% docker --image %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% Git %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% GitHub %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% Jira %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% Slack %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% Confluence %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% SharePoint %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% s3 %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% gcs %'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --results=verified%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of TruffleHog by security teams or developers.

**References:**
- https://github.com/trufflesecurity/trufflehog
- https://www.getsafety.com/blog-posts/shai-hulud-npm-attack

---

## Python WebServer Execution - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `3f0f5957-04f8-4792-ad89-192b0303bde6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048.003 |
| **Author** | Mohamed LAKRI |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_http_server_execution.yml)**

> Detects the execution of Python web servers via command line interface (CLI).
After gaining access to target systems, adversaries may use Python's built-in HTTP server modules to quickly establish a web server without requiring additional software.
This technique is commonly used in post-exploitation scenarios as it provides a simple method for transferring files between the compromised host and attacker-controlled systems.


```sql
-- ============================================================
-- Title:        Python WebServer Execution - Linux
-- Sigma ID:     3f0f5957-04f8-4792-ad89-192b0303bde6
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        exfiltration | T1048.003
-- Author:       Mohamed LAKRI
-- Date:         2025-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_http_server_execution.yml
-- Unmapped:     (none)
-- False Pos:    Testing or development activity
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((procName LIKE '%/python' OR procName LIKE '%/python2' OR procName LIKE '%/python3'))
  OR ((procName LIKE '%/python2.%' OR procName LIKE '%/python3.%'))
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%http.server%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%SimpleHTTPServer%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Testing or development activity

**References:**
- https://www.atomicredteam.io/atomic-red-team/atomics/T1048.003#atomic-test-8---python3-httpserver
- https://docs.python.org/3/library/http.server.html
- https://docs.python.org/2/library/simplehttpserver.html

---

## Python Spawning Pretty TTY Via PTY Module

| Field | Value |
|---|---|
| **Sigma ID** | `c4042d54-110d-45dd-a0e1-05c47822c937` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Nextron Systems |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_pty_spawn.yml)**

> Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.


```sql
-- ============================================================
-- Title:        Python Spawning Pretty TTY Via PTY Module
-- Sigma ID:     c4042d54-110d-45dd-a0e1-05c47822c937
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Nextron Systems
-- Date:         2022-06-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_pty_spawn.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%import pty%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%from pty %'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%spawn%')
  AND ((procName LIKE '%/python' OR procName LIKE '%/python2' OR procName LIKE '%/python3'))
  OR ((procName LIKE '%/python2.%' OR procName LIKE '%/python3.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/

---

## Python Reverse Shell Execution Via PTY And Socket Modules

| Field | Value |
|---|---|
| **Sigma ID** | `32e62bc7-3de0-4bb1-90af-532978fe42c0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | @d4ns4n_, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml)**

> Detects the execution of python with calls to the socket and pty module in order to connect and spawn a potential reverse shell.


```sql
-- ============================================================
-- Title:        Python Reverse Shell Execution Via PTY And Socket Modules
-- Sigma ID:     32e62bc7-3de0-4bb1-90af-532978fe42c0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%python%'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -c %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%import%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%pty%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%socket%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%spawn%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.connect%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.revshells.com/

---

## Inline Python Execution - Spawn Shell Via OS System Library

| Field | Value |
|---|---|
| **Sigma ID** | `2d2f44ff-4611-4778-a8fc-323a0e9850cc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_shell_os_system.yml)**

> Detects execution of inline Python code via the "-c" in order to call the "system" function from the "os" library, and spawn a shell.


```sql
-- ============================================================
-- Title:        Inline Python Execution - Spawn Shell Via OS System Library
-- Sigma ID:     2d2f44ff-4611-4778-a8fc-323a0e9850cc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_python_shell_os_system.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -c %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%os.system(%')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%')))
  AND ((procName LIKE '%/python' OR procName LIKE '%/python2' OR procName LIKE '%/python3'))
  OR ((procName LIKE '%/python2.%' OR procName LIKE '%/python3.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/python/#shell

---

## Remote Access Tool - Team Viewer Session Started On Linux Host

| Field | Value |
|---|---|
| **Sigma ID** | `1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | Josh Nickels, Qi Nan |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_remote_access_tools_teamviewer_incoming_connection.yml)**

> Detects the command line executed when TeamViewer starts a session started by a remote host.
Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.


```sql
-- ============================================================
-- Title:        Remote Access Tool - Team Viewer Session Started On Linux Host
-- Sigma ID:     1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1133
-- Author:       Josh Nickels, Qi Nan
-- Date:         2024-03-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_remote_access_tools_teamviewer_incoming_connection.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
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

## Linux Remote System Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `11063ec2-de63-4153-935e-b1a8b9e616f1` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1018 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_remote_system_discovery.yml)**

> Detects the enumeration of other remote systems.

```sql
-- ============================================================
-- Title:        Linux Remote System Discovery
-- Sigma ID:     11063ec2-de63-4153-935e-b1a8b9e616f1
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1018
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_remote_system_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
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

## Linux Package Uninstall

| Field | Value |
|---|---|
| **Sigma ID** | `95d61234-7f56-465c-6f2d-b562c6fedbc4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1070 |
| **Author** | Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_remove_package.yml)**

> Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".

```sql
-- ============================================================
-- Title:        Linux Package Uninstall
-- Sigma ID:     95d61234-7f56-465c-6f2d-b562c6fedbc4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1070
-- Author:       Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-03-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_remove_package.yml
-- Unmapped:     (none)
-- False Pos:    Administrator or administrator scripts might delete packages for several reasons (debugging, troubleshooting).
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/apt' OR procName LIKE '%/apt-get')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%remove%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%purge%')))
  OR (procName LIKE '%/dpkg'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--remove %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -r %')))
  OR (procName LIKE '%/rpm'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %'))
  OR (procName LIKE '%/yum'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%erase%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%remove%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator or administrator scripts might delete packages for several reasons (debugging, troubleshooting).

**References:**
- https://sysdig.com/blog/mitre-defense-evasion-falco
- https://www.tutorialspoint.com/how-to-install-a-software-on-linux-using-yum-command
- https://linuxhint.com/uninstall_yum_package/
- https://linuxhint.com/uninstall-debian-packages/

---

## Shell Execution via Rsync - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `e2326866-609f-4015-aea9-7ec634e8aa04` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml)**

> Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Execution via Rsync - Linux
-- Sigma ID:     e2326866-609f-4015-aea9-7ec634e8aa04
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate cases in which "rsync" is used to execute a shell
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/ash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/dash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/csh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/sh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/zsh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tcsh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/ksh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'ash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'bash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'dash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'csh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'sh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'zsh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'tcsh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%'ksh %'))
  AND ((procName LIKE '%/rsync' OR procName LIKE '%/rsyncd')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate cases in which "rsync" is used to execute a shell

**References:**
- https://gtfobins.github.io/gtfobins/rsync/#shell

---

## Suspicious Invocation of Shell via Rsync

| Field | Value |
|---|---|
| **Sigma ID** | `297241f3-8108-4b3a-8c15-2dda9f844594` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059, T1203 |
| **Author** | Florian Roth |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml)**

> Detects the execution of a shell as sub process of "rsync" without the expected command line flag "-e" being used, which could be an indication of exploitation as described in CVE-2024-12084. This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.


```sql
-- ============================================================
-- Title:        Suspicious Invocation of Shell via Rsync
-- Sigma ID:     297241f3-8108-4b3a-8c15-2dda9f844594
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1059, T1203
-- Author:       Florian Roth
-- Date:         2025-01-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/rsync' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/rsyncd'))
    AND (procName LIKE '%/ash' OR procName LIKE '%/bash' OR procName LIKE '%/csh' OR procName LIKE '%/dash' OR procName LIKE '%/ksh' OR procName LIKE '%/sh' OR procName LIKE '%/tcsh' OR procName LIKE '%/zsh'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://sysdig.com/blog/detecting-and-mitigating-cve-2024-12084-rsync-remote-code-execution/
- https://gist.github.com/Neo23x0/a20436375a1e26524931dd8ea1a3af10

---

## Potential Ruby Reverse Shell

| Field | Value |
|---|---|
| **Sigma ID** | `b8bdac18-c06e-4016-ac30-221553e74f59` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | @d4ns4n_ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml)**

> Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell

```sql
-- ============================================================
-- Title:        Potential Ruby Reverse Shell
-- Sigma ID:     b8bdac18-c06e-4016-ac30-221553e74f59
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       @d4ns4n_
-- Date:         2023-04-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%ruby%'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -e%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%rsocket%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%TCPSocket%')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% ash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% bsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% csh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% ksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% pdksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% tcsh%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/

---

## Scheduled Cron Task/Job - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `6b14bac8-3e3a-4324-8109-42f0546a347f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.003 |
| **Author** | Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_schedule_task_job_cron.yml)**

> Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.

```sql
-- ============================================================
-- Title:        Scheduled Cron Task/Job - Linux
-- Sigma ID:     6b14bac8-3e3a-4324-8109-42f0546a347f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.003
-- Author:       Alejandro Ortuno, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_schedule_task_job_cron.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%crontab'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md

---

## Security Software Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `c9d8b7fd-78e4-44fe-88f6-599135d46d60` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1518.001 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_security_software_discovery.yml)**

> Detects usage of system utilities (only grep and egrep for now) to discover security software discovery

```sql
-- ============================================================
-- Title:        Security Software Discovery - Linux
-- Sigma ID:     c9d8b7fd-78e4-44fe-88f6-599135d46d60
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1518.001
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_security_software_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/grep' OR procName LIKE '%/egrep')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%nessusd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%td-agent%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%packetbeat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%filebeat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%auditbeat%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%osqueryd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cbagentd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%falcond%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md

---

## Disabling Security Tools

| Field | Value |
|---|---|
| **Sigma ID** | `e3a8a052-111f-4606-9aee-f28ebeb76776` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Ömer Günal, Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_security_tools_disabling.yml)**

> Detects disabling security tools

```sql
-- ============================================================
-- Title:        Disabling Security Tools
-- Sigma ID:     e3a8a052-111f-4606-9aee-f28ebeb76776
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Ömer Günal, Alejandro Ortuno, oscd.community
-- Date:         2020-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_security_tools_disabling.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/service'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cbdaemon%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/chkconfig'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cbdaemon%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%off%'))
  OR (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cbdaemon%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%cbdaemon%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%'))
  OR (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%falcon-sensor%'))
  OR (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%falcon-sensor%'))
  OR (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%firewalld%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%firewalld%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%'))
  OR (procName LIKE '%/service'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%iptables%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/service'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ip6tables%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/chkconfig'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%iptables%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/chkconfig'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ip6tables%' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%'))
  OR (procName LIKE '%/setenforce'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%0%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md

---

## Disable Or Stop Services

| Field | Value |
|---|---|
| **Sigma ID** | `de25eeb8-3655-4643-ac3a-b662d3f26b6b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_services_stop_and_disable.yml)**

> Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services

```sql
-- ============================================================
-- Title:        Disable Or Stop Services
-- Sigma ID:     de25eeb8-3655-4643-ac3a-b662d3f26b6b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_services_stop_and_disable.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/service' OR procName LIKE '%/systemctl' OR procName LIKE '%/chkconfig')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%stop%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%disable%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html

---

## Setuid and Setgid

| Field | Value |
|---|---|
| **Sigma ID** | `c21c4eaa-ba2e-419a-92b2-8371703cbe21` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548.001 |
| **Author** | Ömer Günal |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_setgid_setuid.yml)**

> Detects suspicious change of file privileges with chown and chmod commands

```sql
-- ============================================================
-- Title:        Setuid and Setgid
-- Sigma ID:     c21c4eaa-ba2e-419a-92b2-8371703cbe21
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1548.001
-- Author:       Ömer Günal
-- Date:         2020-06-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_setgid_setuid.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% chmod u+s%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% chmod g+s%'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%chown root%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.001/T1548.001.md

---

## Shell Invocation Via Ssh - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `8737b7f6-8df3-4bb7-b1da-06019b99b687` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_ssh_shell_execution.yml)**

> Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Shell Invocation Via Ssh - Linux
-- Sigma ID:     8737b7f6-8df3-4bb7-b1da-06019b99b687
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
-- Date:         2024-08-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_ssh_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sh 0<&2 1>&2%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%sh 1>&2 0<&2%'))
  AND (procName LIKE '%/ssh'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ProxyCommand=;%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%permitlocalcommand=yes%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%localhost%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/ssh/
- https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html

---

## Potential Linux Amazon SSM Agent Hijacking

| Field | Value |
|---|---|
| **Sigma ID** | `f9b3edc5-3322-4fc7-8aa3-245d646cc4b7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1219.002 |
| **Author** | Muhammad Faisal |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_ssm_agent_abuse.yml)**

> Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.

```sql
-- ============================================================
-- Title:        Potential Linux Amazon SSM Agent Hijacking
-- Sigma ID:     f9b3edc5-3322-4fc7-8aa3-245d646cc4b7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1219.002
-- Author:       Muhammad Faisal
-- Date:         2023-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_ssm_agent_abuse.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate activity of system administrators
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/amazon-ssm-agent'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-register %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-code %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-id %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-region %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activity of system administrators

**References:**
- https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
- https://www.bleepingcomputer.com/news/security/amazons-aws-ssm-agent-can-be-used-as-post-exploitation-rat-malware/
- https://www.helpnetsecurity.com/2023/08/02/aws-instances-attackers-access/

---

## Chmod Suspicious Directory

| Field | Value |
|---|---|
| **Sigma ID** | `6419afd1-3742-47a5-a7e6-b50386cd15f8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1222.002 |
| **Author** | Christopher Peacock @SecurePeacock, SCYTHE @scythe_io |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_chmod_directories.yml)**

> Detects chmod targeting files in abnormal directory paths.

```sql
-- ============================================================
-- Title:        Chmod Suspicious Directory
-- Sigma ID:     6419afd1-3742-47a5-a7e6-b50386cd15f8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1222.002
-- Author:       Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
-- Date:         2022-06-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_chmod_directories.yml
-- Unmapped:     (none)
-- False Pos:    Admin changing file permissions.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/chmod'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/.Library/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/opt/%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin changing file permissions.

**References:**
- https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md

---

## Container Residence Discovery Via Proc Virtual FS

| Field | Value |
|---|---|
| **Sigma ID** | `746c86fb-ccda-4816-8997-01386263acc4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Seth Hanford |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_container_residence_discovery.yml)**

> Detects potential container discovery via listing of certain kernel features in the "/proc" virtual filesystem

```sql
-- ============================================================
-- Title:        Container Residence Discovery Via Proc Virtual FS
-- Sigma ID:     746c86fb-ccda-4816-8997-01386263acc4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Seth Hanford
-- Date:         2023-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_container_residence_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate system administrator usage of these commands; Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%awk' OR procName LIKE '%/cat' OR procName LIKE '%grep' OR procName LIKE '%/head' OR procName LIKE '%/less' OR procName LIKE '%/more' OR procName LIKE '%/nl' OR procName LIKE '%/tail')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate system administrator usage of these commands; Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered

**References:**
- https://blog.skyplabs.net/posts/container-detection/
- https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker

---

## Suspicious Curl File Upload - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `00b90cc1-17ec-402c-96ad-3a8117d7a582` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1105 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Cedric MAURUGEON (Update) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_curl_fileupload.yml)**

> Detects a suspicious curl process start the adds a file to a web request

```sql
-- ============================================================
-- Title:        Suspicious Curl File Upload - Linux
-- Sigma ID:     00b90cc1-17ec-402c-96ad-3a8117d7a582
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567, T1105
-- Author:       Nasreddine Bencherchali (Nextron Systems), Cedric MAURUGEON (Update)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_curl_fileupload.yml
-- Unmapped:     (none)
-- False Pos:    Scripts created by developers and admins
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Scripts created by developers and admins

**References:**
- https://twitter.com/d1r4c/status/1279042657508081664
- https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-19---curl-upload-file
- https://curl.se/docs/manpage.html
- https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html

---

## Suspicious Curl Change User Agents - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `b86d356d-6093-443d-971c-9b07db583c68` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_curl_useragent.yml)**

> Detects a suspicious curl process start on linux with set useragent options

```sql
-- ============================================================
-- Title:        Suspicious Curl Change User Agents - Linux
-- Sigma ID:     b86d356d-6093-443d-971c-9b07db583c68
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_curl_useragent.yml
-- Unmapped:     (none)
-- False Pos:    Scripts created by developers and admins; Administrative activity
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/curl'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -A %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --user-agent %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Scripts created by developers and admins; Administrative activity

**References:**
- https://curl.se/docs/manpage.html

---

## Docker Container Discovery Via Dockerenv Listing

| Field | Value |
|---|---|
| **Sigma ID** | `11701de9-d5a5-44aa-8238-84252f131895` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Seth Hanford |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_dockerenv_recon.yml)**

> Detects listing or file reading of ".dockerenv" which can be a sing of potential container discovery

```sql
-- ============================================================
-- Title:        Docker Container Discovery Via Dockerenv Listing
-- Sigma ID:     11701de9-d5a5-44aa-8238-84252f131895
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Seth Hanford
-- Date:         2023-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_dockerenv_recon.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate system administrator usage of these commands; Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/cat' OR procName LIKE '%/dir' OR procName LIKE '%/find' OR procName LIKE '%/ls' OR procName LIKE '%/stat' OR procName LIKE '%/test' OR procName LIKE '%grep')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.dockerenv'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate system administrator usage of these commands; Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered

**References:**
- https://blog.skyplabs.net/posts/container-detection/
- https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker

---

## Potentially Suspicious Execution From Tmp Folder

| Field | Value |
|---|---|
| **Sigma ID** | `312b42b1-bded-4441-8b58-163a3af58775` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_execution_tmp_folder.yml)**

> Detects a potentially suspicious execution of a process located in the '/tmp/' folder

```sql
-- ============================================================
-- Title:        Potentially Suspicious Execution From Tmp Folder
-- Sigma ID:     312b42b1-bded-4441-8b58-163a3af58775
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_execution_tmp_folder.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '/tmp/%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Potential Discovery Activity Using Find - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_find_execution.yml)**

> Detects usage of "find" binary in a suspicious manner to perform discovery

```sql
-- ============================================================
-- Title:        Potential Discovery Activity Using Find - Linux
-- Sigma ID:     8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_find_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
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

## Suspicious Git Clone - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `cfec9d29-64ec-4a0f-9ffe-0fdb856d5446` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1593.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_git_clone.yml)**

> Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious

```sql
-- ============================================================
-- Title:        Suspicious Git Clone - Linux
-- Sigma ID:     cfec9d29-64ec-4a0f-9ffe-0fdb856d5446
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance | T1593.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_git_clone.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/git'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% clone %'))
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%exploit%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%Vulns%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%vulnerability%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%RCE%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%RemoteCodeExecution%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%Invoke-%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%CVE-%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%poc-%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ProofOfConcept%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%proxyshell%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%log4shell%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%eternalblue%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%eternal-blue%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%MS17-%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt

---

## History File Deletion

| Field | Value |
|---|---|
| **Sigma ID** | `1182f3b3-e716-4efa-99ab-d2685d04360f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1565.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml)**

> Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity

```sql
-- ============================================================
-- Title:        History File Deletion
-- Sigma ID:     1182f3b3-e716-4efa-99ab-d2685d04360f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1565.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/rm' OR procName LIKE '%/unlink' OR procName LIKE '%/shred')
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/.bash\_history%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/.zsh\_history%')))
  OR ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%\_history' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.history' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zhistory'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/sleventyeleven/linuxprivchecker/
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md

---

## Print History File Contents

| Field | Value |
|---|---|
| **Sigma ID** | `d7821ff1-4527-4e33-9f84-d0d57fa2fb66` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1592.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_history_recon.yml)**

> Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance

```sql
-- ============================================================
-- Title:        Print History File Contents
-- Sigma ID:     d7821ff1-4527-4e33-9f84-d0d57fa2fb66
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance | T1592.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_history_recon.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/cat' OR procName LIKE '%/head' OR procName LIKE '%/tail' OR procName LIKE '%/more')
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/.bash\_history%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/.zsh\_history%')))
  OR ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%\_history' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.history' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zhistory'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/sleventyeleven/linuxprivchecker/
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md

---

## Linux HackTool Execution

| Field | Value |
|---|---|
| **Sigma ID** | `a015e032-146d-4717-8944-7a1884122111` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1587 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure]) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_hktl_execution.yml)**

> Detects known hacktool execution based on image name.

```sql
-- ============================================================
-- Title:        Linux HackTool Execution
-- Sigma ID:     a015e032-146d-4717-8944-7a1884122111
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1587
-- Author:       Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure])
-- Date:         2023-01-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_hktl_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/cobaltstrike%' OR procName LIKE '%/teamserver%')
  OR (procName LIKE '%/crackmapexec' OR procName LIKE '%/havoc' OR procName LIKE '%/merlin-agent' OR procName LIKE '%/merlinServer-Linux-x64' OR procName LIKE '%/msfconsole' OR procName LIKE '%/msfvenom' OR procName LIKE '%/ps-empire server' OR procName LIKE '%/ps-empire' OR procName LIKE '%/sliver-client' OR procName LIKE '%/sliver-server' OR procName LIKE '%/Villain.py')
  OR (procName LIKE '%/aircrack-ng' OR procName LIKE '%/bloodhound-python' OR procName LIKE '%/bpfdos' OR procName LIKE '%/ebpfki' OR procName LIKE '%/evil-winrm' OR procName LIKE '%/hashcat' OR procName LIKE '%/hoaxshell.py' OR procName LIKE '%/hydra' OR procName LIKE '%/john' OR procName LIKE '%/ncrack' OR procName LIKE '%/nxc-ubuntu-latest' OR procName LIKE '%/pidhide' OR procName LIKE '%/pspy32' OR procName LIKE '%/pspy32s' OR procName LIKE '%/pspy64' OR procName LIKE '%/pspy64s' OR procName LIKE '%/setoolkit' OR procName LIKE '%/sqlmap' OR procName LIKE '%/writeblocker')
  OR procName LIKE '%/linpeas%'
  OR (procName LIKE '%/autorecon' OR procName LIKE '%/httpx' OR procName LIKE '%/legion' OR procName LIKE '%/naabu' OR procName LIKE '%/netdiscover' OR procName LIKE '%/nuclei' OR procName LIKE '%/recon-ng')
  OR procName LIKE '%/sniper%'
  OR (procName LIKE '%/dirb' OR procName LIKE '%/dirbuster' OR procName LIKE '%/eyewitness' OR procName LIKE '%/feroxbuster' OR procName LIKE '%/ffuf' OR procName LIKE '%/gobuster' OR procName LIKE '%/wfuzz' OR procName LIKE '%/whatweb')
  OR (procName LIKE '%/joomscan' OR procName LIKE '%/nikto' OR procName LIKE '%/wpscan')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/Gui774ume/ebpfkit
- https://github.com/pathtofile/bad-bpf
- https://github.com/carlospolop/PEASS-ng
- https://github.com/t3l3machus/hoaxshell
- https://github.com/t3l3machus/Villain
- https://github.com/HavocFramework/Havoc
- https://github.com/1N3/Sn1per
- https://github.com/Ne0nd0g/merlin
- https://github.com/Pennyw0rth/NetExec/

---

## Potential Container Discovery Via Inodes Listing

| Field | Value |
|---|---|
| **Sigma ID** | `43e26eb5-cd58-48d1-8ce9-a273f5d298d8` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Seth Hanford |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_inod_listing.yml)**

> Detects listing of the inodes of the "/" directory to determine if the we are running inside of a container.

```sql
-- ============================================================
-- Title:        Potential Container Discovery Via Inodes Listing
-- Sigma ID:     43e26eb5-cd58-48d1-8ce9-a273f5d298d8
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1082
-- Author:       Seth Hanford
-- Date:         2023-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_inod_listing.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate system administrator usage of these commands; Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% /'))
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% / %'))
  AND procName LIKE '%/ls'
  AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '(?:\s-[^-\s]{0,20}d|\s--directory\s)'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '(?:\s-[^-\s]{0,20}i|\s--inode\s)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate system administrator usage of these commands; Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered

**References:**
- https://blog.skyplabs.net/posts/container-detection/
- https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker

---

## Interactive Bash Suspicious Children

| Field | Value |
|---|---|
| **Sigma ID** | `ea3ecad2-db86-4a89-ad0b-132a10d2db55` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004, T1036 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.yml)**

> Detects suspicious interactive bash as a parent to rather uncommon child processes

```sql
-- ============================================================
-- Title:        Interactive Bash Suspicious Children
-- Sigma ID:     ea3ecad2-db86-4a89-ad0b-132a10d2db55
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.004, T1036
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software that uses these patterns
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'parentCommand')] AS parentCommandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'parentCommand') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentCommand')] = 'bash -i')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software that uses these patterns

**References:**
- Internal Research

---

## Suspicious Java Children Processes

| Field | Value |
|---|---|
| **Sigma ID** | `d292e0af-9a18-420c-9525-ec0ac3936892` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_java_children.yml)**

> Detects java process spawning suspicious children

```sql
-- ============================================================
-- Title:        Suspicious Java Children Processes
-- Sigma ID:     d292e0af-9a18-420c-9525-ec0ac3936892
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_java_children.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%/java')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%ksh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%zsh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%csh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%curl%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%wget%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%python%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.tecmint.com/different-types-of-linux-shells/

---

## Linux Network Service Scanning Tools Execution

| Field | Value |
|---|---|
| **Sigma ID** | `3e102cd9-a70d-4a7a-9508-403963092f31` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1046 |
| **Author** | Alejandro Ortuno, oscd.community, Georg Lauenstein (sure[secure]) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_network_utilities_execution.yml)**

> Detects execution of network scanning and reconnaisance tools. These tools can be used for the enumeration of local or remote network services for example.

```sql
-- ============================================================
-- Title:        Linux Network Service Scanning Tools Execution
-- Sigma ID:     3e102cd9-a70d-4a7a-9508-403963092f31
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1046
-- Author:       Alejandro Ortuno, oscd.community, Georg Lauenstein (sure[secure])
-- Date:         2020-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_network_utilities_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/nc' OR procName LIKE '%/ncat' OR procName LIKE '%/netcat' OR procName LIKE '%/socat')
  AND NOT ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --listen %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -l %'))))
  OR (procName LIKE '%/autorecon' OR procName LIKE '%/hping' OR procName LIKE '%/hping2' OR procName LIKE '%/hping3' OR procName LIKE '%/naabu' OR procName LIKE '%/nmap' OR procName LIKE '%/nping' OR procName LIKE '%/telnet' OR procName LIKE '%/zenmap')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
- https://github.com/projectdiscovery/naabu
- https://github.com/Tib3rius/AutoRecon

---

## Linux Shell Pipe to Shell

| Field | Value |
|---|---|
| **Sigma ID** | `880973f3-9708-491c-a77b-2a35a1921158` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1140 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml)**

> Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell

```sql
-- ============================================================
-- Title:        Linux Shell Pipe to Shell
-- Sigma ID:     880973f3-9708-491c-a77b-2a35a1921158
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1140
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software that uses these patterns
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE 'sh -c %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE 'bash -c %'))
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| bash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| sh %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%|bash %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%|sh %')))
  OR ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| bash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%| sh' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%|bash' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% |sh'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software that uses these patterns

**References:**
- Internal Research

---

## Access of Sudoers File Content

| Field | Value |
|---|---|
| **Sigma ID** | `0f79c4d2-4e1f-4683-9c36-b5469a665e06` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1592.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_process_reading_sudoers.yml)**

> Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.

```sql
-- ============================================================
-- Title:        Access of Sudoers File Content
-- Sigma ID:     0f79c4d2-4e1f-4683-9c36-b5469a665e06
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance | T1592.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_process_reading_sudoers.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%/cat' OR procName LIKE '%/ed' OR procName LIKE '%/egrep' OR procName LIKE '%/emacs' OR procName LIKE '%/fgrep' OR procName LIKE '%/grep' OR procName LIKE '%/head' OR procName LIKE '%/less' OR procName LIKE '%/more' OR procName LIKE '%/nano' OR procName LIKE '%/tail')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% /etc/sudoers%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/sleventyeleven/linuxprivchecker/

---

## Linux Recon Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `0cf7a157-8879-41a2-8f55-388dd23746b7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1592.004, T1552.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_recon_indicators.yml)**

> Detects events with patterns found in commands used for reconnaissance on linux systems

```sql
-- ============================================================
-- Title:        Linux Recon Indicators
-- Sigma ID:     0cf7a157-8879-41a2-8f55-388dd23746b7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        reconnaissance | T1592.004, T1552.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_recon_indicators.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -name .htpasswd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -perm -4000 %'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/sleventyeleven/linuxprivchecker/blob/0d701080bbf92efd464e97d71a70f97c6f2cd658/linuxprivchecker.py

---

## Potential Suspicious Change To Sensitive/Critical Files

| Field | Value |
|---|---|
| **Sigma ID** | `86157017-c2b1-4d4a-8c33-93b8e67e4af4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1565.001 |
| **Author** | @d4ns4n_ (Wuerth-Phoenix) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_sensitive_file_access.yml)**

> Detects changes of sensitive and critical files. Monitors files that you don't expect to change without planning on Linux system.

```sql
-- ============================================================
-- Title:        Potential Suspicious Change To Sensitive/Critical Files
-- Sigma ID:     86157017-c2b1-4d4a-8c33-93b8e67e4af4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1565.001
-- Author:       @d4ns4n_ (Wuerth-Phoenix)
-- Date:         2023-05-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_sensitive_file_access.yml
-- Unmapped:     (none)
-- False Pos:    Some false positives are to be expected on user or administrator machines. Apply additional filters as needed.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/login%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/passwd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/boot/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/*.conf%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/cron.%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/crontab%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/hosts%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/init.d%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/sudoers%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/opt/bin/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/sbin%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/usr/bin/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/usr/local/bin/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives are to be expected on user or administrator machines. Apply additional filters as needed.

**References:**
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview#which-files-should-i-monitor

---

## Shell Execution Of Process Located In Tmp Directory

| Field | Value |
|---|---|
| **Sigma ID** | `2fade0b6-7423-4835-9d4f-335b39b83867` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder.yml)**

> Detects execution of shells from a parent process located in a temporary (/tmp) directory

```sql
-- ============================================================
-- Title:        Shell Execution Of Process Located In Tmp Directory
-- Sigma ID:     2fade0b6-7423-4835-9d4f-335b39b83867
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '/tmp/%')
    AND (procName LIKE '%/bash' OR procName LIKE '%/csh' OR procName LIKE '%/dash' OR procName LIKE '%/fish' OR procName LIKE '%/ksh' OR procName LIKE '%/sh' OR procName LIKE '%/zsh'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Execution Of Script Located In Potentially Suspicious Directory

| Field | Value |
|---|---|
| **Sigma ID** | `30bcce26-51c5-49f2-99c8-7b59e3af36c7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_shell_script_exec_from_susp_location.yml)**

> Detects executions of scripts located in potentially suspicious locations such as "/tmp" via a shell such as "bash", "sh", etc.

```sql
-- ============================================================
-- Title:        Execution Of Script Located In Potentially Suspicious Directory
-- Sigma ID:     30bcce26-51c5-49f2-99c8-7b59e3af36c7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_shell_script_exec_from_susp_location.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -c %')
  AND (procName LIKE '%/bash' OR procName LIKE '%/csh' OR procName LIKE '%/dash' OR procName LIKE '%/fish' OR procName LIKE '%/ksh' OR procName LIKE '%/sh' OR procName LIKE '%/zsh')
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## System Information Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `42df45e7-e6e9-43b5-8f26-bec5b39cc239` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1082 |
| **Author** | Ömer Günal, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_info_discovery.yml)**

> Detects system information discovery commands

```sql
-- ============================================================
-- Title:        System Information Discovery
-- Sigma ID:     42df45e7-e6e9-43b5-8f26-bec5b39cc239
-- Level:        informational  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        discovery | T1082
-- Author:       Ömer Günal, oscd.community
-- Date:         2020-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_info_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/uname' OR procName LIKE '%/hostname' OR procName LIKE '%/uptime' OR procName LIKE '%/lspci' OR procName LIKE '%/dmidecode' OR procName LIKE '%/lscpu' OR procName LIKE '%/lsmod')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md

---

## System Network Connections Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `4c519226-f0cd-4471-bd2f-6fbb2bb68a79` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1049 |
| **Author** | Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_network_connections_discovery.yml)**

> Detects usage of system utilities to discover system network connections

```sql
-- ============================================================
-- Title:        System Network Connections Discovery - Linux
-- Sigma ID:     4c519226-f0cd-4471-bd2f-6fbb2bb68a79
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1049
-- Author:       Daniil Yugoslavskiy, oscd.community
-- Date:         2020-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_network_connections_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/who' OR procName LIKE '%/w' OR procName LIKE '%/last' OR procName LIKE '%/lsof' OR procName LIKE '%/netstat')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md

---

## System Network Discovery - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `e7bd1cfa-b446-4c88-8afb-403bcd79e3fa` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1016 |
| **Author** | Ömer Günal and remotephone, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_network_discovery.yml)**

> Detects enumeration of local network configuration

```sql
-- ============================================================
-- Title:        System Network Discovery - Linux
-- Sigma ID:     e7bd1cfa-b446-4c88-8afb-403bcd79e3fa
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1016
-- Author:       Ömer Günal and remotephone, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_network_discovery.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/etc/resolv.conf%')
  OR (procName LIKE '%/firewall-cmd' OR procName LIKE '%/ufw' OR procName LIKE '%/iptables' OR procName LIKE '%/netstat' OR procName LIKE '%/ss' OR procName LIKE '%/ip' OR procName LIKE '%/ifconfig' OR procName LIKE '%/systemd-resolve' OR procName LIKE '%/route')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md

---

## Mask System Power Settings Via Systemctl

| Field | Value |
|---|---|
| **Sigma ID** | `c172b7b5-f3a1-4af2-90b7-822c63df86cb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, impact |
| **MITRE Techniques** | T1653 |
| **Author** | Milad Cheraghi, Nasreddine Bencherchali |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_systemctl_mask_power_settings.yml)**

> Detects the use of systemctl mask to disable system power management targets such as suspend, hibernate, or hybrid sleep.
Adversaries may mask these targets to prevent a system from entering sleep or shutdown states, ensuring their malicious processes remain active and uninterrupted.
This behavior can be associated with persistence or defense evasion, as it impairs normal system power operations to maintain long-term access or avoid termination of malicious activity.


```sql
-- ============================================================
-- Title:        Mask System Power Settings Via Systemctl
-- Sigma ID:     c172b7b5-f3a1-4af2-90b7-822c63df86cb
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence, impact | T1653
-- Author:       Milad Cheraghi, Nasreddine Bencherchali
-- Date:         2025-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_systemctl_mask_power_settings.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%suspend.target%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%hibernate.target%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%hybrid-sleep.target%'))
  AND (procName LIKE '%/systemctl'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% mask%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.man7.org/linux/man-pages/man1/systemctl.1.html
- https://linux-audit.com/systemd/faq/what-is-the-difference-between-systemctl-disable-and-systemctl-mask/

---

## Touch Suspicious Service File

| Field | Value |
|---|---|
| **Sigma ID** | `31545105-3444-4584-bebf-c466353230d2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.006 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml)**

> Detects usage of the "touch" process in service file.

```sql
-- ============================================================
-- Title:        Touch Suspicious Service File
-- Sigma ID:     31545105-3444-4584-bebf-c466353230d2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.006
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml
-- Unmapped:     (none)
-- False Pos:    Admin changing date of files.
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/touch'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -t %')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%.service'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admin changing date of files.

**References:**
- https://blogs.blackberry.com/
- https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144

---

## Triple Cross eBPF Rootkit Execve Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `0326c3c8-7803-4a0f-8c5c-368f747f7c3e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_execve_hijack.yml)**

> Detects execution of a the file "execve_hijack" which is used by the Triple Cross rootkit as a way to elevate privileges

```sql
-- ============================================================
-- Title:        Triple Cross eBPF Rootkit Execve Hijack
-- Sigma ID:     0326c3c8-7803-4a0f-8c5c-368f747f7c3e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_execve_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sudo'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%execve\_hijack%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/src/helpers/execve_hijack.c#L275

---

## Triple Cross eBPF Rootkit Install Commands

| Field | Value |
|---|---|
| **Sigma ID** | `22236d75-d5a0-4287-bf06-c93b1770860f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1014 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_install.yml)**

> Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script

```sql
-- ============================================================
-- Title:        Triple Cross eBPF Rootkit Install Commands
-- Sigma ID:     22236d75-d5a0-4287-bf06-c93b1770860f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1014
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_install.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/sudo'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% tc %' AND metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% enp0s3 %')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% qdisc %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% filter %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh

---

## User Has Been Deleted Via Userdel

| Field | Value |
|---|---|
| **Sigma ID** | `08f26069-6f80-474b-8d1f-d971c6fedea0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | Tuan Le (NCSGroup) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_userdel.yml)**

> Detects execution of the "userdel" binary. Which is used to delete a user account and related files. This is sometimes abused by threat actors in order to cover their tracks

```sql
-- ============================================================
-- Title:        User Has Been Deleted Via Userdel
-- Sigma ID:     08f26069-6f80-474b-8d1f-d971c6fedea0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       Tuan Le (NCSGroup)
-- Date:         2022-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_userdel.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%/userdel'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activities

**References:**
- https://linuxize.com/post/how-to-delete-group-in-linux/
- https://www.cyberciti.biz/faq/linux-remove-user-command/
- https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
- https://linux.die.net/man/8/userdel

---

## User Added To Root/Sudoers Group Using Usermod

| Field | Value |
|---|---|
| **Sigma ID** | `6a50f16c-3b7b-42d1-b081-0fdd3ba70a73` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | TuanLe (GTSC) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_usermod_susp_group.yml)**

> Detects usage of the "usermod" binary to add users add users to the root or suoders groups

```sql
-- ============================================================
-- Title:        User Added To Root/Sudoers Group Using Usermod
-- Sigma ID:     6a50f16c-3b7b-42d1-b081-0fdd3ba70a73
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       TuanLe (GTSC)
-- Date:         2022-12-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_usermod_susp_group.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator activities
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/usermod'
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-aG root%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-aG sudoers%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activities

**References:**
- https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/
- https://www.configserverfirewall.com/ubuntu-linux/ubuntu-add-user-to-root-group/

---

## Vim GTFOBin Abuse - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `7ab8f73a-fcff-428b-84aa-6a5ff7877dea` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_vim_shell_execution.yml)**

> Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.


```sql
-- ============================================================
-- Title:        Vim GTFOBin Abuse - Linux
-- Sigma ID:     7ab8f73a-fcff-428b-84aa-6a5ff7877dea
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1083
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_vim_shell_execution.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%:!/%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%:lua %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%:py %' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/bash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/dash%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/fish%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/sh%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/bin/zsh%'))
  AND ((procName LIKE '%/rvim' OR procName LIKE '%/vim' OR procName LIKE '%/vimdiff')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% --cmd%' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% -c %'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://gtfobins.github.io/gtfobins/vim/
- https://gtfobins.github.io/gtfobins/rvim/
- https://gtfobins.github.io/gtfobins/vimdiff/

---

## Linux Webshell Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `818f7b24-0fba-4c49-a073-8b755573b9c7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml)**

> Detects suspicious sub processes of web server processes

```sql
-- ============================================================
-- Title:        Linux Webshell Indicators
-- Sigma ID:     818f7b24-0fba-4c49-a073-8b755573b9c7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml
-- Unmapped:     (none)
-- False Pos:    Web applications that invoke Linux command line tools
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/whoami' OR procName LIKE '%/ifconfig' OR procName LIKE '%/ip' OR procName LIKE '%/bin/uname' OR procName LIKE '%/bin/cat' OR procName LIKE '%/bin/crontab' OR procName LIKE '%/hostname' OR procName LIKE '%/iptables' OR procName LIKE '%/netstat' OR procName LIKE '%/pwd' OR procName LIKE '%/route')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Web applications that invoke Linux command line tools

**References:**
- https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
- https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF

---

## Download File To Potentially Suspicious Directory Via Wget

| Field | Value |
|---|---|
| **Sigma ID** | `cf610c15-ed71-46e1-bdf8-2bd1a99de6c4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_wget_download_suspicious_directory.yml)**

> Detects the use of wget to download content to a suspicious directory

```sql
-- ============================================================
-- Title:        Download File To Potentially Suspicious Directory Via Wget
-- Sigma ID:     cf610c15-ed71-46e1-bdf8-2bd1a99de6c4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2023-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_wget_download_suspicious_directory.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/wget'
  AND (indexOf(metrics_string.name, 'command') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'command')], '\s-O\s')))
  OR (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%--output-document%'))
  AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%/tmp/%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
- https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
- https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
- https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection

---

## Potential Xterm Reverse Shell

| Field | Value |
|---|---|
| **Sigma ID** | `4e25af4b-246d-44ea-8563-e42aacab006b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | @d4ns4n_ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_xterm_reverse_shell.yml)**

> Detects usage of "xterm" as a potential reverse shell tunnel

```sql
-- ============================================================
-- Title:        Potential Xterm Reverse Shell
-- Sigma ID:     4e25af4b-246d-44ea-8563-e42aacab006b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       @d4ns4n_
-- Date:         2023-04-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_xterm_reverse_shell.yml
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
WHERE eventType IN ('LINUX_PROCESS_EXEC')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%xterm%'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%-display%')
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%:1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://www.revshells.com/

---
