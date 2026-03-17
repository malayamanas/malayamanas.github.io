# Sigma → FortiSIEM: Linux 

> 15 rules · Generated 2026-03-17

## Table of Contents

- [Equation Group Indicators](#equation-group-indicators)
- [Buffer Overflow Attempts](#buffer-overflow-attempts)
- [Commands to Clear or Remove the Syslog - Builtin](#commands-to-clear-or-remove-the-syslog-builtin)
- [Remote File Copy](#remote-file-copy)
- [Code Injection by ld.so Preload](#code-injection-by-ldso-preload)
- [Potential Suspicious BPF Activity - Linux](#potential-suspicious-bpf-activity-linux)
- [Privileged User Has Been Created](#privileged-user-has-been-created)
- [Linux Command History Tampering](#linux-command-history-tampering)
- [Suspicious Activity in Shell Commands](#suspicious-activity-in-shell-commands)
- [Suspicious Log Entries](#suspicious-log-entries)
- [Suspicious Reverse Shell Command Line](#suspicious-reverse-shell-command-line)
- [Shellshock Expression](#shellshock-expression)
- [Suspicious Use of /dev/tcp](#suspicious-use-of-devtcp)
- [JexBoss Command Sequence](#jexboss-command-sequence)
- [Symlink Etc Passwd](#symlink-etc-passwd)

## Equation Group Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `41e5c73d-9983-4b69-bd03-e13b67e9623c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_apt_equationgroup_lnx.yml)**

> Detects suspicious shell commands used in various Equation Group scripts and tools

```sql
-- ============================================================
-- Title:        Equation Group Indicators
-- Sigma ID:     41e5c73d-9983-4b69-bd03-e13b67e9623c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-04-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_apt_equationgroup_lnx.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%chown root*chmod 4777 %' OR rawEventMsg LIKE '%cp /bin/sh .;chown%' OR rawEventMsg LIKE '%chmod 4777 /tmp/.scsi/dev/bin/gsh%' OR rawEventMsg LIKE '%chown root:root /tmp/.scsi/dev/bin/%' OR rawEventMsg LIKE '%chown root:root x;%' OR rawEventMsg LIKE '%/bin/telnet locip locport < /dev/console | /bin/sh%' OR rawEventMsg LIKE '%/tmp/ratload%' OR rawEventMsg LIKE '%ewok -t %' OR rawEventMsg LIKE '%xspy -display %' OR rawEventMsg LIKE '%cat > /dev/tcp/127.0.0.1/80 <<END%' OR rawEventMsg LIKE '%rm -f /current/tmp/ftshell.latest%' OR rawEventMsg LIKE '%ghost\_* -v %' OR rawEventMsg LIKE '% --wipe > /dev/null%' OR rawEventMsg LIKE '%ping -c 2 *; grep * /proc/net/arp >/tmp/gx%' OR rawEventMsg LIKE '%iptables * OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;%' OR rawEventMsg LIKE '%> /var/log/audit/audit.log; rm -f .%' OR rawEventMsg LIKE '%cp /var/log/audit/audit.log .tmp%' OR rawEventMsg LIKE '%sh >/dev/tcp/* <&1 2>&1%' OR rawEventMsg LIKE '%ncat -vv -l -p * <%' OR rawEventMsg LIKE '%nc -vv -l -p * <%' OR rawEventMsg LIKE '%< /dev/console | uudecode && uncompress%' OR rawEventMsg LIKE '%sendmail -osendmail;chmod +x sendmail%' OR rawEventMsg LIKE '%/usr/bin/wget -O /tmp/a http* && chmod 755 /tmp/cron%' OR rawEventMsg LIKE '%chmod 666 /var/run/utmp~%' OR rawEventMsg LIKE '%chmod 700 nscd crond%' OR rawEventMsg LIKE '%cp /etc/shadow /tmp/.%' OR rawEventMsg LIKE '%</dev/console |uudecode > /dev/null 2>&1 && uncompress%' OR rawEventMsg LIKE '%chmod 700 jp&&netstat -an|grep%' OR rawEventMsg LIKE '%uudecode > /dev/null 2>&1 && uncompress -f * && chmod 755%' OR rawEventMsg LIKE '%chmod 700 crond%' OR rawEventMsg LIKE '%wget http*; chmod +x /tmp/sendmail%' OR rawEventMsg LIKE '%chmod 700 fp sendmail pt%' OR rawEventMsg LIKE '%chmod 755 /usr/vmsys/bin/pipe%' OR rawEventMsg LIKE '%chmod -R 755 /usr/vmsys%' OR rawEventMsg LIKE '%chmod 755 $opbin/*tunnel%' OR rawEventMsg LIKE '%chmod 700 sendmail%' OR rawEventMsg LIKE '%chmod 0700 sendmail%' OR rawEventMsg LIKE '%/usr/bin/wget http*sendmail;chmod +x sendmail;%' OR rawEventMsg LIKE '%&& telnet * 2>&1 </dev/console%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1

---

## Buffer Overflow Attempts

| Field | Value |
|---|---|
| **Sigma ID** | `18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1068 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_buffer_overflows.yml)**

> Detects buffer overflow attempts in Unix system log files

```sql
-- ============================================================
-- Title:        Buffer Overflow Attempts
-- Sigma ID:     18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1068
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_buffer_overflows.yml
-- Unmapped:     (none)
-- False Pos:    Base64 encoded data in log entries
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%attempt to execute code on stack by%' OR rawEventMsg LIKE '%0bin0sh1%' OR rawEventMsg LIKE '%AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%' OR rawEventMsg LIKE '%stack smashing detected%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Base64 encoded data in log entries

**References:**
- https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/attack_rules.xml
- https://docs.oracle.com/cd/E19683-01/816-4883/6mb2joatd/index.html
- https://www.giac.org/paper/gcih/266/review-ftp-protocol-cyber-defense-initiative/102802
- https://blu.org/mhonarc/discuss/2001/04/msg00285.php
- https://rapid7.com/blog/post/2019/02/19/stack-based-buffer-overflow-attacks-what-you-need-to-know/

---

## Commands to Clear or Remove the Syslog - Builtin

| Field | Value |
|---|---|
| **Sigma ID** | `e09eb557-96d2-4de9-ba2d-30f712a5afd3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1565.001 |
| **Author** | Max Altgelt (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_clear_syslog.yml)**

> Detects specific commands commonly used to remove or empty the syslog

```sql
-- ============================================================
-- Title:        Commands to Clear or Remove the Syslog - Builtin
-- Sigma ID:     e09eb557-96d2-4de9-ba2d-30f712a5afd3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1565.001
-- Author:       Max Altgelt (Nextron Systems)
-- Date:         2021-09-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_clear_syslog.yml
-- Unmapped:     (none)
-- False Pos:    Log rotation
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%rm /var/log/syslog%' OR rawEventMsg LIKE '%rm -r /var/log/syslog%' OR rawEventMsg LIKE '%rm -f /var/log/syslog%' OR rawEventMsg LIKE '%rm -rf /var/log/syslog%' OR rawEventMsg LIKE '%mv /var/log/syslog%' OR rawEventMsg LIKE '% >/var/log/syslog%' OR rawEventMsg LIKE '% > /var/log/syslog%'
  AND NOT (rawEventMsg LIKE '%/syslog.%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Log rotation

**References:**
- https://www.virustotal.com/gui/file/fc614fb4bda24ae8ca2c44e812d12c0fab6dd7a097472a35dd12ded053ab8474

---

## Remote File Copy

| Field | Value |
|---|---|
| **Sigma ID** | `7a14080d-a048-4de8-ae58-604ce58a795b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1105 |
| **Author** | Ömer Günal |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_file_copy.yml)**

> Detects the use of tools that copy files from or to remote systems

```sql
-- ============================================================
-- Title:        Remote File Copy
-- Sigma ID:     7a14080d-a048-4de8-ae58-604ce58a795b
-- Level:        low  |  FSM Severity: 3
-- Status:       stable
-- MITRE:        T1105
-- Author:       Ömer Günal
-- Date:         2020-06-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_file_copy.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%scp %' OR rawEventMsg LIKE '%rsync %' OR rawEventMsg LIKE '%sftp %'
  AND rawEventMsg LIKE '%@%' OR rawEventMsg LIKE '%:%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://www.cisa.gov/stopransomware/ransomware-guide

---

## Code Injection by ld.so Preload

| Field | Value |
|---|---|
| **Sigma ID** | `7e3c4651-c347-40c4-b1d4-d48590fdf684` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.006 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_ldso_preload_injection.yml)**

> Detects the ld.so preload persistence file. See `man ld.so` for more information.

```sql
-- ============================================================
-- Title:        Code Injection by ld.so Preload
-- Sigma ID:     7e3c4651-c347-40c4-b1d4-d48590fdf684
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.006
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_ldso_preload_injection.yml
-- Unmapped:     (none)
-- False Pos:    Rare temporary workaround for library misconfiguration
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%/etc/ld.so.preload%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare temporary workaround for library misconfiguration

**References:**
- https://man7.org/linux/man-pages/man8/ld.so.8.html

---

## Potential Suspicious BPF Activity - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `0fadd880-6af3-4610-b1e5-008dc3a11b8a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Red Canary (idea), Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_potential_susp_ebpf_activity.yml)**

> Detects the presence of "bpf_probe_write_user" BPF helper-generated warning messages. Which could be a sign of suspicious eBPF activity on the system.

```sql
-- ============================================================
-- Title:        Potential Suspicious BPF Activity - Linux
-- Sigma ID:     0fadd880-6af3-4610-b1e5-008dc3a11b8a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Red Canary (idea), Nasreddine Bencherchali
-- Date:         2023-01-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_potential_susp_ebpf_activity.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%bpf\_probe\_write\_user%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/ebpf-malware/
- https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

---

## Privileged User Has Been Created

| Field | Value |
|---|---|
| **Sigma ID** | `0ac15ec3-d24f-4246-aa2a-3077bb1cf90e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001, T1098 |
| **Author** | Pawel Mazur |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_privileged_user_creation.yml)**

> Detects the addition of a new user to a privileged group such as "root" or "sudo"

```sql
-- ============================================================
-- Title:        Privileged User Has Been Created
-- Sigma ID:     0ac15ec3-d24f-4246-aa2a-3077bb1cf90e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1136.001, T1098
-- Author:       Pawel Mazur
-- Date:         2022-12-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_privileged_user_creation.yml
-- Unmapped:     (none)
-- False Pos:    Administrative activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%new user%'
  AND rawEventMsg LIKE '%GID=0,%' OR rawEventMsg LIKE '%UID=0,%' OR rawEventMsg LIKE '%GID=10,%' OR rawEventMsg LIKE '%GID=27,%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative activity

**References:**
- https://digital.nhs.uk/cyber-alerts/2018/cc-2825
- https://linux.die.net/man/8/useradd
- https://github.com/redcanaryco/atomic-red-team/blob/25acadc0b43a07125a8a5b599b28bbc1a91ffb06/atomics/T1136.001/T1136.001.md#atomic-test-5---create-a-new-user-in-linux-with-root-uid-and-gid

---

## Linux Command History Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `fdc88d25-96fb-4b7c-9633-c0e417fdbd4e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.003 |
| **Author** | Patrick Bareiss |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_clear_cmd_history.yml)**

> Detects commands that try to clear or tamper with the Linux command history.
This technique is used by threat actors in order to evade defenses and execute commands without them being recorded in files such as "bash_history" or "zsh_history".


```sql
-- ============================================================
-- Title:        Linux Command History Tampering
-- Sigma ID:     fdc88d25-96fb-4b7c-9633-c0e417fdbd4e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.003
-- Author:       Patrick Bareiss
-- Date:         2019-03-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_clear_cmd_history.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%cat /dev/null >*sh\_history%' OR rawEventMsg LIKE '%cat /dev/zero >*sh\_history%' OR rawEventMsg LIKE '%chattr +i*sh\_history%' OR rawEventMsg LIKE '%echo "" >*sh\_history%' OR rawEventMsg LIKE '%empty\_bash\_history%' OR rawEventMsg LIKE '%export HISTFILESIZE=0%' OR rawEventMsg LIKE '%history -c%' OR rawEventMsg LIKE '%history -w%' OR rawEventMsg LIKE '%ln -sf /dev/null *sh\_history%' OR rawEventMsg LIKE '%ln -sf /dev/zero *sh\_history%' OR rawEventMsg LIKE '%rm *sh\_history%' OR rawEventMsg LIKE '%shopt -ou history%' OR rawEventMsg LIKE '%shopt -uo history%' OR rawEventMsg LIKE '%shred *sh\_history%' OR rawEventMsg LIKE '%truncate -s0 *sh\_history%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.003/T1070.003.md
- https://www.hackers-arise.com/post/2016/06/20/covering-your-bash-shell-tracks-antiforensics
- https://www.cadosecurity.com/spinning-yarn-a-new-linux-malware-campaign-targets-docker-apache-hadoop-redis-and-confluence/

---

## Suspicious Activity in Shell Commands

| Field | Value |
|---|---|
| **Sigma ID** | `2aa1440c-9ae9-4d92-84a7-a9e5f5e31695` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_susp_commands.yml)**

> Detects suspicious shell commands used in various exploit codes (see references)

```sql
-- ============================================================
-- Title:        Suspicious Activity in Shell Commands
-- Sigma ID:     2aa1440c-9ae9-4d92-84a7-a9e5f5e31695
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_susp_commands.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%wget * - http* | perl%' OR rawEventMsg LIKE '%wget * - http* | sh%' OR rawEventMsg LIKE '%wget * - http* | bash%' OR rawEventMsg LIKE '%python -m SimpleHTTPServer%' OR rawEventMsg LIKE '%-m http.server%' OR rawEventMsg LIKE '%import pty; pty.spawn*%' OR rawEventMsg LIKE '%socat exec:*%' OR rawEventMsg LIKE '%socat -O /tmp/*%' OR rawEventMsg LIKE '%socat tcp-connect*%' OR rawEventMsg LIKE '%*echo binary >>*%' OR rawEventMsg LIKE '%*wget *; chmod +x*%' OR rawEventMsg LIKE '%*wget *; chmod 777 *%' OR rawEventMsg LIKE '%*cd /tmp || cd /var/run || cd /mnt*%' OR rawEventMsg LIKE '%*stop;service iptables stop;*%' OR rawEventMsg LIKE '%*stop;SuSEfirewall2 stop;*%' OR rawEventMsg LIKE '%chmod 777 2020*%' OR rawEventMsg LIKE '%*>>/etc/rc.local%' OR rawEventMsg LIKE '%*base64 -d /tmp/*%' OR rawEventMsg LIKE '%* | base64 -d *%' OR rawEventMsg LIKE '%*/chmod u+s *%' OR rawEventMsg LIKE '%*chmod +s /tmp/*%' OR rawEventMsg LIKE '%*chmod u+s /tmp/*%' OR rawEventMsg LIKE '%* /tmp/haxhax*%' OR rawEventMsg LIKE '%* /tmp/ns\_sploit*%' OR rawEventMsg LIKE '%nc -l -p *%' OR rawEventMsg LIKE '%cp /bin/ksh *%' OR rawEventMsg LIKE '%cp /bin/sh *%' OR rawEventMsg LIKE '%* /tmp/*.b64 *%' OR rawEventMsg LIKE '%*/tmp/ysocereal.jar*%' OR rawEventMsg LIKE '%*/tmp/x *%' OR rawEventMsg LIKE '%*; chmod +x /tmp/*%' OR rawEventMsg LIKE '%*;chmod +x /tmp/*%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20170319121015/http://www.threatgeek.com/2017/03/widespread-exploitation-attempts-using-cve-2017-5638.html
- https://github.com/rapid7/metasploit-framework/blob/eb6535009f5fdafa954525687f09294918b5398d/modules/exploits/multi/http/struts_code_exec_exception_delegator.rb
- http://pastebin.com/FtygZ1cg
- https://artkond.com/2017/03/23/pivoting-guide/

---

## Suspicious Log Entries

| Field | Value |
|---|---|
| **Sigma ID** | `f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_susp_log_entries.yml)**

> Detects suspicious log entries in Linux log files

```sql
-- ============================================================
-- Title:        Suspicious Log Entries
-- Sigma ID:     f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_susp_log_entries.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%entered promiscuous mode%' OR rawEventMsg LIKE '%Deactivating service%' OR rawEventMsg LIKE '%Oversized packet received from%' OR rawEventMsg LIKE '%imuxsock begins to drop messages%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/ossec/ossec-hids/blob/f6502012b7380208db81f82311ad4a1994d39905/etc/rules/syslog_rules.xml

---

## Suspicious Reverse Shell Command Line

| Field | Value |
|---|---|
| **Sigma ID** | `738d9bcf-6999-4fdb-b4ac-3033037db8ab` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_susp_rev_shells.yml)**

> Detects suspicious shell commands or program code that may be executed or used in command line to establish a reverse shell

```sql
-- ============================================================
-- Title:        Suspicious Reverse Shell Command Line
-- Sigma ID:     738d9bcf-6999-4fdb-b4ac-3033037db8ab
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shell_susp_rev_shells.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%BEGIN {s = "/inet/tcp/0/%' OR rawEventMsg LIKE '%bash -i >& /dev/tcp/%' OR rawEventMsg LIKE '%bash -i >& /dev/udp/%' OR rawEventMsg LIKE '%sh -i >$ /dev/udp/%' OR rawEventMsg LIKE '%sh -i >$ /dev/tcp/%' OR rawEventMsg LIKE '%&& while read line 0<&5; do%' OR rawEventMsg LIKE '%/bin/bash -c exec 5<>/dev/tcp/%' OR rawEventMsg LIKE '%/bin/bash -c exec 5<>/dev/udp/%' OR rawEventMsg LIKE '%nc -e /bin/sh %' OR rawEventMsg LIKE '%/bin/sh | nc%' OR rawEventMsg LIKE '%rm -f backpipe; mknod /tmp/backpipe p && nc %' OR rawEventMsg LIKE '%;socket(S,PF\_INET,SOCK\_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr\_in($p,inet\_aton($i))))%' OR rawEventMsg LIKE '%;STDIN->fdopen($c,r);$~->fdopen($c,w);system$\_ while<>;%' OR rawEventMsg LIKE '%/bin/sh -i <&3 >&3 2>&3%' OR rawEventMsg LIKE '%uname -a; w; id; /bin/bash -i%' OR rawEventMsg LIKE '%$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()};%' OR rawEventMsg LIKE '%;os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv('HISTFILE','/dev/null');%' OR rawEventMsg LIKE '%.to\_i;exec sprintf("/bin/sh -i <&\%d >&\%d 2>&\%d",f,f,f)%' OR rawEventMsg LIKE '%;while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print%' OR rawEventMsg LIKE '%socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%' OR rawEventMsg LIKE '%rm -f /tmp/p; mknod /tmp/p p &&%' OR rawEventMsg LIKE '% | /bin/bash | telnet %' OR rawEventMsg LIKE '%,echo=0,raw tcp-listen:%' OR rawEventMsg LIKE '%nc -lvvp %' OR rawEventMsg LIKE '%xterm -display 1%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://alamot.github.io/reverse_shells/

---

## Shellshock Expression

| Field | Value |
|---|---|
| **Sigma ID** | `c67e0c98-4d39-46ee-8f6b-437ebf6b950e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shellshock.yml)**

> Detects shellshock expressions in log files

```sql
-- ============================================================
-- Title:        Shellshock Expression
-- Sigma ID:     c67e0c98-4d39-46ee-8f6b-437ebf6b950e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_shellshock.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%(){:;};%' OR rawEventMsg LIKE '%() {:;};%' OR rawEventMsg LIKE '%() { :;};%' OR rawEventMsg LIKE '%() { :; };%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf

---

## Suspicious Use of /dev/tcp

| Field | Value |
|---|---|
| **Sigma ID** | `6cc5fceb-9a71-4c23-aeeb-963abe0b279c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_susp_dev_tcp.yml)**

> Detects suspicious command with /dev/tcp

```sql
-- ============================================================
-- Title:        Suspicious Use of /dev/tcp
-- Sigma ID:     6cc5fceb-9a71-4c23-aeeb-963abe0b279c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance
-- Author:       frack113
-- Date:         2021-12-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_susp_dev_tcp.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%cat </dev/tcp/%' OR rawEventMsg LIKE '%exec 3<>/dev/tcp/%' OR rawEventMsg LIKE '%echo >/dev/tcp/%' OR rawEventMsg LIKE '%bash -i >& /dev/tcp/%' OR rawEventMsg LIKE '%sh -i >& /dev/udp/%' OR rawEventMsg LIKE '%0<&196;exec 196<>/dev/tcp/%' OR rawEventMsg LIKE '%exec 5<>/dev/tcp/%' OR rawEventMsg LIKE '%(sh)0>/dev/tcp/%' OR rawEventMsg LIKE '%bash -c 'bash -i >& /dev/tcp/%' OR rawEventMsg LIKE '%echo -e '#!/bin/bash\\nbash -i >& /dev/tcp/%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.andreafortuna.org/2021/03/06/some-useful-tips-about-dev-tcp/
- https://book.hacktricks.xyz/shells/shells/linux
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md#atomic-test-1---port-scan

---

## JexBoss Command Sequence

| Field | Value |
|---|---|
| **Sigma ID** | `8ec2c8b4-557a-4121-b87c-5dfb3a602fae` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_susp_jexboss.yml)**

> Detects suspicious command sequence that JexBoss

```sql
-- ============================================================
-- Title:        JexBoss Command Sequence
-- Sigma ID:     8ec2c8b4-557a-4121-b87c-5dfb3a602fae
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_susp_jexboss.yml
-- Unmapped:     
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%bash -c /bin/bash%' OR rawEventMsg LIKE '%&/dev/tcp/%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.us-cert.gov/ncas/analysis-reports/AR18-312A

---

## Symlink Etc Passwd

| Field | Value |
|---|---|
| **Sigma ID** | `c67fc22a-0be5-4b4f-aad5-2b32c4b69523` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_symlink_etc_passwd.yml)**

> Detects suspicious command lines that look as if they would create symbolic links to /etc/passwd

```sql
-- ============================================================
-- Title:        Symlink Etc Passwd
-- Sigma ID:     c67fc22a-0be5-4b4f-aad5-2b32c4b69523
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1204.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-04-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/lnx_symlink_etc_passwd.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ln -s -f /etc/passwd%' OR rawEventMsg LIKE '%ln -s /etc/passwd%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.qualys.com/2021/05/04/21nails/21nails.txt

---
