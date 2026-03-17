# Sigma → FortiSIEM: Zeek Smb Files

> 7 rules · Generated 2026-03-17

## Table of Contents

- [SMB Spoolss Name Piped Usage](#smb-spoolss-name-piped-usage)
- [Remote Task Creation via ATSVC Named Pipe - Zeek](#remote-task-creation-via-atsvc-named-pipe-zeek)
- [Possible Impacket SecretDump Remote Activity - Zeek](#possible-impacket-secretdump-remote-activity-zeek)
- [First Time Seen Remote Named Pipe - Zeek](#first-time-seen-remote-named-pipe-zeek)
- [Suspicious PsExec Execution - Zeek](#suspicious-psexec-execution-zeek)
- [Suspicious Access to Sensitive File Extensions - Zeek](#suspicious-access-to-sensitive-file-extensions-zeek)
- [Transferring Files with Credential Data via Network Shares - Zeek](#transferring-files-with-credential-data-via-network-shares-zeek)

## SMB Spoolss Name Piped Usage

| Field | Value |
|---|---|
| **Sigma ID** | `bae2865c-5565-470d-b505-9496c87d0c30` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.002 |
| **Author** | OTR (Open Threat Research), @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_smb_spoolss_named_pipe.yml)**

> Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.

```sql
-- ============================================================
-- Title:        SMB Spoolss Name Piped Usage
-- Sigma ID:     bae2865c-5565-470d-b505-9496c87d0c30
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.002
-- Author:       OTR (Open Threat Research), @neu5ron
-- Date:         2018-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_smb_spoolss_named_pipe.yml
-- Unmapped:     path, name
-- False Pos:    Domain Controllers that are sometimes, commonly although should not be, acting as printer servers too
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: path
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%IPC$'
    AND rawEventMsg = 'spoolss')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Domain Controllers that are sometimes, commonly although should not be, acting as printer servers too

**References:**
- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://dirkjanm.io/a-different-way-of-abusing-zerologon/
- https://twitter.com/_dirkjan/status/1309214379003588608

---

## Remote Task Creation via ATSVC Named Pipe - Zeek

| Field | Value |
|---|---|
| **Sigma ID** | `dde85b37-40cd-4a94-b00c-0b8794f956b5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.002 |
| **Author** | Samir Bousseaden, @neu5rn |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_atsvc_task.yml)**

> Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

```sql
-- ============================================================
-- Title:        Remote Task Creation via ATSVC Named Pipe - Zeek
-- Sigma ID:     dde85b37-40cd-4a94-b00c-0b8794f956b5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence | T1053.002
-- Author:       Samir Bousseaden, @neu5rn
-- Date:         2020-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_atsvc_task.yml
-- Unmapped:     path, name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: path
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = '\\\*\IPC$'
    AND rawEventMsg = 'atsvc')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230409194125/https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html

---

## Possible Impacket SecretDump Remote Activity - Zeek

| Field | Value |
|---|---|
| **Sigma ID** | `92dae1ed-1c9d-4eff-a567-33acbd95b00e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002, T1003.004, T1003.003 |
| **Author** | Samir Bousseaden, @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_impacket_secretdump.yml)**

> Detect AD credential dumping using impacket secretdump HKTL. Based on the SIGMA rules/windows/builtin/win_impacket_secretdump.yml

```sql
-- ============================================================
-- Title:        Possible Impacket SecretDump Remote Activity - Zeek
-- Sigma ID:     92dae1ed-1c9d-4eff-a567-33acbd95b00e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002, T1003.004, T1003.003
-- Author:       Samir Bousseaden, @neu5ron
-- Date:         2020-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_impacket_secretdump.yml
-- Unmapped:     path, name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: path
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\%' AND rawEventMsg LIKE '%ADMIN$%'
    AND rawEventMsg LIKE '%SYSTEM32\\%'
    AND rawEventMsg LIKE '%.tmp')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329153811/https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html

---

## First Time Seen Remote Named Pipe - Zeek

| Field | Value |
|---|---|
| **Sigma ID** | `021310d9-30a6-480a-84b7-eaa69aeb92bb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Samir Bousseaden, @neu5ron, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_lm_namedpipe.yml)**

> This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes

```sql
-- ============================================================
-- Title:        First Time Seen Remote Named Pipe - Zeek
-- Sigma ID:     021310d9-30a6-480a-84b7-eaa69aeb92bb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Samir Bousseaden, @neu5ron, Tim Shelton
-- Date:         2020-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_lm_namedpipe.yml
-- Unmapped:     path
-- False Pos:    Update the excluded named pipe to filter out any newly observed legit named pipe
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: path

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '\\\\\*\\IPC$'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Update the excluded named pipe to filter out any newly observed legit named pipe

**References:**
- https://twitter.com/menasec1/status/1104489274387451904

---

## Suspicious PsExec Execution - Zeek

| Field | Value |
|---|---|
| **Sigma ID** | `f1b3a22a-45e6-4004-afb5-4291f9c21166` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Samir Bousseaden, @neu5ron, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml)**

> detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

```sql
-- ============================================================
-- Title:        Suspicious PsExec Execution - Zeek
-- Sigma ID:     f1b3a22a-45e6-4004-afb5-4291f9c21166
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.002
-- Author:       Samir Bousseaden, @neu5ron, Tim Shelton
-- Date:         2020-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml
-- Unmapped:     path, name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: path
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\\\%' AND rawEventMsg LIKE '%\\IPC$%'
    AND (rawEventMsg LIKE '%-stdin' OR rawEventMsg LIKE '%-stdout' OR rawEventMsg LIKE '%-stderr'))
  AND NOT (rawEventMsg LIKE 'PSEXESVC%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329171218/https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html

---

## Suspicious Access to Sensitive File Extensions - Zeek

| Field | Value |
|---|---|
| **Sigma ID** | `286b47ed-f6fe-40b3-b3a8-35129acd43bc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **Author** | Samir Bousseaden, @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_susp_raccess_sensitive_fext.yml)**

> Detects known sensitive file extensions via Zeek

```sql
-- ============================================================
-- Title:        Suspicious Access to Sensitive File Extensions - Zeek
-- Sigma ID:     286b47ed-f6fe-40b3-b3a8-35129acd43bc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection
-- Author:       Samir Bousseaden, @neu5ron
-- Date:         2020-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_susp_raccess_sensitive_fext.yml
-- Unmapped:     name
-- False Pos:    Help Desk operator doing backup or re-imaging end user machine or backup software; Users working with these data types or exchanging message files
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.pst' OR rawEventMsg LIKE '%.ost' OR rawEventMsg LIKE '%.msg' OR rawEventMsg LIKE '%.nst' OR rawEventMsg LIKE '%.oab' OR rawEventMsg LIKE '%.edb' OR rawEventMsg LIKE '%.nsf' OR rawEventMsg LIKE '%.bak' OR rawEventMsg LIKE '%.dmp' OR rawEventMsg LIKE '%.kirbi' OR rawEventMsg LIKE '%.rdp')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Help Desk operator doing backup or re-imaging end user machine or backup software; Users working with these data types or exchanging message files

**References:**
- Internal Research

---

## Transferring Files with Credential Data via Network Shares - Zeek

| Field | Value |
|---|---|
| **Sigma ID** | `2e69f167-47b5-4ae7-a390-47764529eff5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.002, T1003.001, T1003.003 |
| **Author** | @neu5ron, Teymur Kheirkhabarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_transferring_files_with_credential_data.yml)**

> Transferring files with well-known filenames (sensitive files with credential data) using network shares

```sql
-- ============================================================
-- Title:        Transferring Files with Credential Data via Network Shares - Zeek
-- Sigma ID:     2e69f167-47b5-4ae7-a390-47764529eff5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.002, T1003.001, T1003.003
-- Author:       @neu5ron, Teymur Kheirkhabarov, oscd.community
-- Date:         2020-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_smb_converted_win_transferring_files_with_credential_data.yml
-- Unmapped:     name
-- False Pos:    Transferring sensitive files for legitimate administration work by legitimate administrator
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/smb_files
-- UNMAPPED_FIELD: name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('\mimidrv', '\lsass', '\windows\minidump\', '\hiberfil', '\sqldmpr', '\sam', '\ntds.dit', '\security')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Transferring sensitive files for legitimate administration work by legitimate administrator

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---
