# Sigma → FortiSIEM: Windows Bits-Client

> 7 rules · Generated 2026-03-17

## Table of Contents

- [New BITS Job Created Via Bitsadmin](#new-bits-job-created-via-bitsadmin)
- [New BITS Job Created Via PowerShell](#new-bits-job-created-via-powershell)
- [BITS Transfer Job Downloading File Potential Suspicious Extension](#bits-transfer-job-downloading-file-potential-suspicious-extension)
- [BITS Transfer Job Download From File Sharing Domains](#bits-transfer-job-download-from-file-sharing-domains)
- [BITS Transfer Job Download From Direct IP](#bits-transfer-job-download-from-direct-ip)
- [BITS Transfer Job With Uncommon Or Suspicious Remote TLD](#bits-transfer-job-with-uncommon-or-suspicious-remote-tld)
- [BITS Transfer Job Download To Potential Suspicious Folder](#bits-transfer-job-download-to-potential-suspicious-folder)

## New BITS Job Created Via Bitsadmin

| Field | Value |
|---|---|
| **Sigma ID** | `1ff315dc-2a3a-4b71-8dde-873818d25d39` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_job_via_bitsadmin.yml)**

> Detects the creation of a new bits job by Bitsadmin

```sql
-- ============================================================
-- Title:        New BITS Job Created Via Bitsadmin
-- Sigma ID:     1ff315dc-2a3a-4b71-8dde-873818d25d39
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       frack113
-- Date:         2022-03-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_job_via_bitsadmin.yml
-- Unmapped:     processPath
-- False Pos:    Many legitimate applications or scripts could leverage "bitsadmin". This event is best correlated with EID 16403 via the JobID field
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client
-- UNMAPPED_FIELD: processPath

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
  AND (winEventId = '3'
    AND rawEventMsg LIKE '%\\bitsadmin.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Many legitimate applications or scripts could leverage "bitsadmin". This event is best correlated with EID 16403 via the JobID field

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md

---

## New BITS Job Created Via PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `fe3a2d49-f255-4d10-935c-bda7391108eb` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_job_via_powershell.yml)**

> Detects the creation of a new bits job by PowerShell

```sql
-- ============================================================
-- Title:        New BITS Job Created Via PowerShell
-- Sigma ID:     fe3a2d49-f255-4d10-935c-bda7391108eb
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       frack113
-- Date:         2022-03-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_job_via_powershell.yml
-- Unmapped:     processPath
-- False Pos:    Administrator PowerShell scripts
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client
-- UNMAPPED_FIELD: processPath

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
  AND (winEventId = '3'
    AND (rawEventMsg LIKE '%\\powershell.exe' OR rawEventMsg LIKE '%\\pwsh.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator PowerShell scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md

---

## BITS Transfer Job Downloading File Potential Suspicious Extension

| Field | Value |
|---|---|
| **Sigma ID** | `b85e5894-9b19-4d86-8c87-a2f3b81f0521` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_saving_susp_extensions.yml)**

> Detects new BITS transfer job saving local files with potential suspicious extensions

```sql
-- ============================================================
-- Title:        BITS Transfer Job Downloading File Potential Suspicious Extension
-- Sigma ID:     b85e5894-9b19-4d86-8c87-a2f3b81f0521
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       frack113
-- Date:         2022-03-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_saving_susp_extensions.yml
-- Unmapped:     LocalName
-- False Pos:    While the file extensions in question can be suspicious at times. It's best to add filters according to your environment to avoid large amount false positives
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client
-- UNMAPPED_FIELD: LocalName

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
  AND (winEventId = '16403'
    AND (rawEventMsg LIKE '%.bat' OR rawEventMsg LIKE '%.dll' OR rawEventMsg LIKE '%.exe' OR rawEventMsg LIKE '%.hta' OR rawEventMsg LIKE '%.ps1' OR rawEventMsg LIKE '%.psd1' OR rawEventMsg LIKE '%.sh' OR rawEventMsg LIKE '%.vbe' OR rawEventMsg LIKE '%.vbs'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** While the file extensions in question can be suspicious at times. It's best to add filters according to your environment to avoid large amount false positives

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md

---

## BITS Transfer Job Download From File Sharing Domains

| Field | Value |
|---|---|
| **Sigma ID** | `d635249d-86b5-4dad-a8c7-d7272b788586` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_file_sharing_domains.yml)**

> Detects BITS transfer job downloading files from a file sharing domain.

```sql
-- ============================================================
-- Title:        BITS Transfer Job Download From File Sharing Domains
-- Sigma ID:     d635249d-86b5-4dad-a8c7-d7272b788586
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_file_sharing_domains.yml
-- Unmapped:     RemoteName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client
-- UNMAPPED_FIELD: RemoteName

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
  AND (winEventId = '16403'
    AND (rawEventMsg LIKE '%.githubusercontent.com%' OR rawEventMsg LIKE '%anonfiles.com%' OR rawEventMsg LIKE '%cdn.discordapp.com%' OR rawEventMsg LIKE '%ddns.net%' OR rawEventMsg LIKE '%dl.dropboxusercontent.com%' OR rawEventMsg LIKE '%ghostbin.co%' OR rawEventMsg LIKE '%github.com%' OR rawEventMsg LIKE '%glitch.me%' OR rawEventMsg LIKE '%gofile.io%' OR rawEventMsg LIKE '%hastebin.com%' OR rawEventMsg LIKE '%mediafire.com%' OR rawEventMsg LIKE '%mega.nz%' OR rawEventMsg LIKE '%onrender.com%' OR rawEventMsg LIKE '%pages.dev%' OR rawEventMsg LIKE '%paste.ee%' OR rawEventMsg LIKE '%pastebin.com%' OR rawEventMsg LIKE '%pastebin.pl%' OR rawEventMsg LIKE '%pastetext.net%' OR rawEventMsg LIKE '%pixeldrain.com%' OR rawEventMsg LIKE '%privatlab.com%' OR rawEventMsg LIKE '%privatlab.net%' OR rawEventMsg LIKE '%send.exploit.in%' OR rawEventMsg LIKE '%sendspace.com%' OR rawEventMsg LIKE '%storage.googleapis.com%' OR rawEventMsg LIKE '%storjshare.io%' OR rawEventMsg LIKE '%supabase.co%' OR rawEventMsg LIKE '%temp.sh%' OR rawEventMsg LIKE '%transfer.sh%' OR rawEventMsg LIKE '%trycloudflare.com%' OR rawEventMsg LIKE '%ufile.io%' OR rawEventMsg LIKE '%w3spaces.com%' OR rawEventMsg LIKE '%workers.dev%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
- https://twitter.com/malmoeb/status/1535142803075960832
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
- https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/

---

## BITS Transfer Job Download From Direct IP

| Field | Value |
|---|---|
| **Sigma ID** | `90f138c1-f578-4ac3-8c49-eecfd847c8b7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_ip_address.yml)**

> Detects a BITS transfer job downloading file(s) from a direct IP address.

```sql
-- ============================================================
-- Title:        BITS Transfer Job Download From Direct IP
-- Sigma ID:     90f138c1-f578-4ac3-8c49-eecfd847c8b7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_ip_address.yml
-- Unmapped:     RemoteName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client
-- UNMAPPED_FIELD: RemoteName

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
  AND (winEventId = '16403'
    AND (rawEventMsg LIKE '%http://1%' OR rawEventMsg LIKE '%http://2%' OR rawEventMsg LIKE '%http://3%' OR rawEventMsg LIKE '%http://4%' OR rawEventMsg LIKE '%http://5%' OR rawEventMsg LIKE '%http://6%' OR rawEventMsg LIKE '%http://7%' OR rawEventMsg LIKE '%http://8%' OR rawEventMsg LIKE '%http://9%' OR rawEventMsg LIKE '%https://1%' OR rawEventMsg LIKE '%https://2%' OR rawEventMsg LIKE '%https://3%' OR rawEventMsg LIKE '%https://4%' OR rawEventMsg LIKE '%https://5%' OR rawEventMsg LIKE '%https://6%' OR rawEventMsg LIKE '%https://7%' OR rawEventMsg LIKE '%https://8%' OR rawEventMsg LIKE '%https://9%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
- https://isc.sans.edu/diary/22264
- https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
- https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/

---

## BITS Transfer Job With Uncommon Or Suspicious Remote TLD

| Field | Value |
|---|---|
| **Sigma ID** | `6d44fb93-e7d2-475c-9d3d-54c9c1e33427` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_uncommon_tld.yml)**

> Detects a suspicious download using the BITS client from a FQDN that is unusual. Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.

```sql
-- ============================================================
-- Title:        BITS Transfer Job With Uncommon Or Suspicious Remote TLD
-- Sigma ID:     6d44fb93-e7d2-475c-9d3d-54c9c1e33427
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_uncommon_tld.yml
-- Unmapped:     (none)
-- False Pos:    This rule doesn't exclude other known TLDs such as ".org" or ".net". It's recommended to apply additional filters for software and scripts that leverage the BITS service
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client

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
  AND winEventId = '16403'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This rule doesn't exclude other known TLDs such as ".org" or ".net". It's recommended to apply additional filters for software and scripts that leverage the BITS service

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
- https://twitter.com/malmoeb/status/1535142803075960832

---

## BITS Transfer Job Download To Potential Suspicious Folder

| Field | Value |
|---|---|
| **Sigma ID** | `f8a56cb7-a363-44ed-a82f-5926bb44cd05` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1197 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_trasnfer_susp_local_folder.yml)**

> Detects new BITS transfer job where the LocalName/Saved file is stored in a potentially suspicious location

```sql
-- ============================================================
-- Title:        BITS Transfer Job Download To Potential Suspicious Folder
-- Sigma ID:     f8a56cb7-a363-44ed-a82f-5926bb44cd05
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1197
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_trasnfer_susp_local_folder.yml
-- Unmapped:     LocalName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/bits-client
-- UNMAPPED_FIELD: LocalName

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
  AND (winEventId = '16403'
    AND (rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%C:\\Users\\Public\\%' OR rawEventMsg LIKE '%C:\\PerfLogs\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md

---
