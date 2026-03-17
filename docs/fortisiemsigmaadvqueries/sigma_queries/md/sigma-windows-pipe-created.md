# Sigma → FortiSIEM: Windows Pipe Created

> 17 rules · Generated 2026-03-17

## Table of Contents

- [ADFS Database Named Pipe Connection By Uncommon Tool](#adfs-database-named-pipe-connection-by-uncommon-tool)
- [CobaltStrike Named Pipe](#cobaltstrike-named-pipe)
- [CobaltStrike Named Pipe Pattern Regex](#cobaltstrike-named-pipe-pattern-regex)
- [CobaltStrike Named Pipe Patterns](#cobaltstrike-named-pipe-patterns)
- [HackTool - CoercedPotato Named Pipe Creation](#hacktool-coercedpotato-named-pipe-creation)
- [HackTool - DiagTrackEoP Default Named Pipe](#hacktool-diagtrackeop-default-named-pipe)
- [HackTool - EfsPotato Named Pipe Creation](#hacktool-efspotato-named-pipe-creation)
- [HackTool - Credential Dumping Tools Named Pipe Created](#hacktool-credential-dumping-tools-named-pipe-created)
- [HackTool - Koh Default Named Pipe](#hacktool-koh-default-named-pipe)
- [Alternate PowerShell Hosts Pipe](#alternate-powershell-hosts-pipe)
- [New PowerShell Instance Created](#new-powershell-instance-created)
- [PUA - CSExec Default Named Pipe](#pua-csexec-default-named-pipe)
- [PUA - PAExec Default Named Pipe](#pua-paexec-default-named-pipe)
- [PUA - RemCom Default Named Pipe](#pua-remcom-default-named-pipe)
- [WMI Event Consumer Created Named Pipe](#wmi-event-consumer-created-named-pipe)
- [Malicious Named Pipe Created](#malicious-named-pipe-created)
- [PsExec Tool Execution From Suspicious Locations - PipeName](#psexec-tool-execution-from-suspicious-locations-pipename)

## ADFS Database Named Pipe Connection By Uncommon Tool

| Field | Value |
|---|---|
| **Sigma ID** | `1ea13e8c-03ea-409b-877d-ce5c3d2c1cb3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1005 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_adfs_namedpipe_connection_uncommon_tool.yml)**

> Detects suspicious local connections via a named pipe to the AD FS configuration database (Windows Internal Database).
Used to access information such as the AD FS configuration settings which contains sensitive information used to sign SAML tokens.


```sql
-- ============================================================
-- Title:        ADFS Database Named Pipe Connection By Uncommon Tool
-- Sigma ID:     1ea13e8c-03ea-409b-877d-ce5c3d2c1cb3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1005
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2021-10-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_adfs_namedpipe_connection_uncommon_tool.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] = '\MICROSOFT##WID\tsql\query')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/SecurityEvent/ADFSDBNamedPipeConnection.yaml
- https://o365blog.com/post/adfs/
- https://github.com/Azure/SimuLand

---

## CobaltStrike Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `d5601f8c-b26f-4ab0-9035-69e11a8d4ad2` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1055 |
| **Author** | Florian Roth (Nextron Systems), Wojciech Lesicki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike.yml)**

> Detects the creation of a named pipe as used by CobaltStrike

```sql
-- ============================================================
-- Title:        CobaltStrike Named Pipe
-- Sigma ID:     d5601f8c-b26f-4ab0-9035-69e11a8d4ad2
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1055
-- Author:       Florian Roth (Nextron Systems), Wojciech Lesicki
-- Date:         2021-05-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\MSSE-%' AND metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%-server%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\interprocess\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\lsarpc\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\mojo\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\msagent\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\netlogon\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\postex\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\samr\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\srvsvc\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\status\_%')
  OR indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\wkssvc\_%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/d4rksystem/status/1357010969264873472
- https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/
- https://github.com/SigmaHQ/sigma/issues/253
- https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/
- https://redcanary.com/threat-detection-report/threats/cobalt-strike/

---

## CobaltStrike Named Pipe Pattern Regex

| Field | Value |
|---|---|
| **Sigma ID** | `0e7163d4-9e19-4fa7-9be6-000c61aad77a` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1055 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike_re.yml)**

> Detects the creation of a named pipe matching a pattern used by CobaltStrike Malleable C2 profiles

```sql
-- ============================================================
-- Title:        CobaltStrike Named Pipe Pattern Regex
-- Sigma ID:     0e7163d4-9e19-4fa7-9be6-000c61aad77a
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1055
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike_re.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\mojo\.5688\.8052\.(?:183894939787088877|35780273329370473)[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\wkssvc_?[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\ntsvcs[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\DserNamePipe[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\SearchTextHarvester[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\mypipe-(?:f|h)[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\windows\.update\.manager[0-9a-f]{2,3}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\ntsvcs_[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\scerpc_?[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\PGMessagePipe[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\MsFteWds[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\f4c3[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\fullduplex_[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\msrpc_[0-9a-f]{4}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\win\\msrpc_[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\f53f[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\rpc_[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\spoolss_[0-9a-f]{2}')))
  OR (indexOf(metrics_string.name, 'pipeName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'pipeName')], '\\Winsock2\\CatalogChangeListener-[0-9a-f]{3}-0,')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575
- https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752

---

## CobaltStrike Named Pipe Patterns

| Field | Value |
|---|---|
| **Sigma ID** | `85adeb13-4fc9-4e68-8a4a-c7cb2c336eb7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1055 |
| **Author** | Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike_susp_pipe_patterns.yml)**

> Detects the creation of a named pipe with a pattern found in CobaltStrike malleable C2 profiles

```sql
-- ============================================================
-- Title:        CobaltStrike Named Pipe Patterns
-- Sigma ID:     85adeb13-4fc9-4e68-8a4a-c7cb2c336eb7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1055
-- Author:       Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)
-- Date:         2021-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike_susp_pipe_patterns.yml
-- Unmapped:     (none)
-- False Pos:    Chrome instances using the exact same pipe name "mojo.xxx"; Websense Endpoint using the pipe name "DserNamePipe(R|W)\d{1,5}"
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Chrome instances using the exact same pipe name "mojo.xxx"; Websense Endpoint using the pipe name "DserNamePipe(R|W)\d{1,5}"

**References:**
- https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575
- https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752

---

## HackTool - CoercedPotato Named Pipe Creation

| Field | Value |
|---|---|
| **Sigma ID** | `4d0083b3-580b-40da-9bba-626c19fe4033` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1055 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_coercedpotato.yml)**

> Detects the pattern of a pipe name as used by the hack tool CoercedPotato

```sql
-- ============================================================
-- Title:        HackTool - CoercedPotato Named Pipe Creation
-- Sigma ID:     4d0083b3-580b-40da-9bba-626c19fe4033
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1055
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2023-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_coercedpotato.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\coerced\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.hackvens.fr/articles/CoercedPotato.html
- https://github.com/hackvens/CoercedPotato

---

## HackTool - DiagTrackEoP Default Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `1f7025a6-e747-4130-aac4-961eb47015f1` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_diagtrack_eop.yml)**

> Detects creation of default named pipe used by the DiagTrackEoP POC, a tool that abuses "SeImpersonate" privilege.

```sql
-- ============================================================
-- Title:        HackTool - DiagTrackEoP Default Named Pipe
-- Sigma ID:     1f7025a6-e747-4130-aac4-961eb47015f1
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_diagtrack_eop.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%thisispipe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/Wh04m1001/DiagTrackEoP/blob/3a2fc99c9700623eb7dc7d4b5f314fd9ce5ef51f/main.cpp#L22

---

## HackTool - EfsPotato Named Pipe Creation

| Field | Value |
|---|---|
| **Sigma ID** | `637f689e-b4a5-4a86-be0e-0100a0a33ba2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1055 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_efspotato.yml)**

> Detects the pattern of a pipe name as used by the hack tool EfsPotato

```sql
-- ============================================================
-- Title:        HackTool - EfsPotato Named Pipe Creation
-- Sigma ID:     637f689e-b4a5-4a86-be0e-0100a0a33ba2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1055
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_efspotato.yml
-- Unmapped:     (none)
-- False Pos:    \pipe\LOCAL\Monitorian
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\pipe\\%' OR metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\pipe\\srvsvc%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** \pipe\LOCAL\Monitorian

**References:**
- https://twitter.com/SBousseaden/status/1429530155291193354?s=20
- https://github.com/zcgonvh/EfsPotato

---

## HackTool - Credential Dumping Tools Named Pipe Created

| Field | Value |
|---|---|
| **Sigma ID** | `961d0ba2-3eea-4303-a930-2cf78bbfcc5e` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003.001, T1003.002, T1003.004, T1003.005 |
| **Author** | Teymur Kheirkhabarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_generic_cred_dump_tools_pipes.yml)**

> Detects well-known credential dumping tools execution via specific named pipe creation

```sql
-- ============================================================
-- Title:        HackTool - Credential Dumping Tools Named Pipe Created
-- Sigma ID:     961d0ba2-3eea-4303-a930-2cf78bbfcc5e
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003.001, T1003.002, T1003.004, T1003.005
-- Author:       Teymur Kheirkhabarov, oscd.community
-- Date:         2019-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_generic_cred_dump_tools_pipes.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Administrator using tool for password recovery
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\cachedump%' OR metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\lsadump%' OR metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\wceservicepipe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator using tool for password recovery

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
- https://image.slidesharecdn.com/zeronights2017kheirkhabarov-171118103000/75/hunting-for-credentials-dumping-in-windows-environment-57-2048.jpg?cb=1666035799

---

## HackTool - Koh Default Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `0adc67e0-a68f-4ffd-9c43-28905aad5d6a` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1528, T1134.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_koh_default_pipe.yml)**

> Detects creation of default named pipes used by the Koh tool

```sql
-- ============================================================
-- Title:        HackTool - Koh Default Named Pipe
-- Sigma ID:     0adc67e0-a68f-4ffd-9c43-28905aad5d6a
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1528, T1134.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_hktl_koh_default_pipe.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\imposecost%' OR metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\imposingcost%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/GhostPack/Koh/blob/0283d9f3f91cf74732ad377821986cfcb088e20a/Clients/BOF/KohClient.c#L12

---

## Alternate PowerShell Hosts Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `58cb02d5-78ce-4692-b3e1-dce850aae41a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_powershell_alternate_host_pipe.yml)**

> Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe

```sql
-- ============================================================
-- Title:        Alternate PowerShell Hosts Pipe
-- Sigma ID:     58cb02d5-78ce-4692-b3e1-dce850aae41a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
-- Date:         2019-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_powershell_alternate_host_pipe.yml
-- Unmapped:     (none)
-- False Pos:    Programs using PowerShell directly without invocation of a dedicated interpreter.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\PSHost%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Programs using PowerShell directly without invocation of a dedicated interpreter.

**References:**
- https://threathunterplaybook.com/hunts/windows/190610-PwshAlternateHosts/notebook.html
- https://threathunterplaybook.com/hunts/windows/190410-LocalPwshExecution/notebook.html

---

## New PowerShell Instance Created

| Field | Value |
|---|---|
| **Sigma ID** | `ac7102b4-9e1e-4802-9b4f-17c5524c015c` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_powershell_execution_pipe.yml)**

> Detects the execution of PowerShell via the creation of a named pipe starting with PSHost

```sql
-- ============================================================
-- Title:        New PowerShell Instance Created
-- Sigma ID:     ac7102b4-9e1e-4802-9b4f-17c5524c015c
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2019-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_powershell_execution_pipe.yml
-- Unmapped:     (none)
-- False Pos:    Likely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\PSHost%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://threathunterplaybook.com/hunts/windows/190610-PwshAlternateHosts/notebook.html
- https://threathunterplaybook.com/hunts/windows/190410-LocalPwshExecution/notebook.html

---

## PUA - CSExec Default Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `f318b911-ea88-43f4-9281-0de23ede628e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1021.002, T1569.002 |
| **Author** | Nikita Nazarov, oscd.community, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_csexec_default_pipe.yml)**

> Detects default CSExec pipe creation

```sql
-- ============================================================
-- Title:        PUA - CSExec Default Named Pipe
-- Sigma ID:     f318b911-ea88-43f4-9281-0de23ede628e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1021.002, T1569.002
-- Author:       Nikita Nazarov, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_csexec_default_pipe.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Administrator activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\csexecsvc%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator activity

**References:**
- https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
- https://github.com/malcomvetter/CSExec

---

## PUA - PAExec Default Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `f6451de4-df0a-41fa-8d72-b39f54a08db5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_paexec_default_pipe.yml)**

> Detects PAExec default named pipe

```sql
-- ============================================================
-- Title:        PUA - PAExec Default Named Pipe
-- Sigma ID:     f6451de4-df0a-41fa-8d72-b39f54a08db5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_paexec_default_pipe.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '\\PAExec%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/efa17a600b43c897b4b7463cc8541daa1987eeb4/Command%20and%20Control/C2-NamedPipe.md
- https://github.com/poweradminllc/PAExec

---

## PUA - RemCom Default Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `d36f87ea-c403-44d2-aa79-1a0ac7c24456` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1021.002, T1569.002 |
| **Author** | Nikita Nazarov, oscd.community, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_remcom_default_pipe.yml)**

> Detects default RemCom pipe creation

```sql
-- ============================================================
-- Title:        PUA - RemCom Default Named Pipe
-- Sigma ID:     d36f87ea-c403-44d2-aa79-1a0ac7c24456
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1021.002, T1569.002
-- Author:       Nikita Nazarov, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_remcom_default_pipe.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Administrator activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] LIKE '%\\RemCom%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator activity

**References:**
- https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
- https://github.com/kavika13/RemCom

---

## WMI Event Consumer Created Named Pipe

| Field | Value |
|---|---|
| **Sigma ID** | `493fb4ab-cdcc-4c4f-818c-0e363bd1e4bb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_scrcons_wmi_consumer_namedpipe.yml)**

> Detects the WMI Event Consumer service scrcons.exe creating a named pipe

```sql
-- ============================================================
-- Title:        WMI Event Consumer Created Named Pipe
-- Sigma ID:     493fb4ab-cdcc-4c4f-818c-0e363bd1e4bb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1047
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-09-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_scrcons_wmi_consumer_namedpipe.yml
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
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\scrcons.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/RiccardoAncarani/LiquidSnake

---

## Malicious Named Pipe Created

| Field | Value |
|---|---|
| **Sigma ID** | `fe3ac066-98bb-432a-b1e7-a5229cb39d4a` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1055 |
| **Author** | Florian Roth (Nextron Systems), blueteam0ps, elhoim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_susp_malicious_namedpipes.yml)**

> Detects the creation of a named pipe seen used by known APTs or malware.

```sql
-- ============================================================
-- Title:        Malicious Named Pipe Created
-- Sigma ID:     fe3ac066-98bb-432a-b1e7-a5229cb39d4a
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1055
-- Author:       Florian Roth (Nextron Systems), blueteam0ps, elhoim
-- Date:         2017-11-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_susp_malicious_namedpipes.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] IN ('\46a676ab7f179e511e30dd2dc41bd388', '\583da945-62af-10e8-4902-a8f205c72b2e', '\6e7645c4-32c5-4fe3-aabf-e94c2f4370e7', '\9f81f59bc58452127884ce513865ed20', '\adschemerpc', '\ahexec', '\AnonymousPipe', '\bc31a7', '\bc367', '\bizkaz', '\csexecsvc', '\dce_3d', '\e710f28d59aa529d6792ca6ff0ca1b34', '\gruntsvc', '\isapi_dg', '\isapi_dg2', '\isapi_http', '\jaccdpqnvbrrxlaf', '\lsassw', '\NamePipe_MoreWindows', '\pcheap_reuse', '\Posh*', '\rpchlp_3', '\sdlrpc', '\svcctl', '\testPipe', '\winsession'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://securelist.com/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/71275/
- https://securelist.com/faq-the-projectsauron-apt/75533/
- https://web.archive.org/web/20180725233601/https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
- https://www.us-cert.gov/ncas/alerts/TA17-117A
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://thedfirreport.com/2020/06/21/snatch-ransomware/
- https://github.com/RiccardoAncarani/LiquidSnake
- https://www.accenture.com/us-en/blogs/cyber-defense/turla-belugasturgeon-compromises-government-entity
- https://us-cert.cisa.gov/ncas/analysis-reports/ar19-304a
- https://download.bitdefender.com/resources/files/News/CaseStudies/study/115/Bitdefender-Whitepaper-PAC-A4-en-EN1.pdf
- https://unit42.paloaltonetworks.com/emissary-panda-attacks-middle-east-government-sharepoint-servers/
- https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

---

## PsExec Tool Execution From Suspicious Locations - PipeName

| Field | Value |
|---|---|
| **Sigma ID** | `41504465-5e3a-4a5b-a5b4-2a0baadd4463` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe_susp_location.yml)**

> Detects PsExec default pipe creation where the image executed is located in a suspicious location. Which could indicate that the tool is being used in an attack

```sql
-- ============================================================
-- Title:        PsExec Tool Execution From Suspicious Locations - PipeName
-- Sigma ID:     41504465-5e3a-4a5b-a5b4-2a0baadd4463
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe_susp_location.yml
-- Unmapped:     (none)
-- False Pos:    Rare legitimate use of psexec from the locations mentioned above. This will require initial tuning based on your environment.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'pipeName')] AS pipeName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-17-Pipe-Created')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'pipeName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'pipeName')] = '\PSEXESVC')
    AND (procName LIKE '%:\\Users\\Public\\%' OR procName LIKE '%:\\Windows\\Temp\\%' OR procName LIKE '%\\AppData\\Local\\Temp\\%' OR procName LIKE '%\\Desktop\\%' OR procName LIKE '%\\Downloads\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate use of psexec from the locations mentioned above. This will require initial tuning based on your environment.

**References:**
- https://www.jpcert.or.jp/english/pub/sr/ir_research.html
- https://jpcertcc.github.io/ToolAnalysisResultSheet

---
