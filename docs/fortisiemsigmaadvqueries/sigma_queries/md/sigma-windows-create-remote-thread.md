# Sigma → FortiSIEM: Windows Create Remote Thread

> 11 rules · Generated 2026-03-17

## Table of Contents

- [HackTool - CACTUSTORCH Remote Thread Creation](#hacktool-cactustorch-remote-thread-creation)
- [HackTool - Potential CobaltStrike Process Injection](#hacktool-potential-cobaltstrike-process-injection)
- [Remote Thread Created In KeePass.EXE](#remote-thread-created-in-keepassexe)
- [Remote Thread Creation In Mstsc.Exe From Suspicious Location](#remote-thread-creation-in-mstscexe-from-suspicious-location)
- [Potential Credential Dumping Attempt Via PowerShell Remote Thread](#potential-credential-dumping-attempt-via-powershell-remote-thread)
- [Remote Thread Creation Via PowerShell In Uncommon Target](#remote-thread-creation-via-powershell-in-uncommon-target)
- [Password Dumper Remote Thread in LSASS](#password-dumper-remote-thread-in-lsass)
- [Rare Remote Thread Creation By Uncommon Source Image](#rare-remote-thread-creation-by-uncommon-source-image)
- [Remote Thread Creation By Uncommon Source Image](#remote-thread-creation-by-uncommon-source-image)
- [Remote Thread Creation In Uncommon Target Image](#remote-thread-creation-in-uncommon-target-image)
- [Remote Thread Creation Ttdinject.exe Proxy](#remote-thread-creation-ttdinjectexe-proxy)

## HackTool - CACTUSTORCH Remote Thread Creation

| Field | Value |
|---|---|
| **Sigma ID** | `2e4e488a-6164-4811-9ea1-f960c7359c40` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1055.012, T1059.005, T1059.007, T1218.005 |
| **Author** | @SBousseaden (detection), Thomas Patzke (rule) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_hktl_cactustorch.yml)**

> Detects remote thread creation from CACTUSTORCH as described in references.

```sql
-- ============================================================
-- Title:        HackTool - CACTUSTORCH Remote Thread Creation
-- Sigma ID:     2e4e488a-6164-4811-9ea1-f960c7359c40
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1055.012, T1059.005, T1059.007, T1218.005
-- Author:       @SBousseaden (detection), Thomas Patzke (rule)
-- Date:         2019-02-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_hktl_cactustorch.yml
-- Unmapped:     SourceImage, TargetImage, StartModule
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: StartModule

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\System32\\cscript.exe' OR rawEventMsg LIKE '%\\System32\\wscript.exe' OR rawEventMsg LIKE '%\\System32\\mshta.exe' OR rawEventMsg LIKE '%\\winword.exe' OR rawEventMsg LIKE '%\\excel.exe')
    AND rawEventMsg LIKE '%\\SysWOW64\\%'
    AND rawEventMsg = 'None')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1090588499517079552
- https://github.com/mdsecactivebreach/CACTUSTORCH

---

## HackTool - Potential CobaltStrike Process Injection

| Field | Value |
|---|---|
| **Sigma ID** | `6309645e-122d-4c5b-bb2b-22e4f9c2fa42` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1055.001 |
| **Author** | Olaf Hartong, Florian Roth (Nextron Systems), Aleksey Potapov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_hktl_cobaltstrike.yml)**

> Detects a potential remote threat creation with certain characteristics which are typical for Cobalt Strike beacons

```sql
-- ============================================================
-- Title:        HackTool - Potential CobaltStrike Process Injection
-- Sigma ID:     6309645e-122d-4c5b-bb2b-22e4f9c2fa42
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1055.001
-- Author:       Olaf Hartong, Florian Roth (Nextron Systems), Aleksey Potapov, oscd.community
-- Date:         2018-11-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_hktl_cobaltstrike.yml
-- Unmapped:     StartAddress
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: StartAddress

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%0B80' OR rawEventMsg LIKE '%0C7C' OR rawEventMsg LIKE '%0C88')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
- https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/

---

## Remote Thread Created In KeePass.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `77564cc2-7382-438b-a7f6-395c2ae53b9a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1555.005 |
| **Author** | Timon Hackenjos |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_keepass.yml)**

> Detects remote thread creation in "KeePass.exe" which could indicates potential password dumping activity

```sql
-- ============================================================
-- Title:        Remote Thread Created In KeePass.EXE
-- Sigma ID:     77564cc2-7382-438b-a7f6-395c2ae53b9a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1555.005
-- Author:       Timon Hackenjos
-- Date:         2022-04-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_keepass.yml
-- Unmapped:     TargetImage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%\\KeePass.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisa.gov/uscert/ncas/alerts/aa20-259a
- https://github.com/denandz/KeeFarce
- https://github.com/GhostPack/KeeThief

---

## Remote Thread Creation In Mstsc.Exe From Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `c0aac16a-b1e7-4330-bab0-3c27bb4987c7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_mstsc_susp_location.yml)**

> Detects remote thread creation in the "mstsc.exe" process by a process located in a potentially suspicious location.
This technique is often used by attackers in order to hook some APIs used by DLLs loaded by "mstsc.exe" during RDP authentications in order to steal credentials.


```sql
-- ============================================================
-- Title:        Remote Thread Creation In Mstsc.Exe From Suspicious Location
-- Sigma ID:     c0aac16a-b1e7-4330-bab0-3c27bb4987c7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_mstsc_susp_location.yml
-- Unmapped:     TargetImage, SourceImage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: SourceImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\mstsc.exe'
    AND (rawEventMsg LIKE '%:\\Temp\\%' OR rawEventMsg LIKE '%:\\Users\\Public\\%' OR rawEventMsg LIKE '%:\\Windows\\PerfLogs\\%' OR rawEventMsg LIKE '%:\\Windows\\Tasks\\%' OR rawEventMsg LIKE '%:\\Windows\\Temp\\%' OR rawEventMsg LIKE '%\\AppData\\Local\\Temp\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/S12cybersecurity/RDPCredentialStealer/blob/1b8947cdd065a06c1b62e80967d3c7af895fcfed/APIHookInjectorBin/APIHookInjectorBin/Inject.h#L25

---

## Potential Credential Dumping Attempt Via PowerShell Remote Thread

| Field | Value |
|---|---|
| **Sigma ID** | `fb656378-f909-47c1-8747-278bf09f4f4f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | oscd.community, Natalia Shornikova |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_powershell_lsass.yml)**

> Detects remote thread creation by PowerShell processes into "lsass.exe"

```sql
-- ============================================================
-- Title:        Potential Credential Dumping Attempt Via PowerShell Remote Thread
-- Sigma ID:     fb656378-f909-47c1-8747-278bf09f4f4f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       oscd.community, Natalia Shornikova
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_powershell_lsass.yml
-- Unmapped:     SourceImage, TargetImage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: TargetImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\powershell.exe' OR rawEventMsg LIKE '%\\pwsh.exe')
    AND rawEventMsg LIKE '%\\lsass.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

---

## Remote Thread Creation Via PowerShell In Uncommon Target

| Field | Value |
|---|---|
| **Sigma ID** | `99b97608-3e21-4bfe-8217-2a127c396a0e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1218.011, T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_powershell_susp_targets.yml)**

> Detects the creation of a remote thread from a Powershell process in an uncommon target process

```sql
-- ============================================================
-- Title:        Remote Thread Creation Via PowerShell In Uncommon Target
-- Sigma ID:     99b97608-3e21-4bfe-8217-2a127c396a0e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1218.011, T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-06-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_powershell_susp_targets.yml
-- Unmapped:     SourceImage, TargetImage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: TargetImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\powershell.exe' OR rawEventMsg LIKE '%\\pwsh.exe')
    AND (rawEventMsg LIKE '%\\rundll32.exe' OR rawEventMsg LIKE '%\\regsvr32.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html

---

## Password Dumper Remote Thread in LSASS

| Field | Value |
|---|---|
| **Sigma ID** | `f239b326-2f41-4d6b-9dfa-c846a60ef505` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml)**

> Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage.
The process in field Process is the malicious program. A single execution can lead to hundreds of events.


```sql
-- ============================================================
-- Title:        Password Dumper Remote Thread in LSASS
-- Sigma ID:     f239b326-2f41-4d6b-9dfa-c846a60ef505
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1003.001
-- Author:       Thomas Patzke
-- Date:         2017-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml
-- Unmapped:     TargetImage, StartModule
-- False Pos:    Antivirus products
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: StartModule

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg = '')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Antivirus products

**References:**
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm

---

## Rare Remote Thread Creation By Uncommon Source Image

| Field | Value |
|---|---|
| **Sigma ID** | `02d1d718-dd13-41af-989d-ea85c7fab93f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1055 |
| **Author** | Perez Diego (@darkquassar), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_relevant_source_image.yml)**

> Detects uncommon processes creating remote threads.

```sql
-- ============================================================
-- Title:        Rare Remote Thread Creation By Uncommon Source Image
-- Sigma ID:     02d1d718-dd13-41af-989d-ea85c7fab93f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1055
-- Author:       Perez Diego (@darkquassar), oscd.community
-- Date:         2019-10-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_relevant_source_image.yml
-- Unmapped:     SourceImage
-- False Pos:    This rule is best put in testing first in order to create a baseline that reflects the data in your environment.
-- ============================================================
-- UNMAPPED_FIELD: SourceImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\bash.exe' OR rawEventMsg LIKE '%\\cscript.exe' OR rawEventMsg LIKE '%\\cvtres.exe' OR rawEventMsg LIKE '%\\defrag.exe' OR rawEventMsg LIKE '%\\dialer.exe' OR rawEventMsg LIKE '%\\dnx.exe' OR rawEventMsg LIKE '%\\esentutl.exe' OR rawEventMsg LIKE '%\\excel.exe' OR rawEventMsg LIKE '%\\expand.exe' OR rawEventMsg LIKE '%\\find.exe' OR rawEventMsg LIKE '%\\findstr.exe' OR rawEventMsg LIKE '%\\forfiles.exe' OR rawEventMsg LIKE '%\\gpupdate.exe' OR rawEventMsg LIKE '%\\hh.exe' OR rawEventMsg LIKE '%\\installutil.exe' OR rawEventMsg LIKE '%\\lync.exe' OR rawEventMsg LIKE '%\\makecab.exe' OR rawEventMsg LIKE '%\\mDNSResponder.exe' OR rawEventMsg LIKE '%\\monitoringhost.exe' OR rawEventMsg LIKE '%\\msbuild.exe' OR rawEventMsg LIKE '%\\mshta.exe' OR rawEventMsg LIKE '%\\mspaint.exe' OR rawEventMsg LIKE '%\\outlook.exe' OR rawEventMsg LIKE '%\\ping.exe' OR rawEventMsg LIKE '%\\provtool.exe' OR rawEventMsg LIKE '%\\python.exe' OR rawEventMsg LIKE '%\\regsvr32.exe' OR rawEventMsg LIKE '%\\robocopy.exe' OR rawEventMsg LIKE '%\\runonce.exe' OR rawEventMsg LIKE '%\\sapcimc.exe' OR rawEventMsg LIKE '%\\smartscreen.exe' OR rawEventMsg LIKE '%\\spoolsv.exe' OR rawEventMsg LIKE '%\\tstheme.exe' OR rawEventMsg LIKE '%\\userinit.exe' OR rawEventMsg LIKE '%\\vssadmin.exe' OR rawEventMsg LIKE '%\\vssvc.exe' OR rawEventMsg LIKE '%\\w3wp.exe' OR rawEventMsg LIKE '%\\winscp.exe' OR rawEventMsg LIKE '%\\winword.exe' OR rawEventMsg LIKE '%\\wmic.exe' OR rawEventMsg LIKE '%\\wscript.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This rule is best put in testing first in order to create a baseline that reflects the data in your environment.

**References:**
- Personal research, statistical analysis
- https://lolbas-project.github.io

---

## Remote Thread Creation By Uncommon Source Image

| Field | Value |
|---|---|
| **Sigma ID** | `66d31e5f-52d6-40a4-9615-002d3789a119` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1055 |
| **Author** | Perez Diego (@darkquassar), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_uncommon_source_image.yml)**

> Detects uncommon processes creating remote threads.

```sql
-- ============================================================
-- Title:        Remote Thread Creation By Uncommon Source Image
-- Sigma ID:     66d31e5f-52d6-40a4-9615-002d3789a119
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1055
-- Author:       Perez Diego (@darkquassar), oscd.community
-- Date:         2019-10-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_uncommon_source_image.yml
-- Unmapped:     SourceImage
-- False Pos:    This rule is best put in testing first in order to create a baseline that reflects the data in your environment.
-- ============================================================
-- UNMAPPED_FIELD: SourceImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\explorer.exe' OR rawEventMsg LIKE '%\\iexplore.exe' OR rawEventMsg LIKE '%\\msiexec.exe' OR rawEventMsg LIKE '%\\powerpnt.exe' OR rawEventMsg LIKE '%\\schtasks.exe' OR rawEventMsg LIKE '%\\winlogon.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This rule is best put in testing first in order to create a baseline that reflects the data in your environment.

**References:**
- Personal research, statistical analysis
- https://lolbas-project.github.io

---

## Remote Thread Creation In Uncommon Target Image

| Field | Value |
|---|---|
| **Sigma ID** | `a1a144b7-5c9b-4853-a559-2172be8d4a03` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1055.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_uncommon_target_image.yml)**

> Detects uncommon target processes for remote thread creation

```sql
-- ============================================================
-- Title:        Remote Thread Creation In Uncommon Target Image
-- Sigma ID:     a1a144b7-5c9b-4853-a559-2172be8d4a03
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1055.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_susp_uncommon_target_image.yml
-- Unmapped:     TargetImage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\calc.exe' OR rawEventMsg LIKE '%\\calculator.exe' OR rawEventMsg LIKE '%\\mspaint.exe' OR rawEventMsg LIKE '%\\notepad.exe' OR rawEventMsg LIKE '%\\ping.exe' OR rawEventMsg LIKE '%\\sethc.exe' OR rawEventMsg LIKE '%\\spoolsv.exe' OR rawEventMsg LIKE '%\\wordpad.exe' OR rawEventMsg LIKE '%\\write.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20220319032520/https://blog.redbluepurple.io/offensive-research/bypassing-injection-detection

---

## Remote Thread Creation Ttdinject.exe Proxy

| Field | Value |
|---|---|
| **Sigma ID** | `c15e99a3-c474-48ab-b9a7-84549a7a9d16` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1127 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_ttdinjec.yml)**

> Detects a remote thread creation of Ttdinject.exe used as proxy

```sql
-- ============================================================
-- Title:        Remote Thread Creation Ttdinject.exe Proxy
-- Sigma ID:     c15e99a3-c474-48ab-b9a7-84549a7a9d16
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1127
-- Author:       frack113
-- Date:         2022-05-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/create_remote_thread/create_remote_thread_win_ttdinjec.yml
-- Unmapped:     SourceImage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SourceImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-8-Create-Remote-Thread')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%\\ttdinject.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/

---
