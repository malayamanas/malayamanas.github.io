# Sigma → FortiSIEM: Windows Application

> 23 rules · Generated 2026-03-17

## Table of Contents

- [Relevant Anti-Virus Signature Keywords In Application Log](#relevant-anti-virus-signature-keywords-in-application-log)
- [LSASS Process Crashed - Application](#lsass-process-crashed-application)
- [Microsoft Malware Protection Engine Crash](#microsoft-malware-protection-engine-crash)
- [Ntdsutil Abuse](#ntdsutil-abuse)
- [Dump Ntds.dit To Suspicious Location](#dump-ntdsdit-to-suspicious-location)
- [Audit CVE Event](#audit-cve-event)
- [Backup Catalog Deleted](#backup-catalog-deleted)
- [Restricted Software Access By SRP](#restricted-software-access-by-srp)
- [Application Uninstalled](#application-uninstalled)
- [MSI Installation From Suspicious Locations](#msi-installation-from-suspicious-locations)
- [MSI Installation From Web](#msi-installation-from-web)
- [Atera Agent Installation](#atera-agent-installation)
- [MSSQL Add Account To Sysadmin Role](#mssql-add-account-to-sysadmin-role)
- [MSSQL Destructive Query](#mssql-destructive-query)
- [MSSQL Disable Audit Settings](#mssql-disable-audit-settings)
- [MSSQL Server Failed Logon](#mssql-server-failed-logon)
- [MSSQL Server Failed Logon From External Network](#mssql-server-failed-logon-from-external-network)
- [MSSQL SPProcoption Set](#mssql-spprocoption-set)
- [MSSQL XPCmdshell Suspicious Execution](#mssql-xpcmdshell-suspicious-execution)
- [MSSQL XPCmdshell Option Change](#mssql-xpcmdshell-option-change)
- [Remote Access Tool - ScreenConnect Command Execution](#remote-access-tool-screenconnect-command-execution)
- [Remote Access Tool - ScreenConnect File Transfer](#remote-access-tool-screenconnect-file-transfer)
- [Microsoft Malware Protection Engine Crash - WER](#microsoft-malware-protection-engine-crash-wer)

## Relevant Anti-Virus Signature Keywords In Application Log

| Field | Value |
|---|---|
| **Sigma ID** | `78bc5783-81d9-4d73-ac97-59f6db4f72a8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1588 |
| **Author** | Florian Roth (Nextron Systems), Arnim Rupp |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/Other/win_av_relevant_match.yml)**

> Detects potentially highly relevant antivirus events in the application log based on known virus signature names and malware keywords.


```sql
-- ============================================================
-- Title:        Relevant Anti-Virus Signature Keywords In Application Log
-- Sigma ID:     78bc5783-81d9-4d73-ac97-59f6db4f72a8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1588
-- Author:       Florian Roth (Nextron Systems), Arnim Rupp
-- Date:         2017-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/Other/win_av_relevant_match.yml
-- Unmapped:     (none)
-- False Pos:    Some software piracy tools (key generators, cracks) are classified as hack tools
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Adfind%' OR rawEventMsg LIKE '%ASP/BackDoor %' OR rawEventMsg LIKE '%ATK/%' OR rawEventMsg LIKE '%Backdoor.ASP%' OR rawEventMsg LIKE '%Backdoor.Cobalt%' OR rawEventMsg LIKE '%Backdoor.JSP%' OR rawEventMsg LIKE '%Backdoor.PHP%' OR rawEventMsg LIKE '%Blackworm%' OR rawEventMsg LIKE '%Brutel%' OR rawEventMsg LIKE '%BruteR%' OR rawEventMsg LIKE '%Chopper%' OR rawEventMsg LIKE '%Cobalt%' OR rawEventMsg LIKE '%COBEACON%' OR rawEventMsg LIKE '%Cometer%' OR rawEventMsg LIKE '%CRYPTES%' OR rawEventMsg LIKE '%Cryptor%' OR rawEventMsg LIKE '%Destructor%' OR rawEventMsg LIKE '%DumpCreds%' OR rawEventMsg LIKE '%Exploit.Script.CVE%' OR rawEventMsg LIKE '%FastReverseProxy%' OR rawEventMsg LIKE '%Filecoder%' OR rawEventMsg LIKE '%GrandCrab %' OR rawEventMsg LIKE '%HackTool%' OR rawEventMsg LIKE '%HKTL%' OR rawEventMsg LIKE '%HTool-%' OR rawEventMsg LIKE '%/HTool%' OR rawEventMsg LIKE '%.HTool%' OR rawEventMsg LIKE '%IISExchgSpawnCMD%' OR rawEventMsg LIKE '%Impacket%' OR rawEventMsg LIKE '%JSP/BackDoor %' OR rawEventMsg LIKE '%Keylogger%' OR rawEventMsg LIKE '%Koadic%' OR rawEventMsg LIKE '%Krypt%' OR rawEventMsg LIKE '%Lazagne%' OR rawEventMsg LIKE '%Metasploit%' OR rawEventMsg LIKE '%Meterpreter%' OR rawEventMsg LIKE '%MeteTool%' OR rawEventMsg LIKE '%mikatz%' OR rawEventMsg LIKE '%Mimikatz%' OR rawEventMsg LIKE '%Mpreter%' OR rawEventMsg LIKE '%MsfShell%' OR rawEventMsg LIKE '%Nighthawk%' OR rawEventMsg LIKE '%Packed.Generic.347%' OR rawEventMsg LIKE '%PentestPowerShell%' OR rawEventMsg LIKE '%Phobos%' OR rawEventMsg LIKE '%PHP/BackDoor %' OR rawEventMsg LIKE '%Potato%' OR rawEventMsg LIKE '%PowerSploit%' OR rawEventMsg LIKE '%PowerSSH%' OR rawEventMsg LIKE '%PshlSpy%' OR rawEventMsg LIKE '%PSWTool%' OR rawEventMsg LIKE '%PWCrack%' OR rawEventMsg LIKE '%PWDump%' OR rawEventMsg LIKE '%Ransom%' OR rawEventMsg LIKE '%Rozena%' OR rawEventMsg LIKE '%Ryzerlo%' OR rawEventMsg LIKE '%Sbelt%' OR rawEventMsg LIKE '%Seatbelt%' OR rawEventMsg LIKE '%SecurityTool %' OR rawEventMsg LIKE '%SharpDump%' OR rawEventMsg LIKE '%Shellcode%' OR rawEventMsg LIKE '%Sliver%' OR rawEventMsg LIKE '%Splinter%' OR rawEventMsg LIKE '%Swrort%' OR rawEventMsg LIKE '%Tescrypt%' OR rawEventMsg LIKE '%TeslaCrypt%' OR rawEventMsg LIKE '%TurtleLoader%' OR rawEventMsg LIKE '%Valyria%' OR rawEventMsg LIKE '%Webshell%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some software piracy tools (key generators, cracks) are classified as hack tools

**References:**
- https://www.virustotal.com/gui/file/13828b390d5f58b002e808c2c4f02fdd920e236cc8015480fa33b6c1a9300e31
- https://www.virustotal.com/gui/file/15b57c1b68cd6ce3c161042e0f3be9f32d78151fe95461eedc59a79fc222c7ed
- https://www.virustotal.com/gui/file/5092b2672b4cb87a8dd1c2e6047b487b95995ad8ed5e9fc217f46b8bfb1b8c01
- https://www.nextron-systems.com/?s=antivirus

---

## LSASS Process Crashed - Application

| Field | Value |
|---|---|
| **Sigma ID** | `a18e0862-127b-43ca-be12-1a542c75c7c5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/application_error/win_application_error_lsass_crash.yml)**

> Detects Windows error reporting events where the process that crashed is LSASS (Local Security Authority Subsystem Service).
This could be the cause of a provoked crash by techniques such as Lsass-Shtinkering to dump credentials.


```sql
-- ============================================================
-- Title:        LSASS Process Crashed - Application
-- Sigma ID:     a18e0862-127b-43ca-be12-1a542c75c7c5
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1003.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/application_error/win_application_error_lsass_crash.yml
-- Unmapped:     AppName, ExceptionCode
-- False Pos:    Rare legitimate crashing of the lsass process
-- ============================================================
-- UNMAPPED_FIELD: AppName
-- UNMAPPED_FIELD: ExceptionCode

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1000')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Application Error')
    AND winEventId = '1000'
    AND rawEventMsg = 'lsass.exe'
    AND rawEventMsg = 'c0000001')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate crashing of the lsass process

**References:**
- https://github.com/deepinstinct/Lsass-Shtinkering
- https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

---

## Microsoft Malware Protection Engine Crash

| Field | Value |
|---|---|
| **Sigma ID** | `545a5da6-f103-4919-a519-e9aec1026ee4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1211, T1562.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/application_error/win_application_error_msmpeng_crash.yml)**

> This rule detects a suspicious crash of the Microsoft Malware Protection Engine

```sql
-- ============================================================
-- Title:        Microsoft Malware Protection Engine Crash
-- Sigma ID:     545a5da6-f103-4919-a519-e9aec1026ee4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1211, T1562.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/application_error/win_application_error_msmpeng_crash.yml
-- Unmapped:     (none)
-- False Pos:    MsMpEng might crash if the "C:\" partition is full
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1000')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Application Error')
    AND winEventId = '1000'
    AND rawEventMsg LIKE '%MsMpEng.exe%' AND rawEventMsg LIKE '%mpengine.dll%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** MsMpEng might crash if the "C:\" partition is full

**References:**
- https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
- https://technet.microsoft.com/en-us/library/security/4022344

---

## Ntdsutil Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `e6e88853-5f20-4c4a-8d26-cd469fd8d31f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse.yml)**

> Detects potential abuse of ntdsutil to dump ntds.dit database

```sql
-- ============================================================
-- Title:        Ntdsutil Abuse
-- Sigma ID:     e6e88853-5f20-4c4a-8d26-cd469fd8d31f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate backup operation/creating shadow copies
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-216', 'Win-Application-325', 'Win-Application-326', 'Win-Application-327')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'ESENT')
    AND winEventId IN ('216', '325', '326', '327')
    AND rawEventMsg LIKE '%ntds.dit%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate backup operation/creating shadow copies

**References:**
- https://twitter.com/mgreen27/status/1558223256704122882
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj574207(v=ws.11)

---

## Dump Ntds.dit To Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `94dc4390-6b7c-4784-8ffc-335334404650` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse_susp_location.yml)**

> Detects potential abuse of ntdsutil to dump ntds.dit database to a suspicious location

```sql
-- ============================================================
-- Title:        Dump Ntds.dit To Suspicious Location
-- Sigma ID:     94dc4390-6b7c-4784-8ffc-335334404650
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse_susp_location.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate backup operation/creating shadow copies
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-325')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%:\\ntds.dit%' OR rawEventMsg LIKE '%\\Appdata\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\Downloads\\%' OR rawEventMsg LIKE '%\\Perflogs\\%' OR rawEventMsg LIKE '%\\Temp\\%' OR rawEventMsg LIKE '%\\Users\\Public\\%')
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'ESENT')
    AND winEventId = '325'
    AND rawEventMsg LIKE '%ntds.dit%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate backup operation/creating shadow copies

**References:**
- https://twitter.com/mgreen27/status/1558223256704122882
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj574207(v=ws.11)

---

## Audit CVE Event

| Field | Value |
|---|---|
| **Sigma ID** | `48d91a3a-2363-43ba-a456-ca71ac3da5c2` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution, impact |
| **MITRE Techniques** | T1203, T1068, T1211, T1212, T1210, T1499.004 |
| **Author** | Florian Roth (Nextron Systems), Zach Mathis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml)**

> Detects events generated by user-mode applications when they call the CveEventWrite API when a known vulnerability is trying to be exploited.
MS started using this log in Jan. 2020 with CVE-2020-0601 (a Windows CryptoAPI vulnerability.
Unfortunately, that is about the only instance of CVEs being written to this log.


```sql
-- ============================================================
-- Title:        Audit CVE Event
-- Sigma ID:     48d91a3a-2363-43ba-a456-ca71ac3da5c2
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        execution, impact | T1203, T1068, T1211, T1212, T1210, T1499.004
-- Author:       Florian Roth (Nextron Systems), Zach Mathis
-- Date:         2020-01-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] IN ('Microsoft-Windows-Audit-CVE', 'Audit-CVE'))
    AND winEventId = '1')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/VM_vivisector/status/1217190929330655232
- https://twitter.com/DidierStevens/status/1217533958096924676
- https://twitter.com/FlemmingRiis/status/1217147415482060800
- https://www.youtube.com/watch?v=ebmW42YYveI
- https://nullsec.us/windows-event-log-audit-cve/

---

## Backup Catalog Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `9703792d-fd9a-456d-a672-ff92efe4806a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.004 |
| **Author** | Florian Roth (Nextron Systems), Tom U. @c_APT_ure (collection) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/microsoft_windows_backup/win_susp_backup_delete.yml)**

> Detects backup catalog deletions

```sql
-- ============================================================
-- Title:        Backup Catalog Deleted
-- Sigma ID:     9703792d-fd9a-456d-a672-ff92efe4806a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.004
-- Author:       Florian Roth (Nextron Systems), Tom U. @c_APT_ure (collection)
-- Date:         2017-05-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/microsoft_windows_backup/win_susp_backup_delete.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-524')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '524'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Backup'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx
- https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100

---

## Restricted Software Access By SRP

| Field | Value |
|---|---|
| **Sigma ID** | `b4c8da4a-1c12-46b0-8a2b-0a8521d03442` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1072 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/microsoft_windows_software_restriction_policies/win_software_restriction_policies_block.yml)**

> Detects restricted access to applications by the Software Restriction Policies (SRP) policy

```sql
-- ============================================================
-- Title:        Restricted Software Access By SRP
-- Sigma ID:     b4c8da4a-1c12-46b0-8a2b-0a8521d03442
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1072
-- Author:       frack113
-- Date:         2023-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/microsoft_windows_software_restriction_policies/win_software_restriction_policies_block.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-865', 'Win-Application-866', 'Win-Application-867', 'Win-Application-868', 'Win-Application-882')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-SoftwareRestrictionPolicies')
    AND winEventId IN ('865', '866', '867', '868', '882'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies
- https://github.com/nasbench/EVTX-ETW-Resources/blob/7a806a148b3d9d381193d4a80356016e6e8b1ee8/ETWEventsList/CSV/Windows11/22H2/W11_22H2_Pro_20220920_22621.382/Providers/Microsoft-Windows-AppXDeployment-Server.csv

---

## Application Uninstalled

| Field | Value |
|---|---|
| **Sigma ID** | `570ae5ec-33dc-427c-b815-db86228ad43e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1489 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_builtin_remove_application.yml)**

> An application has been removed. Check if it is critical.

```sql
-- ============================================================
-- Title:        Application Uninstalled
-- Sigma ID:     570ae5ec-33dc-427c-b815-db86228ad43e
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1489
-- Author:       frack113
-- Date:         2022-01-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_builtin_remove_application.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1034', 'Win-Application-11724')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'MsiInstaller')
    AND winEventId IN ('1034', '11724'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nasbench/EVTX-ETW-Resources/blob/f1b010ce0ee1b71e3024180de1a3e67f99701fe4/ETWProvidersManifests/Windows11/22H2/W11_22H2_Pro_20221220_22621.963/WEPExplorer/Microsoft-Windows-MsiServer.xml
- https://learn.microsoft.com/en-us/windows/win32/msi/event-logging

---

## MSI Installation From Suspicious Locations

| Field | Value |
|---|---|
| **Sigma ID** | `c7c8aa1c-5aff-408e-828b-998e3620b341` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_msi_install_from_susp_locations.yml)**

> Detects MSI package installation from suspicious locations

```sql
-- ============================================================
-- Title:        MSI Installation From Suspicious Locations
-- Sigma ID:     c7c8aa1c-5aff-408e-828b-998e3620b341
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_msi_install_from_susp_locations.yml
-- Unmapped:     (none)
-- False Pos:    False positives may occur if you allow installation from folders such as the desktop, the public folder or remote shares. A baseline is required before production use.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1040', 'Win-Application-1042')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'MsiInstaller')
    AND winEventId IN ('1040', '1042')
    AND (rawEventMsg LIKE '%:\\Windows\\TEMP\\%' OR rawEventMsg LIKE '%\\\\\\\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\PerfLogs\\%' OR rawEventMsg LIKE '%\\Users\\Public\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives may occur if you allow installation from folders such as the desktop, the public folder or remote shares. A baseline is required before production use.

**References:**
- https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html

---

## MSI Installation From Web

| Field | Value |
|---|---|
| **Sigma ID** | `5594e67a-7f92-4a04-b65d-1a42fd824a60` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218, T1218.007 |
| **Author** | Stamatis Chatzimangou |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_msi_install_from_web.yml)**

> Detects installation of a remote msi file from web.

```sql
-- ============================================================
-- Title:        MSI Installation From Web
-- Sigma ID:     5594e67a-7f92-4a04-b65d-1a42fd824a60
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218, T1218.007
-- Author:       Stamatis Chatzimangou
-- Date:         2022-10-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_msi_install_from_web.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1040', 'Win-Application-1042')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'MsiInstaller')
    AND winEventId IN ('1040', '1042')
    AND rawEventMsg LIKE '%://%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/_st0pp3r_/status/1583922009842802689

---

## Atera Agent Installation

| Field | Value |
|---|---|
| **Sigma ID** | `87261fb2-69d0-42fe-b9de-88c6b5f65a43` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_software_atera_rmm_agent_install.yml)**

> Detects successful installation of Atera Remote Monitoring & Management (RMM) agent as recently found to be used by Conti operators

```sql
-- ============================================================
-- Title:        Atera Agent Installation
-- Sigma ID:     87261fb2-69d0-42fe-b9de-88c6b5f65a43
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Bhabesh Raj
-- Date:         2021-09-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/msiinstaller/win_software_atera_rmm_agent_install.yml
-- Unmapped:     Message
-- False Pos:    Legitimate Atera agent installation
-- ============================================================
-- UNMAPPED_FIELD: Message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1033')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '1033'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'MsiInstaller')
    AND rawEventMsg LIKE '%AteraAgent%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Atera agent installation

**References:**
- https://www.advintel.io/post/secret-backdoor-behind-conti-ransomware-operation-introducing-atera-agent

---

## MSSQL Add Account To Sysadmin Role

| Field | Value |
|---|---|
| **Sigma ID** | `08200f85-2678-463e-9c32-88dce2f073d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_add_sysadmin_account.yml)**

> Detects when an attacker tries to backdoor the MSSQL server by adding a backdoor account to the sysadmin fixed server role

```sql
-- ============================================================
-- Title:        MSSQL Add Account To Sysadmin Role
-- Sigma ID:     08200f85-2678-463e-9c32-88dce2f073d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_add_sysadmin_account.yml
-- Unmapped:     (none)
-- False Pos:    Rare legitimate administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-33205')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '33205'
    AND rawEventMsg LIKE '%object\_name:sysadmin%' AND rawEventMsg LIKE '%statement:alter server role [sysadmin] add member %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate administrative activity

**References:**
- https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/

---

## MSSQL Destructive Query

| Field | Value |
|---|---|
| **Sigma ID** | `00321fee-ca72-4cce-b011-5415af3b9960` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration, impact |
| **MITRE Techniques** | T1485 |
| **Author** | Daniel Degasperi '@d4ns4n_' |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_destructive_query.yml)**

> Detects the invocation of MS SQL transactions that are destructive towards table or database data, such as "DROP TABLE" or "DROP DATABASE".


```sql
-- ============================================================
-- Title:        MSSQL Destructive Query
-- Sigma ID:     00321fee-ca72-4cce-b011-5415af3b9960
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        exfiltration, impact | T1485
-- Author:       Daniel Degasperi '@d4ns4n_'
-- Date:         2025-06-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_destructive_query.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate transaction from a sysadmin.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-33205')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'MSSQLSERVER$AUDIT')
    AND winEventId = '33205'
    AND (rawEventMsg LIKE '%statement:TRUNCATE TABLE%' OR rawEventMsg LIKE '%statement:DROP TABLE%' OR rawEventMsg LIKE '%statement:DROP DATABASE%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate transaction from a sysadmin.

**References:**
- https://learn.microsoft.com/en-us/sql/t-sql/statements/drop-table-transact-sql?view=sql-server-ver16
- https://learn.microsoft.com/en-us/sql/t-sql/statements/drop-database-transact-sql?view=sql-server-ver16
- https://learn.microsoft.com/en-us/sql/t-sql/statements/truncate-table-transact-sql?view=sql-server-ver16

---

## MSSQL Disable Audit Settings

| Field | Value |
|---|---|
| **Sigma ID** | `350dfb37-3706-4cdc-9e2e-5e24bc3a46df` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_disable_audit_settings.yml)**

> Detects when an attacker calls the "ALTER SERVER AUDIT" or "DROP SERVER AUDIT" transaction in order to delete or disable audit logs on the server

```sql
-- ============================================================
-- Title:        MSSQL Disable Audit Settings
-- Sigma ID:     350dfb37-3706-4cdc-9e2e-5e24bc3a46df
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_disable_audit_settings.yml
-- Unmapped:     (none)
-- False Pos:    This event should only fire when an administrator is modifying the audit policy. Which should be a rare occurrence once it's set up
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-33205')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '33205'
    AND (rawEventMsg LIKE '%statement:ALTER SERVER AUDIT%' OR rawEventMsg LIKE '%statement:DROP SERVER AUDIT%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This event should only fire when an administrator is modifying the audit policy. Which should be a rare occurrence once it's set up

**References:**
- https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/
- https://learn.microsoft.com/en-us/sql/t-sql/statements/drop-server-audit-transact-sql?view=sql-server-ver16
- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-audit-transact-sql?view=sql-server-ver16

---

## MSSQL Server Failed Logon

| Field | Value |
|---|---|
| **Sigma ID** | `218d2855-2bba-4f61-9c85-81d0ea63ac71` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1110 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), j4son |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon.yml)**

> Detects failed logon attempts from clients to MSSQL server.

```sql
-- ============================================================
-- Title:        MSSQL Server Failed Logon
-- Sigma ID:     218d2855-2bba-4f61-9c85-81d0ea63ac71
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1110
-- Author:       Nasreddine Bencherchali (Nextron Systems), j4son
-- Date:         2023-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon.yml
-- Unmapped:     (none)
-- False Pos:    This event could stem from users changing an account's password that's used to authenticate via a job or an automated process. Investigate the source of such events and mitigate them
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-18456')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '18456')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This event could stem from users changing an account's password that's used to authenticate via a job or an automated process. Investigate the source of such events and mitigate them

**References:**
- https://cybersecthreat.com/2020/07/08/enable-mssql-authentication-log-to-eventlog/
- https://www.experts-exchange.com/questions/27800944/EventID-18456-Failed-to-open-the-explicitly-specified-database.html

---

## MSSQL Server Failed Logon From External Network

| Field | Value |
|---|---|
| **Sigma ID** | `ebfe73c2-5bc9-4ed9-aaa8-8b54b2b4777d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1110 |
| **Author** | j4son |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon_from_external_network.yml)**

> Detects failed logon attempts from clients with external network IP to an MSSQL server. This can be a sign of a bruteforce attack.

```sql
-- ============================================================
-- Title:        MSSQL Server Failed Logon From External Network
-- Sigma ID:     ebfe73c2-5bc9-4ed9-aaa8-8b54b2b4777d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1110
-- Author:       j4son
-- Date:         2023-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon_from_external_network.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-18456')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '18456')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cybersecthreat.com/2020/07/08/enable-mssql-authentication-log-to-eventlog/
- https://www.experts-exchange.com/questions/27800944/EventID-18456-Failed-to-open-the-explicitly-specified-database.html

---

## MSSQL SPProcoption Set

| Field | Value |
|---|---|
| **Sigma ID** | `b3d57a5c-c92e-4b48-9a79-5f124b7cf964` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_sp_procoption_set.yml)**

> Detects when the a stored procedure is set or cleared for automatic execution in MSSQL. A stored procedure that is set to automatic execution runs every time an instance of SQL Server is started

```sql
-- ============================================================
-- Title:        MSSQL SPProcoption Set
-- Sigma ID:     b3d57a5c-c92e-4b48-9a79-5f124b7cf964
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_sp_procoption_set.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the feature by administrators (rare)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-33205')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '33205'
    AND rawEventMsg LIKE '%object\_name:sp\_procoption%' AND rawEventMsg LIKE '%statement:EXEC%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the feature by administrators (rare)

**References:**
- https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/
- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-procoption-transact-sql?view=sql-server-ver16

---

## MSSQL XPCmdshell Suspicious Execution

| Field | Value |
|---|---|
| **Sigma ID** | `7f103213-a04e-4d59-8261-213dddf22314` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log.yml)**

> Detects when the MSSQL "xp_cmdshell" stored procedure is used to execute commands

```sql
-- ============================================================
-- Title:        MSSQL XPCmdshell Suspicious Execution
-- Sigma ID:     7f103213-a04e-4d59-8261-213dddf22314
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-33205')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '33205'
    AND rawEventMsg LIKE '%object\_name:xp\_cmdshell%' AND rawEventMsg LIKE '%statement:EXEC%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/
- https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/

---

## MSSQL XPCmdshell Option Change

| Field | Value |
|---|---|
| **Sigma ID** | `d08dd86f-681e-4a00-a92c-1db218754417` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml)**

> Detects when the MSSQL "xp_cmdshell" stored procedure setting is changed.


```sql
-- ============================================================
-- Title:        MSSQL XPCmdshell Option Change
-- Sigma ID:     d08dd86f-681e-4a00-a92c-1db218754417
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate enable/disable of the setting; Note that since the event contain the change for both values. This means that this will trigger on both enable and disable
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-15457')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] LIKE '%MSSQL%')
    AND winEventId = '15457'
    AND rawEventMsg LIKE '%xp\_cmdshell%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate enable/disable of the setting; Note that since the event contain the change for both values. This means that this will trigger on both enable and disable

**References:**
- https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/
- https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/

---

## Remote Access Tool - ScreenConnect Command Execution

| Field | Value |
|---|---|
| **Sigma ID** | `076ebe48-cc05-4d8f-9d41-89245cd93a14` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.003 |
| **Author** | Ali Alwashali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_command_exec.yml)**

> Detects command execution via ScreenConnect RMM

```sql
-- ============================================================
-- Title:        Remote Access Tool - ScreenConnect Command Execution
-- Sigma ID:     076ebe48-cc05-4d8f-9d41-89245cd93a14
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1059.003
-- Author:       Ali Alwashali
-- Date:         2023-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_command_exec.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of ScreenConnect
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-200')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'ScreenConnect')
    AND winEventId = '200'
    AND rawEventMsg LIKE '%Executed command of length%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of ScreenConnect

**References:**
- https://www.huntandhackett.com/blog/revil-the-usage-of-legitimate-remote-admin-tooling
- https://github.com/SigmaHQ/sigma/pull/4467

---

## Remote Access Tool - ScreenConnect File Transfer

| Field | Value |
|---|---|
| **Sigma ID** | `5d19eb78-5b5b-4ef2-a9f0-4bfa94d58a13` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.003 |
| **Author** | Ali Alwashali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_file_transfer.yml)**

> Detects file being transferred via ScreenConnect RMM

```sql
-- ============================================================
-- Title:        Remote Access Tool - ScreenConnect File Transfer
-- Sigma ID:     5d19eb78-5b5b-4ef2-a9f0-4bfa94d58a13
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1059.003
-- Author:       Ali Alwashali
-- Date:         2023-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_file_transfer.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of ScreenConnect
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-201')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'ScreenConnect')
    AND winEventId = '201'
    AND rawEventMsg LIKE '%Transferred files with action%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of ScreenConnect

**References:**
- https://www.huntandhackett.com/blog/revil-the-usage-of-legitimate-remote-admin-tooling
- https://github.com/SigmaHQ/sigma/pull/4467

---

## Microsoft Malware Protection Engine Crash - WER

| Field | Value |
|---|---|
| **Sigma ID** | `6c82cf5c-090d-4d57-9188-533577631108` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1211, T1562.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/windows_error_reporting/win_application_msmpeng_crash_wer.yml)**

> This rule detects a suspicious crash of the Microsoft Malware Protection Engine

```sql
-- ============================================================
-- Title:        Microsoft Malware Protection Engine Crash - WER
-- Sigma ID:     6c82cf5c-090d-4d57-9188-533577631108
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1211, T1562.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/application/windows_error_reporting/win_application_msmpeng_crash_wer.yml
-- Unmapped:     (none)
-- False Pos:    MsMpEng might crash if the "C:\" partition is full
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Application-1001')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Windows Error Reporting')
    AND winEventId = '1001'
    AND rawEventMsg LIKE '%MsMpEng.exe%' AND rawEventMsg LIKE '%mpengine.dll%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** MsMpEng might crash if the "C:\" partition is full

**References:**
- https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
- https://technet.microsoft.com/en-us/library/security/4022344

---
