# Sigma → FortiSIEM: Windows Process Access

> 23 rules · Generated 2026-03-17

## Table of Contents

- [CMSTP Execution Process Access](#cmstp-execution-process-access)
- [HackTool - CobaltStrike BOF Injection Pattern](#hacktool-cobaltstrike-bof-injection-pattern)
- [HackTool - Generic Process Access](#hacktool-generic-process-access)
- [HackTool - HandleKatz Duplicating LSASS Handle](#hacktool-handlekatz-duplicating-lsass-handle)
- [HackTool - LittleCorporal Generated Maldoc Injection](#hacktool-littlecorporal-generated-maldoc-injection)
- [HackTool - SysmonEnte Execution](#hacktool-sysmonente-execution)
- [Lsass Memory Dump via Comsvcs DLL](#lsass-memory-dump-via-comsvcs-dll)
- [LSASS Memory Access by Tool With Dump Keyword In Name](#lsass-memory-access-by-tool-with-dump-keyword-in-name)
- [Potential Credential Dumping Activity Via LSASS](#potential-credential-dumping-activity-via-lsass)
- [Credential Dumping Activity By Python Based Tool](#credential-dumping-activity-by-python-based-tool)
- [Remote LSASS Process Access Through Windows Remote Management](#remote-lsass-process-access-through-windows-remote-management)
- [Suspicious LSASS Access Via MalSecLogon](#suspicious-lsass-access-via-malseclogon)
- [Potentially Suspicious GrantedAccess Flags On LSASS](#potentially-suspicious-grantedaccess-flags-on-lsass)
- [Credential Dumping Attempt Via WerFault](#credential-dumping-attempt-via-werfault)
- [LSASS Access From Potentially White-Listed Processes](#lsass-access-from-potentially-white-listed-processes)
- [Uncommon Process Access Rights For Target Image](#uncommon-process-access-rights-for-target-image)
- [Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs](#suspicious-process-access-to-lsass-with-dbgcoredbghelp-dlls)
- [Potential Direct Syscall of NtOpenProcess](#potential-direct-syscall-of-ntopenprocess)
- [Credential Dumping Attempt Via Svchost](#credential-dumping-attempt-via-svchost)
- [Suspicious Svchost Process Access](#suspicious-svchost-process-access)
- [Function Call From Undocumented COM Interface EditionUpgradeManager](#function-call-from-undocumented-com-interface-editionupgrademanager)
- [UAC Bypass Using WOW64 Logger DLL Hijack](#uac-bypass-using-wow64-logger-dll-hijack)
- [Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze](#suspicious-process-access-of-msmpeng-by-werfaultsecure-edr-freeze)

## CMSTP Execution Process Access

| Field | Value |
|---|---|
| **Sigma ID** | `3b4b232a-af90-427c-a22f-30b0c0837b95` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1218.003, T1559.001 |
| **Author** | Nik Seetharaman |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_cmstp_execution_by_access.yml)**

> Detects various indicators of Microsoft Connection Manager Profile Installer execution

```sql
-- ============================================================
-- Title:        CMSTP Execution Process Access
-- Sigma ID:     3b4b232a-af90-427c-a22f-30b0c0837b95
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        execution | T1218.003, T1559.001
-- Author:       Nik Seetharaman
-- Date:         2018-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_cmstp_execution_by_access.yml
-- Unmapped:     CallTrace
-- False Pos:    Legitimate CMSTP use (unlikely in modern enterprise environments)
-- ============================================================
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%cmlua.dll%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate CMSTP use (unlikely in modern enterprise environments)

**References:**
- https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/

---

## HackTool - CobaltStrike BOF Injection Pattern

| Field | Value |
|---|---|
| **Sigma ID** | `09706624-b7f6-455d-9d02-adee024cee1d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1106, T1562.001 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_cobaltstrike_bof_injection_pattern.yml)**

> Detects a typical pattern of a CobaltStrike BOF which inject into other processes

```sql
-- ============================================================
-- Title:        HackTool - CobaltStrike BOF Injection Pattern
-- Sigma ID:     09706624-b7f6-455d-9d02-adee024cee1d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1106, T1562.001
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_cobaltstrike_bof_injection_pattern.yml
-- Unmapped:     CallTrace, GrantedAccess
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: CallTrace
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (match(rawEventMsg, '^C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-z0-9]{4,6}\|C:\\Windows\\System32\\KERNELBASE\.dll\+[a-z0-9]{4,6}\|UNKNOWN\([A-Z0-9]{16}\)$')
    AND rawEventMsg IN ('0x1028', '0x1fffff'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/boku7/injectAmsiBypass
- https://github.com/boku7/spawn

---

## HackTool - Generic Process Access

| Field | Value |
|---|---|
| **Sigma ID** | `d0d2f720-d14f-448d-8242-51ff396a334e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_generic_access.yml)**

> Detects process access requests from hacktool processes based on their default image name

```sql
-- ============================================================
-- Title:        HackTool - Generic Process Access
-- Sigma ID:     d0d2f720-d14f-448d-8242-51ff396a334e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
-- Date:         2023-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_generic_access.yml
-- Unmapped:     SourceImage
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: SourceImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\Akagi.exe' OR rawEventMsg LIKE '%\\Akagi64.exe' OR rawEventMsg LIKE '%\\atexec\_windows.exe' OR rawEventMsg LIKE '%\\Certify.exe' OR rawEventMsg LIKE '%\\Certipy.exe' OR rawEventMsg LIKE '%\\CoercedPotato.exe' OR rawEventMsg LIKE '%\\crackmapexec.exe' OR rawEventMsg LIKE '%\\CreateMiniDump.exe' OR rawEventMsg LIKE '%\\dcomexec\_windows.exe' OR rawEventMsg LIKE '%\\dpapi\_windows.exe' OR rawEventMsg LIKE '%\\findDelegation\_windows.exe' OR rawEventMsg LIKE '%\\GetADUsers\_windows.exe' OR rawEventMsg LIKE '%\\GetNPUsers\_windows.exe' OR rawEventMsg LIKE '%\\getPac\_windows.exe' OR rawEventMsg LIKE '%\\getST\_windows.exe' OR rawEventMsg LIKE '%\\getTGT\_windows.exe' OR rawEventMsg LIKE '%\\GetUserSPNs\_windows.exe' OR rawEventMsg LIKE '%\\gmer.exe' OR rawEventMsg LIKE '%\\hashcat.exe' OR rawEventMsg LIKE '%\\htran.exe' OR rawEventMsg LIKE '%\\ifmap\_windows.exe' OR rawEventMsg LIKE '%\\impersonate.exe' OR rawEventMsg LIKE '%\\Inveigh.exe' OR rawEventMsg LIKE '%\\LocalPotato.exe' OR rawEventMsg LIKE '%\\mimikatz\_windows.exe' OR rawEventMsg LIKE '%\\mimikatz.exe' OR rawEventMsg LIKE '%\\netview\_windows.exe' OR rawEventMsg LIKE '%\\nmapAnswerMachine\_windows.exe' OR rawEventMsg LIKE '%\\opdump\_windows.exe' OR rawEventMsg LIKE '%\\PasswordDump.exe' OR rawEventMsg LIKE '%\\Potato.exe' OR rawEventMsg LIKE '%\\PowerTool.exe' OR rawEventMsg LIKE '%\\PowerTool64.exe' OR rawEventMsg LIKE '%\\psexec\_windows.exe' OR rawEventMsg LIKE '%\\PurpleSharp.exe' OR rawEventMsg LIKE '%\\pypykatz.exe' OR rawEventMsg LIKE '%\\QuarksPwDump.exe' OR rawEventMsg LIKE '%\\rdp\_check\_windows.exe' OR rawEventMsg LIKE '%\\Rubeus.exe' OR rawEventMsg LIKE '%\\SafetyKatz.exe' OR rawEventMsg LIKE '%\\sambaPipe\_windows.exe' OR rawEventMsg LIKE '%\\SelectMyParent.exe' OR rawEventMsg LIKE '%\\SharpChisel.exe' OR rawEventMsg LIKE '%\\SharPersist.exe' OR rawEventMsg LIKE '%\\SharpEvtMute.exe' OR rawEventMsg LIKE '%\\SharpImpersonation.exe' OR rawEventMsg LIKE '%\\SharpLDAPmonitor.exe' OR rawEventMsg LIKE '%\\SharpLdapWhoami.exe' OR rawEventMsg LIKE '%\\SharpUp.exe' OR rawEventMsg LIKE '%\\SharpView.exe' OR rawEventMsg LIKE '%\\smbclient\_windows.exe' OR rawEventMsg LIKE '%\\smbserver\_windows.exe' OR rawEventMsg LIKE '%\\sniff\_windows.exe' OR rawEventMsg LIKE '%\\sniffer\_windows.exe' OR rawEventMsg LIKE '%\\split\_windows.exe' OR rawEventMsg LIKE '%\\SpoolSample.exe' OR rawEventMsg LIKE '%\\Stracciatella.exe' OR rawEventMsg LIKE '%\\SysmonEOP.exe' OR rawEventMsg LIKE '%\\temp\\rot.exe' OR rawEventMsg LIKE '%\\ticketer\_windows.exe' OR rawEventMsg LIKE '%\\TruffleSnout.exe' OR rawEventMsg LIKE '%\\winPEASany\_ofs.exe' OR rawEventMsg LIKE '%\\winPEASany.exe' OR rawEventMsg LIKE '%\\winPEASx64\_ofs.exe' OR rawEventMsg LIKE '%\\winPEASx64.exe' OR rawEventMsg LIKE '%\\winPEASx86\_ofs.exe' OR rawEventMsg LIKE '%\\winPEASx86.exe' OR rawEventMsg LIKE '%\\xordump.exe'))
  OR ((rawEventMsg LIKE '%\\goldenPac%' OR rawEventMsg LIKE '%\\just\_dce\_%' OR rawEventMsg LIKE '%\\karmaSMB%' OR rawEventMsg LIKE '%\\kintercept%' OR rawEventMsg LIKE '%\\LocalPotato%' OR rawEventMsg LIKE '%\\ntlmrelayx%' OR rawEventMsg LIKE '%\\rpcdump%' OR rawEventMsg LIKE '%\\samrdump%' OR rawEventMsg LIKE '%\\secretsdump%' OR rawEventMsg LIKE '%\\smbexec%' OR rawEventMsg LIKE '%\\smbrelayx%' OR rawEventMsg LIKE '%\\wmiexec%' OR rawEventMsg LIKE '%\\wmipersist%' OR rawEventMsg LIKE '%HotPotato%' OR rawEventMsg LIKE '%Juicy Potato%' OR rawEventMsg LIKE '%JuicyPotato%' OR rawEventMsg LIKE '%PetitPotam%' OR rawEventMsg LIKE '%RottenPotato%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://jsecurity101.medium.com/bypassing-access-mask-auditing-strategies-480fb641c158
- https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html

---

## HackTool - HandleKatz Duplicating LSASS Handle

| Field | Value |
|---|---|
| **Sigma ID** | `b1bd3a59-c1fd-4860-9f40-4dd161a7d1f5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1106, T1003.001 |
| **Author** | Bhabesh Raj (rule), @thefLinkk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_handlekatz_lsass_access.yml)**

> Detects HandleKatz opening LSASS to duplicate its handle to later dump the memory without opening any new handles

```sql
-- ============================================================
-- Title:        HackTool - HandleKatz Duplicating LSASS Handle
-- Sigma ID:     b1bd3a59-c1fd-4860-9f40-4dd161a7d1f5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1106, T1003.001
-- Author:       Bhabesh Raj (rule), @thefLinkk
-- Date:         2022-06-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_handlekatz_lsass_access.yml
-- Unmapped:     TargetImage, GrantedAccess, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: GrantedAccess
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg = '0x1440'
    AND rawEventMsg LIKE 'C:\\Windows\\System32\\ntdll.dll+%'
    AND rawEventMsg LIKE '%|UNKNOWN(%'
    AND rawEventMsg LIKE '%)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/codewhitesec/HandleKatz

---

## HackTool - LittleCorporal Generated Maldoc Injection

| Field | Value |
|---|---|
| **Sigma ID** | `7bdde3bf-2a42-4c39-aa31-a92b3e17afac` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002, T1055.003 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_littlecorporal_generated_maldoc.yml)**

> Detects the process injection of a LittleCorporal generated Maldoc.

```sql
-- ============================================================
-- Title:        HackTool - LittleCorporal Generated Maldoc Injection
-- Sigma ID:     7bdde3bf-2a42-4c39-aa31-a92b3e17afac
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1204.002, T1055.003
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_littlecorporal_generated_maldoc.yml
-- Unmapped:     SourceImage, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\winword.exe'
    AND rawEventMsg LIKE '%:\\Windows\\Microsoft.NET\\Framework64\\v2.%' AND rawEventMsg LIKE '%UNKNOWN%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/connormcgarr/LittleCorporal

---

## HackTool - SysmonEnte Execution

| Field | Value |
|---|---|
| **Sigma ID** | `d29ada0f-af45-4f27-8f32-f7b77c3dbc4e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_sysmonente.yml)**

> Detects the use of SysmonEnte, a tool to attack the integrity of Sysmon

```sql
-- ============================================================
-- Title:        HackTool - SysmonEnte Execution
-- Sigma ID:     d29ada0f-af45-4f27-8f32-f7b77c3dbc4e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_hktl_sysmonente.yml
-- Unmapped:     CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Ente'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://codewhitesec.blogspot.com/2022/09/attacks-on-sysmon-revisited-sysmonente.html
- https://github.com/codewhitesec/SysmonEnte/
- https://github.com/codewhitesec/SysmonEnte/blob/fe267690fcc799fbda15398243615a30451d9099/screens/1.png

---

## Lsass Memory Dump via Comsvcs DLL

| Field | Value |
|---|---|
| **Sigma ID** | `a49fa4d5-11db-418c-8473-1e014a8dd462` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml)**

> Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.

```sql
-- ============================================================
-- Title:        Lsass Memory Dump via Comsvcs DLL
-- Sigma ID:     a49fa4d5-11db-418c-8473-1e014a8dd462
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml
-- Unmapped:     TargetImage, SourceImage, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg LIKE '%\\rundll32.exe'
    AND rawEventMsg LIKE '%comsvcs.dll%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/shantanukhande/status/1229348874298388484
- https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/

---

## LSASS Memory Access by Tool With Dump Keyword In Name

| Field | Value |
|---|---|
| **Sigma ID** | `9bd012ee-0dff-44d7-84a0-aa698cfd87a3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml)**

> Detects LSASS process access requests from a source process with the "dump" keyword in its image name.

```sql
-- ============================================================
-- Title:        LSASS Memory Access by Tool With Dump Keyword In Name
-- Sigma ID:     9bd012ee-0dff-44d7-84a0-aa698cfd87a3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-02-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml
-- Unmapped:     TargetImage, SourceImage, GrantedAccess
-- False Pos:    Rare programs that contain the word dump in their name and access lsass
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg LIKE '%dump%'
    AND (rawEventMsg LIKE '%10' OR rawEventMsg LIKE '%30' OR rawEventMsg LIKE '%50' OR rawEventMsg LIKE '%70' OR rawEventMsg LIKE '%90' OR rawEventMsg LIKE '%B0' OR rawEventMsg LIKE '%D0' OR rawEventMsg LIKE '%F0' OR rawEventMsg LIKE '%18' OR rawEventMsg LIKE '%38' OR rawEventMsg LIKE '%58' OR rawEventMsg LIKE '%78' OR rawEventMsg LIKE '%98' OR rawEventMsg LIKE '%B8' OR rawEventMsg LIKE '%D8' OR rawEventMsg LIKE '%F8' OR rawEventMsg LIKE '%1A' OR rawEventMsg LIKE '%3A' OR rawEventMsg LIKE '%5A' OR rawEventMsg LIKE '%7A' OR rawEventMsg LIKE '%9A' OR rawEventMsg LIKE '%BA' OR rawEventMsg LIKE '%DA' OR rawEventMsg LIKE '%FA' OR rawEventMsg LIKE '%0x14C2' OR rawEventMsg LIKE '%FF'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare programs that contain the word dump in their name and access lsass

**References:**
- https://twitter.com/_xpn_/status/1491557187168178176
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz

---

## Potential Credential Dumping Activity Via LSASS

| Field | Value |
|---|---|
| **Sigma ID** | `5ef9853e-4d0e-4a70-846f-a9ca37d876da` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Samir Bousseaden, Michael Haag |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_memdump.yml)**

> Detects process access requests to the LSASS process with specific call trace calls and access masks.
This behaviour is expressed by many credential dumping tools such as Mimikatz, NanoDump, Invoke-Mimikatz, Procdump and even the Taskmgr dumping feature.


```sql
-- ============================================================
-- Title:        Potential Credential Dumping Activity Via LSASS
-- Sigma ID:     5ef9853e-4d0e-4a70-846f-a9ca37d876da
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Samir Bousseaden, Michael Haag
-- Date:         2019-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_memdump.yml
-- Unmapped:     TargetImage, GrantedAccess, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: GrantedAccess
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND (rawEventMsg LIKE '%0x1038%' OR rawEventMsg LIKE '%0x1438%' OR rawEventMsg LIKE '%0x143a%' OR rawEventMsg LIKE '%0x1fffff%')
    AND (rawEventMsg LIKE '%dbgcore.dll%' OR rawEventMsg LIKE '%dbghelp.dll%' OR rawEventMsg LIKE '%kernel32.dll%' OR rawEventMsg LIKE '%kernelbase.dll%' OR rawEventMsg LIKE '%ntdll.dll%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20230329170326/https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
- https://web.archive.org/web/20230208123920/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.001/T1003.001.md
- https://research.splunk.com/endpoint/windows_possible_credential_dumping/

---

## Credential Dumping Activity By Python Based Tool

| Field | Value |
|---|---|
| **Sigma ID** | `f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Bhabesh Raj, Jonhnathan Ribeiro |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_python_based_tool.yml)**

> Detects LSASS process access for potential credential dumping by a Python-like tool such as LaZagne or Pypykatz.

```sql
-- ============================================================
-- Title:        Credential Dumping Activity By Python Based Tool
-- Sigma ID:     f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1003.001
-- Author:       Bhabesh Raj, Jonhnathan Ribeiro
-- Date:         2023-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_python_based_tool.yml
-- Unmapped:     TargetImage, CallTrace, GrantedAccess
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: CallTrace
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg LIKE '%\_ctypes.pyd+%' AND rawEventMsg LIKE '%:\\Windows\\System32\\KERNELBASE.dll+%' AND rawEventMsg LIKE '%:\\Windows\\SYSTEM32\\ntdll.dll+%'
    AND (rawEventMsg LIKE '%python27.dll+%' OR rawEventMsg LIKE '%python3*.dll+%')
    AND rawEventMsg = '0x1FFFFF')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/bh4b3sh/status/1303674603819081728
- https://github.com/skelsec/pypykatz

---

## Remote LSASS Process Access Through Windows Remote Management

| Field | Value |
|---|---|
| **Sigma ID** | `aa35a627-33fb-4d04-a165-d33b4afca3e8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1003.001, T1059.001, T1021.006 |
| **Author** | Patryk Prauze - ING Tech |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_remote_access_trough_winrm.yml)**

> Detects remote access to the LSASS process via WinRM. This could be a sign of credential dumping from tools like mimikatz.

```sql
-- ============================================================
-- Title:        Remote LSASS Process Access Through Windows Remote Management
-- Sigma ID:     aa35a627-33fb-4d04-a165-d33b4afca3e8
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        execution | T1003.001, T1059.001, T1021.006
-- Author:       Patryk Prauze - ING Tech
-- Date:         2019-05-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_remote_access_trough_winrm.yml
-- Unmapped:     TargetImage, SourceImage
-- False Pos:    Unlikely
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
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg LIKE '%:\\Windows\\system32\\wsmprovhost.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://pentestlab.blog/2018/05/15/lateral-movement-winrm/

---

## Suspicious LSASS Access Via MalSecLogon

| Field | Value |
|---|---|
| **Sigma ID** | `472159c5-31b9-4f56-b794-b766faa8b0a7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Samir Bousseaden (original elastic rule), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_seclogon_access.yml)**

> Detects suspicious access to LSASS handle via a call trace to "seclogon.dll" with a suspicious access right.

```sql
-- ============================================================
-- Title:        Suspicious LSASS Access Via MalSecLogon
-- Sigma ID:     472159c5-31b9-4f56-b794-b766faa8b0a7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Samir Bousseaden (original elastic rule), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_seclogon_access.yml
-- Unmapped:     TargetImage, SourceImage, GrantedAccess, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: GrantedAccess
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg LIKE '%\\svchost.exe'
    AND rawEventMsg = '0x14c0'
    AND rawEventMsg LIKE '%seclogon.dll%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/SBousseaden/status/1541920424635912196
- https://github.com/elastic/detection-rules/blob/2bc1795f3d7bcc3946452eb4f07ae799a756d94e/rules/windows/credential_access_lsass_handle_via_malseclogon.toml
- https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html

---

## Potentially Suspicious GrantedAccess Flags On LSASS

| Field | Value |
|---|---|
| **Sigma ID** | `a18dd26b-6450-46de-8c91-9659150cf088` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth, Roberto Rodriguez, Dimitrios Slamaris, Mark Russinovich, Thomas Patzke, Teymur Kheirkhabarov, Sherif Eldeeb, James Dickenson, Aleksey Potapov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml)**

> Detects process access requests to LSASS process with potentially suspicious access flags

```sql
-- ============================================================
-- Title:        Potentially Suspicious GrantedAccess Flags On LSASS
-- Sigma ID:     a18dd26b-6450-46de-8c91-9659150cf088
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth, Roberto Rodriguez, Dimitrios Slamaris, Mark Russinovich, Thomas Patzke, Teymur Kheirkhabarov, Sherif Eldeeb, James Dickenson, Aleksey Potapov, oscd.community
-- Date:         2021-11-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software such as AV and EDR
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software such as AV and EDR

**References:**
- https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
- https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow
- https://web.archive.org/web/20230208123920/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
- https://web.archive.org/web/20230420013146/http://security-research.dyndns.org/pub/slides/FIRST2017/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL_notes.pdf

---

## Credential Dumping Attempt Via WerFault

| Field | Value |
|---|---|
| **Sigma ID** | `e5b33f7d-eb93-48b6-9851-09e1e610b6d7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_werfault.yml)**

> Detects process LSASS memory dump using Mimikatz, NanoDump, Invoke-Mimikatz, Procdump or Taskmgr based on the CallTrace pointing to ntdll.dll, dbghelp.dll or dbgcore.dll for win10, server2016 and up.

```sql
-- ============================================================
-- Title:        Credential Dumping Attempt Via WerFault
-- Sigma ID:     e5b33f7d-eb93-48b6-9851-09e1e610b6d7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2012-06-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_werfault.yml
-- Unmapped:     SourceImage, TargetImage, GrantedAccess
-- False Pos:    Actual failures in lsass.exe that trigger a crash dump (unlikely); Unknown cases in which WerFault accesses lsass.exe
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\WerFault.exe'
    AND rawEventMsg LIKE '%\\lsass.exe'
    AND rawEventMsg = '0x1FFFFF')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Actual failures in lsass.exe that trigger a crash dump (unlikely); Unknown cases in which WerFault accesses lsass.exe

**References:**
- https://github.com/helpsystems/nanodump/commit/578116faea3d278d53d70ea932e2bbfe42569507

---

## LSASS Access From Potentially White-Listed Processes

| Field | Value |
|---|---|
| **Sigma ID** | `4be8b654-0c01-4c9d-a10c-6b28467fc651` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_whitelisted_process_names.yml)**

> Detects a possible process memory dump that uses a white-listed filename like TrolleyExpress.exe as a way to dump the LSASS process memory without Microsoft Defender interference


```sql
-- ============================================================
-- Title:        LSASS Access From Potentially White-Listed Processes
-- Sigma ID:     4be8b654-0c01-4c9d-a10c-6b28467fc651
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-02-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_whitelisted_process_names.yml
-- Unmapped:     TargetImage, SourceImage, GrantedAccess
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\lsass.exe'
    AND (rawEventMsg LIKE '%\\TrolleyExpress.exe' OR rawEventMsg LIKE '%\\ProcessDump.exe' OR rawEventMsg LIKE '%\\dump64.exe')
    AND (rawEventMsg LIKE '%10' OR rawEventMsg LIKE '%30' OR rawEventMsg LIKE '%50' OR rawEventMsg LIKE '%70' OR rawEventMsg LIKE '%90' OR rawEventMsg LIKE '%B0' OR rawEventMsg LIKE '%D0' OR rawEventMsg LIKE '%F0' OR rawEventMsg LIKE '%18' OR rawEventMsg LIKE '%38' OR rawEventMsg LIKE '%58' OR rawEventMsg LIKE '%78' OR rawEventMsg LIKE '%98' OR rawEventMsg LIKE '%B8' OR rawEventMsg LIKE '%D8' OR rawEventMsg LIKE '%F8' OR rawEventMsg LIKE '%1A' OR rawEventMsg LIKE '%3A' OR rawEventMsg LIKE '%5A' OR rawEventMsg LIKE '%7A' OR rawEventMsg LIKE '%9A' OR rawEventMsg LIKE '%BA' OR rawEventMsg LIKE '%DA' OR rawEventMsg LIKE '%FA' OR rawEventMsg LIKE '%0x14C2' OR rawEventMsg LIKE '%FF'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/_xpn_/status/1491557187168178176
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
- https://twitter.com/mrd0x/status/1460597833917251595

---

## Uncommon Process Access Rights For Target Image

| Field | Value |
|---|---|
| **Sigma ID** | `a24e5861-c6ca-4fde-a93c-ba9256feddf0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1055.011 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_all_access_uncommon_target.yml)**

> Detects process access request to uncommon target images with a "PROCESS_ALL_ACCESS" access mask.


```sql
-- ============================================================
-- Title:        Uncommon Process Access Rights For Target Image
-- Sigma ID:     a24e5861-c6ca-4fde-a93c-ba9256feddf0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1055.011
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2024-05-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_all_access_uncommon_target.yml
-- Unmapped:     TargetImage, GrantedAccess
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\calc.exe' OR rawEventMsg LIKE '%\\calculator.exe' OR rawEventMsg LIKE '%\\mspaint.exe' OR rawEventMsg LIKE '%\\notepad.exe' OR rawEventMsg LIKE '%\\ping.exe' OR rawEventMsg LIKE '%\\wordpad.exe' OR rawEventMsg LIKE '%\\write.exe')
    AND rawEventMsg = '0x1FFFFF')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

---

## Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs

| Field | Value |
|---|---|
| **Sigma ID** | `9f5c1d59-33be-4e60-bcab-85d2f566effd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001, T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_dbgcore_dbghelp_load.yml)**

> Detects suspicious process access to LSASS.exe from processes located in uncommon locations with dbgcore.dll or dbghelp.dll in the call trace.
These DLLs contain functions like MiniDumpWriteDump that can be abused for credential dumping purposes. While modern tools like Mimikatz have moved to using ntdll.dll,
dbgcore.dll and dbghelp.dll are still used by basic credential dumping utilities and legacy tools for LSASS memory access and process suspension techniques.


```sql
-- ============================================================
-- Title:        Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs
-- Sigma ID:     9f5c1d59-33be-4e60-bcab-85d2f566effd
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1003.001, T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_dbgcore_dbghelp_load.yml
-- Unmapped:     TargetImage, CallTrace, SourceImage
-- False Pos:    Possibly during software installation or update processes
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: CallTrace
-- UNMAPPED_FIELD: SourceImage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\lsass.exe'
    AND (rawEventMsg LIKE '%dbgcore.dll%' OR rawEventMsg LIKE '%dbghelp.dll%'))
  AND (rawEventMsg LIKE '%:\\Perflogs\\%' OR rawEventMsg LIKE '%:\\Temp\\%' OR rawEventMsg LIKE '%:\\Users\\Public\\%' OR rawEventMsg LIKE '%\\$Recycle.Bin\\%' OR rawEventMsg LIKE '%\\AppData\\Roaming\\%' OR rawEventMsg LIKE '%\\Contacts\\%' OR rawEventMsg LIKE '%\\Desktop\\%' OR rawEventMsg LIKE '%\\Documents\\%' OR rawEventMsg LIKE '%\\Downloads\\%' OR rawEventMsg LIKE '%\\Favorites\\%' OR rawEventMsg LIKE '%\\Favourites\\%' OR rawEventMsg LIKE '%\\inetpub\\wwwroot\\%' OR rawEventMsg LIKE '%\\Music\\%' OR rawEventMsg LIKE '%\\Pictures\\%' OR rawEventMsg LIKE '%\\Start Menu\\Programs\\Startup\\%' OR rawEventMsg LIKE '%\\Users\\Default\\%' OR rawEventMsg LIKE '%\\Videos\\%' OR rawEventMsg LIKE '%\\Windows\\Temp\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Possibly during software installation or update processes

**References:**
- https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html
- https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpwritedump

---

## Potential Direct Syscall of NtOpenProcess

| Field | Value |
|---|---|
| **Sigma ID** | `3f3f3506-1895-401b-9cc3-e86b16e630d0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1106 |
| **Author** | Christian Burkard (Nextron Systems), Tim Shelton (FP) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_direct_ntopenprocess_call.yml)**

> Detects potential calls to NtOpenProcess directly from NTDLL.

```sql
-- ============================================================
-- Title:        Potential Direct Syscall of NtOpenProcess
-- Sigma ID:     3f3f3506-1895-401b-9cc3-e86b16e630d0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1106
-- Author:       Christian Burkard (Nextron Systems), Tim Shelton (FP)
-- Date:         2021-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_direct_ntopenprocess_call.yml
-- Unmapped:     CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE 'UNKNOWN%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/falconforce/falconfriday-direct-system-calls-and-cobalt-strike-bofs-0xff14-741fa8e1bdd6

---

## Credential Dumping Attempt Via Svchost

| Field | Value |
|---|---|
| **Sigma ID** | `174afcfa-6e40-4ae9-af64-496546389294` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548 |
| **Author** | Florent Labouyrie |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_svchost_credential_dumping.yml)**

> Detects when a process tries to access the memory of svchost to potentially dump credentials.

```sql
-- ============================================================
-- Title:        Credential Dumping Attempt Via Svchost
-- Sigma ID:     174afcfa-6e40-4ae9-af64-496546389294
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548
-- Author:       Florent Labouyrie
-- Date:         2021-04-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_svchost_credential_dumping.yml
-- Unmapped:     TargetImage, GrantedAccess
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: GrantedAccess

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\svchost.exe'
    AND rawEventMsg = '0x143a')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Suspicious Svchost Process Access

| Field | Value |
|---|---|
| **Sigma ID** | `166e9c50-8cd9-44af-815d-d1f0c0e90dde` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | Tim Burrell |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_svchost_susp_access_request.yml)**

> Detects suspicious access to the "svchost" process such as that used by Invoke-Phantom to kill the thread of the Windows event logging service.

```sql
-- ============================================================
-- Title:        Suspicious Svchost Process Access
-- Sigma ID:     166e9c50-8cd9-44af-815d-d1f0c0e90dde
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       Tim Burrell
-- Date:         2020-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_svchost_susp_access_request.yml
-- Unmapped:     TargetImage, GrantedAccess, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: GrantedAccess
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%:\\Windows\\System32\\svchost.exe'
    AND rawEventMsg = '0x1F3FFF'
    AND rawEventMsg LIKE '%UNKNOWN%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hlldz/Invoke-Phant0m
- https://twitter.com/timbmsft/status/900724491076214784

---

## Function Call From Undocumented COM Interface EditionUpgradeManager

| Field | Value |
|---|---|
| **Sigma ID** | `fb3722e4-1a06-46b6-b772-253e2e7db933` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548.002 |
| **Author** | oscd.community, Dmitry Uchakin |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_uac_bypass_editionupgrademanagerobj.yml)**

> Detects function calls from the EditionUpgradeManager COM interface. Which is an interface that is not used by standard executables.

```sql
-- ============================================================
-- Title:        Function Call From Undocumented COM Interface EditionUpgradeManager
-- Sigma ID:     fb3722e4-1a06-46b6-b772-253e2e7db933
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1548.002
-- Author:       oscd.community, Dmitry Uchakin
-- Date:         2020-10-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_uac_bypass_editionupgrademanagerobj.yml
-- Unmapped:     CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%editionupgrademanagerobj.dll%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/
- https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611

---

## UAC Bypass Using WOW64 Logger DLL Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `4f6c43e2-f989-4ea5-bcd8-843b49a0317c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_uac_bypass_wow64_logger.yml)**

> Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)

```sql
-- ============================================================
-- Title:        UAC Bypass Using WOW64 Logger DLL Hijack
-- Sigma ID:     4f6c43e2-f989-4ea5-bcd8-843b49a0317c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_uac_bypass_wow64_logger.yml
-- Unmapped:     SourceImage, GrantedAccess, CallTrace
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: GrantedAccess
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%:\\Windows\\SysWOW64\\%'
    AND rawEventMsg = '0x1fffff'
    AND rawEventMsg LIKE 'UNKNOWN(0000000000000000)|UNKNOWN(0000000000000000)|%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze

| Field | Value |
|---|---|
| **Sigma ID** | `387df17d-3b04-448f-8669-9e7fd5e5fd8c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_werfaultsecure_msmpeng_access.yml)**

> Detects process access events where WerFaultSecure accesses MsMpEng.exe with dbgcore.dll or dbghelp.dll in the call trace, indicating potential EDR freeze techniques.
This technique leverages WerFaultSecure.exe running as a Protected Process Light (PPL) with WinTCB protection level to call MiniDumpWriteDump and suspend EDR/AV processes, allowing malicious activity to execute undetected during the suspension period.


```sql
-- ============================================================
-- Title:        Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze
-- Sigma ID:     387df17d-3b04-448f-8669-9e7fd5e5fd8c
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_werfaultsecure_msmpeng_access.yml
-- Unmapped:     SourceImage, TargetImage, CallTrace
-- False Pos:    Legitimate Windows Error Reporting operations
-- ============================================================
-- UNMAPPED_FIELD: SourceImage
-- UNMAPPED_FIELD: TargetImage
-- UNMAPPED_FIELD: CallTrace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-10-Process-Access')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\WerFaultSecure.exe'
    AND rawEventMsg LIKE '%\\MsMpEng.exe'
    AND (rawEventMsg LIKE '%\\dbgcore.dll%' OR rawEventMsg LIKE '%\\dbghelp.dll%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Windows Error Reporting operations

**References:**
- https://blog.axelarator.net/hunting-for-edr-freeze/

---
