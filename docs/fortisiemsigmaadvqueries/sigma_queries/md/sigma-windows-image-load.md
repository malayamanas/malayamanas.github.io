# Sigma → FortiSIEM: Windows Image Load

> 99 rules · Generated 2026-03-17

## Table of Contents

- [Clfs.SYS Loaded By Process Located In a Potential Suspicious Location](#clfssys-loaded-by-process-located-in-a-potential-suspicious-location)
- [DLL Loaded From Suspicious Location Via Cmspt.EXE](#dll-loaded-from-suspicious-location-via-cmsptexe)
- [Amsi.DLL Loaded Via LOLBIN Process](#amsidll-loaded-via-lolbin-process)
- [Potential Azure Browser SSO Abuse](#potential-azure-browser-sso-abuse)
- [Suspicious Renamed Comsvcs DLL Loaded By Rundll32](#suspicious-renamed-comsvcs-dll-loaded-by-rundll32)
- [CredUI.DLL Loaded By Uncommon Process](#creduidll-loaded-by-uncommon-process)
- [Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded](#suspicious-unsigned-dbghelpdbgcore-dll-loaded)
- [PCRE.NET Package Image Load](#pcrenet-package-image-load)
- [Load Of RstrtMgr.DLL By A Suspicious Process](#load-of-rstrtmgrdll-by-a-suspicious-process)
- [Load Of RstrtMgr.DLL By An Uncommon Process](#load-of-rstrtmgrdll-by-an-uncommon-process)
- [Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE](#diagnostic-library-sdiagengdll-loaded-by-msdtexe)
- [PowerShell Core DLL Loaded By Non PowerShell Process](#powershell-core-dll-loaded-by-non-powershell-process)
- [Time Travel Debugging Utility Usage - Image](#time-travel-debugging-utility-usage-image)
- [Unsigned .node File Loaded](#unsigned-node-file-loaded)
- [Suspicious Volume Shadow Copy VSS_PS.dll Load](#suspicious-volume-shadow-copy-vsspsdll-load)
- [Suspicious Volume Shadow Copy Vssapi.dll Load](#suspicious-volume-shadow-copy-vssapidll-load)
- [Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load](#potentially-suspicious-volume-shadow-copy-vsstracedll-load)
- [HackTool - SharpEvtMute DLL Load](#hacktool-sharpevtmute-dll-load)
- [HackTool - SILENTTRINITY Stager DLL Load](#hacktool-silenttrinity-stager-dll-load)
- [Potential DCOM InternetExplorer.Application DLL Hijack - Image Load](#potential-dcom-internetexplorerapplication-dll-hijack-image-load)
- [Unsigned Image Loaded Into LSASS Process](#unsigned-image-loaded-into-lsass-process)
- [DotNET Assembly DLL Loaded Via Office Application](#dotnet-assembly-dll-loaded-via-office-application)
- [CLR DLL Loaded Via Office Applications](#clr-dll-loaded-via-office-applications)
- [GAC DLL Loaded Via Office Applications](#gac-dll-loaded-via-office-applications)
- [Microsoft Excel Add-In Loaded From Uncommon Location](#microsoft-excel-add-in-loaded-from-uncommon-location)
- [Microsoft VBA For Outlook Addin Loaded Via Outlook](#microsoft-vba-for-outlook-addin-loaded-via-outlook)
- [PowerShell Core DLL Loaded Via Office Application](#powershell-core-dll-loaded-via-office-application)
- [VBA DLL Loaded Via Office Application](#vba-dll-loaded-via-office-application)
- [Remote DLL Load Via Rundll32.EXE](#remote-dll-load-via-rundll32exe)
- [WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load](#wmi-activescripteventconsumers-activity-via-scrconsexe-dll-load)
- [Potential 7za.DLL Sideloading](#potential-7zadll-sideloading)
- [Abusable DLL Potential Sideloading From Suspicious Location](#abusable-dll-potential-sideloading-from-suspicious-location)
- [Potential Antivirus Software DLL Sideloading](#potential-antivirus-software-dll-sideloading)
- [Potential appverifUI.DLL Sideloading](#potential-appverifuidll-sideloading)
- [Aruba Network Service Potential DLL Sideloading](#aruba-network-service-potential-dll-sideloading)
- [Potential AVKkid.DLL Sideloading](#potential-avkkiddll-sideloading)
- [Potential CCleanerDU.DLL Sideloading](#potential-ccleanerdudll-sideloading)
- [Potential CCleanerReactivator.DLL Sideloading](#potential-ccleanerreactivatordll-sideloading)
- [Potential Chrome Frame Helper DLL Sideloading](#potential-chrome-frame-helper-dll-sideloading)
- [Potential DLL Sideloading Via ClassicExplorer32.dll](#potential-dll-sideloading-via-classicexplorer32dll)
- [Potential DLL Sideloading Via comctl32.dll](#potential-dll-sideloading-via-comctl32dll)
- [Potential DLL Sideloading Using Coregen.exe](#potential-dll-sideloading-using-coregenexe)
- [System Control Panel Item Loaded From Uncommon Location](#system-control-panel-item-loaded-from-uncommon-location)
- [Potential DLL Sideloading Of DBGCORE.DLL](#potential-dll-sideloading-of-dbgcoredll)
- [Potential DLL Sideloading Of DBGHELP.DLL](#potential-dll-sideloading-of-dbghelpdll)
- [Potential DLL Sideloading Of DbgModel.DLL](#potential-dll-sideloading-of-dbgmodeldll)
- [Potential EACore.DLL Sideloading](#potential-eacoredll-sideloading)
- [Potential Edputil.DLL Sideloading](#potential-edputildll-sideloading)
- [Potential System DLL Sideloading From Non System Locations](#potential-system-dll-sideloading-from-non-system-locations)
- [Potential Goopdate.DLL Sideloading](#potential-goopdatedll-sideloading)
- [Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE](#potential-dll-sideloading-of-libcurldll-via-gupexe)
- [Potential Iviewers.DLL Sideloading](#potential-iviewersdll-sideloading)
- [Potential JLI.dll Side-Loading](#potential-jlidll-side-loading)
- [Potential DLL Sideloading Via JsSchHlp](#potential-dll-sideloading-via-jsschhlp)
- [Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE](#potential-dll-sideloading-of-keyscrambleriedll-via-keyscramblerexe)
- [Potential Libvlc.DLL Sideloading](#potential-libvlcdll-sideloading)
- [Potential Mfdetours.DLL Sideloading](#potential-mfdetoursdll-sideloading)
- [Unsigned Mfdetours.DLL Sideloading](#unsigned-mfdetoursdll-sideloading)
- [Potential DLL Sideloading Of MpSvc.DLL](#potential-dll-sideloading-of-mpsvcdll)
- [Potential DLL Sideloading Of MsCorSvc.DLL](#potential-dll-sideloading-of-mscorsvcdll)
- [Potential DLL Sideloading Of Non-Existent DLLs From System Folders](#potential-dll-sideloading-of-non-existent-dlls-from-system-folders)
- [Microsoft Office DLL Sideload](#microsoft-office-dll-sideload)
- [Potential Python DLL SideLoading](#potential-python-dll-sideloading)
- [Potential Rcdll.DLL Sideloading](#potential-rcdlldll-sideloading)
- [Potential RjvPlatform.DLL Sideloading From Default Location](#potential-rjvplatformdll-sideloading-from-default-location)
- [Potential RjvPlatform.DLL Sideloading From Non-Default Location](#potential-rjvplatformdll-sideloading-from-non-default-location)
- [Potential RoboForm.DLL Sideloading](#potential-roboformdll-sideloading)
- [DLL Sideloading Of ShellChromeAPI.DLL](#dll-sideloading-of-shellchromeapidll)
- [Potential ShellDispatch.DLL Sideloading](#potential-shelldispatchdll-sideloading)
- [Potential SmadHook.DLL Sideloading](#potential-smadhookdll-sideloading)
- [Potential SolidPDFCreator.DLL Sideloading](#potential-solidpdfcreatordll-sideloading)
- [Third Party Software DLL Sideloading](#third-party-software-dll-sideloading)
- [Fax Service DLL Search Order Hijack](#fax-service-dll-search-order-hijack)
- [Potential Vivaldi_elf.DLL Sideloading](#potential-vivaldielfdll-sideloading)
- [VMGuestLib DLL Sideload](#vmguestlib-dll-sideload)
- [VMMap Signed Dbghelp.DLL Potential Sideloading](#vmmap-signed-dbghelpdll-potential-sideloading)
- [VMMap Unsigned Dbghelp.DLL Potential Sideloading](#vmmap-unsigned-dbghelpdll-potential-sideloading)
- [Potential DLL Sideloading Via VMware Xfer](#potential-dll-sideloading-via-vmware-xfer)
- [Potential Waveedit.DLL Sideloading](#potential-waveeditdll-sideloading)
- [Potential Wazuh Security Platform DLL Sideloading](#potential-wazuh-security-platform-dll-sideloading)
- [Potential Mpclient.DLL Sideloading](#potential-mpclientdll-sideloading)
- [Potential WWlib.DLL Sideloading](#potential-wwlibdll-sideloading)
- [BaaUpdate.exe Suspicious DLL Load](#baaupdateexe-suspicious-dll-load)
- [Unsigned Module Loaded by ClickOnce Application](#unsigned-module-loaded-by-clickonce-application)
- [DLL Load By System Process From Suspicious Locations](#dll-load-by-system-process-from-suspicious-locations)
- [Python Image Load By Non-Python Process](#python-image-load-by-non-python-process)
- [DotNet CLR DLL Loaded By Scripting Applications](#dotnet-clr-dll-loaded-by-scripting-applications)
- [Unsigned DLL Loaded by Windows Utility](#unsigned-dll-loaded-by-windows-utility)
- [Suspicious Unsigned Thor Scanner Execution](#suspicious-unsigned-thor-scanner-execution)
- [UAC Bypass Using Iscsicpl - ImageLoad](#uac-bypass-using-iscsicpl-imageload)
- [UAC Bypass With Fake DLL](#uac-bypass-with-fake-dll)
- [MMC Loading Script Engines DLLs](#mmc-loading-script-engines-dlls)
- [Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location](#suspicious-loading-of-dbgcoredbghelp-dlls-from-uncommon-location)
- [Trusted Path Bypass via Windows Directory Spoofing](#trusted-path-bypass-via-windows-directory-spoofing)
- [WerFaultSecure Loading DbgCore or DbgHelp - EDR-Freeze](#werfaultsecure-loading-dbgcore-or-dbghelp-edr-freeze)
- [WMI Persistence - Command Line Event Consumer](#wmi-persistence-command-line-event-consumer)
- [WMIC Loading Scripting Libraries](#wmic-loading-scripting-libraries)
- [Wmiprvse Wbemcomn DLL Hijack](#wmiprvse-wbemcomn-dll-hijack)
- [Suspicious WSMAN Provider Image Loads](#suspicious-wsman-provider-image-loads)

## Clfs.SYS Loaded By Process Located In a Potential Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `fb4e2211-6d08-426b-8e6f-0d4a161e3b1d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | X__Junior |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_clfs_load.yml)**

> Detects Clfs.sys being loaded by a process running from a potentially suspicious location. Clfs.sys is loaded as part of many CVEs exploits that targets Common Log File.

```sql
-- ============================================================
-- Title:        Clfs.SYS Loaded By Process Located In a Potential Suspicious Location
-- Sigma ID:     fb4e2211-6d08-426b-8e6f-0d4a161e3b1d
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution | T1059
-- Author:       X__Junior
-- Date:         2025-01-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_clfs_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\clfs.sys')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://ssd-disclosure.com/ssd-advisory-common-log-file-system-clfs-driver-pe/
- https://x.com/Threatlabz/status/1879956781360976155

---

## DLL Loaded From Suspicious Location Via Cmspt.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `75e508f7-932d-4ebc-af77-269237a84ce1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_cmstp_load_dll_from_susp_location.yml)**

> Detects cmstp loading "dll" or "ocx" files from suspicious locations

```sql
-- ============================================================
-- Title:        DLL Loaded From Suspicious Location Via Cmspt.EXE
-- Sigma ID:     75e508f7-932d-4ebc-af77-269237a84ce1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_cmstp_load_dll_from_susp_location.yml
-- Unmapped:     (none)
-- False Pos:    Unikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\cmstp.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Users\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%C:\\Temp\\%'))
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%.ocx')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unikely

**References:**
- https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/TTPs/Defense%20Evasion/T1218%20-%20Signed%20Binary%20Proxy%20Execution/T1218.003%20-%20CMSTP/Procedures.yaml

---

## Amsi.DLL Loaded Via LOLBIN Process

| Field | Value |
|---|---|
| **Sigma ID** | `6ec86d9e-912e-4726-91a2-209359b999b9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_amsi_suspicious_process.yml)**

> Detects loading of "Amsi.dll" by a living of the land process. This could be an indication of a "PowerShell without PowerShell" attack

```sql
-- ============================================================
-- Title:        Amsi.DLL Loaded Via LOLBIN Process
-- Sigma ID:     6ec86d9e-912e-4726-91a2-209359b999b9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_amsi_suspicious_process.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\amsi.dll')
    AND (procName LIKE '%\\ExtExport.exe' OR procName LIKE '%\\odbcconf.exe' OR procName LIKE '%\\rundll32.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research
- https://www.paloaltonetworks.com/blog/security-operations/stopping-powershell-without-powershell/

---

## Potential Azure Browser SSO Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `50f852e6-af22-4c78-9ede-42ef36aa3453` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Den Iuzvyk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_azure_microsoft_account_token_provider_dll_load.yml)**

> Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser.
An attacker can use this to authenticate to Azure AD in a browser as that user.


```sql
-- ============================================================
-- Title:        Potential Azure Browser SSO Abuse
-- Sigma ID:     50f852e6-af22-4c78-9ede-42ef36aa3453
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Den Iuzvyk
-- Date:         2020-07-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_azure_microsoft_account_token_provider_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    False positives are expected since this rules is only looking for the DLL load event. This rule is better used in correlation with related activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] = 'C:\Windows\System32\MicrosoftAccountTokenProvider.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives are expected since this rules is only looking for the DLL load event. This rule is better used in correlation with related activity

**References:**
- https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30

---

## Suspicious Renamed Comsvcs DLL Loaded By Rundll32

| Field | Value |
|---|---|
| **Sigma ID** | `8cde342c-ba48-4b74-b615-172c330f2e93` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_comsvcs_load_renamed_version_by_rundll32.yml)**

> Detects rundll32 loading a renamed comsvcs.dll to dump process memory

```sql
-- ============================================================
-- Title:        Suspicious Renamed Comsvcs DLL Loaded By Rundll32
-- Sigma ID:     8cde342c-ba48-4b74-b615-172c330f2e93
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_comsvcs_load_renamed_version_by_rundll32.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'hashMD5')] AS hashes,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\rundll32.exe'
    AND (indexOf(metrics_string.name, 'hashMD5') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'hashMD5')] LIKE '%IMPHASH=eed93054cb555f3de70eaa9787f32ebb%' OR metrics_string.value[indexOf(metrics_string.name,'hashMD5')] LIKE '%IMPHASH=5e0dbdec1fce52daae251a110b4f309d%' OR metrics_string.value[indexOf(metrics_string.name,'hashMD5')] LIKE '%IMPHASH=eadbccbb324829acb5f2bbe87e5549a8%' OR metrics_string.value[indexOf(metrics_string.name,'hashMD5')] LIKE '%IMPHASH=407ca0f7b523319d758a40d7c0193699%' OR metrics_string.value[indexOf(metrics_string.name,'hashMD5')] LIKE '%IMPHASH=281d618f4e6271e527e6386ea6f748de%')))
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\comsvcs.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/sbousseaden/status/1555200155351228419

---

## CredUI.DLL Loaded By Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `9ae01559-cf7e-4f8e-8e14-4c290a1b4784` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1056.002 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_credui_uncommon_process_load.yml)**

> Detects loading of "credui.dll" and related DLLs by an uncommon process. Attackers might leverage this DLL for potential use of "CredUIPromptForCredentials" or "CredUnPackAuthenticationBufferW".

```sql
-- ============================================================
-- Title:        CredUI.DLL Loaded By Uncommon Process
-- Sigma ID:     9ae01559-cf7e-4f8e-8e14-4c290a1b4784
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1056.002
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_credui_uncommon_process_load.yml
-- Unmapped:     (none)
-- False Pos:    Other legitimate processes loading those DLLs in your environment.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  metrics_string.value[indexOf(metrics_string.name,'originalFileName')] AS originalFileName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\credui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wincredui.dll')))
  OR (indexOf(metrics_string.name, 'originalFileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'originalFileName')] IN ('credui.dll', 'wincredui.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legitimate processes loading those DLLs in your environment.

**References:**
- https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-201020013208.html
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.002/T1056.002.md#atomic-test-2---powershell---prompt-user-for-password
- https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforcredentialsa
- https://github.com/S12cybersecurity/RDPCredentialStealer

---

## Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded

| Field | Value |
|---|---|
| **Sigma ID** | `bdc64095-d59a-42a2-8588-71fd9c9d9abc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Perez Diego (@darkquassar), oscd.community, Ecco |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_dbghelp_dbgcore_unsigned_load.yml)**

> Detects the load of dbghelp/dbgcore DLL (used to make memory dumps) by suspicious processes.
Tools like ProcessHacker and some attacker tradecract use MiniDumpWriteDump API found in dbghelp.dll or dbgcore.dll.
As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and transfer it over the network back to the attacker's machine.


```sql
-- ============================================================
-- Title:        Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded
-- Sigma ID:     bdc64095-d59a-42a2-8588-71fd9c9d9abc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Perez Diego (@darkquassar), oscd.community, Ecco
-- Date:         2019-10-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_dbghelp_dbgcore_unsigned_load.yml
-- Unmapped:     Signed
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Signed

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbghelp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbgcore.dll'))
    AND rawEventMsg = 'false')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
- https://www.pinvoke.net/default.aspx/dbghelp/MiniDumpWriteDump.html
- https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6

---

## PCRE.NET Package Image Load

| Field | Value |
|---|---|
| **Sigma ID** | `84b0a8f3-680b-4096-a45b-e9a89221727c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_pcre_dotnet_dll_load.yml)**

> Detects processes loading modules related to PCRE.NET package

```sql
-- ============================================================
-- Title:        PCRE.NET Package Image Load
-- Sigma ID:     84b0a8f3-680b-4096-a45b-e9a89221727c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_pcre_dotnet_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/rbmaslen/status/1321859647091970051
- https://twitter.com/tifkin_/status/1321916444557365248

---

## Load Of RstrtMgr.DLL By A Suspicious Process

| Field | Value |
|---|---|
| **Sigma ID** | `b48492dc-c5ef-4572-8dff-32bc241c15c8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486, T1562.001 |
| **Author** | Luc Génaux |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_rstrtmgr_suspicious_load.yml)**

> Detects the load of RstrtMgr DLL (Restart Manager) by a suspicious process.
This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
It could also be used for anti-analysis purposes by shut downing specific processes.


```sql
-- ============================================================
-- Title:        Load Of RstrtMgr.DLL By A Suspicious Process
-- Sigma ID:     b48492dc-c5ef-4572-8dff-32bc241c15c8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1486, T1562.001
-- Author:       Luc Génaux
-- Date:         2023-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_rstrtmgr_suspicious_load.yml
-- Unmapped:     (none)
-- False Pos:    Processes related to software installation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  metrics_string.value[indexOf(metrics_string.name,'originalFileName')] AS originalFileName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\RstrtMgr.dll'))
  OR (indexOf(metrics_string.name, 'originalFileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'originalFileName')] = 'RstrtMgr.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Processes related to software installation

**References:**
- https://www.crowdstrike.com/blog/windows-restart-manager-part-1/
- https://www.crowdstrike.com/blog/windows-restart-manager-part-2/
- https://web.archive.org/web/20231221193106/https://www.swascan.com/cactus-ransomware-malware-analysis/
- https://taiwan.postsen.com/business/88601/Hamas-hackers-use-data-destruction-software-BiBi-which-consumes-a-lot-of-processor-resources-to-wipe-Windows-computer-data--iThome.html

---

## Load Of RstrtMgr.DLL By An Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `3669afd2-9891-4534-a626-e5cf03810a61` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486, T1562.001 |
| **Author** | Luc Génaux |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_rstrtmgr_uncommon_load.yml)**

> Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process.
This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
It could also be used for anti-analysis purposes by shut downing specific processes.


```sql
-- ============================================================
-- Title:        Load Of RstrtMgr.DLL By An Uncommon Process
-- Sigma ID:     3669afd2-9891-4534-a626-e5cf03810a61
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1486, T1562.001
-- Author:       Luc Génaux
-- Date:         2023-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_rstrtmgr_uncommon_load.yml
-- Unmapped:     (none)
-- False Pos:    Other legitimate Windows processes not currently listed; Processes related to software installation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  metrics_string.value[indexOf(metrics_string.name,'originalFileName')] AS originalFileName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\RstrtMgr.dll'))
  OR (indexOf(metrics_string.name, 'originalFileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'originalFileName')] = 'RstrtMgr.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legitimate Windows processes not currently listed; Processes related to software installation

**References:**
- https://www.crowdstrike.com/blog/windows-restart-manager-part-1/
- https://www.crowdstrike.com/blog/windows-restart-manager-part-2/
- https://web.archive.org/web/20231221193106/https://www.swascan.com/cactus-ransomware-malware-analysis/
- https://taiwan.postsen.com/business/88601/Hamas-hackers-use-data-destruction-software-BiBi-which-consumes-a-lot-of-processor-resources-to-wipe-Windows-computer-data--iThome.html

---

## Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `ec8c4047-fad9-416a-8c81-0f479353d7f6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1202 |
| **Author** | Greg (rule) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_sdiageng_load_by_msdt.yml)**

> Detects both of CVE-2022-30190 (Follina) and DogWalk vulnerabilities exploiting msdt.exe binary to load the "sdiageng.dll" library

```sql
-- ============================================================
-- Title:        Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE
-- Sigma ID:     ec8c4047-fad9-416a-8c81-0f479353d7f6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1202
-- Author:       Greg (rule)
-- Date:         2022-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_sdiageng_load_by_msdt.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\msdt.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sdiageng.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.securonix.com/blog/detecting-microsoft-msdt-dogwalk/

---

## PowerShell Core DLL Loaded By Non PowerShell Process

| Field | Value |
|---|---|
| **Sigma ID** | `092bc4b9-3d1d-43b4-a6b4-8c8acd83522f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Tom Kern, oscd.community, Natalia Shornikova, Tim Shelton, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_system_management_automation_susp_load.yml)**

> Detects loading of essential DLLs used by PowerShell by non-PowerShell process.
Detects behavior similar to meterpreter's "load powershell" extension.


```sql
-- ============================================================
-- Title:        PowerShell Core DLL Loaded By Non PowerShell Process
-- Sigma ID:     092bc4b9-3d1d-43b4-a6b4-8c8acd83522f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Tom Kern, oscd.community, Natalia Shornikova, Tim Shelton, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2019-11-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_system_management_automation_susp_load.yml
-- Unmapped:     Description
-- False Pos:    Used by some .NET binaries, minimal on user workstation.; Used by Microsoft SQL Server Management Studio
-- ============================================================
-- UNMAPPED_FIELD: Description

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'originalFileName')] AS originalFileName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'System.Management.Automation')
  OR (indexOf(metrics_string.name, 'originalFileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'originalFileName')] = 'System.Management.Automation.dll'))
  OR ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\System.Management.Automation.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\System.Management.Automation.ni.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Used by some .NET binaries, minimal on user workstation.; Used by Microsoft SQL Server Management Studio

**References:**
- https://adsecurity.org/?p=2921
- https://github.com/p3nt4/PowerShdll

---

## Time Travel Debugging Utility Usage - Image

| Field | Value |
|---|---|
| **Sigma ID** | `e76c8240-d68f-4773-8880-5c6f63595aaf` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218, T1003.001 |
| **Author** | Ensar Şamil, @sblmsrsn, @oscd_initiative |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_tttracer_module_load.yml)**

> Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.

```sql
-- ============================================================
-- Title:        Time Travel Debugging Utility Usage - Image
-- Sigma ID:     e76c8240-d68f-4773-8880-5c6f63595aaf
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218, T1003.001
-- Author:       Ensar Şamil, @sblmsrsn, @oscd_initiative
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_tttracer_module_load.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage by software developers/testers
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ttdrecord.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ttdwriter.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ttdloader.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage by software developers/testers

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
- https://twitter.com/mattifestation/status/1196390321783025666
- https://twitter.com/oulusoyum/status/1191329746069655553

---

## Unsigned .node File Loaded

| Field | Value |
|---|---|
| **Sigma ID** | `e5f5c693-52d7-4de5-88ae-afbfbce85595` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1129, T1574.001, T1036.005 |
| **Author** | Jonathan Beierle (@hullabrian) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_unsigned_node_load.yml)**

> Detects the loading of unsigned .node files.
Adversaries may abuse a lack of .node integrity checking to execute arbitrary code inside of trusted applications such as Slack.
.node files are native add-ons for Electron-based applications, which are commonly used for desktop applications like Slack, Discord, and Visual Studio Code.
This technique has been observed in the DripLoader malware, which uses unsigned .node files to load malicious native code into Electron applications.


```sql
-- ============================================================
-- Title:        Unsigned .node File Loaded
-- Sigma ID:     e5f5c693-52d7-4de5-88ae-afbfbce85595
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution, persistence | T1129, T1574.001, T1036.005
-- Author:       Jonathan Beierle (@hullabrian)
-- Date:         2025-11-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_unsigned_node_load.yml
-- Unmapped:     (none)
-- False Pos:    VsCode extensions or similar legitimate tools might use unsigned .node files. These should be investigated on a case-by-case basis, and whitelisted if determined to be benign.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** VsCode extensions or similar legitimate tools might use unsigned .node files. These should be investigated on a case-by-case basis, and whitelisted if determined to be benign.

**References:**
- https://www.coreycburton.com/blog/driploader-case-study
- https://github.com/CoreyCBurton/DripLoaderNG
- https://www.electronjs.org/docs/latest/tutorial/native-code-and-electron

---

## Suspicious Volume Shadow Copy VSS_PS.dll Load

| Field | Value |
|---|---|
| **Sigma ID** | `333cdbe8-27bb-4246-bf82-b41a0dca4b70` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | Markus Neis, @markus_neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vss_ps_susp_load.yml)**

> Detects the image load of vss_ps.dll by uncommon executables. This DLL is used by the Volume Shadow Copy Service (VSS) to manage shadow copies of files and volumes.
It is often abused by attackers to delete or manipulate shadow copies, which can hinder forensic investigations and data recovery efforts.
The fact that it is loaded by processes that are not typically associated with VSS operations can indicate suspicious activity.


```sql
-- ============================================================
-- Title:        Suspicious Volume Shadow Copy VSS_PS.dll Load
-- Sigma ID:     333cdbe8-27bb-4246-bf82-b41a0dca4b70
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       Markus Neis, @markus_neis
-- Date:         2021-07-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vss_ps_susp_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vss\_ps.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.virustotal.com/gui/file/ba88ca45589fae0139a40ca27738a8fc2dfbe1be5a64a9558f4e0f52b35c5add
- https://twitter.com/am0nsec/status/1412232114980982787

---

## Suspicious Volume Shadow Copy Vssapi.dll Load

| Field | Value |
|---|---|
| **Sigma ID** | `37774c23-25a1-4adb-bb6d-8bb9fd59c0f8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vssapi_susp_load.yml)**

> Detects the image load of VSS DLL by uncommon executables

```sql
-- ============================================================
-- Title:        Suspicious Volume Shadow Copy Vssapi.dll Load
-- Sigma ID:     37774c23-25a1-4adb-bb6d-8bb9fd59c0f8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       frack113
-- Date:         2022-10-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vssapi_susp_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vssapi.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/ORCx41/DeleteShadowCopies

---

## Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load

| Field | Value |
|---|---|
| **Sigma ID** | `48bfd177-7cf2-412b-ad77-baf923489e82` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vsstrace_susp_load.yml)**

> Detects the image load of VSS DLL by uncommon executables

```sql
-- ============================================================
-- Title:        Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load
-- Sigma ID:     48bfd177-7cf2-412b-ad77-baf923489e82
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       frack113
-- Date:         2023-02-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_dll_vsstrace_susp_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vsstrace.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/ORCx41/DeleteShadowCopies

---

## HackTool - SharpEvtMute DLL Load

| Field | Value |
|---|---|
| **Sigma ID** | `49329257-089d-46e6-af37-4afce4290685` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_hktl_sharpevtmute.yml)**

> Detects the load of EvtMuteHook.dll, a key component of SharpEvtHook, a tool that tampers with the Windows event logs

```sql
-- ============================================================
-- Title:        HackTool - SharpEvtMute DLL Load
-- Sigma ID:     49329257-089d-46e6-af37-4afce4290685
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_hktl_sharpevtmute.yml
-- Unmapped:     (none)
-- False Pos:    Other DLLs with the same Imphash
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'hashMD5')] AS hashes,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'hashMD5') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'hashMD5')] LIKE '%IMPHASH=330768A4F172E10ACB6287B87289D83B%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other DLLs with the same Imphash

**References:**
- https://github.com/bats3c/EvtMute

---

## HackTool - SILENTTRINITY Stager DLL Load

| Field | Value |
|---|---|
| **Sigma ID** | `75c505b1-711d-4f68-a357-8c3fe37dbf2d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071 |
| **Author** | Aleksey Potapov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_hktl_silenttrinity_stager.yml)**

> Detects SILENTTRINITY stager dll loading activity

```sql
-- ============================================================
-- Title:        HackTool - SILENTTRINITY Stager DLL Load
-- Sigma ID:     75c505b1-711d-4f68-a357-8c3fe37dbf2d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071
-- Author:       Aleksey Potapov, oscd.community
-- Date:         2019-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_hktl_silenttrinity_stager.yml
-- Unmapped:     Description
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: Description

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%st2stager%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/byt3bl33d3r/SILENTTRINITY

---

## Potential DCOM InternetExplorer.Application DLL Hijack - Image Load

| Field | Value |
|---|---|
| **Sigma ID** | `f354eba5-623b-450f-b073-0b5b2773b6aa` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1021.002, T1021.003 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_iexplore_dcom_iertutil_dll_hijack.yml)**

> Detects potential DLL hijack of "iertutil.dll" found in the DCOM InternetExplorer.Application Class

```sql
-- ============================================================
-- Title:        Potential DCOM InternetExplorer.Application DLL Hijack - Image Load
-- Sigma ID:     f354eba5-623b-450f-b073-0b5b2773b6aa
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1021.002, T1021.003
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_iexplore_dcom_iertutil_dll_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\Internet Explorer\\iexplore.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Internet Explorer\\iertutil.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html

---

## Unsigned Image Loaded Into LSASS Process

| Field | Value |
|---|---|
| **Sigma ID** | `857c8db3-c89b-42fb-882b-f681c7cf4da2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Teymur Kheirkhabarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_lsass_unsigned_image_load.yml)**

> Loading unsigned image (DLL, EXE) into LSASS process

```sql
-- ============================================================
-- Title:        Unsigned Image Loaded Into LSASS Process
-- Sigma ID:     857c8db3-c89b-42fb-882b-f681c7cf4da2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Teymur Kheirkhabarov, oscd.community
-- Date:         2019-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_lsass_unsigned_image_load.yml
-- Unmapped:     Signed
-- False Pos:    Valid user connecting using RDP
-- ============================================================
-- UNMAPPED_FIELD: Signed

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\lsass.exe'
    AND rawEventMsg = 'false')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid user connecting using RDP

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---

## DotNET Assembly DLL Loaded Via Office Application

| Field | Value |
|---|---|
| **Sigma ID** | `ff0f2b05-09db-4095-b96d-1b75ca24894a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Antonlovesdnb |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_dotnet_assembly_dll_load.yml)**

> Detects any assembly DLL being loaded by an Office Product

```sql
-- ============================================================
-- Title:        DotNET Assembly DLL Loaded Via Office Application
-- Sigma ID:     ff0f2b05-09db-4095-b96d-1b75ca24894a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Antonlovesdnb
-- Date:         2020-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_dotnet_assembly_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\excel.exe' OR procName LIKE '%\\mspub.exe' OR procName LIKE '%\\onenote.exe' OR procName LIKE '%\\onenoteim.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe')
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\assembly\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16

---

## CLR DLL Loaded Via Office Applications

| Field | Value |
|---|---|
| **Sigma ID** | `d13c43f0-f66b-4279-8b2c-5912077c1780` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Antonlovesdnb |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_dotnet_clr_dll_load.yml)**

> Detects CLR DLL being loaded by an Office Product

```sql
-- ============================================================
-- Title:        CLR DLL Loaded Via Office Applications
-- Sigma ID:     d13c43f0-f66b-4279-8b2c-5912077c1780
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Antonlovesdnb
-- Date:         2020-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_dotnet_clr_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\excel.exe' OR procName LIKE '%\\mspub.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\onenote.exe' OR procName LIKE '%\\onenoteim.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe')
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\clr.dll%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16

---

## GAC DLL Loaded Via Office Applications

| Field | Value |
|---|---|
| **Sigma ID** | `90217a70-13fc-48e4-b3db-0d836c5824ac` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Antonlovesdnb |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_dotnet_gac_dll_load.yml)**

> Detects any GAC DLL being loaded by an Office Product

```sql
-- ============================================================
-- Title:        GAC DLL Loaded Via Office Applications
-- Sigma ID:     90217a70-13fc-48e4-b3db-0d836c5824ac
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Antonlovesdnb
-- Date:         2020-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_dotnet_gac_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate macro usage. Add the appropriate filter according to your environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\excel.exe' OR procName LIKE '%\\mspub.exe' OR procName LIKE '%\\onenote.exe' OR procName LIKE '%\\onenoteim.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe')
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\Microsoft.NET\\assembly\\GAC\_MSIL%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate macro usage. Add the appropriate filter according to your environment

**References:**
- https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16

---

## Microsoft Excel Add-In Loaded From Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `af4c4609-5755-42fe-8075-4effb49f5d44` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_excel_xll_susp_load.yml)**

> Detects Microsoft Excel loading an Add-In (.xll) file from an uncommon location

```sql
-- ============================================================
-- Title:        Microsoft Excel Add-In Loaded From Uncommon Location
-- Sigma ID:     af4c4609-5755-42fe-8075-4effb49f5d44
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_excel_xll_susp_load.yml
-- Unmapped:     (none)
-- False Pos:    Some tuning might be required to allow or remove certain locations used by the rule if you consider them as safe locations
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\excel.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Desktop\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Downloads\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Perflogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Windows\\Tasks\\%'))
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%.xll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some tuning might be required to allow or remove certain locations used by the rule if you consider them as safe locations

**References:**
- https://www.mandiant.com/resources/blog/lnk-between-browsers
- https://wazuh.com/blog/detecting-xll-files-used-for-dropping-fin7-jssloader-with-wazuh/

---

## Microsoft VBA For Outlook Addin Loaded Via Outlook

| Field | Value |
|---|---|
| **Sigma ID** | `9a0b8719-cd3c-4f0a-90de-765a4cb3f5ed` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_outlook_outlvba_load.yml)**

> Detects outlvba (Microsoft VBA for Outlook Addin) DLL being loaded by the outlook process

```sql
-- ============================================================
-- Title:        Microsoft VBA For Outlook Addin Loaded Via Outlook
-- Sigma ID:     9a0b8719-cd3c-4f0a-90de-765a4cb3f5ed
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_outlook_outlvba_load.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate macro usage. Add the appropriate filter according to your environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\outlook.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\outlvba.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate macro usage. Add the appropriate filter according to your environment

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=58

---

## PowerShell Core DLL Loaded Via Office Application

| Field | Value |
|---|---|
| **Sigma ID** | `bb2ba6fb-95d4-4a25-89fc-30bb736c021a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_powershell_dll_load.yml)**

> Detects PowerShell core DLL being loaded by an Office Product

```sql
-- ============================================================
-- Title:        PowerShell Core DLL Loaded Via Office Application
-- Sigma ID:     bb2ba6fb-95d4-4a25-89fc-30bb736c021a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_powershell_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\excel.exe' OR procName LIKE '%\\mspub.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\onenote.exe' OR procName LIKE '%\\onenoteim.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe')
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\System.Management.Automation.Dll%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\System.Management.Automation.ni.Dll%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## VBA DLL Loaded Via Office Application

| Field | Value |
|---|---|
| **Sigma ID** | `e6ce8457-68b1-485b-9bdd-3c2b5d679aa9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Antonlovesdnb |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_vbadll_load.yml)**

> Detects VB DLL's loaded by an office application. Which could indicate the presence of VBA Macros.

```sql
-- ============================================================
-- Title:        VBA DLL Loaded Via Office Application
-- Sigma ID:     e6ce8457-68b1-485b-9bdd-3c2b5d679aa9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Antonlovesdnb
-- Date:         2020-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_office_vbadll_load.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate macro usage. Add the appropriate filter according to your environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\excel.exe' OR procName LIKE '%\\mspub.exe' OR procName LIKE '%\\onenote.exe' OR procName LIKE '%\\onenoteim.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe')
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\VBE7.DLL' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\VBEUI.DLL' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\VBE7INTL.DLL')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate macro usage. Add the appropriate filter according to your environment

**References:**
- https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16

---

## Remote DLL Load Via Rundll32.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `f40017b3-cb2e-4335-ab5d-3babf679c1de` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_rundll32_remote_share_load.yml)**

> Detects a remote DLL load event via "rundll32.exe".

```sql
-- ============================================================
-- Title:        Remote DLL Load Via Rundll32.EXE
-- Sigma ID:     f40017b3-cb2e-4335-ab5d-3babf679c1de
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-09-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_rundll32_remote_share_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\rundll32.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '\\\\\\\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/gabe-k/themebleed
- Internal Research

---

## WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load

| Field | Value |
|---|---|
| **Sigma ID** | `b439f47d-ef52-4b29-9a2f-57d8a96cb6b8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_scrcons_wmi_scripteventconsumer.yml)**

> Detects signs of the WMI script host process "scrcons.exe" loading scripting DLLs which could indicates WMI ActiveScriptEventConsumers EventConsumers activity.

```sql
-- ============================================================
-- Title:        WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load
-- Sigma ID:     b439f47d-ef52-4b29-9a2f-57d8a96cb6b8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_scrcons_wmi_scripteventconsumer.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate event consumers; Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\scrcons.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vbscript.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wbemdisp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wshom.ocx' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\scrrun.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate event consumers; Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button

**References:**
- https://twitter.com/HunterPlaybook/status/1301207718355759107
- https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
- https://threathunterplaybook.com/hunts/windows/200902-RemoteWMIActiveScriptEventConsumers/notebook.html

---

## Potential 7za.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `4f6edb78-5c21-42ab-a558-fd2a6fc1fd57` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_7za.yml)**

> Detects potential DLL sideloading of "7za.dll"

```sql
-- ============================================================
-- Title:        Potential 7za.DLL Sideloading
-- Sigma ID:     4f6edb78-5c21-42ab-a558-fd2a6fc1fd57
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior
-- Date:         2023-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_7za.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate third party application located in "AppData" may leverage this DLL to offer 7z compression functionality and may generate false positives. Apply additional filters as needed.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\7za.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate third party application located in "AppData" may leverage this DLL to offer 7z compression functionality and may generate false positives. Apply additional filters as needed.

**References:**
- https://www.gov.pl/attachment/ee91f24d-3e67-436d-aa50-7fa56acf789d

---

## Abusable DLL Potential Sideloading From Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `799a5f48-0ac1-4e0f-9152-71d137d48c2a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_abused_dlls_susp_paths.yml)**

> Detects potential DLL sideloading of DLLs that are known to be abused from suspicious locations

```sql
-- ============================================================
-- Title:        Abusable DLL Potential Sideloading From Suspicious Location
-- Sigma ID:     799a5f48-0ac1-4e0f-9152-71d137d48c2a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_abused_dlls_susp_paths.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\coreclr.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\facesdk.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\HPCustPartUI.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\libcef.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ZIPDLL.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.trendmicro.com/en_us/research/23/f/behind-the-scenes-unveiling-the-hidden-workings-of-earth-preta.html
- https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/

---

## Potential Antivirus Software DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `552b6b65-df37-4d3e-a258-f2fc4771ae54` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_antivirus.yml)**

> Detects potential DLL sideloading of DLLs that are part of antivirus software suchas McAfee, Symantec...etc

```sql
-- ============================================================
-- Title:        Potential Antivirus Software DLL Sideloading
-- Sigma ID:     552b6b65-df37-4d3e-a258-f2fc4771ae54
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
-- Date:         2022-08-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_antivirus.yml
-- Unmapped:     (none)
-- False Pos:    Applications that load the same dlls mentioned in the detection section. Investigate them and filter them out if a lot FPs are caused.; Dell SARemediation plugin folder (C:\Program Files\Dell\SARemediation\plugin\log.dll) is known to contain the 'log.dll' file.; The Canon MyPrinter folder 'C:\Program Files\Canon\MyPrinter\' is known to contain the 'log.dll' file
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\log.dll')
  OR (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\qrt.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\F-Secure\\Anti-Virus\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\F-Secure\\Anti-Virus\\%'))))
  OR ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ashldres.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\lockdown.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vsodscpl.dll'))
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\McAfee\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\McAfee\\%'))))
  OR (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vftrace.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\CyberArk\\Endpoint Privilege Manager\\Agent\\x32\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\CyberArk\\Endpoint Privilege Manager\\Agent\\x32\\%'))))
  OR indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wsc.dll')
  OR (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tmdbglog.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\program Files\\Trend Micro\\Titanium\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\program Files (x86)\\Trend Micro\\Titanium\\%'))))
  OR (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\DLPPREM32.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\program Files\\ESET%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\program Files (x86)\\ESET%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Applications that load the same dlls mentioned in the detection section. Investigate them and filter them out if a lot FPs are caused.; Dell SARemediation plugin folder (C:\Program Files\Dell\SARemediation\plugin\log.dll) is known to contain the 'log.dll' file.; The Canon MyPrinter folder 'C:\Program Files\Canon\MyPrinter\' is known to contain the 'log.dll' file

**References:**
- https://hijacklibs.net/

---

## Potential appverifUI.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `ee6cea48-c5b6-4304-a332-10fc6446f484` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_appverifui.yml)**

> Detects potential DLL sideloading of "appverifUI.dll"

```sql
-- ============================================================
-- Title:        Potential appverifUI.DLL Sideloading
-- Sigma ID:     ee6cea48-c5b6-4304-a332-10fc6446f484
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_appverifui.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\appverifUI.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://web.archive.org/web/20220519091349/https://fatrodzianko.com/2020/02/15/dll-side-loading-appverif-exe/

---

## Aruba Network Service Potential DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `90ae0469-0cee-4509-b67f-e5efcef040f7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_aruba_networks_virtual_intranet_access.yml)**

> Detects potential DLL sideloading activity via the Aruba Networks Virtual Intranet Access "arubanetsvc.exe" process using DLL Search Order Hijacking

```sql
-- ============================================================
-- Title:        Aruba Network Service Potential DLL Sideloading
-- Sigma ID:     90ae0469-0cee-4509-b67f-e5efcef040f7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_aruba_networks_virtual_intranet_access.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\arubanetsvc.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wtsapi32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msvcr100.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msvcp100.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbghelp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbgcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wininet.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iphlpapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\version.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptsp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptbase.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wldp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\profapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sspicli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winsta.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dpapi.dll')))
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\System32\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\SysWOW64\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\WinSxS\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/wdormann/status/1616581559892545537?t=XLCBO9BziGzD7Bmbt8oMEQ&s=09

---

## Potential AVKkid.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `952ed57c-8f99-453d-aee0-53a49c22f95d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_avkkid.yml)**

> Detects potential DLL sideloading of "AVKkid.dll"

```sql
-- ============================================================
-- Title:        Potential AVKkid.DLL Sideloading
-- Sigma ID:     952ed57c-8f99-453d-aee0-53a49c22f95d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_avkkid.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\AVKkid.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/

---

## Potential CCleanerDU.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `1fbc0671-5596-4e17-8682-f020a0b995dc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_ccleaner_du.yml)**

> Detects potential DLL sideloading of "CCleanerDU.dll"

```sql
-- ============================================================
-- Title:        Potential CCleanerDU.DLL Sideloading
-- Sigma ID:     1fbc0671-5596-4e17-8682-f020a0b995dc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_ccleaner_du.yml
-- Unmapped:     (none)
-- False Pos:    False positives could occur from other custom installation paths. Apply additional filters accordingly.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\CCleanerDU.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives could occur from other custom installation paths. Apply additional filters accordingly.

**References:**
- https://lab52.io/blog/2344-2/

---

## Potential CCleanerReactivator.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `3735d5ac-d770-4da0-99ff-156b180bc600` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_ccleaner_reactivator.yml)**

> Detects potential DLL sideloading of "CCleanerReactivator.dll"

```sql
-- ============================================================
-- Title:        Potential CCleanerReactivator.DLL Sideloading
-- Sigma ID:     3735d5ac-d770-4da0-99ff-156b180bc600
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior
-- Date:         2023-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_ccleaner_reactivator.yml
-- Unmapped:     (none)
-- False Pos:    False positives could occur from other custom installation paths. Apply additional filters accordingly.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\CCleanerReactivator.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives could occur from other custom installation paths. Apply additional filters accordingly.

**References:**
- https://lab52.io/blog/2344-2/

---

## Potential Chrome Frame Helper DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `72ca7c75-bf85-45cd-aca7-255d360e423c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_chrome_frame_helper.yml)**

> Detects potential DLL sideloading of "chrome_frame_helper.dll"

```sql
-- ============================================================
-- Title:        Potential Chrome Frame Helper DLL Sideloading
-- Sigma ID:     72ca7c75-bf85-45cd-aca7-255d360e423c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
-- Date:         2022-08-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_chrome_frame_helper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\chrome\_frame\_helper.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://hijacklibs.net/entries/3rd_party/google/chrome_frame_helper.html

---

## Potential DLL Sideloading Via ClassicExplorer32.dll

| Field | Value |
|---|---|
| **Sigma ID** | `caa02837-f659-466f-bca6-48bde2826ab4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_classicexplorer32.yml)**

> Detects potential DLL sideloading using ClassicExplorer32.dll from the Classic Shell software

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Via ClassicExplorer32.dll
-- Sigma ID:     caa02837-f659-466f-bca6-48bde2826ab4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       frack113
-- Date:         2022-12-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_classicexplorer32.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ClassicExplorer32.dll')
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Classic Shell\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.blackberry.com/en/2022/12/mustang-panda-uses-the-russian-ukrainian-war-to-attack-europe-and-asia-pacific-targets
- https://app.any.run/tasks/6d8cabb0-dcda-44b6-8050-28d6ce281687/

---

## Potential DLL Sideloading Via comctl32.dll

| Field | Value |
|---|---|
| **Sigma ID** | `6360757a-d460-456c-8b13-74cf0e60cceb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Subhash Popuri (@pbssubhash) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_comctl32.yml)**

> Detects potential DLL sideloading using comctl32.dll to obtain system privileges

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Via comctl32.dll
-- Sigma ID:     6360757a-d460-456c-8b13-74cf0e60cceb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Subhash Popuri (@pbssubhash)
-- Date:         2022-12-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_comctl32.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\System32\\logonUI.exe.local\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\System32\\werFault.exe.local\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\System32\\consent.exe.local\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\System32\\narrator.exe.local\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\windows\\system32\\wermgr.exe.local\\%'))
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\comctl32.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/binderlabs/DirCreate2System
- https://github.com/sailay1996/awesome_windows_logical_bugs/blob/60cbb23a801f4c3195deac1cc46df27c225c3d07/dir_create2system.txt

---

## Potential DLL Sideloading Using Coregen.exe

| Field | Value |
|---|---|
| **Sigma ID** | `0fa66f66-e3f6-4a9c-93f8-4f2610b00171` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218, T1055 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_coregen.yml)**

> Detect usage of the "coregen.exe" (Microsoft CoreCLR Native Image Generator) binary to sideload arbitrary DLLs.

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Using Coregen.exe
-- Sigma ID:     0fa66f66-e3f6-4a9c-93f8-4f2610b00171
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218, T1055
-- Author:       frack113
-- Date:         2022-12-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_coregen.yml
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
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\coregen.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lolbas-project.github.io/lolbas/OtherMSBinaries/Coregen/

---

## System Control Panel Item Loaded From Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `2b140a5c-dc02-4bb8-b6b1-8bdb45714cde` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Anish Bogati |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_cpl_from_non_system_location.yml)**

> Detects image load events of system control panel items (.cpl) from uncommon or non-system locations that may indicate DLL sideloading or other abuse techniques.


```sql
-- ============================================================
-- Title:        System Control Panel Item Loaded From Uncommon Location
-- Sigma ID:     2b140a5c-dc02-4bb8-b6b1-8bdb45714cde
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Anish Bogati
-- Date:         2024-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_cpl_from_non_system_location.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\appwiz.cpl' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bthprops.cpl' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\hdwwiz.cpl'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.hexacorn.com/blog/2024/01/06/1-little-known-secret-of-fondue-exe/
- https://www.hexacorn.com/blog/2024/01/01/1-little-known-secret-of-hdwwiz-exe/
- https://github.com/mhaskar/FsquirtCPLPoC
- https://securelist.com/sidewinder-apt/114089/

---

## Potential DLL Sideloading Of DBGCORE.DLL

| Field | Value |
|---|---|
| **Sigma ID** | `9ca2bf31-0570-44d8-a543-534c47c33ed7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_dbgcore.yml)**

> Detects DLL sideloading of "dbgcore.dll"

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of DBGCORE.DLL
-- Sigma ID:     9ca2bf31-0570-44d8-a543-534c47c33ed7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
-- Date:         2022-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_dbgcore.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications loading their own versions of the DLL mentioned in this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbgcore.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications loading their own versions of the DLL mentioned in this rule

**References:**
- https://hijacklibs.net/

---

## Potential DLL Sideloading Of DBGHELP.DLL

| Field | Value |
|---|---|
| **Sigma ID** | `6414b5cd-b19d-447e-bb5e-9f03940b5784` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_dbghelp.yml)**

> Detects potential DLL sideloading of "dbghelp.dll"

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of DBGHELP.DLL
-- Sigma ID:     6414b5cd-b19d-447e-bb5e-9f03940b5784
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
-- Date:         2022-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_dbghelp.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications loading their own versions of the DLL mentioned in this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbghelp.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications loading their own versions of the DLL mentioned in this rule

**References:**
- https://hijacklibs.net/

---

## Potential DLL Sideloading Of DbgModel.DLL

| Field | Value |
|---|---|
| **Sigma ID** | `fef394cd-f44d-4040-9b18-95d92fe278c0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Gary Lobermier |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_dbgmodel.yml)**

> Detects potential DLL sideloading of "DbgModel.dll"

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of DbgModel.DLL
-- Sigma ID:     fef394cd-f44d-4040-9b18-95d92fe278c0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Gary Lobermier
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_dbgmodel.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications loading their own versions of the DLL mentioned in this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbgmodel.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications loading their own versions of the DLL mentioned in this rule

**References:**
- https://hijacklibs.net/entries/microsoft/built-in/dbgmodel.html

---

## Potential EACore.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `edd3ddc3-386f-4ba5-9ada-4376b2cfa7b5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_eacore.yml)**

> Detects potential DLL sideloading of "EACore.dll"

```sql
-- ============================================================
-- Title:        Potential EACore.DLL Sideloading
-- Sigma ID:     edd3ddc3-386f-4ba5-9ada-4376b2cfa7b5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_eacore.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\EACore.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/

---

## Potential Edputil.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `e4903324-1a10-4ed3-981b-f6fe3be3a2c2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_edputil.yml)**

> Detects potential DLL sideloading of "edputil.dll"

```sql
-- ============================================================
-- Title:        Potential Edputil.DLL Sideloading
-- Sigma ID:     e4903324-1a10-4ed3-981b-f6fe3be3a2c2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_edputil.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\edputil.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://alternativeto.net/news/2023/5/cybercriminals-use-wordpad-vulnerability-to-spread-qbot-malware/

---

## Potential System DLL Sideloading From Non System Locations

| Field | Value |
|---|---|
| **Sigma ID** | `4fc0deee-0057-4998-ab31-d24e46e0aba4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_from_non_system_location.yml)**

> Detects DLL sideloading of DLLs usually located in system locations (System32, SysWOW64, etc.).

```sql
-- ============================================================
-- Title:        Potential System DLL Sideloading From Non System Locations
-- Sigma ID:     4fc0deee-0057-4998-ab31-d24e46e0aba4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_from_non_system_location.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications loading their own versions of the DLLs mentioned in this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\aclui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\activeds.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\adsldpc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\aepic.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\apphelp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\applicationframe.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\appvpolicy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\appxalluserstore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\appxdeploymentclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\archiveint.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\atl.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\audioses.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\auditpolcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\authfwcfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\authz.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\avrt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\batmeter.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bcd.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bcp47langs.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bcp47mrm.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bcrypt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bderepair.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bootmenuux.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\bootux.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cabinet.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cabview.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\certcli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\certenroll.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cfgmgr32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cldapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\clipc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\clusapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cmpbk32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cmutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\coloradapterclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\colorui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\comdlg32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\configmanager2.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\connect.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\coredplus.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\coremessaging.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\coreuicomponents.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\credui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptbase.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptdll.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptsp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptxml.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cscapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cscobj.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cscui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d2d1.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d10\_1.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d10\_1core.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d10.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d10core.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d10warp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d11.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d12.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3d9.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\d3dx9\_43.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dataexchange.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\davclnt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dcntel.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dcomp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\defragproxy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\desktopshellext.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\deviceassociation.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\devicecredential.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\devicepairing.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\devobj.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\devrtl.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dhcpcmonitor.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dhcpcsvc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dhcpcsvc6.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\directmanipulation.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dismapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dismcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmcfgutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmcmnutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmcommandlineutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmenrollengine.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmenterprisediagnostics.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmiso8601utils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmoleaututils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmprocessxmlfiltered.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmpushproxy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dmxmlhelputils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dnsapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dot3api.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dot3cfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dpx.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\drprov.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\drvstore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dsclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dsparse.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dsprop.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dsreg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dsrole.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dui70.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\duser.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dusmapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dwmapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dwmcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dwrite.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dxcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dxgi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dxva2.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dynamoapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\eappcfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\eappprxy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\edgeiso.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\edputil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\efsadu.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\efsutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\esent.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\execmodelproxy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\explorerframe.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fastprox.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\faultrep.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fddevquery.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\feclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fhcfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fhsvcctl.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\firewallapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\flightsettings.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fltlib.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\framedynos.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fveapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fveskybackup.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fvewiz.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fwbase.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fwcfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fwpolicyiomgr.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fwpuclnt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fxsapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fxsst.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\fxstiff.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\getuname.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\gpapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\hid.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\hnetmon.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\httpapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\icmp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\idstore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ieadvpack.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iedkcs32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iernonce.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iertutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ifmon.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ifsutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\inproclogger.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iphlpapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iri.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iscsidsc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iscsium.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\isv.exe\_rsaenh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iumbase.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iumsdk.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\joinutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\kdstub.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ksuser.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ktmw32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\licensemanagerapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\licensingdiagspp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\linkinfo.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\loadperf.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\lockhostingframework.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\logoncli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\logoncontroller.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\lpksetupproxyserv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\lrwizdll.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\magnification.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\maintenanceui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mapistub.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mbaexmlparser.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mdmdiagnostics.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mfc42u.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mfcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mfplat.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\midimap.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mintdh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\miutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mlang.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mmdevapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mobilenetworking.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mpr.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mprapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mrmcorer.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msacm32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mscms.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mscoree.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msctf.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msctfmonitor.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msdrm.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msdtctm.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msftedit.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msiso.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msutb.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msvcp110\_win.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mswb7.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mswsock.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msxml3.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mtxclu.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\napinsp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ncrypt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ndfapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netapi32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netid.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netiohlp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netjoin.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netplwiz.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netprofm.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netprovfw.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netsetupapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netshell.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\nettrace.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\netutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\networkexplorer.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\newdev.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ninput.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\nlaapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\nlansp\_c.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\npmproxy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\nshhttp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\nshipsec.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\nshwfp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ntdsapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ntlanman.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ntlmshared.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ntmarta.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ntshrui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\oleacc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\omadmapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\onex.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\opcservices.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\osbaseln.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\osksupport.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\osuninst.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\p2p.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\p2pnetsh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\p9np.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\pcaui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\pdh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\peerdistsh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\pkeyhelper.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\pla.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\playsndsrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\pnrpnsp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\policymanager.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\polstore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\powrprof.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\printui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\prntvpt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\profapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\propsys.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\proximitycommon.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\proximityservicepal.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\prvdmofcomp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\puiapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\radcui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rasapi32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rasdlg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rasgcw.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rasman.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rasmontr.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\reagent.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\regapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\reseteng.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\resetengine.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\resutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rmclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rpcnsh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rsaenh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rtutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rtworkq.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\samcli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\samlib.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sapi\_onecore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sas.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\scansetting.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\scecli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\schedcli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\secur32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\security.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sensapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\shell32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\shfolder.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\slc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\snmpapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\spectrumsyncclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\spp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sppc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sppcext.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\srclient.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\srcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\srmtrace.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\srpapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\srvcli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ssp\_isv.exe\_rsaenh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ssp.exe\_rsaenh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sspicli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ssshim.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\staterepository.core.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\structuredquery.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\sxshared.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\systemsettingsthresholdadminflowui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tapi32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tbs.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tdh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\textshaping.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\timesync.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tpmcoreprovisioning.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tquery.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tsworkspace.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ttdrecord.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\twext.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\twinapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\twinui.appcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\uianimation.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\uiautomationcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\uireng.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\uiribbon.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\umpdc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\unattend.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\updatepolicy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\upshared.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\urlmon.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\userenv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\utildll.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\uxinit.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\uxtheme.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vaultcli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vdsutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\version.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\virtdisk.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vssapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vsstrace.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wbemprox.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wbemsvc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wcmapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wcnnetsh.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wdi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wdscore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\webservices.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wecapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wer.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wevtapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\whhelper.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wimgapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winbio.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winbrand.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\windows.storage.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\windows.storage.search.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\windows.ui.immersive.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\windowscodecs.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\windowscodecsext.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\windowsudk.shellcommon.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winhttp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wininet.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winipsec.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winmde.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winmm.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winnsi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winrnr.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winscard.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winsqlite3.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winsta.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\winsync.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wkscli.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wlanapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wlancfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wldp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wlidprov.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wmiclnt.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wmidcom.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wmiutils.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wmpdui.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wmsgapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wofutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wpdshext.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wscapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wsdapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wshbth.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wshelper.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wsmsvc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wtsapi32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wwancfg.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wwapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\xmllite.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\xolehlp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\xpsservices.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\xwizards.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\xwtpw32.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\amsi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\appraiser.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\COMRES.DLL' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\cryptnet.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\DispBroker.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dsound.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dxilconv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\FxsCompose.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\FXSRESM.DLL' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\msdtcVSp1res.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\PrintIsolationProxy.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rdpendp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rpchttp.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\storageusage.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\utcutil.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\WfsR.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\igd10iumd64.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\igd12umd64.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\igdumdim64.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\igdusc64.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\TSMSISrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\TSVIPSrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wbemcomn.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\WLBSCTRL.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wow64log.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\WptsExtensions.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications loading their own versions of the DLLs mentioned in this rule

**References:**
- https://hijacklibs.net/
- https://blog.cyble.com/2022/07/21/qakbot-resurfaces-with-new-playbook/
- https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/
- https://github.com/XForceIR/SideLoadHunter/blob/cc7ef2e5d8908279b0c4cee4e8b6f85f7b8eed52/SideLoads/README.md
- https://www.hexacorn.com/blog/2023/12/26/1-little-known-secret-of-runonce-exe-32-bit/

---

## Potential Goopdate.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `b6188d2f-b3c4-4d2c-a17d-9706e0851af0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_goopdate.yml)**

> Detects potential DLL sideloading of "goopdate.dll", a DLL used by googleupdate.exe

```sql
-- ============================================================
-- Title:        Potential Goopdate.DLL Sideloading
-- Sigma ID:     b6188d2f-b3c4-4d2c-a17d-9706e0851af0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_goopdate.yml
-- Unmapped:     (none)
-- False Pos:    False positives are expected from Google Chrome installations running from user locations (AppData) and other custom locations. Apply additional filters accordingly.; Other third party chromium browsers located in AppData
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\goopdate.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives are expected from Google Chrome installations running from user locations (AppData) and other custom locations. Apply additional filters accordingly.; Other third party chromium browsers located in AppData

**References:**
- https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf

---

## Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `e49b5745-1064-4ac1-9a2e-f687bc2dd37e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_gup_libcurl.yml)**

> Detects potential DLL sideloading of "libcurl.dll" by the "gup.exe" process from an uncommon location

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE
-- Sigma ID:     e49b5745-1064-4ac1-9a2e-f687bc2dd37e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_gup_libcurl.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\gup.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\libcurl.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://labs.withsecure.com/publications/fin7-target-veeam-servers

---

## Potential Iviewers.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `4c21b805-4dd7-469f-b47d-7383a8fcb437` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_iviewers.yml)**

> Detects potential DLL sideloading of "iviewers.dll" (OLE/COM Object Interface Viewer)

```sql
-- ============================================================
-- Title:        Potential Iviewers.DLL Sideloading
-- Sigma ID:     4c21b805-4dd7-469f-b47d-7383a8fcb437
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-03-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_iviewers.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iviewers.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Windows Kits\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Windows Kits\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.secureworks.com/research/shadowpad-malware-analysis

---

## Potential JLI.dll Side-Loading

| Field | Value |
|---|---|
| **Sigma ID** | `7a3b6d1f-4a2b-4f8c-9d7e-e9f8cbf21a35` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_jli.yml)**

> Detects potential DLL side-loading of jli.dll.
JLI.dll has been observed being side-loaded by Java processes by various threat actors, including APT41, XWorm,
and others in order to load malicious payloads in context of legitimate Java processes.


```sql
-- ============================================================
-- Title:        Potential JLI.dll Side-Loading
-- Sigma ID:     7a3b6d1f-4a2b-4f8c-9d7e-e9f8cbf21a35
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1574.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-07-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_jli.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\jli.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://securelist.com/apt41-in-africa/116986/
- https://lab52.io/blog/snake-keylogger-in-geopolitical-affairs-abuse-of-trusted-java-utilities-in-cybercrime-operations/
- https://hijacklibs.net/entries/3rd_party/oracle/jli.html
- https://www.proofpoint.com/us/blog/threat-insight/phish-china-aligned-espionage-actors-ramp-up-taiwan-semiconductor-targeting

---

## Potential DLL Sideloading Via JsSchHlp

| Field | Value |
|---|---|
| **Sigma ID** | `68654bf0-4412-43d5-bfe8-5eaa393cd939` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_jsschhlp.yml)**

> Detects potential DLL sideloading using JUSTSYSTEMS Japanese word processor

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Via JsSchHlp
-- Sigma ID:     68654bf0-4412-43d5-bfe8-5eaa393cd939
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       frack113
-- Date:         2022-12-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_jsschhlp.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\JSESPR.dll')
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Common Files\\Justsystem\\JsSchHlp\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.welivesecurity.com/2022/12/14/unmasking-mirrorface-operation-liberalface-targeting-japanese-political-entities/
- http://www.windowexe.com/bbs/board.php?q=jsschhlp-exe-c-program-files-common-files-justsystem-jsschhlp-jsschhlp

---

## Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `d2451be2-b582-4e15-8701-4196ac180260` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_keyscrambler.yml)**

> Detects potential DLL side loading of "KeyScramblerIE.dll" by "KeyScrambler.exe".
Various threat actors and malware have been found side loading a masqueraded "KeyScramblerIE.dll" through "KeyScrambler.exe".


```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE
-- Sigma ID:     d2451be2-b582-4e15-8701-4196ac180260
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Swachchhanda Shrawan Poudel
-- Date:         2024-04-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_keyscrambler.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\KeyScrambler.exe' OR procName LIKE '%\\KeyScramblerLogon.exe')
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\KeyScramblerIE.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://thehackernews.com/2024/03/two-chinese-apt-groups-ramp-up-cyber.html
- https://csirt-cti.net/2024/02/01/stately-taurus-continued-new-information-on-cyberespionage-attacks-against-myanmar-military-junta/
- https://bazaar.abuse.ch/sample/5cb9876681f78d3ee8a01a5aaa5d38b05ec81edc48b09e3865b75c49a2187831/
- https://twitter.com/Max_Mal_/status/1775222576639291859
- https://twitter.com/DTCERT/status/1712785426895839339

---

## Potential Libvlc.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `bf9808c4-d24f-44a2-8398-b65227d406b6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_libvlc.yml)**

> Detects potential DLL sideloading of "libvlc.dll", a DLL that is legitimately used by "VLC.exe"

```sql
-- ============================================================
-- Title:        Potential Libvlc.DLL Sideloading
-- Sigma ID:     bf9808c4-d24f-44a2-8398-b65227d406b6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior
-- Date:         2023-04-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_libvlc.yml
-- Unmapped:     (none)
-- False Pos:    False positives are expected if VLC is installed in non-default locations
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\libvlc.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives are expected if VLC is installed in non-default locations

**References:**
- https://www.trendmicro.com/en_us/research/23/c/earth-preta-updated-stealthy-strategies.html
- https://hijacklibs.net/entries/3rd_party/vlc/libvlc.html

---

## Potential Mfdetours.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `d2605a99-2218-4894-8fd3-2afb7946514d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mfdetours.yml)**

> Detects potential DLL sideloading of "mfdetours.dll". While using "mftrace.exe" it can be abused to attach to an arbitrary process and force load any DLL named "mfdetours.dll" from the current directory of execution.

```sql
-- ============================================================
-- Title:        Potential Mfdetours.DLL Sideloading
-- Sigma ID:     d2605a99-2218-4894-8fd3-2afb7946514d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mfdetours.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mfdetours.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research

---

## Unsigned Mfdetours.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `948a0953-f287-4806-bbcb-3b2e396df89f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mfdetours_unsigned.yml)**

> Detects DLL sideloading of unsigned "mfdetours.dll". Executing "mftrace.exe" can be abused to attach to an arbitrary process and force load any DLL named "mfdetours.dll" from the current directory of execution.

```sql
-- ============================================================
-- Title:        Unsigned Mfdetours.DLL Sideloading
-- Sigma ID:     948a0953-f287-4806-bbcb-3b2e396df89f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mfdetours_unsigned.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mfdetours.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research

---

## Potential DLL Sideloading Of MpSvc.DLL

| Field | Value |
|---|---|
| **Sigma ID** | `5ba243e5-8165-4cf7-8c69-e1d3669654c1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mpsvc.yml)**

> Detects potential DLL sideloading of "MpSvc.dll".

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of MpSvc.DLL
-- Sigma ID:     5ba243e5-8165-4cf7-8c69-e1d3669654c1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mpsvc.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications loading their own versions of the DLL mentioned in this rule.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\MpSvc.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications loading their own versions of the DLL mentioned in this rule.

**References:**
- https://hijacklibs.net/entries/microsoft/built-in/mpsvc.html

---

## Potential DLL Sideloading Of MsCorSvc.DLL

| Field | Value |
|---|---|
| **Sigma ID** | `cdb15e19-c2d0-432a-928e-e49c8c60dcf2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Wietze Beukema |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mscorsvc.yml)**

> Detects potential DLL sideloading of "mscorsvc.dll".

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of MsCorSvc.DLL
-- Sigma ID:     cdb15e19-c2d0-432a-928e-e49c8c60dcf2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Wietze Beukema
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_mscorsvc.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications loading their own versions of the DLL mentioned in this rule.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mscorsvc.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications loading their own versions of the DLL mentioned in this rule.

**References:**
- https://hijacklibs.net/entries/microsoft/built-in/mscorsvc.html

---

## Potential DLL Sideloading Of Non-Existent DLLs From System Folders

| Field | Value |
|---|---|
| **Sigma ID** | `6b98b92b-4f00-4f62-b4fe-4d1920215771` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), SBousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_non_existent_dlls.yml)**

> Detects loading of specific system DLL files that are usually not present on the system (or at least not in system directories) but may be loaded by legitimate processes, potentially indicating phantom DLL hijacking attempts.
Phantom DLL hijacking involves placing malicious DLLs with names of non-existent system binaries in locations where legitimate applications may search for them, leading to execution of the malicious DLLs.


```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Of Non-Existent DLLs From System Folders
-- Sigma ID:     6b98b92b-4f00-4f62-b4fe-4d1920215771
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), SBousseaden
-- Date:         2022-12-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_non_existent_dlls.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\axeonoffhelper.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\cdpsgshims.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\oci.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\offdmpsvc.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\shellchromeapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\TSMSISrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\TSVIPSrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\wbem\\wbemcomn.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\WLBSCTRL.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\wow64log.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\System32\\WptsExtensions.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html
- https://clement.notin.org/blog/2020/09/12/CVE-2020-7315-McAfee-Agent-DLL-injection/
- https://decoded.avast.io/martinchlumecky/png-steganography/
- https://github.com/Wh04m1001/SysmonEoP
- https://itm4n.github.io/cdpsvc-dll-hijacking/
- https://posts.specterops.io/lateral-movement-scm-and-dll-hijacking-primer-d2f61e8ab992
- https://securelist.com/passiveneuron-campaign-with-apt-implants-and-cobalt-strike/117745/
- https://www.crowdstrike.com/en-us/blog/4-ways-adversaries-hijack-dlls/
- https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/
- https://www.hexacorn.com/blog/2025/06/14/wermgr-exe-boot-offdmpsvc-dll-lolbin/
- https://www.hexacorn.com/blog/2025/06/14/wpr-exe-boottrace-phantom-dll-axeonoffhelper-dll-lolbin/
- https://x.com/0gtweet/status/1564131230941122561

---

## Microsoft Office DLL Sideload

| Field | Value |
|---|---|
| **Sigma ID** | `829a3bdf-34da-4051-9cf4-8ed221a8ae4f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_office_dlls.yml)**

> Detects DLL sideloading of DLLs that are part of Microsoft Office from non standard location

```sql
-- ============================================================
-- Title:        Microsoft Office DLL Sideload
-- Sigma ID:     829a3bdf-34da-4051-9cf4-8ed221a8ae4f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
-- Date:         2022-08-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_office_dlls.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\outllib.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Microsoft Office\\OFFICE%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Microsoft Office\\OFFICE%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Microsoft Office\\Root\\OFFICE%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Microsoft Office\\Root\\OFFICE%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://hijacklibs.net/

---

## Potential Python DLL SideLoading

| Field | Value |
|---|---|
| **Sigma ID** | `d36f7c12-14a3-4d48-b6b8-774b9c66f44d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_python.yml)**

> Detects potential DLL sideloading of Python DLL files.

```sql
-- ============================================================
-- Title:        Potential Python DLL SideLoading
-- Sigma ID:     d36f7c12-14a3-4d48-b6b8-774b9c66f44d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Swachchhanda Shrawan Poudel
-- Date:         2024-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_python.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software using Python DLLs
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\python39.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\python310.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\python311.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\python312.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software using Python DLLs

**References:**
- https://www.securonix.com/blog/seolurker-attack-campaign-uses-seo-poisoning-fake-google-ads-to-install-malware/
- https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/
- https://github.com/wietze/HijackLibs/tree/dc9c9f2f94e6872051dab58fbafb043fdd8b4176/yml/3rd_party/python

---

## Potential Rcdll.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `6e78b74f-c762-4800-82ad-f66787f10c8a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rcdll.yml)**

> Detects potential DLL sideloading of rcdll.dll

```sql
-- ============================================================
-- Title:        Potential Rcdll.DLL Sideloading
-- Sigma ID:     6e78b74f-c762-4800-82ad-f66787f10c8a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-03-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rcdll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\rcdll.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Microsoft Visual Studio\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Windows Kits\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html

---

## Potential RjvPlatform.DLL Sideloading From Default Location

| Field | Value |
|---|---|
| **Sigma ID** | `259dda31-b7a3-444f-b7d8-17f96e8a7d0d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rjvplatform_default_location.yml)**

> Detects loading of "RjvPlatform.dll" by the "SystemResetPlatform.exe" binary which can be abused as a method of DLL side loading since the "$SysReset" directory isn't created by default.

```sql
-- ============================================================
-- Title:        Potential RjvPlatform.DLL Sideloading From Default Location
-- Sigma ID:     259dda31-b7a3-444f-b7d8-17f96e8a7d0d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rjvplatform_default_location.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = 'C:\Windows\System32\SystemResetPlatform\SystemResetPlatform.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] = 'C:\$SysReset\Framework\Stack\RjvPlatform.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/0gtweet/status/1666716511988330499

---

## Potential RjvPlatform.DLL Sideloading From Non-Default Location

| Field | Value |
|---|---|
| **Sigma ID** | `0e0bc253-07ed-43f1-816d-e1b220fe8971` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rjvplatform_non_default_location.yml)**

> Detects potential DLL sideloading of "RjvPlatform.dll" by "SystemResetPlatform.exe" located in a non-default location.

```sql
-- ============================================================
-- Title:        Potential RjvPlatform.DLL Sideloading From Non-Default Location
-- Sigma ID:     0e0bc253-07ed-43f1-816d-e1b220fe8971
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rjvplatform_non_default_location.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\RjvPlatform.dll')
    AND procName = '\SystemResetPlatform.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/0gtweet/status/1666716511988330499

---

## Potential RoboForm.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `f64c9b2d-b0ad-481d-9d03-7fc75020892a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_robform.yml)**

> Detects potential DLL sideloading of "roboform.dll", a DLL used by RoboForm Password Manager

```sql
-- ============================================================
-- Title:        Potential RoboForm.DLL Sideloading
-- Sigma ID:     f64c9b2d-b0ad-481d-9d03-7fc75020892a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_robform.yml
-- Unmapped:     (none)
-- False Pos:    If installed on a per-user level, the path would be located in "AppData\Local". Add additional filters to reflect this mode of installation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\roboform.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\roboform-x64.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If installed on a per-user level, the path would be located in "AppData\Local". Add additional filters to reflect this mode of installation

**References:**
- https://twitter.com/StopMalvertisin/status/1648604148848549888
- https://twitter.com/t3ft3lb/status/1656194831830401024
- https://www.roboform.com/

---

## DLL Sideloading Of ShellChromeAPI.DLL

| Field | Value |
|---|---|
| **Sigma ID** | `ee4c5d06-3abc-48cc-8885-77f1c20f4451` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_shell_chrome_api.yml)**

> Detects processes loading the non-existent DLL "ShellChromeAPI". One known example is the "DeviceEnroller" binary in combination with the "PhoneDeepLink" flag tries to load this DLL.
Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter


```sql
-- ============================================================
-- Title:        DLL Sideloading Of ShellChromeAPI.DLL
-- Sigma ID:     ee4c5d06-3abc-48cc-8885-77f1c20f4451
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_shell_chrome_api.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ShellChromeAPI.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://mobile.twitter.com/0gtweet/status/1564131230941122561
- https://strontic.github.io/xcyclopedia/library/DeviceEnroller.exe-24BEF0D6B0ECED36BB41831759FDE18D.html

---

## Potential ShellDispatch.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `844f8eb2-610b-42c8-89a4-47596e089663` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_shelldispatch.yml)**

> Detects potential DLL sideloading of "ShellDispatch.dll"

```sql
-- ============================================================
-- Title:        Potential ShellDispatch.DLL Sideloading
-- Sigma ID:     844f8eb2-610b-42c8-89a4-47596e089663
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_shelldispatch.yml
-- Unmapped:     (none)
-- False Pos:    Some installers may trigger some false positives
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ShellDispatch.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some installers may trigger some false positives

**References:**
- https://www.hexacorn.com/blog/2023/06/07/this-lolbin-doesnt-exist/

---

## Potential SmadHook.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `24b6cf51-6122-469e-861a-22974e9c1e5b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_smadhook.yml)**

> Detects potential DLL sideloading of "SmadHook.dll", a DLL used by SmadAV antivirus

```sql
-- ============================================================
-- Title:        Potential SmadHook.DLL Sideloading
-- Sigma ID:     24b6cf51-6122-469e-861a-22974e9c1e5b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_smadhook.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\SmadHook32c.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\SmadHook64c.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://research.checkpoint.com/2023/malware-spotlight-camaro-dragons-tinynote-backdoor/
- https://www.qurium.org/alerts/targeted-malware-against-crph/

---

## Potential SolidPDFCreator.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `a2edbce1-95c8-4291-8676-0d45146862b3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_solidpdfcreator.yml)**

> Detects potential DLL sideloading of "SolidPDFCreator.dll"

```sql
-- ============================================================
-- Title:        Potential SolidPDFCreator.DLL Sideloading
-- Sigma ID:     a2edbce1-95c8-4291-8676-0d45146862b3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-05-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_solidpdfcreator.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\SolidPDFCreator.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lab52.io/blog/new-mustang-pandas-campaing-against-australia/

---

## Third Party Software DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `f9df325d-d7bc-4a32-8a1a-2cc61dcefc63` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_third_party.yml)**

> Detects DLL sideloading of DLLs that are part of third party software (zoom, discord....etc)

```sql
-- ============================================================
-- Title:        Third Party Software DLL Sideloading
-- Sigma ID:     f9df325d-d7bc-4a32-8a1a-2cc61dcefc63
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
-- Date:         2022-08-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_third_party.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\commfunc.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\AppData\\local\\Google\\Chrome\\Application\\%'))
  OR ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Lenovo\\Communications Utility\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Lenovo\\Communications Utility\\%')))))
  OR (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\tosbtkbd.dll')
  AND NOT ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\Toshiba\\Bluetooth Toshiba Stack\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files (x86)\\Toshiba\\Bluetooth Toshiba Stack\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://hijacklibs.net/

---

## Fax Service DLL Search Order Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `828af599-4c53-4ed2-ba4a-a9f835c434ea` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | NVISO |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_ualapi.yml)**

> The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.

```sql
-- ============================================================
-- Title:        Fax Service DLL Search Order Hijack
-- Sigma ID:     828af599-4c53-4ed2-ba4a-a9f835c434ea
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       NVISO
-- Date:         2020-05-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_ualapi.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\fxssvc.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%ualapi.dll'))
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Windows\\WinSxS\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://windows-internals.com/faxing-your-way-to-system/

---

## Potential Vivaldi_elf.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `2092cacb-d77b-4f98-ab0d-32b32f99a054` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vivaldi_elf.yml)**

> Detects potential DLL sideloading of "vivaldi_elf.dll"

```sql
-- ============================================================
-- Title:        Potential Vivaldi_elf.DLL Sideloading
-- Sigma ID:     2092cacb-d77b-4f98-ab0d-32b32f99a054
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vivaldi_elf.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vivaldi\_elf.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/

---

## VMGuestLib DLL Sideload

| Field | Value |
|---|---|
| **Sigma ID** | `70e8e9b4-6a93-4cb7-8cde-da69502e7aff` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmguestlib.yml)**

> Detects DLL sideloading of VMGuestLib.dll by the WmiApSrv service.

```sql
-- ============================================================
-- Title:        VMGuestLib DLL Sideload
-- Sigma ID:     70e8e9b4-6a93-4cb7-8cde-da69502e7aff
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmguestlib.yml
-- Unmapped:     Signed
-- False Pos:    FP could occur if the legitimate version of vmGuestLib already exists on the system
-- ============================================================
-- UNMAPPED_FIELD: Signed

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\VMware\\VMware Tools\\vmStatsProvider\\win32%' AND metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vmGuestLib.dll%')
    AND procName LIKE '%\\Windows\\System32\\wbem\\WmiApSrv.exe')
  AND NOT (rawEventMsg = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** FP could occur if the legitimate version of vmGuestLib already exists on the system

**References:**
- https://decoded.avast.io/martinchlumecky/png-steganography/

---

## VMMap Signed Dbghelp.DLL Potential Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `98ffaed4-aec2-4e04-9b07-31492fe68b3d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmmap_dbghelp_signed.yml)**

> Detects potential DLL sideloading of a signed dbghelp.dll by the Sysinternals VMMap.

```sql
-- ============================================================
-- Title:        VMMap Signed Dbghelp.DLL Potential Sideloading
-- Sigma ID:     98ffaed4-aec2-4e04-9b07-31492fe68b3d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-09-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmmap_dbghelp_signed.yml
-- Unmapped:     Signed
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Signed

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%C:\\Debuggers\\dbghelp.dll%')
    AND (procName LIKE '%\\vmmap.exe' OR procName LIKE '%\\vmmap64.exe')
    AND rawEventMsg = 'true')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://techcommunity.microsoft.com/t5/sysinternals-blog/zoomit-v7-1-procdump-2-0-for-linux-process-explorer-v17-05/ba-p/3884766

---

## VMMap Unsigned Dbghelp.DLL Potential Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `273a8dd8-3742-4302-bcc7-7df5a80fe425` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmmap_dbghelp_unsigned.yml)**

> Detects potential DLL sideloading of an unsigned dbghelp.dll by the Sysinternals VMMap.

```sql
-- ============================================================
-- Title:        VMMap Unsigned Dbghelp.DLL Potential Sideloading
-- Sigma ID:     273a8dd8-3742-4302-bcc7-7df5a80fe425
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmmap_dbghelp_unsigned.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%C:\\Debuggers\\dbghelp.dll%')
    AND (procName LIKE '%\\vmmap.exe' OR procName LIKE '%\\vmmap64.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://techcommunity.microsoft.com/t5/sysinternals-blog/zoomit-v7-1-procdump-2-0-for-linux-process-explorer-v17-05/ba-p/3884766

---

## Potential DLL Sideloading Via VMware Xfer

| Field | Value |
|---|---|
| **Sigma ID** | `9313dc13-d04c-46d8-af4a-a930cc55d93b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmware_xfer.yml)**

> Detects loading of a DLL by the VMware Xfer utility from the non-default directory which may be an attempt to sideload arbitrary DLL

```sql
-- ============================================================
-- Title:        Potential DLL Sideloading Via VMware Xfer
-- Sigma ID:     9313dc13-d04c-46d8-af4a-a930cc55d93b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_vmware_xfer.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\VMwareXferlogs.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\glib-2.0.dll'))
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Program Files\\VMware\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/

---

## Potential Waveedit.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `71b31e99-9ad0-47d4-aeb5-c0ca3928eeeb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_waveedit.yml)**

> Detects potential DLL sideloading of "waveedit.dll", which is part of the Nero WaveEditor audio editing software.

```sql
-- ============================================================
-- Title:        Potential Waveedit.DLL Sideloading
-- Sigma ID:     71b31e99-9ad0-47d4-aeb5-c0ca3928eeeb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-06-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_waveedit.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\waveedit.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.trendmicro.com/en_us/research/23/f/behind-the-scenes-unveiling-the-hidden-workings-of-earth-preta.html

---

## Potential Wazuh Security Platform DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `db77ce78-7e28-4188-9337-cf30e2b3ba9f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_wazuh.yml)**

> Detects potential DLL side loading of DLLs that are part of the Wazuh security platform

```sql
-- ============================================================
-- Title:        Potential Wazuh Security Platform DLL Sideloading
-- Sigma ID:     db77ce78-7e28-4188-9337-cf30e2b3ba9f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-03-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_wazuh.yml
-- Unmapped:     (none)
-- False Pos:    Many legitimate applications leverage this DLL. (Visual Studio, JetBrains, Ruby, Anaconda, GithubDesktop, etc.)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\libwazuhshared.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\libwinpthread-1.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Many legitimate applications leverage this DLL. (Visual Studio, JetBrains, Ruby, Anaconda, GithubDesktop, etc.)

**References:**
- https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html

---

## Potential Mpclient.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `418dc89a-9808-4b87-b1d7-e5ae0cb6effc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_windows_defender.yml)**

> Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.

```sql
-- ============================================================
-- Title:        Potential Mpclient.DLL Sideloading
-- Sigma ID:     418dc89a-9808-4b87-b1d7-e5ae0cb6effc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Bhabesh Raj
-- Date:         2022-08-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_windows_defender.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mpclient.dll')
    AND (procName LIKE '%\\MpCmdRun.exe' OR procName LIKE '%\\NisSrv.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool

---

## Potential WWlib.DLL Sideloading

| Field | Value |
|---|---|
| **Sigma ID** | `e2e01011-5910-4267-9c3b-4149ed5479cf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_wwlib.yml)**

> Detects potential DLL sideloading of "wwlib.dll"

```sql
-- ============================================================
-- Title:        Potential WWlib.DLL Sideloading
-- Sigma ID:     e2e01011-5910-4267-9c3b-4149ed5479cf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-05-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_wwlib.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wwlib.dll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/WhichbufferArda/status/1658829954182774784
- https://news.sophos.com/en-us/2022/11/03/family-tree-dll-sideloading-cases-may-be-related/
- https://securelist.com/apt-luminousmoth/103332/

---

## BaaUpdate.exe Suspicious DLL Load

| Field | Value |
|---|---|
| **Sigma ID** | `6e8fe0a8-ba0b-4a93-8f9e-82657e7a5984` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218, T1021.003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_baaupdate_dll_load.yml)**

> Detects BitLocker Access Agent Update Utility (baaupdate.exe) loading DLLs from suspicious locations that are publicly writable which could indicate an attempt to lateral movement via BitLocker DCOM & COM Hijacking.
This technique abuses COM Classes configured as INTERACTIVE USER to spawn processes in the context of the logged-on user's session. Specifically, it targets the BDEUILauncher Class (CLSID ab93b6f1-be76-4185-a488-a9001b105b94)
which can launch BaaUpdate.exe, which is vulnerable to COM Hijacking when started with input parameters. This allows attackers to execute code in the user's context without needing to steal credentials or use additional techniques to compromise the account.


```sql
-- ============================================================
-- Title:        BaaUpdate.exe Suspicious DLL Load
-- Sigma ID:     6e8fe0a8-ba0b-4a93-8f9e-82657e7a5984
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1218, T1021.003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_baaupdate_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\BaaUpdate.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%.dll')
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Perflogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Users\\Default\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\AppData\\Roaming\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Contacts\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Favorites\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Favourites\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Links\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Music\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Pictures\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Temporary Internet%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\Videos\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/rtecCyberSec/BitlockMove

---

## Unsigned Module Loaded by ClickOnce Application

| Field | Value |
|---|---|
| **Sigma ID** | `060d5ad4-3153-47bb-8382-43e5e29eda92` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | @SerkinValery |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_clickonce_unsigned_module_loaded.yml)**

> Detects unsigned module load by ClickOnce application.

```sql
-- ============================================================
-- Title:        Unsigned Module Loaded by ClickOnce Application
-- Sigma ID:     060d5ad4-3153-47bb-8382-43e5e29eda92
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       @SerkinValery
-- Date:         2023-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_clickonce_unsigned_module_loaded.yml
-- Unmapped:     Signed
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: Signed

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'signatureStatus')] AS signatureStatus,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\AppData\\Local\\Apps\\2.0\\%'
  AND (rawEventMsg = 'false')
  OR (indexOf(metrics_string.name, 'signatureStatus') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signatureStatus')] = 'Expired')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5

---

## DLL Load By System Process From Suspicious Locations

| Field | Value |
|---|---|
| **Sigma ID** | `9e9a9002-56c4-40fd-9eff-e4b09bfa5f6c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_dll_load_system_process.yml)**

> Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as "C:\Users\Public"

```sql
-- ============================================================
-- Title:        DLL Load By System Process From Suspicious Locations
-- Sigma ID:     9e9a9002-56c4-40fd-9eff-e4b09bfa5f6c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_dll_load_system_process.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE 'C:\\Windows\\%'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE 'C:\\PerfLogs\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC (Idea)

---

## Python Image Load By Non-Python Process

| Field | Value |
|---|---|
| **Sigma ID** | `cbb56d62-4060-40f7-9466-d8aaf3123f83` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027.002 |
| **Author** | Patrick St. John, OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_python_image_load.yml)**

> Detects the image load of "Python Core" by a non-Python process. This might be indicative of a execution of executable that has been bundled from Python code.
Various tools like Py2Exe, PyInstaller, and cx_Freeze are used to bundle Python code into standalone executables.
Threat actors often use these tools to bundle malicious Python scripts into executables, sometimes to obfuscate the code or to bypass security measures.


```sql
-- ============================================================
-- Title:        Python Image Load By Non-Python Process
-- Sigma ID:     cbb56d62-4060-40f7-9466-d8aaf3123f83
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027.002
-- Author:       Patrick St. John, OTR (Open Threat Research)
-- Date:         2020-05-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_python_image_load.yml
-- Unmapped:     Description
-- False Pos:    Legitimate Py2Exe Binaries; Known false positive caused with Python Anaconda; Various legitimate software is bundled from Python code into executables
-- ============================================================
-- UNMAPPED_FIELD: Description

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Python Core'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Py2Exe Binaries; Known false positive caused with Python Anaconda; Various legitimate software is bundled from Python code into executables

**References:**
- https://www.py2exe.org/
- https://unit42.paloaltonetworks.com/unit-42-technical-analysis-seaduke/

---

## DotNet CLR DLL Loaded By Scripting Applications

| Field | Value |
|---|---|
| **Sigma ID** | `4508a70e-97ef-4300-b62b-ff27992990ea` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1055 |
| **Author** | omkar72, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_script_dotnet_clr_dll_load.yml)**

> Detects .NET CLR DLLs being loaded by scripting applications such as wscript or cscript. This could be an indication of potential suspicious execution.

```sql
-- ============================================================
-- Title:        DotNet CLR DLL Loaded By Scripting Applications
-- Sigma ID:     4508a70e-97ef-4300-b62b-ff27992990ea
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1055
-- Author:       omkar72, oscd.community
-- Date:         2020-10-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_script_dotnet_clr_dll_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\cmstp.exe' OR procName LIKE '%\\cscript.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\msxsl.exe' OR procName LIKE '%\\regsvr32.exe' OR procName LIKE '%\\wmic.exe' OR procName LIKE '%\\wscript.exe')
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\clr.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mscoree.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\mscorlib.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/tyranid/DotNetToJScript
- https://thewover.github.io/Introducing-Donut/
- https://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html
- https://web.archive.org/web/20221026202428/https://gist.github.com/code-scrap/d7f152ffcdb3e0b02f7f394f5187f008

---

## Unsigned DLL Loaded by Windows Utility

| Field | Value |
|---|---|
| **Sigma ID** | `b5de0c9a-6f19-43e0-af4e-55ad01f550af` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218.011, T1218.010 |
| **Author** | Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_unsigned_dll.yml)**

> Detects windows utilities loading an unsigned or untrusted DLL.
Adversaries often abuse those programs to proxy execution of malicious code.


```sql
-- ============================================================
-- Title:        Unsigned DLL Loaded by Windows Utility
-- Sigma ID:     b5de0c9a-6f19-43e0-af4e-55ad01f550af
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218.011, T1218.010
-- Author:       Swachchhanda Shrawan Poudel
-- Date:         2024-02-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_susp_unsigned_dll.yml
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
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\InstallUtil.exe' OR procName LIKE '%\\RegAsm.exe' OR procName LIKE '%\\RegSvcs.exe' OR procName LIKE '%\\regsvr32.exe' OR procName LIKE '%\\rundll32.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion
- https://akhere.hashnode.dev/hunting-unsigned-dlls-using-kql
- https://unit42.paloaltonetworks.com/unsigned-dlls/?web_view=true

---

## Suspicious Unsigned Thor Scanner Execution

| Field | Value |
|---|---|
| **Sigma ID** | `ea5c131b-380d-49f9-aeb3-920694da4d4b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_thor_unsigned_execution.yml)**

> Detects loading and execution of an unsigned thor scanner binary.

```sql
-- ============================================================
-- Title:        Suspicious Unsigned Thor Scanner Execution
-- Sigma ID:     ea5c131b-380d-49f9-aeb3-920694da4d4b
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-10-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_thor_unsigned_execution.yml
-- Unmapped:     Signed
-- False Pos:    Other legitimate binaries named "thor.exe" that aren't published by Nextron Systems
-- ============================================================
-- UNMAPPED_FIELD: Signed

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  metrics_string.value[indexOf(metrics_string.name,'signatureStatus')] AS signatureStatus,
  metrics_string.value[indexOf(metrics_string.name,'signature')] AS signature,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((procName LIKE '%\\thor.exe' OR procName LIKE '%\\thor64.exe')
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\thor.exe' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\thor64.exe')))
  AND NOT ((rawEventMsg = 'true'
    AND indexOf(metrics_string.name, 'signatureStatus') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signatureStatus')] = 'valid')
    AND indexOf(metrics_string.name, 'signature') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'signature')] = 'Nextron Systems GmbH'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legitimate binaries named "thor.exe" that aren't published by Nextron Systems

**References:**
- Internal Research

---

## UAC Bypass Using Iscsicpl - ImageLoad

| Field | Value |
|---|---|
| **Sigma ID** | `9ed5959a-c43c-4c59-84e3-d28628429456` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_uac_bypass_iscsicpl.yml)**

> Detects the "iscsicpl.exe" UAC bypass technique that leverages a DLL Search Order hijacking technique to load a custom DLL's from temp or a any user controlled location in the users %PATH%

```sql
-- ============================================================
-- Title:        UAC Bypass Using Iscsicpl - ImageLoad
-- Sigma ID:     9ed5959a-c43c-4c59-84e3-d28628429456
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_uac_bypass_iscsicpl.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName = 'C:\Windows\SysWOW64\iscsicpl.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\iscsiexe.dll'))
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%C:\\Windows\\%' AND metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%iscsiexe.dll%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
- https://twitter.com/wdormann/status/1547583317410607110

---

## UAC Bypass With Fake DLL

| Field | Value |
|---|---|
| **Sigma ID** | `a5ea83a7-05a5-44c1-be2e-addccbbd8c03` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548.002, T1574.001 |
| **Author** | oscd.community, Dmitry Uchakin |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_uac_bypass_via_dism.yml)**

> Attempts to load dismcore.dll after dropping it

```sql
-- ============================================================
-- Title:        UAC Bypass With Fake DLL
-- Sigma ID:     a5ea83a7-05a5-44c1-be2e-addccbbd8c03
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1548.002, T1574.001
-- Author:       oscd.community, Dmitry Uchakin
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_uac_bypass_via_dism.yml
-- Unmapped:     (none)
-- False Pos:    Actions of a legitimate telnet client
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\dism.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dismcore.dll'))
  AND NOT (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] = 'C:\Windows\System32\Dism\dismcore.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Actions of a legitimate telnet client

**References:**
- https://steemit.com/utopian-io/@ah101/uac-bypassing-utility

---

## MMC Loading Script Engines DLLs

| Field | Value |
|---|---|
| **Sigma ID** | `a9c73e8b-3b2d-4c45-8ef2-5f9a9c9998ad` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.005, T1218.014 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_mmc_loads_script_engine_dll.yml)**

> Detects when the Microsoft Management Console (MMC) loads the DLL libraries like vbscript, jscript etc which might indicate an attempt
to execute malicious scripts within a trusted system process for bypassing application whitelisting or defense evasion.


```sql
-- ============================================================
-- Title:        MMC Loading Script Engines DLLs
-- Sigma ID:     a9c73e8b-3b2d-4c45-8ef2-5f9a9c9998ad
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution | T1059.005, T1218.014
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-02-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_mmc_loads_script_engine_dll.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate MMC operations or extensions loading these libraries
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\mmc.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vbscript.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\jscript.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\jscript9.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate MMC operations or extensions loading these libraries

**References:**
- https://tria.ge/241015-l98snsyeje/behavioral2
- https://www.elastic.co/security-labs/grimresource

---

## Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `416bc4a2-7217-4519-8dc7-c3271817f1d5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003, T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_susp_dbgcore_dbghelp_load.yml)**

> Detects loading of dbgcore.dll or dbghelp.dll from uncommon locations such as user directories.
These DLLs contain the MiniDumpWriteDump function, which can be abused for credential dumping purposes or in some cases for evading EDR/AV detection by suspending processes.


```sql
-- ============================================================
-- Title:        Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location
-- Sigma ID:     416bc4a2-7217-4519-8dc7-c3271817f1d5
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1003, T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_susp_dbgcore_dbghelp_load.yml
-- Unmapped:     (none)
-- False Pos:    Possibly during software installation or update processes
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbgcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbghelp.dll'))
  AND (procName LIKE '%:\\Perflogs\\%' OR procName LIKE '%:\\Temp\\%' OR procName LIKE '%:\\Users\\Public\\%' OR procName LIKE '%\\$Recycle.Bin\\%' OR procName LIKE '%\\Contacts\\%' OR procName LIKE '%\\Desktop\\%' OR procName LIKE '%\\Documents\\%' OR procName LIKE '%\\Downloads\\%' OR procName LIKE '%\\Favorites\\%' OR procName LIKE '%\\Favourites\\%' OR procName LIKE '%\\inetpub\\wwwroot\\%' OR procName LIKE '%\\Music\\%' OR procName LIKE '%\\Pictures\\%' OR procName LIKE '%\\Start Menu\\Programs\\Startup\\%' OR procName LIKE '%\\Users\\Default\\%' OR procName LIKE '%\\Videos\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Possibly during software installation or update processes

**References:**
- https://blog.axelarator.net/hunting-for-edr-freeze/
- https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html
- https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html

---

## Trusted Path Bypass via Windows Directory Spoofing

| Field | Value |
|---|---|
| **Sigma ID** | `0cbe38c0-270c-41d9-ab79-6e5a9a669290` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.007, T1548.002 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_trusted_path_bypass.yml)**

> Detects DLLs loading from a spoofed Windows directory path with an extra space (e.g "C:\Windows \System32") which can bypass Windows trusted path verification.
This technique tricks Windows into treating the path as trusted, allowing malicious DLLs to load with high integrity privileges bypassing UAC.


```sql
-- ============================================================
-- Title:        Trusted Path Bypass via Windows Directory Spoofing
-- Sigma ID:     0cbe38c0-270c-41d9-ab79-6e5a9a669290
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1574.007, T1548.002
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_trusted_path_bypass.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows \\System32\\%' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%:\\Windows \\SysWOW64\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://x.com/Wietze/status/1933495426952421843

---

## WerFaultSecure Loading DbgCore or DbgHelp - EDR-Freeze

| Field | Value |
|---|---|
| **Sigma ID** | `8a2f4b1c-3d5e-4f7a-9b2c-1e4f6d8a9c2b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_werfaultsecure_dbgcore_dbghelp_load.yml)**

> Detects WerFaultSecure.exe loading dbgcore.dll or dbghelp.dll which contains the MiniDumpWriteDump function.
The MiniDumpWriteDump function creates a minidump of a process by suspending all threads in the target process to ensure a consistent memory snapshot.
The EDR-Freeze technique abuses WerFaultSecure.exe running as a Protected Process Light (PPL) with WinTCB protection level to suspend EDR/AV processes.
By leveraging MiniDumpWriteDump's thread suspension behavior, edr-freeze allows malicious activity to execute undetected during the suspension period.


```sql
-- ============================================================
-- Title:        WerFaultSecure Loading DbgCore or DbgHelp - EDR-Freeze
-- Sigma ID:     8a2f4b1c-3d5e-4f7a-9b2c-1e4f6d8a9c2b
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_werfaultsecure_dbgcore_dbghelp_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\WerFaultSecure.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbgcore.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\dbghelp.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/TwoSevenOneT/EDR-Freeze
- https://blog.axelarator.net/hunting-for-edr-freeze/

---

## WMI Persistence - Command Line Event Consumer

| Field | Value |
|---|---|
| **Sigma ID** | `05936ce2-ee05-4dae-9d03-9a391cf2d2c6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wmi_persistence_commandline_event_consumer.yml)**

> Detects WMI command line event consumers

```sql
-- ============================================================
-- Title:        WMI Persistence - Command Line Event Consumer
-- Sigma ID:     05936ce2-ee05-4dae-9d03-9a391cf2d2c6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       Thomas Patzke
-- Date:         2018-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wmi_persistence_commandline_event_consumer.yml
-- Unmapped:     (none)
-- False Pos:    Unknown (data set is too small; further testing needed)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = 'C:\Windows\System32\wbem\WmiPrvSE.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wbemcons.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown (data set is too small; further testing needed)

**References:**
- https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/

---

## WMIC Loading Scripting Libraries

| Field | Value |
|---|---|
| **Sigma ID** | `06ce37c2-61ab-4f05-9ff5-b1a96d18ae32` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1220 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.yml)**

> Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc).
It could be an indicator of SquiblyTwo technique, which uses Windows Management Instrumentation (WMI) to execute malicious code.


```sql
-- ============================================================
-- Title:        WMIC Loading Scripting Libraries
-- Sigma ID:     06ce37c2-61ab-4f05-9ff5-b1a96d18ae32
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1220
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.yml
-- Unmapped:     (none)
-- False Pos:    The command wmic os get lastbootuptime loads vbscript.dll; The command wmic os get locale loads vbscript.dll; Since the ImageLoad event doesn't have enough information in this case. It's better to look at the recent process creation events that spawned the WMIC process and investigate the command line and parent/child processes to get more insights; The command `wmic ntevent` loads vbscript.dll
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\wmic.exe'
    AND (indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\jscript.dll' OR metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\vbscript.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The command wmic os get lastbootuptime loads vbscript.dll; The command wmic os get locale loads vbscript.dll; Since the ImageLoad event doesn't have enough information in this case. It's better to look at the recent process creation events that spawned the WMIC process and investigate the command line and parent/child processes to get more insights; The command `wmic ntevent` loads vbscript.dll

**References:**
- https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-201017061100.html
- https://twitter.com/dez_/status/986614411711442944
- https://lolbas-project.github.io/lolbas/Binaries/Wmic/

---

## Wmiprvse Wbemcomn DLL Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `7707a579-e0d8-4886-a853-ce47e4575aaa` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047, T1021.002 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wmiprvse_wbemcomn_dll_hijack.yml)**

> Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.

```sql
-- ============================================================
-- Title:        Wmiprvse Wbemcomn DLL Hijack
-- Sigma ID:     7707a579-e0d8-4886-a853-ce47e4575aaa
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1047, T1021.002
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wmiprvse_wbemcomn_dll_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] AS imageLoaded,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\wmiprvse.exe'
    AND indexOf(metrics_string.name, 'imageLoaded') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'imageLoaded')] LIKE '%\\wbem\\wbemcomn.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html

---

## Suspicious WSMAN Provider Image Loads

| Field | Value |
|---|---|
| **Sigma ID** | `ad1f4bb9-8dfb-4765-adb6-2a7cfb6c0f94` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1021.003 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wsman_provider_image_load.yml)**

> Detects signs of potential use of the WSMAN provider from uncommon processes locally and remote execution.

```sql
-- ============================================================
-- Title:        Suspicious WSMAN Provider Image Loads
-- Sigma ID:     ad1f4bb9-8dfb-4765-adb6-2a7cfb6c0f94
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059.001, T1021.003
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_wsman_provider_image_load.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-7-Image-Load')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/chadtilbury/status/1275851297770610688
- https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
- https://learn.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-architecture
- https://github.com/bohops/WSMan-WinRM

---
