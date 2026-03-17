# Sigma → FortiSIEM: Windows File Event

> 165 rules · Generated 2026-03-17

## Table of Contents

- [ADSI-Cache File Creation By Uncommon Tool](#adsi-cache-file-creation-by-uncommon-tool)
- [Advanced IP Scanner - File Event](#advanced-ip-scanner-file-event)
- [Anydesk Temporary Artefact](#anydesk-temporary-artefact)
- [Suspicious Binary Writes Via AnyDesk](#suspicious-binary-writes-via-anydesk)
- [Suspicious File Created by ArcSOC.exe](#suspicious-file-created-by-arcsocexe)
- [Assembly DLL Creation Via AspNetCompiler](#assembly-dll-creation-via-aspnetcompiler)
- [BloodHound Collection Files](#bloodhound-collection-files)
- [Potentially Suspicious File Creation by OpenEDR's ITSMService](#potentially-suspicious-file-creation-by-openedrs-itsmservice)
- [EVTX Created In Uncommon Location](#evtx-created-in-uncommon-location)
- [Creation Of Non-Existent System DLL](#creation-of-non-existent-system-dll)
- [Suspicious Deno File Written from Remote Source](#suspicious-deno-file-written-from-remote-source)
- [New Custom Shim Database Created](#new-custom-shim-database-created)
- [Suspicious Screensaver Binary File Creation](#suspicious-screensaver-binary-file-creation)
- [Files With System DLL Name In Unsuspected Locations](#files-with-system-dll-name-in-unsuspected-locations)
- [Files With System Process Name In Unsuspected Locations](#files-with-system-process-name-in-unsuspected-locations)
- [Creation Exe for Service with Unquoted Path](#creation-exe-for-service-with-unquoted-path)
- [Cred Dump Tools Dropped Files](#cred-dump-tools-dropped-files)
- [WScript or CScript Dropper - File](#wscript-or-cscript-dropper-file)
- [CSExec Service File Creation](#csexec-service-file-creation)
- [Dynamic CSharp Compile Artefact](#dynamic-csharp-compile-artefact)
- [Potential DCOM InternetExplorer.Application DLL Hijack](#potential-dcom-internetexplorerapplication-dll-hijack)
- [Desktop.INI Created by Uncommon Process](#desktopini-created-by-uncommon-process)
- [DLL Search Order Hijackig Via Additional Space in Path](#dll-search-order-hijackig-via-additional-space-in-path)
- [Potentially Suspicious DMP/HDMP File Creation](#potentially-suspicious-dmphdmp-file-creation)
- [Potential Persistence Attempt Via ErrorHandler.Cmd](#potential-persistence-attempt-via-errorhandlercmd)
- [Suspicious ASPX File Drop by Exchange](#suspicious-aspx-file-drop-by-exchange)
- [Suspicious File Drop by Exchange](#suspicious-file-drop-by-exchange)
- [GoToAssist Temporary Installation Artefact](#gotoassist-temporary-installation-artefact)
- [Uncommon File Created by Notepad++ Updater Gup.EXE](#uncommon-file-created-by-notepad-updater-gupexe)
- [HackTool - CrackMapExec File Indicators](#hacktool-crackmapexec-file-indicators)
- [HackTool - Dumpert Process Dumper Default File](#hacktool-dumpert-process-dumper-default-file)
- [HackTool - Typical HiveNightmare SAM File Export](#hacktool-typical-hivenightmare-sam-file-export)
- [HackTool - Inveigh Execution Artefacts](#hacktool-inveigh-execution-artefacts)
- [HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators](#hacktool-remotekrbrelay-smb-relay-secrets-dump-module-indicators)
- [HackTool - Mimikatz Kirbi File Creation](#hacktool-mimikatz-kirbi-file-creation)
- [HackTool - NPPSpy Hacktool Usage](#hacktool-nppspy-hacktool-usage)
- [HackTool - Powerup Write Hijack DLL](#hacktool-powerup-write-hijack-dll)
- [HackTool - QuarksPwDump Dump File](#hacktool-quarkspwdump-dump-file)
- [HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump](#hacktool-potential-remote-credential-dumping-activity-via-crackmapexec-or-impacket-secretsdump)
- [HackTool - SafetyKatz Dump Indicator](#hacktool-safetykatz-dump-indicator)
- [HackTool - Impacket File Indicators](#hacktool-impacket-file-indicators)
- [Potential Initial Access via DLL Search Order Hijacking](#potential-initial-access-via-dll-search-order-hijacking)
- [Installation of TeamViewer Desktop](#installation-of-teamviewer-desktop)
- [Malicious DLL File Dropped in the Teams or OneDrive Folder](#malicious-dll-file-dropped-in-the-teams-or-onedrive-folder)
- [ISO File Created Within Temp Folders](#iso-file-created-within-temp-folders)
- [ISO or Image Mount Indicator in Recent Files](#iso-or-image-mount-indicator-in-recent-files)
- [GatherNetworkInfo.VBS Reconnaissance Script Output](#gathernetworkinfovbs-reconnaissance-script-output)
- [LSASS Process Memory Dump Files](#lsass-process-memory-dump-files)
- [LSASS Process Dump Artefact In CrashDumps Folder](#lsass-process-dump-artefact-in-crashdumps-folder)
- [WerFault LSASS Process Memory Dump](#werfault-lsass-process-memory-dump)
- [Adwind RAT / JRAT File Artifact](#adwind-rat-jrat-file-artifact)
- [Octopus Scanner Malware](#octopus-scanner-malware)
- [File Creation In Suspicious Directory By Msdt.EXE](#file-creation-in-suspicious-directory-by-msdtexe)
- [Uncommon File Creation By Mysql Daemon Process](#uncommon-file-creation-by-mysql-daemon-process)
- [Suspicious DotNET CLR Usage Log Artifact](#suspicious-dotnet-clr-usage-log-artifact)
- [Suspicious File Creation In Uncommon AppData Folder](#suspicious-file-creation-in-uncommon-appdata-folder)
- [SCR File Write Event](#scr-file-write-event)
- [Potential Persistence Via Notepad++ Plugins](#potential-persistence-via-notepad-plugins)
- [NTDS.DIT Created](#ntdsdit-created)
- [NTDS.DIT Creation By Uncommon Parent Process](#ntdsdit-creation-by-uncommon-parent-process)
- [NTDS.DIT Creation By Uncommon Process](#ntdsdit-creation-by-uncommon-process)
- [NTDS Exfiltration Filename Patterns](#ntds-exfiltration-filename-patterns)
- [Potential Persistence Via Microsoft Office Add-In](#potential-persistence-via-microsoft-office-add-in)
- [Office Macro File Creation](#office-macro-file-creation)
- [Office Macro File Download](#office-macro-file-download)
- [Office Macro File Creation From Suspicious Process](#office-macro-file-creation-from-suspicious-process)
- [OneNote Attachment File Dropped In Suspicious Location](#onenote-attachment-file-dropped-in-suspicious-location)
- [Suspicious File Created Via OneNote Application](#suspicious-file-created-via-onenote-application)
- [New Outlook Macro Created](#new-outlook-macro-created)
- [Potential Persistence Via Outlook Form](#potential-persistence-via-outlook-form)
- [Suspicious File Created in Outlook Temporary Directory](#suspicious-file-created-in-outlook-temporary-directory)
- [Suspicious Outlook Macro Created](#suspicious-outlook-macro-created)
- [Publisher Attachment File Dropped In Suspicious Location](#publisher-attachment-file-dropped-in-suspicious-location)
- [Potential Persistence Via Microsoft Office Startup Folder](#potential-persistence-via-microsoft-office-startup-folder)
- [File With Uncommon Extension Created By An Office Application](#file-with-uncommon-extension-created-by-an-office-application)
- [Uncommon File Created In Office Startup Folder](#uncommon-file-created-in-office-startup-folder)
- [PCRE.NET Package Temp Files](#pcrenet-package-temp-files)
- [Suspicious File Created In PerfLogs](#suspicious-file-created-in-perflogs)
- [Potential Binary Or Script Dropper Via PowerShell](#potential-binary-or-script-dropper-via-powershell)
- [PowerShell Script Dropped Via PowerShell.EXE](#powershell-script-dropped-via-powershellexe)
- [Malicious PowerShell Scripts - FileCreation](#malicious-powershell-scripts-filecreation)
- [PowerShell Module File Created](#powershell-module-file-created)
- [Potential Suspicious PowerShell Module File Created](#potential-suspicious-powershell-module-file-created)
- [PowerShell Module File Created By Non-PowerShell Process](#powershell-module-file-created-by-non-powershell-process)
- [Potential Startup Shortcut Persistence Via PowerShell.EXE](#potential-startup-shortcut-persistence-via-powershellexe)
- [PSScriptPolicyTest Creation By Uncommon Process](#psscriptpolicytest-creation-by-uncommon-process)
- [Rclone Config File Creation](#rclone-config-file-creation)
- [.RDP File Created By Uncommon Application](#rdp-file-created-by-uncommon-application)
- [Potential Winnti Dropper Activity](#potential-winnti-dropper-activity)
- [PDF File Created By RegEdit.EXE](#pdf-file-created-by-regeditexe)
- [RemCom Service File Creation](#remcom-service-file-creation)
- [ScreenConnect Temporary Installation Artefact](#screenconnect-temporary-installation-artefact)
- [Remote Access Tool - ScreenConnect Temporary File](#remote-access-tool-screenconnect-temporary-file)
- [Potential RipZip Attack on Startup Folder](#potential-ripzip-attack-on-startup-folder)
- [Potential SAM Database Dump](#potential-sam-database-dump)
- [Self Extraction Directive File Created In Potentially Suspicious Location](#self-extraction-directive-file-created-in-potentially-suspicious-location)
- [Windows Shell/Scripting Application File Write to Suspicious Folder](#windows-shellscripting-application-file-write-to-suspicious-folder)
- [Windows Binaries Write Suspicious Extensions](#windows-binaries-write-suspicious-extensions)
- [Startup Folder File Write](#startup-folder-file-write)
- [Suspicious Creation with Colorcpl](#suspicious-creation-with-colorcpl)
- [Created Files by Microsoft Sync Center](#created-files-by-microsoft-sync-center)
- [Suspicious Files in Default GPO Folder](#suspicious-files-in-default-gpo-folder)
- [Suspicious Creation TXT File in User Desktop](#suspicious-creation-txt-file-in-user-desktop)
- [Suspicious Desktopimgdownldr Target File](#suspicious-desktopimgdownldr-target-file)
- [Creation of a Diagcab](#creation-of-a-diagcab)
- [Suspicious Double Extension Files](#suspicious-double-extension-files)
- [DPAPI Backup Keys And Certificate Export Activity IOC](#dpapi-backup-keys-and-certificate-export-activity-ioc)
- [Suspicious MSExchangeMailboxReplication ASPX Write](#suspicious-msexchangemailboxreplication-aspx-write)
- [Suspicious Executable File Creation](#suspicious-executable-file-creation)
- [Suspicious File Write to Webapps Root Directory](#suspicious-file-write-to-webapps-root-directory)
- [Suspicious File Write to SharePoint Layouts Directory](#suspicious-file-write-to-sharepoint-layouts-directory)
- [Suspicious Get-Variable.exe Creation](#suspicious-get-variableexe-creation)
- [Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream](#potential-hidden-directory-creation-via-ntfs-indexallocation-stream)
- [Potential Homoglyph Attack Using Lookalike Characters in Filename](#potential-homoglyph-attack-using-lookalike-characters-in-filename)
- [Legitimate Application Dropped Archive](#legitimate-application-dropped-archive)
- [Legitimate Application Dropped Executable](#legitimate-application-dropped-executable)
- [Legitimate Application Writing Files In Uncommon Location](#legitimate-application-writing-files-in-uncommon-location)
- [Legitimate Application Dropped Script](#legitimate-application-dropped-script)
- [Suspicious LNK Double Extension File Created](#suspicious-lnk-double-extension-file-created)
- [PowerShell Profile Modification](#powershell-profile-modification)
- [Suspicious PROCEXP152.sys File Created In TMP](#suspicious-procexp152sys-file-created-in-tmp)
- [Suspicious Binaries and Scripts in Public Folder](#suspicious-binaries-and-scripts-in-public-folder)
- [Suspicious File Creation Activity From Fake Recycle.Bin Folder](#suspicious-file-creation-activity-from-fake-recyclebin-folder)
- [Potential File Extension Spoofing Using Right-to-Left Override](#potential-file-extension-spoofing-using-right-to-left-override)
- [Drop Binaries Into Spool Drivers Color Folder](#drop-binaries-into-spool-drivers-color-folder)
- [Suspicious Startup Folder Persistence](#suspicious-startup-folder-persistence)
- [Suspicious Interactive PowerShell as SYSTEM](#suspicious-interactive-powershell-as-system)
- [Suspicious Scheduled Task Write to System32 Tasks](#suspicious-scheduled-task-write-to-system32-tasks)
- [TeamViewer Remote Session](#teamviewer-remote-session)
- [VsCode Powershell Profile Modification](#vscode-powershell-profile-modification)
- [Potentially Suspicious WDAC Policy File Creation](#potentially-suspicious-wdac-policy-file-creation)
- [Windows Terminal Profile Settings Modification By Uncommon Process](#windows-terminal-profile-settings-modification-by-uncommon-process)
- [WinSxS Executable File Creation By Non-System Process](#winsxs-executable-file-creation-by-non-system-process)
- [ADExplorer Writing Complete AD Snapshot Into .dat File](#adexplorer-writing-complete-ad-snapshot-into-dat-file)
- [LiveKD Kernel Memory Dump File Created](#livekd-kernel-memory-dump-file-created)
- [LiveKD Driver Creation](#livekd-driver-creation)
- [LiveKD Driver Creation By Uncommon Process](#livekd-driver-creation-by-uncommon-process)
- [Process Explorer Driver Creation By Non-Sysinternals Binary](#process-explorer-driver-creation-by-non-sysinternals-binary)
- [Process Monitor Driver Creation By Non-Sysinternals Binary](#process-monitor-driver-creation-by-non-sysinternals-binary)
- [PsExec Service File Creation](#psexec-service-file-creation)
- [PSEXEC Remote Execution File Artefact](#psexec-remote-execution-file-artefact)
- [Potential Privilege Escalation Attempt Via .Exe.Local Technique](#potential-privilege-escalation-attempt-via-exelocal-technique)
- [LSASS Process Memory Dump Creation Via Taskmgr.EXE](#lsass-process-memory-dump-creation-via-taskmgrexe)
- [Hijack Legit RDP Session to Move Laterally](#hijack-legit-rdp-session-to-move-laterally)
- [UAC Bypass Using Consent and Comctl32 - File](#uac-bypass-using-consent-and-comctl32-file)
- [UAC Bypass Using .NET Code Profiler on MMC](#uac-bypass-using-net-code-profiler-on-mmc)
- [UAC Bypass Using EventVwr](#uac-bypass-using-eventvwr)
- [UAC Bypass Using IDiagnostic Profile - File](#uac-bypass-using-idiagnostic-profile-file)
- [UAC Bypass Using IEInstal - File](#uac-bypass-using-ieinstal-file)
- [UAC Bypass Using MSConfig Token Modification - File](#uac-bypass-using-msconfig-token-modification-file)
- [UAC Bypass Using NTFS Reparse Point - File](#uac-bypass-using-ntfs-reparse-point-file)
- [UAC Bypass Abusing Winsat Path Parsing - File](#uac-bypass-abusing-winsat-path-parsing-file)
- [UAC Bypass Using Windows Media Player - File](#uac-bypass-using-windows-media-player-file)
- [VHD Image Download Via Browser](#vhd-image-download-via-browser)
- [Visual Studio Code Tunnel Remote File Creation](#visual-studio-code-tunnel-remote-file-creation)
- [Renamed VsCode Code Tunnel Execution - File Indicator](#renamed-vscode-code-tunnel-execution-file-indicator)
- [Potential Webshell Creation On Static Website](#potential-webshell-creation-on-static-website)
- [Creation of WerFault.exe/Wer.dll in Unusual Folder](#creation-of-werfaultexewerdll-in-unusual-folder)
- [WinRAR Creating Files in Startup Locations](#winrar-creating-files-in-startup-locations)
- [AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File](#awl-bypass-with-winrmvbs-and-malicious-wsmptyxslwsmtxtxsl-file)
- [WMI Persistence - Script Event Consumer File Write](#wmi-persistence-script-event-consumer-file-write)
- [Wmiexec Default Output File](#wmiexec-default-output-file)
- [Wmiprvse Wbemcomn DLL Hijack - File](#wmiprvse-wbemcomn-dll-hijack-file)
- [UEFI Persistence Via Wpbbin - FileCreation](#uefi-persistence-via-wpbbin-filecreation)
- [Writing Local Admin Share](#writing-local-admin-share)

## ADSI-Cache File Creation By Uncommon Tool

| Field | Value |
|---|---|
| **Sigma ID** | `75bf09fa-1dd7-4d18-9af9-dd9e492562eb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1001.003 |
| **Author** | xknow @xknow_infosec, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_adsi_cache_creation_by_uncommon_tool.yml)**

> Detects the creation of an "Active Directory Schema Cache File" (.sch) file by an uncommon tool.

```sql
-- ============================================================
-- Title:        ADSI-Cache File Creation By Uncommon Tool
-- Sigma ID:     75bf09fa-1dd7-4d18-9af9-dd9e492562eb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1001.003
-- Author:       xknow @xknow_infosec, Tim Shelton
-- Date:         2019-03-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_adsi_cache_creation_by_uncommon_tool.yml
-- Unmapped:     (none)
-- False Pos:    Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Local\\Microsoft\\Windows\\SchCache\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sch'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.

**References:**
- https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
- https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
- https://github.com/fox-it/LDAPFragger

---

## Advanced IP Scanner - File Event

| Field | Value |
|---|---|
| **Sigma ID** | `fed85bf9-e075-4280-9159-fbe8a023d6fa` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1046 |
| **Author** | @ROxPinTeddy |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_advanced_ip_scanner.yml)**

> Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.

```sql
-- ============================================================
-- Title:        Advanced IP Scanner - File Event
-- Sigma ID:     fed85bf9-e075-4280-9159-fbe8a023d6fa
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1046
-- Author:       @ROxPinTeddy
-- Date:         2020-05-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_advanced_ip_scanner.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative use
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\Advanced IP Scanner 2%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative use

**References:**
- https://news.sophos.com/en-us/2019/12/09/snatch-ransomware-reboots-pcs-into-safe-mode-to-bypass-protection/
- https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
- https://labs.f-secure.com/blog/prelude-to-ransomware-systembc
- https://assets.documentcloud.org/documents/20444693/fbi-pin-egregor-ransomware-bc-01062021.pdf
- https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer

---

## Anydesk Temporary Artefact

| Field | Value |
|---|---|
| **Sigma ID** | `0b9ad457-2554-44c1-82c2-d56a99c42377` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_anydesk_artefact.yml)**

> An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


```sql
-- ============================================================
-- Title:        Anydesk Temporary Artefact
-- Sigma ID:     0b9ad457-2554-44c1-82c2-d56a99c42377
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       frack113
-- Date:         2022-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_anydesk_artefact.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Roaming\\AnyDesk\\user.conf%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Roaming\\AnyDesk\\system.conf%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-2---anydesk-files-detected-test-on-windows

---

## Suspicious Binary Writes Via AnyDesk

| Field | Value |
|---|---|
| **Sigma ID** | `2d367498-5112-4ae5-a06a-96e7bc33a211` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_anydesk_writing_susp_binaries.yml)**

> Detects AnyDesk writing binary files to disk other than "gcapi.dll".
According to RedCanary research it is highly abnormal for AnyDesk to write executable files to disk besides gcapi.dll,
which is a legitimate DLL that is part of the Google Chrome web browser used to interact with the Google Cloud API. (See reference section for more details)


```sql
-- ============================================================
-- Title:        Suspicious Binary Writes Via AnyDesk
-- Sigma ID:     2d367498-5112-4ae5-a06a-96e7bc33a211
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_anydesk_writing_susp_binaries.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\AnyDesk.exe' OR procName LIKE '%\\AnyDeskMSI.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/misbehaving-rats/
- https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/

---

## Suspicious File Created by ArcSOC.exe

| Field | Value |
|---|---|
| **Sigma ID** | `e890acee-d488-420e-8f20-d9b19b3c3d43` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1127, T1105, T1133 |
| **Author** | Micah Babinski |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_arcsoc_susp_file_created.yml)**

> Detects instances where the ArcGIS Server process ArcSOC.exe, which hosts REST services running on an ArcGIS
server, creates a file with suspicious file type, indicating that it may be an executable, script file,
or otherwise unusual.


```sql
-- ============================================================
-- Title:        Suspicious File Created by ArcSOC.exe
-- Sigma ID:     e890acee-d488-420e-8f20-d9b19b3c3d43
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1127, T1105, T1133
-- Author:       Micah Babinski
-- Date:         2025-11-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_arcsoc_susp_file_created.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\ArcSOC.exe'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ahk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.aspx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.au3' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.py' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://reliaquest.com/blog/threat-spotlight-inside-flax-typhoons-arcgis-compromise/
- https://enterprise.arcgis.com/en/server/12.0/administer/windows/inside-an-arcgis-server-site.htm

---

## Assembly DLL Creation Via AspNetCompiler

| Field | Value |
|---|---|
| **Sigma ID** | `4c7f49ee-2638-43bb-b85b-ce676c30b260` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_aspnet_temp_files.yml)**

> Detects the creation of new DLL assembly files by "aspnet_compiler.exe", which could be a sign of "aspnet_compiler" abuse to proxy execution through a build provider.


```sql
-- ============================================================
-- Title:        Assembly DLL Creation Via AspNetCompiler
-- Sigma ID:     4c7f49ee-2638-43bb-b85b-ce676c30b260
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_aspnet_temp_files.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate assembly compilation using a build provider
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\aspnet\_compiler.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Temporary ASP.NET Files\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\assembly\\tmp\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate assembly compilation using a build provider

**References:**
- Internal Research

---

## BloodHound Collection Files

| Field | Value |
|---|---|
| **Sigma ID** | `02773bed-83bf-469f-b7ff-e676e7d78bab` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery, execution |
| **MITRE Techniques** | T1087.001, T1087.002, T1482, T1069.001, T1069.002, T1059.001 |
| **Author** | C.J. May |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml)**

> Detects default file names outputted by the BloodHound collection tool SharpHound

```sql
-- ============================================================
-- Title:        BloodHound Collection Files
-- Sigma ID:     02773bed-83bf-469f-b7ff-e676e7d78bab
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery, execution | T1087.001, T1087.002, T1482, T1069.001, T1069.002, T1059.001
-- Author:       C.J. May
-- Date:         2022-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml
-- Unmapped:     (none)
-- False Pos:    Some false positives may arise in some environment and this may require some tuning. Add additional filters or reduce level depending on the level of noise
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%BloodHound.zip' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_computers.json' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_containers.json' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_gpos.json' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_groups.json' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_ous.json' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_users.json'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives may arise in some environment and this may require some tuning. Add additional filters or reduce level depending on the level of noise

**References:**
- https://academy.hackthebox.com/course/preview/active-directory-bloodhound/bloodhound--data-collection

---

## Potentially Suspicious File Creation by OpenEDR's ITSMService

| Field | Value |
|---|---|
| **Sigma ID** | `9e4b7d3a-6f2c-4e9a-8d1b-3c5e7a9f2b4d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105, T1570, T1219 |
| **Author** | @kostastsale |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_comodo_itsm_potentially_suspicious_file_creation.yml)**

> Detects the creation of potentially suspicious files by OpenEDR's ITSMService process.
The ITSMService is responsible for remote management operations and can create files on the system through the Process Explorer or file management features.
While legitimate for IT operations, creation of executable or script files could indicate unauthorized file uploads, data staging, or malicious file deployment.


```sql
-- ============================================================
-- Title:        Potentially Suspicious File Creation by OpenEDR's ITSMService
-- Sigma ID:     9e4b7d3a-6f2c-4e9a-8d1b-3c5e7a9f2b4d
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1105, T1570, T1219
-- Author:       @kostastsale
-- Date:         2026-02-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_comodo_itsm_potentially_suspicious_file_creation.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate OpenEDR file management operations; Authorized remote file uploads by IT administrators; Software deployment through OpenEDR console
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\COMODO\\Endpoint Manager\\ITSMService.exe'
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.7z' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.com' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pif' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rar' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate OpenEDR file management operations; Authorized remote file uploads by IT administrators; Software deployment through OpenEDR console

**References:**
- https://kostas-ts.medium.com/detecting-abuse-of-openedrs-permissive-edr-trial-a-security-researcher-s-perspective-fc55bf53972c

---

## EVTX Created In Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `65236ec7-ace0-4f0c-82fd-737b04fd4dcb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.002 |
| **Author** | D3F7A5105 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_create_evtx_non_common_locations.yml)**

> Detects the creation of new files with the ".evtx" extension in non-common or non-standard location.
This could indicate tampering with default EVTX locations in order to evade security controls or simply exfiltration of event log to search for sensitive information within.
Note that backup software and legitimate administrator might perform similar actions during troubleshooting.


```sql
-- ============================================================
-- Title:        EVTX Created In Uncommon Location
-- Sigma ID:     65236ec7-ace0-4f0c-82fd-737b04fd4dcb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.002
-- Author:       D3F7A5105
-- Date:         2023-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_create_evtx_non_common_locations.yml
-- Unmapped:     (none)
-- False Pos:    Administrator or backup activity; An unknown bug seems to trigger the Windows "svchost" process to drop EVTX files in the "C:\Windows\Temp" directory in the form "<log_name">_<uuid>.evtx". See https://superuser.com/questions/1371229/low-disk-space-after-filling-up-c-windows-temp-with-evtx-and-txt-files
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.evtx')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator or backup activity; An unknown bug seems to trigger the Windows "svchost" process to drop EVTX files in the "C:\Windows\Temp" directory in the form "<log_name">_<uuid>.evtx". See https://superuser.com/questions/1371229/low-disk-space-after-filling-up-c-windows-temp-with-evtx-and-txt-files

**References:**
- https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key

---

## Creation Of Non-Existent System DLL

| Field | Value |
|---|---|
| **Sigma ID** | `df6ecb8b-7822-4f4b-b412-08f524b4576c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), fornotes |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_create_non_existent_dlls.yml)**

> Detects creation of specific system DLL files that are  usually not present on the system (or at least not in system directories) but may be loaded by legitimate processes.
Phantom DLL hijacking involves placing malicious DLLs with names of non-existent system binaries in locations where legitimate applications may search for them, leading to execution of the malicious DLLs.
Thus, the creation of such DLLs may indicate preparation for phantom DLL hijacking attacks.


```sql
-- ============================================================
-- Title:        Creation Of Non-Existent System DLL
-- Sigma ID:     df6ecb8b-7822-4f4b-b412-08f524b4576c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), fornotes
-- Date:         2022-12-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_create_non_existent_dlls.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\axeonoffhelper.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\cdpsgshims.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\oci.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\offdmpsvc.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\shellchromeapi.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\TSMSISrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\TSVIPSrv.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\wbem\\wbemcomn.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\WLBSCTRL.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\wow64log.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\WptsExtensions.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SprintCSP.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html
- https://clement.notin.org/blog/2020/09/12/CVE-2020-7315-McAfee-Agent-DLL-injection/
- https://decoded.avast.io/martinchlumecky/png-steganography/
- https://github.com/blackarrowsec/redteam-research/tree/26e6fc0c0d30d364758fa11c2922064a9a7fd309/LPE%20via%20StorSvc
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

## Suspicious Deno File Written from Remote Source

| Field | Value |
|---|---|
| **Sigma ID** | `6c0ce3b6-85e2-49d4-9c3f-6e008ce9796e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204, T1059.007, T1105 |
| **Author** | Josh Nickels, Michael Taggart |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_deno.yml)**

> Detects Deno writing a file from a direct HTTP(s) call and writing to the appdata folder or bringing it's own malicious DLL.
This behavior may indicate an attempt to execute remotely hosted, potentially malicious files through deno.


```sql
-- ============================================================
-- Title:        Suspicious Deno File Written from Remote Source
-- Sigma ID:     6c0ce3b6-85e2-49d4-9c3f-6e008ce9796e
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        execution | T1204, T1059.007, T1105
-- Author:       Josh Nickels, Michael Taggart
-- Date:         2025-05-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_deno.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of deno to request a file or bring a DLL to a host
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\deno\\gen\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\deno\\remote\\https\\%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Users\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of deno to request a file or bring a DLL to a host

**References:**
- https://taggart-tech.com/evildeno/

---

## New Custom Shim Database Created

| Field | Value |
|---|---|
| **Sigma ID** | `ee63c85c-6d51-4d12-ad09-04e25877a947` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.009 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_new_shim_database.yml)**

> Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time.


```sql
-- ============================================================
-- Title:        New Custom Shim Database Created
-- Sigma ID:     ee63c85c-6d51-4d12-ad09-04e25877a947
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.009
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-12-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_new_shim_database.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate custom SHIM installations will also trigger this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\apppatch\\Custom\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\apppatch\\CustomSDB\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate custom SHIM installations will also trigger this rule

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.011/T1546.011.md#atomic-test-2---new-shim-database-files-created-in-the-default-shim-database-directory
- https://www.mandiant.com/resources/blog/fin7-shim-databases-persistence
- https://liberty-shell.com/sec/2020/02/25/shim-persistence/
- https://andreafortuna.org/2018/11/12/process-injection-and-persistence-using-application-shimming/

---

## Suspicious Screensaver Binary File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `97aa2e88-555c-450d-85a6-229bcd87efb8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_scr_binary_file.yml)**

> Adversaries may establish persistence by executing malicious content triggered by user inactivity.
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension


```sql
-- ============================================================
-- Title:        Suspicious Screensaver Binary File Creation
-- Sigma ID:     97aa2e88-555c-450d-85a6-229bcd87efb8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.002
-- Author:       frack113
-- Date:         2021-12-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_scr_binary_file.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md

---

## Files With System DLL Name In Unsuspected Locations

| Field | Value |
|---|---|
| **Sigma ID** | `13c02350-4177-4e45-ac17-cf7ca628ff5e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_system_dll_files.yml)**

> Detects the creation of a file with the ".dll" extension that has the name of a System DLL in uncommon or unsuspected locations. (Outisde of "System32", "SysWOW64", etc.).
It is highly recommended to perform an initial baseline before using this rule in production.


```sql
-- ============================================================
-- Title:        Files With System DLL Name In Unsuspected Locations
-- Sigma ID:     13c02350-4177-4e45-ac17-cf7ca628ff5e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_system_dll_files.yml
-- Unmapped:     (none)
-- False Pos:    Third party software might bundle specific versions of system DLLs.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\secur32.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\tdh.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Third party software might bundle specific versions of system DLLs.

**References:**
- Internal Research

---

## Files With System Process Name In Unsuspected Locations

| Field | Value |
|---|---|
| **Sigma ID** | `d5866ddf-ce8f-4aea-b28e-d96485a20d3d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.005 |
| **Author** | Sander Wiebing, Tim Shelton, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_system_file.yml)**

> Detects the creation of an executable with a system process name in folders other than the system ones (System32, SysWOW64, etc.).
It is highly recommended to perform an initial baseline before using this rule in production.


```sql
-- ============================================================
-- Title:        Files With System Process Name In Unsuspected Locations
-- Sigma ID:     d5866ddf-ce8f-4aea-b28e-d96485a20d3d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.005
-- Author:       Sander Wiebing, Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2020-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_system_file.yml
-- Unmapped:     (none)
-- False Pos:    System processes copied outside their default folders for testing purposes; Third party software naming their software with the same names as the processes mentioned here
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AtBroker.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\audiodg.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\backgroundTaskHost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\bcdedit.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\bitsadmin.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\cmdl32.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\cmstp.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\conhost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\csrss.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\dasHost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\dfrgui.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\dllhost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\dwm.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\eventcreate.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\eventvwr.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\explorer.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\extrac32.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\fontdrvhost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\fsquirt.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ipconfig.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\iscsicli.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\iscsicpl.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\logman.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\LogonUI.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\LsaIso.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsm.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\msiexec.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\msinfo32.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\mstsc.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\nbtstat.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\odbcconf.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\powershell.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\pwsh.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\regini.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\regsvr32.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\rundll32.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\RuntimeBroker.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\schtasks.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SearchFilterHost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SearchIndexer.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SearchProtocolHost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SecurityHealthService.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SecurityHealthSystray.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\services.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ShellAppRuntime.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sihost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\smartscreen.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\smss.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\spoolsv.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\svchost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SystemSettingsBroker.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\taskhost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\taskhostw.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Taskmgr.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TiWorker.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\vssadmin.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\w32tm.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WerFault.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WerFaultSecure.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wermgr.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wevtutil.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wininit.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\winlogon.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\winrshost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WinRTNetMUAHostServer.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wlanext.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wlrmdr.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WmiPrvSE.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wslhost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WSReset.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WUDFHost.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WWAHost.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System processes copied outside their default folders for testing purposes; Third party software naming their software with the same names as the processes mentioned here

**References:**
- Internal Research

---

## Creation Exe for Service with Unquoted Path

| Field | Value |
|---|---|
| **Sigma ID** | `8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.009 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_unquoted_service_path.yml)**

> Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.


```sql
-- ============================================================
-- Title:        Creation Exe for Service with Unquoted Path
-- Sigma ID:     8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.009
-- Author:       frack113
-- Date:         2021-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_unquoted_service_path.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\program.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.009/T1574.009.md

---

## Cred Dump Tools Dropped Files

| Field | Value |
|---|---|
| **Sigma ID** | `8fbf3271-1ef6-4e94-8210-03c2317947f6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001, T1003.002, T1003.003, T1003.004, T1003.005 |
| **Author** | Teymur Kheirkhabarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_cred_dump_tools_dropped_files.yml)**

> Files with well-known filenames (parts of credential dump software or files produced by them) creation

```sql
-- ============================================================
-- Title:        Cred Dump Tools Dropped Files
-- Sigma ID:     8fbf3271-1ef6-4e94-8210-03c2317947f6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001, T1003.002, T1003.003, T1003.004, T1003.005
-- Author:       Teymur Kheirkhabarov, oscd.community
-- Date:         2019-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_cred_dump_tools_dropped_files.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Administrator using tool for password recovery
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\fgdump-log%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\kirbi%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\pwdump%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\pwhashes%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wce\_ccache%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wce\_krbtkts%')))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\cachedump.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\cachedump64.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\DumpExt.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\DumpSvc.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Dumpy.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\fgexec.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsremora.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsremora64.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\NTDS.out' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\procdump.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\procdump64.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\procdump64a.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\pstgdump.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\pwdump.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SAM.out' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SECURITY.out' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\servpw.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\servpw64.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SYSTEM.out' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\test.pwd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wceaux.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator using tool for password recovery

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---

## WScript or CScript Dropper - File

| Field | Value |
|---|---|
| **Sigma ID** | `002bdb95-0cf1-46a6-9e08-d38c128a6127` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.005, T1059.007 |
| **Author** | Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml)**

> Detects a file ending in jse, vbe, js, vba, vbs written by cscript.exe or wscript.exe

```sql
-- ============================================================
-- Title:        WScript or CScript Dropper - File
-- Sigma ID:     002bdb95-0cf1-46a6-9e08-d38c128a6127
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.005, T1059.007
-- Author:       Tim Shelton
-- Date:         2022-01-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\wscript.exe' OR procName LIKE '%\\cscript.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\ProgramData%'))
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jse' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vba' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- WScript or CScript Dropper (cea72823-df4d-4567-950c-0b579eaf0846)

---

## CSExec Service File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `f0e2b768-5220-47dd-b891-d57b96fc0ec1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_csexec_service.yml)**

> Detects default CSExec service filename which indicates CSExec service installation and execution

```sql
-- ============================================================
-- Title:        CSExec Service File Creation
-- Sigma ID:     f0e2b768-5220-47dd-b891-d57b96fc0ec1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_csexec_service.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\csexecsvc.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/malcomvetter/CSExec

---

## Dynamic CSharp Compile Artefact

| Field | Value |
|---|---|
| **Sigma ID** | `e4a74e34-ecde-4aab-b2fb-9112dd01aed0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1027.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_csharp_compile_artefact.yml)**

> When C# is compiled dynamically, a .cmdline file will be created as a part of the process.
Certain processes are not typically observed compiling C# code, but can do so without touching disk.
This can be used to unpack a payload for execution


```sql
-- ============================================================
-- Title:        Dynamic CSharp Compile Artefact
-- Sigma ID:     e4a74e34-ecde-4aab-b2fb-9112dd01aed0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1027.004
-- Author:       frack113
-- Date:         2022-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_csharp_compile_artefact.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmdline')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027.004/T1027.004.md#atomic-test-2---dynamic-c-compile

---

## Potential DCOM InternetExplorer.Application DLL Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `2f7979ae-f82b-45af-ac1d-2b10e93b0baa` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1021.002, T1021.003 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_dcom_iertutil_dll_hijack.yml)**

> Detects potential DLL hijack of "iertutil.dll" found in the DCOM InternetExplorer.Application Class over the network

```sql
-- ============================================================
-- Title:        Potential DCOM InternetExplorer.Application DLL Hijack
-- Sigma ID:     2f7979ae-f82b-45af-ac1d-2b10e93b0baa
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1021.002, T1021.003
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_dcom_iertutil_dll_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = 'System'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Internet Explorer\\iertutil.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html

---

## Desktop.INI Created by Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `81315b50-6b60-4d8f-9928-3466e1022515` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.009 |
| **Author** | Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_desktop_ini_created_by_uncommon_process.yml)**

> Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

```sql
-- ============================================================
-- Title:        Desktop.INI Created by Uncommon Process
-- Sigma ID:     81315b50-6b60-4d8f-9928-3466e1022515
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.009
-- Author:       Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO)
-- Date:         2020-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_desktop_ini_created_by_uncommon_process.yml
-- Unmapped:     (none)
-- False Pos:    Operations performed through Windows SCCM or equivalent; Read only access list authority
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\desktop.ini')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Operations performed through Windows SCCM or equivalent; Read only access list authority

**References:**
- https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/

---

## DLL Search Order Hijackig Via Additional Space in Path

| Field | Value |
|---|---|
| **Sigma ID** | `b6f91281-20aa-446a-b986-38a92813a18f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_dll_sideloading_space_path.yml)**

> Detects when an attacker create a similar folder structure to windows system folders such as (Windows, Program Files...)
but with a space in order to trick DLL load search order and perform a "DLL Search Order Hijacking" attack


```sql
-- ============================================================
-- Title:        DLL Search Order Hijackig Via Additional Space in Path
-- Sigma ID:     b6f91281-20aa-446a-b986-38a92813a18f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_dll_sideloading_space_path.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows \\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Program Files \\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Program Files (x86) \\%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/cyb3rops/status/1552932770464292864
- https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows

---

## Potentially Suspicious DMP/HDMP File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `aba15bdd-657f-422a-bab3-ac2d2a0d6f1c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_dump_file_susp_creation.yml)**

> Detects the creation of a file with the ".dmp"/".hdmp" extension by a shell or scripting application such as "cmd", "powershell", etc. Often created by software during a crash. Memory dumps can sometimes contain sensitive information such as credentials. It's best to determine the source of the crash.

```sql
-- ============================================================
-- Title:        Potentially Suspicious DMP/HDMP File Creation
-- Sigma ID:     aba15bdd-657f-422a-bab3-ac2d2a0d6f1c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_dump_file_susp_creation.yml
-- Unmapped:     (none)
-- False Pos:    Some administrative PowerShell or VB scripts might have the ability to collect dumps and move them to other folders which might trigger a false positive.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\cmd.exe' OR procName LIKE '%\\cscript.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe' OR procName LIKE '%\\wscript.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dump' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hdmp')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some administrative PowerShell or VB scripts might have the ability to collect dumps and move them to other folders which might trigger a false positive.

**References:**
- https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps

---

## Potential Persistence Attempt Via ErrorHandler.Cmd

| Field | Value |
|---|---|
| **Sigma ID** | `15904280-565c-4b73-9303-3291f964e7f9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_errorhandler_persistence.yml)**

> Detects creation of a file named "ErrorHandler.cmd" in the "C:\WINDOWS\Setup\Scripts\" directory which could be used as a method of persistence
The content of C:\WINDOWS\Setup\Scripts\ErrorHandler.cmd is read whenever some tools under C:\WINDOWS\System32\oobe\ (e.g. Setup.exe) fail to run for any reason.


```sql
-- ============================================================
-- Title:        Potential Persistence Attempt Via ErrorHandler.Cmd
-- Sigma ID:     15904280-565c-4b73-9303-3291f964e7f9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_errorhandler_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WINDOWS\\Setup\\Scripts\\ErrorHandler.cmd')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.hexacorn.com/blog/2022/01/16/beyond-good-ol-run-key-part-135/
- https://github.com/last-byte/PersistenceSniper

---

## Suspicious ASPX File Drop by Exchange

| Field | Value |
|---|---|
| **Sigma ID** | `bd1212e5-78da-431e-95fa-c58e3237a8e6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Florian Roth (Nextron Systems), MSTI (query, idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml)**

> Detects suspicious file type dropped by an Exchange component in IIS into a suspicious folder

```sql
-- ============================================================
-- Title:        Suspicious ASPX File Drop by Exchange
-- Sigma ID:     bd1212e5-78da-431e-95fa-c58e3237a8e6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Florian Roth (Nextron Systems), MSTI (query, idea)
-- Date:         2022-10-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml
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
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\w3wp.exe'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%MSExchange%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%FrontEnd\\HttpProxy\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\inetpub\\wwwroot\\aspnet\_client\\%')))
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.aspx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.asp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ashx')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
- https://www.gteltsc.vn/blog/canh-bao-chien-dich-tan-cong-su-dung-lo-hong-zero-day-tren-microsoft-exchange-server-12714.html
- https://en.gteltsc.vn/blog/cap-nhat-nhe-ve-lo-hong-bao-mat-0day-microsoft-exchange-dang-duoc-su-dung-de-tan-cong-cac-to-chuc-tai-viet-nam-9685.html

---

## Suspicious File Drop by Exchange

| Field | Value |
|---|---|
| **Sigma ID** | `6b269392-9eba-40b5-acb6-55c882b20ba6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1190, T1505.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_exchange_webshell_drop_suspicious.yml)**

> Detects suspicious file type dropped by an Exchange component in IIS

```sql
-- ============================================================
-- Title:        Suspicious File Drop by Exchange
-- Sigma ID:     6b269392-9eba-40b5-acb6-55c882b20ba6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1190, T1505.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-10-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_exchange_webshell_drop_suspicious.yml
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
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\w3wp.exe'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%MSExchange%'))
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.aspx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.asp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ashx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
- https://www.gteltsc.vn/blog/canh-bao-chien-dich-tan-cong-su-dung-lo-hong-zero-day-tren-microsoft-exchange-server-12714.html
- https://en.gteltsc.vn/blog/cap-nhat-nhe-ve-lo-hong-bao-mat-0day-microsoft-exchange-dang-duoc-su-dung-de-tan-cong-cac-to-chuc-tai-viet-nam-9685.html

---

## GoToAssist Temporary Installation Artefact

| Field | Value |
|---|---|
| **Sigma ID** | `5d756aee-ad3e-4306-ad95-cb1abec48de2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_gotoopener_artefact.yml)**

> An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


```sql
-- ============================================================
-- Title:        GoToAssist Temporary Installation Artefact
-- Sigma ID:     5d756aee-ad3e-4306-ad95-cb1abec48de2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       frack113
-- Date:         2022-02-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_gotoopener_artefact.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\LogMeInInc\\GoToAssist Remote Support Expert\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows

---

## Uncommon File Created by Notepad++ Updater Gup.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1195.002, T1557 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_gup_uncommon_file_creation.yml)**

> Detects when the Notepad++ updater (gup.exe) creates files in suspicious or uncommon locations.
This could indicate potential exploitation of the updater component to deliver unwanted malware or unwarranted files.


```sql
-- ============================================================
-- Title:        Uncommon File Created by Notepad++ Updater Gup.EXE
-- Sigma ID:     3b8f4c92-6a51-4d7e-9c3a-8e2d1f5a7b09
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        collection | T1195.002, T1557
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2026-02-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_gup_uncommon_file_creation.yml
-- Unmapped:     (none)
-- False Pos:    Custom or portable Notepad++ installations in non-standard directories.; Legitimate update processes creating temporary files in unexpected locations.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\gup.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Custom or portable Notepad++ installations in non-standard directories.; Legitimate update processes creating temporary files in unexpected locations.

**References:**
- https://notepad-plus-plus.org/news/v889-released/
- https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
- https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
- https://www.validin.com/blog/exploring_notepad_plus_plus_network_indicators/
- https://securelist.com/notepad-supply-chain-attack/118708/

---

## HackTool - CrackMapExec File Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `736ffa74-5f6f-44ca-94ef-1c0df4f51d2a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_crackmapexec_indicators.yml)**

> Detects file creation events with filename patterns used by CrackMapExec.

```sql
-- ============================================================
-- Title:        HackTool - CrackMapExec File Indicators
-- Sigma ID:     736ffa74-5f6f-44ca-94ef-1c0df4f51d2a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-03-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_crackmapexec_indicators.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\Temp\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/byt3bl33d3r/CrackMapExec/

---

## HackTool - Dumpert Process Dumper Default File

| Field | Value |
|---|---|
| **Sigma ID** | `93d94efc-d7ad-4161-ad7d-1638c4f908d8` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_dumpert.yml)**

> Detects the creation of the default dump file used by Outflank Dumpert tool. A process dumper, which dumps the lsass process memory

```sql
-- ============================================================
-- Title:        HackTool - Dumpert Process Dumper Default File
-- Sigma ID:     93d94efc-d7ad-4161-ad7d-1638c4f908d8
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2020-02-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_dumpert.yml
-- Unmapped:     (none)
-- False Pos:    Very unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%dumpert.dmp')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Very unlikely

**References:**
- https://github.com/outflanknl/Dumpert
- https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/

---

## HackTool - Typical HiveNightmare SAM File Export

| Field | Value |
|---|---|
| **Sigma ID** | `6ea858a8-ba71-4a12-b2cc-5d83312404c7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1552.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_hivenightmare_file_exports.yml)**

> Detects files written by the different tools that exploit HiveNightmare

```sql
-- ============================================================
-- Title:        HackTool - Typical HiveNightmare SAM File Export
-- Sigma ID:     6ea858a8-ba71-4a12-b2cc-5d83312404c7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1552.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-07-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_hivenightmare_file_exports.yml
-- Unmapped:     (none)
-- False Pos:    Files that accidentally contain these strings
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\hive\_sam\_%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SAM-2021-%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SAM-2022-%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SAM-2023-%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\SAM-haxx%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Sam.save%')))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\windows\temp\sam'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Files that accidentally contain these strings

**References:**
- https://github.com/GossiTheDog/HiveNightmare
- https://github.com/FireFart/hivenightmare/
- https://github.com/WiredPulse/Invoke-HiveNightmare
- https://twitter.com/cube0x0/status/1418920190759378944

---

## HackTool - Inveigh Execution Artefacts

| Field | Value |
|---|---|
| **Sigma ID** | `bb09dd3e-2b78-4819-8e35-a7c1b874e449` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_inveigh_artefacts.yml)**

> Detects the presence and execution of Inveigh via dropped artefacts

```sql
-- ============================================================
-- Title:        HackTool - Inveigh Execution Artefacts
-- Sigma ID:     bb09dd3e-2b78-4819-8e35-a7c1b874e449
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_inveigh_artefacts.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-Log.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-Cleartext.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-NTLMv1Users.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-NTLMv2Users.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-NTLMv1.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-NTLMv2.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-FormInput.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Inveigh-Relay.ps1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/Kevin-Robertson/Inveigh/blob/29d9e3c3a625b3033cdaf4683efaafadcecb9007/Inveigh/Support/Output.cs
- https://github.com/Kevin-Robertson/Inveigh/blob/29d9e3c3a625b3033cdaf4683efaafadcecb9007/Inveigh/Support/Control.cs
- https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/

---

## HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `3ab79e90-9fab-4cdf-a7b2-6522bc742adb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_krbrelay_remote_ioc.yml)**

> Detects the creation of file with specific names used by RemoteKrbRelay SMB Relay attack module.

```sql
-- ============================================================
-- Title:        HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators
-- Sigma ID:     3ab79e90-9fab-4cdf-a7b2-6522bc742adb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-06-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_krbrelay_remote_ioc.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\windows\\temp\\sam.tmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\windows\\temp\\sec.tmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\windows\\temp\\sys.tmp'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/CICADA8-Research/RemoteKrbRelay/blob/19ec76ba7aa50c2722b23359bc4541c0a9b2611c/Exploit/RemoteKrbRelay/Relay/Attacks/RemoteRegistry.cs#L31-L40

---

## HackTool - Mimikatz Kirbi File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `9e099d99-44c2-42b6-a6d8-54c3545cab29` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1558 |
| **Author** | Florian Roth (Nextron Systems), David ANDRE |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml)**

> Detects the creation of files created by mimikatz such as ".kirbi", "mimilsa.log", etc.

```sql
-- ============================================================
-- Title:        HackTool - Mimikatz Kirbi File Creation
-- Sigma ID:     9e099d99-44c2-42b6-a6d8-54c3545cab29
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1558
-- Author:       Florian Roth (Nextron Systems), David ANDRE
-- Date:         2021-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.kirbi' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%mimilsa.log'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://cobalt.io/blog/kerberoast-attack-techniques
- https://pentestlab.blog/2019/10/21/persistence-security-support-provider/

---

## HackTool - NPPSpy Hacktool Usage

| Field | Value |
|---|---|
| **Sigma ID** | `cad1fe90-2406-44dc-bd03-59d0b58fe722` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_nppspy.yml)**

> Detects the use of NPPSpy hacktool that stores cleartext passwords of users that logged in to a local file

```sql
-- ============================================================
-- Title:        HackTool - NPPSpy Hacktool Usage
-- Sigma ID:     cad1fe90-2406-44dc-bd03-59d0b58fe722
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-11-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_nppspy.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\NPPSpy.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\NPPSpy.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003/T1003.md#atomic-test-2---credential-dumping-with-nppspy
- https://twitter.com/0gtweet/status/1465282548494487554

---

## HackTool - Powerup Write Hijack DLL

| Field | Value |
|---|---|
| **Sigma ID** | `602a1f13-c640-4d73-b053-be9a2fa58b96` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Subhash Popuri (@pbssubhash) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_powerup_dllhijacking.yml)**

> Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation.
In it's default mode, it builds a self deleting .bat file which executes malicious command.
The detection rule relies on creation of the malicious bat file (debug.bat by default).


```sql
-- ============================================================
-- Title:        HackTool - Powerup Write Hijack DLL
-- Sigma ID:     602a1f13-c640-4d73-b053-be9a2fa58b96
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Subhash Popuri (@pbssubhash)
-- Date:         2021-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_powerup_dllhijacking.yml
-- Unmapped:     (none)
-- False Pos:    Any powershell script that creates bat files
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Any powershell script that creates bat files

**References:**
- https://powersploit.readthedocs.io/en/latest/Privesc/Write-HijackDll/

---

## HackTool - QuarksPwDump Dump File

| Field | Value |
|---|---|
| **Sigma ID** | `847def9e-924d-4e90-b7c4-5f581395a2b4` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1003.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_quarkspw_filedump.yml)**

> Detects a dump file written by QuarksPwDump password dumper

```sql
-- ============================================================
-- Title:        HackTool - QuarksPwDump Dump File
-- Sigma ID:     847def9e-924d-4e90-b7c4-5f581395a2b4
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1003.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-02-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_quarkspw_filedump.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\SAM-%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dmp%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm

---

## HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump

| Field | Value |
|---|---|
| **Sigma ID** | `6e2a900a-ced9-4e4a-a9c2-13e706f9518a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003 |
| **Author** | SecurityAura |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml)**

> Detects default filenames output from the execution of CrackMapExec and Impacket-secretsdump against an endpoint.

```sql
-- ============================================================
-- Title:        HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump
-- Sigma ID:     6e2a900a-ced9-4e4a-a9c2-13e706f9518a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003
-- Author:       SecurityAura
-- Date:         2022-11-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\svchost.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'fileName')], '\\Windows\\System32\\[a-zA-Z0-9]{8}\.tmp$')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Porchetta-Industries/CrackMapExec
- https://github.com/fortra/impacket/blob/ff8c200fd040b04d3b5ff05449646737f836235d/examples/secretsdump.py

---

## HackTool - SafetyKatz Dump Indicator

| Field | Value |
|---|---|
| **Sigma ID** | `e074832a-eada-4fd7-94a1-10642b130e16` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Markus Neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_safetykatz.yml)**

> Detects default lsass dump filename generated by SafetyKatz.

```sql
-- ============================================================
-- Title:        HackTool - SafetyKatz Dump Indicator
-- Sigma ID:     e074832a-eada-4fd7-94a1-10642b130e16
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Markus Neis
-- Date:         2018-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_hktl_safetykatz.yml
-- Unmapped:     (none)
-- False Pos:    Rare legitimate files with similar filename structure
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Temp\\debug.bin')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate files with similar filename structure

**References:**
- https://github.com/GhostPack/SafetyKatz
- https://github.com/GhostPack/SafetyKatz/blob/715b311f76eb3a4c8d00a1bd29c6cd1899e450b7/SafetyKatz/Program.cs#L63

---

## HackTool - Impacket File Indicators

| Field | Value |
|---|---|
| **Sigma ID** | `03f4ca17-de95-428d-a75a-4ee78b047256` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | The DFIR Report, IrishDeath |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_impacket_file_indicators.yml)**

> Detects file creation events with filename patterns used by Impacket.

```sql
-- ============================================================
-- Title:        HackTool - Impacket File Indicators
-- Sigma ID:     03f4ca17-de95-428d-a75a-4ee78b047256
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1003.001
-- Author:       The DFIR Report, IrishDeath
-- Date:         2025-05-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_impacket_file_indicators.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'fileName')], '\\sessionresume_[a-zA-Z]{8}$'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/
- https://github.com/fortra/impacket

---

## Potential Initial Access via DLL Search Order Hijacking

| Field | Value |
|---|---|
| **Sigma ID** | `dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1566, T1566.001, T1574, T1574.001 |
| **Author** | Tim Rauch (rule), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_initial_access_dll_search_order_hijacking.yml)**

> Detects attempts to create a DLL file to a known desktop application dependencies folder such as Slack, Teams or OneDrive and by an unusual process. This may indicate an attempt to load a malicious module via DLL search order hijacking.

```sql
-- ============================================================
-- Title:        Potential Initial Access via DLL Search Order Hijacking
-- Sigma ID:     dbbd9f66-2ed3-4ca2-98a4-6ea985dd1a1c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1566, T1566.001, T1574, T1574.001
-- Author:       Tim Rauch (rule), Elastic (idea)
-- Date:         2022-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_initial_access_dll_search_order_hijacking.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((procName LIKE '%\\winword.exe' OR procName LIKE '%\\excel.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\MSACCESS.EXE' OR procName LIKE '%\\MSPUB.EXE' OR procName LIKE '%\\fltldr.exe' OR procName LIKE '%\\cmd.exe' OR procName LIKE '%\\certutil.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\cscript.exe' OR procName LIKE '%\\wscript.exe' OR procName LIKE '%\\curl.exe' OR procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\OneDrive\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft OneDrive\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Teams\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Local\\slack\\app-%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Local\\Programs\\Microsoft VS Code\\%')))
  AND NOT ((procName LIKE '%\\cmd.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\OneDrive\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\api-ms-win-core-%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-5d46dd4ac6866b4337ec126be8cee0e115467b3e8703794ba6f6df6432c806bc
- https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0

---

## Installation of TeamViewer Desktop

| Field | Value |
|---|---|
| **Sigma ID** | `9711de76-5d4f-4c50-a94f-21e4e8f8384d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_install_teamviewer_desktop.yml)**

> TeamViewer_Desktop.exe is create during install

```sql
-- ============================================================
-- Title:        Installation of TeamViewer Desktop
-- Sigma ID:     9711de76-5d4f-4c50-a94f-21e4e8f8384d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       frack113
-- Date:         2022-01-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_install_teamviewer_desktop.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TeamViewer\_Desktop.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-1---teamviewer-files-detected-test-on-windows

---

## Malicious DLL File Dropped in the Teams or OneDrive Folder

| Field | Value |
|---|---|
| **Sigma ID** | `1908fcc1-1b92-4272-8214-0fbaf2fa5163` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.yml)**

> Detects creation of a malicious DLL file in the location where the OneDrive or Team applications
Upon execution of the Teams or OneDrive application, the dropped malicious DLL file ("iphlpapi.dll") is sideloaded


```sql
-- ============================================================
-- Title:        Malicious DLL File Dropped in the Teams or OneDrive Folder
-- Sigma ID:     1908fcc1-1b92-4272-8214-0fbaf2fa5163
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       frack113
-- Date:         2022-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%iphlpapi.dll%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/

---

## ISO File Created Within Temp Folders

| Field | Value |
|---|---|
| **Sigma ID** | `2f9356ae-bf43-41b8-b858-4496d83b2acb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1566.001 |
| **Author** | @sam0x90 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_iso_file_mount.yml)**

> Detects the creation of a ISO file in the Outlook temp folder or in the Appdata temp folder. Typical of Qakbot TTP from end-July 2022.

```sql
-- ============================================================
-- Title:        ISO File Created Within Temp Folders
-- Sigma ID:     2f9356ae-bf43-41b8-b858-4496d83b2acb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1566.001
-- Author:       @sam0x90
-- Date:         2022-07-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_iso_file_mount.yml
-- Unmapped:     (none)
-- False Pos:    Potential FP by sysadmin opening a zip file containing a legitimate ISO file
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.iso'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.iso'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Potential FP by sysadmin opening a zip file containing a legitimate ISO file

**References:**
- https://twitter.com/Sam0x90/status/1552011547974696960
- https://securityaffairs.co/wordpress/133680/malware/dll-sideloading-spread-qakbot.html
- https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1553.005/T1553.005.md#atomic-test-1---mount-iso-image

---

## ISO or Image Mount Indicator in Recent Files

| Field | Value |
|---|---|
| **Sigma ID** | `4358e5a5-7542-4dcb-b9f3-87667371839b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1566.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_iso_file_recent.yml)**

> Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks.
This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.


```sql
-- ============================================================
-- Title:        ISO or Image Mount Indicator in Recent Files
-- Sigma ID:     4358e5a5-7542-4dcb-b9f3-87667371839b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1566.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_iso_file_recent.yml
-- Unmapped:     (none)
-- False Pos:    Cases in which a user mounts an image file for legitimate reasons
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.iso.lnk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.img.lnk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vhd.lnk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vhdx.lnk'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Windows\\Recent\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Cases in which a user mounts an image file for legitimate reasons

**References:**
- https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
- https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
- https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
- https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files/

---

## GatherNetworkInfo.VBS Reconnaissance Script Output

| Field | Value |
|---|---|
| **Sigma ID** | `f92a6f1e-a512-4a15-9735-da09e78d7273` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lolbin_gather_network_info_script_output.yml)**

> Detects creation of files which are the results of executing the built-in reconnaissance script "C:\Windows\System32\gatherNetworkInfo.vbs".

```sql
-- ============================================================
-- Title:        GatherNetworkInfo.VBS Reconnaissance Script Output
-- Sigma ID:     f92a6f1e-a512-4a15-9735-da09e78d7273
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lolbin_gather_network_info_script_output.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\config%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Hotfixinfo.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\netiostate.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sysportslog.txt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\VmSwitchLog.evtx')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
- https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government

---

## LSASS Process Memory Dump Files

| Field | Value |
|---|---|
| **Sigma ID** | `a5a2d357-1ab8-4675-a967-ef9990a59391` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml)**

> Detects creation of files with names used by different memory dumping tools to create a memory dump of the LSASS process memory, which contains user credentials.

```sql
-- ============================================================
-- Title:        LSASS Process Memory Dump Files
-- Sigma ID:     a5a2d357-1ab8-4675-a967-ef9990a59391
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-11-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Andrew.dmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Coredump.dmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass.dmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass.rar' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass.zip' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\NotLSASS.zip' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PPLBlade.dmp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\rustive.dmp'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass\_2%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsassdmp%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsassdump%'))
  OR indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dmp%')
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%SQLDmpr%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.mdmp'))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\nanodump%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\proc\_%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dmp'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.google.com/search?q=procdump+lsass
- https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
- https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/credential_access_lsass_memdump_file_created.toml
- https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/
- https://github.com/helpsystems/nanodump
- https://github.com/CCob/MirrorDump
- https://github.com/safedv/RustiveDump/blob/1a9b026b477587becfb62df9677cede619d42030/src/main.rs#L35
- https://github.com/ricardojoserf/NativeDump/blob/01d8cd17f31f51f5955a38e85cd3c83a17596175/NativeDump/Program.cs#L258

---

## LSASS Process Dump Artefact In CrashDumps Folder

| Field | Value |
|---|---|
| **Sigma ID** | `6902955a-01b7-432c-b32a-6f5f81d8f625` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | @pbssubhash |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lsass_shtinkering.yml)**

> Detects the presence of an LSASS dump file in the "CrashDumps" folder. This could be a sign of LSASS credential dumping. Techniques such as the LSASS Shtinkering have been seen abusing the Windows Error Reporting to dump said process.

```sql
-- ============================================================
-- Title:        LSASS Process Dump Artefact In CrashDumps Folder
-- Sigma ID:     6902955a-01b7-432c-b32a-6f5f81d8f625
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       @pbssubhash
-- Date:         2022-12-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lsass_shtinkering.yml
-- Unmapped:     (none)
-- False Pos:    Rare legitimate dump of the process by the operating system due to a crash of lsass
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%lsass.exe.%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dmp'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate dump of the process by the operating system due to a crash of lsass

**References:**
- https://github.com/deepinstinct/Lsass-Shtinkering
- https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf

---

## WerFault LSASS Process Memory Dump

| Field | Value |
|---|---|
| **Sigma ID** | `c3e76af5-4ce0-4a14-9c9a-25ceb8fda182` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lsass_werfault_dump.yml)**

> Detects WerFault creating a dump file with a name that indicates that the dump file could be an LSASS process memory, which contains user credentials

```sql
-- ============================================================
-- Title:        WerFault LSASS Process Memory Dump
-- Sigma ID:     c3e76af5-4ce0-4a14-9c9a-25ceb8fda182
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_lsass_werfault_dump.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = 'C:\WINDOWS\system32\WerFault.exe'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%lsass.exe%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/helpsystems/nanodump

---

## Adwind RAT / JRAT File Artifact

| Field | Value |
|---|---|
| **Sigma ID** | `0bcfabcb-7929-47f4-93d6-b33fb67d34d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.005, T1059.007 |
| **Author** | Florian Roth (Nextron Systems), Tom Ueltschi, Jonhnathan Ribeiro, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_mal_adwind.yml)**

> Detects javaw.exe in AppData folder as used by Adwind / JRAT

```sql
-- ============================================================
-- Title:        Adwind RAT / JRAT File Artifact
-- Sigma ID:     0bcfabcb-7929-47f4-93d6-b33fb67d34d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.005, T1059.007
-- Author:       Florian Roth (Nextron Systems), Tom Ueltschi, Jonhnathan Ribeiro, oscd.community
-- Date:         2017-11-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_mal_adwind.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Roaming\\Oracle\\bin\\java%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe%'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Retrive%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://www.hybrid-analysis.com/sample/ba86fa0d4b6af2db0656a88b1dd29f36fe362473ae8ad04255c4e52f214a541c?environmentId=100
- https://www.first.org/resources/papers/conf2017/Advanced-Incident-Detection-and-Threat-Hunting-using-Sysmon-and-Splunk.pdf

---

## Octopus Scanner Malware

| Field | Value |
|---|---|
| **Sigma ID** | `805c55d9-31e6-4846-9878-c34c75054fe9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1195, T1195.001 |
| **Author** | NVISO |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_mal_octopus_scanner.yml)**

> Detects Octopus Scanner Malware.

```sql
-- ============================================================
-- Title:        Octopus Scanner Malware
-- Sigma ID:     805c55d9-31e6-4846-9878-c34c75054fe9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1195, T1195.001
-- Author:       NVISO
-- Date:         2020-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_mal_octopus_scanner.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft\\Cache134.dat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft\\ExplorerSync.db'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain

---

## File Creation In Suspicious Directory By Msdt.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `318557a5-150c-4c8d-b70e-a9910e199857` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Vadim Varganov, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_msdt_susp_directories.yml)**

> Detects msdt.exe creating files in suspicious directories which could be a sign of exploitation of either Follina or Dogwalk vulnerabilities

```sql
-- ============================================================
-- Title:        File Creation In Suspicious Directory By Msdt.EXE
-- Sigma ID:     318557a5-150c-4c8d-b70e-a9910e199857
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Vadim Varganov, Florian Roth (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_msdt_susp_directories.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\msdt.exe'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Desktop\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Start Menu\\Programs\\Startup\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\Users\\Public\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://irsl.medium.com/the-trouble-with-microsofts-troubleshooters-6e32fc80b8bd
- https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/

---

## Uncommon File Creation By Mysql Daemon Process

| Field | Value |
|---|---|
| **Sigma ID** | `c61daa90-3c1e-4f18-af62-8f288b5c9aaf` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Joseph Kamau |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.yml)**

> Detects the creation of files with scripting or executable extensions by Mysql daemon.
Which could be an indicator of "User Defined Functions" abuse to download malware.


```sql
-- ============================================================
-- Title:        Uncommon File Creation By Mysql Daemon Process
-- Sigma ID:     c61daa90-3c1e-4f18-af62-8f288b5c9aaf
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Joseph Kamau
-- Date:         2024-05-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\mysqld.exe' OR procName LIKE '%\\mysqld-nt.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.psm1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://asec.ahnlab.com/en/58878/
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/honeypot-recon-mysql-malware-infection-via-user-defined-functions-udf/

---

## Suspicious DotNET CLR Usage Log Artifact

| Field | Value |
|---|---|
| **Sigma ID** | `e0b06658-7d1d-4cd3-bf15-03467507ff7c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | frack113, omkar72, oscd.community, Wojciech Lesicki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_net_cli_artefact.yml)**

> Detects the creation of Usage Log files by the CLR (clr.dll). These files are named after the executing process once the assembly is finished executing for the first time in the (user) session context.

```sql
-- ============================================================
-- Title:        Suspicious DotNET CLR Usage Log Artifact
-- Sigma ID:     e0b06658-7d1d-4cd3-bf15-03467507ff7c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       frack113, omkar72, oscd.community, Wojciech Lesicki
-- Date:         2022-11-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_net_cli_artefact.yml
-- Unmapped:     (none)
-- False Pos:    Rundll32.exe with zzzzInvokeManagedCustomActionOutOfProc in command line and msiexec.exe as parent process - https://twitter.com/SBousseaden/status/1388064061087260675
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\cmstp.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\cscript.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\mshta.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\msxsl.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\regsvr32.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\rundll32.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\svchost.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\wscript.exe.log' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\UsageLogs\\wmic.exe.log'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rundll32.exe with zzzzInvokeManagedCustomActionOutOfProc in command line and msiexec.exe as parent process - https://twitter.com/SBousseaden/status/1388064061087260675

**References:**
- https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
- https://github.com/olafhartong/sysmon-modular/blob/fa1ae53132403d262be2bbd7f17ceea7e15e8c78/11_file_create/include_dotnet.xml
- https://web.archive.org/web/20221026202428/https://gist.github.com/code-scrap/d7f152ffcdb3e0b02f7f394f5187f008
- https://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html

---

## Suspicious File Creation In Uncommon AppData Folder

| Field | Value |
|---|---|
| **Sigma ID** | `d7b50671-d1ad-4871-aa60-5aa5b331fe04` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_new_files_in_uncommon_appdata_folder.yml)**

> Detects the creation of suspicious files and folders inside the user's AppData folder but not inside any of the common and well known directories (Local, Romaing, LocalLow). This method could be used as a method to bypass detection who exclude the AppData folder in fear of FPs

```sql
-- ============================================================
-- Title:        Suspicious File Creation In Uncommon AppData Folder
-- Sigma ID:     d7b50671-d1ad-4871-aa60-5aa5b331fe04
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_new_files_in_uncommon_appdata_folder.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cpl' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.iso' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.msi' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.psm1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs')))
  AND NOT ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\LocalLow\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Roaming\\%')))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research

---

## SCR File Write Event

| Field | Value |
|---|---|
| **Sigma ID** | `c048f047-7e2a-4888-b302-55f509d4a91d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218.011 |
| **Author** | Christopher Peacock @securepeacock, SCYTHE @scythe_io |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_new_scr_file.yml)**

> Detects the creation of screensaver files (.scr) outside of system folders. Attackers may execute an application as an ".SCR" file using "rundll32.exe desk.cpl,InstallScreenSaver" for example.

```sql
-- ============================================================
-- Title:        SCR File Write Event
-- Sigma ID:     c048f047-7e2a-4888-b302-55f509d4a91d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218.011
-- Author:       Christopher Peacock @securepeacock, SCYTHE @scythe_io
-- Date:         2022-04-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_new_scr_file.yml
-- Unmapped:     (none)
-- False Pos:    The installation of new screen savers by third party software
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr')
  AND NOT ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\$WINDOWS.~BT\\NewOS\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\SysWOW64\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\WinSxS\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\WUDownloadCache\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The installation of new screen savers by third party software

**References:**
- https://lolbas-project.github.io/lolbas/Libraries/Desk/

---

## Potential Persistence Via Notepad++ Plugins

| Field | Value |
|---|---|
| **Sigma ID** | `54127bd4-f541-4ac3-afdb-ea073f63f692` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_notepad_plus_plus_persistence.yml)**

> Detects creation of new ".dll" files inside the plugins directory of a notepad++ installation by a process other than "gup.exe". Which could indicates possible persistence

```sql
-- ============================================================
-- Title:        Potential Persistence Via Notepad++ Plugins
-- Sigma ID:     54127bd4-f541-4ac3-afdb-ea073f63f692
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_notepad_plus_plus_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Possible FPs during first installation of Notepad++; Legitimate use of custom plugins by users in order to enhance notepad++ functionalities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Notepad++\\plugins\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Possible FPs during first installation of Notepad++; Legitimate use of custom plugins by users in order to enhance notepad++ functionalities

**References:**
- https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/

---

## NTDS.DIT Created

| Field | Value |
|---|---|
| **Sigma ID** | `0b8baa3f-575c-46ee-8715-d6f28cc7d33c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1003.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_dit_creation.yml)**

> Detects creation of a file named "ntds.dit" (Active Directory Database)

```sql
-- ============================================================
-- Title:        NTDS.DIT Created
-- Sigma ID:     0b8baa3f-575c-46ee-8715-d6f28cc7d33c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1003.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_dit_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ntds.dit')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## NTDS.DIT Creation By Uncommon Parent Process

| Field | Value |
|---|---|
| **Sigma ID** | `4e7050dd-e548-483f-b7d6-527ab4fa784d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_parent_process.yml)**

> Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon parent process or directory

```sql
-- ============================================================
-- Title:        NTDS.DIT Creation By Uncommon Parent Process
-- Sigma ID:     4e7050dd-e548-483f-b7d6-527ab4fa784d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_parent_process.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ntds.dit')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
- https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
- https://pentestlab.blog/tag/ntds-dit/
- https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Copy-VSS.ps1

---

## NTDS.DIT Creation By Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `11b1ed55-154d-4e82-8ad7-83739298f720` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002, T1003.003 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_process.yml)**

> Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon process or a process located in a suspicious directory

```sql
-- ============================================================
-- Title:        NTDS.DIT Creation By Uncommon Process
-- Sigma ID:     11b1ed55-154d-4e82-8ad7-83739298f720
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002, T1003.003
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_process.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ntds.dit')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/
- https://adsecurity.org/?p=2398

---

## NTDS Exfiltration Filename Patterns

| Field | Value |
|---|---|
| **Sigma ID** | `3a8da4e0-36c1-40d2-8b29-b3e890d5172a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_exfil_tools.yml)**

> Detects creation of files with specific name patterns seen used in various tools that export the NTDS.DIT for exfiltration.

```sql
-- ============================================================
-- Title:        NTDS Exfiltration Filename Patterns
-- Sigma ID:     3a8da4e0-36c1-40d2-8b29-b3e890d5172a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ntds_exfil_tools.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\All.cab' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ntds.cleartext'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/rapid7/metasploit-framework/blob/eb6535009f5fdafa954525687f09294918b5398d/modules/post/windows/gather/ntds_grabber.rb
- https://github.com/rapid7/metasploit-framework/blob/eb6535009f5fdafa954525687f09294918b5398d/data/post/powershell/NTDSgrab.ps1
- https://github.com/SecureAuthCorp/impacket/blob/7d2991d78836b376452ca58b3d14daa61b67cb40/impacket/examples/secretsdump.py#L2405

---

## Potential Persistence Via Microsoft Office Add-In

| Field | Value |
|---|---|
| **Sigma ID** | `8e1cb247-6cf6-42fa-b440-3f27d57e9936` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137.006 |
| **Author** | NVISO |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_addin_persistence.yml)**

> Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel).

```sql
-- ============================================================
-- Title:        Potential Persistence Via Microsoft Office Add-In
-- Sigma ID:     8e1cb247-6cf6-42fa-b440-3f27d57e9936
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137.006
-- Author:       NVISO
-- Date:         2020-05-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_addin_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate add-ins
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Addins\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xla' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ppam')))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Word\\Startup\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wll'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Microsoft\\Excel\\XLSTART\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlam'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Excel\\Startup\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate add-ins

**References:**
- Internal Research
- https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence
- https://github.com/redcanaryco/atomic-red-team/blob/4ae9580a1a8772db87a1b6cdb0d03e5af231e966/atomics/T1137.006/T1137.006.md

---

## Office Macro File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `91174a41-dc8f-401b-be89-7bfc140612a0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1566.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_created.yml)**

> Detects the creation of a new office macro files on the systems

```sql
-- ============================================================
-- Title:        Office Macro File Creation
-- Sigma ID:     91174a41-dc8f-401b-be89-7bfc140612a0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1566.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_created.yml
-- Unmapped:     (none)
-- False Pos:    Very common in environments that rely heavily on macro documents
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dotm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xltm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.potm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptm'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Very common in environments that rely heavily on macro documents

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
- https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference

---

## Office Macro File Download

| Field | Value |
|---|---|
| **Sigma ID** | `0e29e3a7-1ad8-40aa-b691-9f82ecd33d66` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1566.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_downloaded.yml)**

> Detects the creation of a new office macro files on the system via an application (browser, mail client).
This can help identify potential malicious activity, such as the download of macro-enabled documents that could be used for exploitation.


```sql
-- ============================================================
-- Title:        Office Macro File Download
-- Sigma ID:     0e29e3a7-1ad8-40aa-b691-9f82ecd33d66
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1566.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_downloaded.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate macro files downloaded from the internet; Legitimate macro files sent as attachments via emails
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dotm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xltm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.potm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptm')))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dotm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xltm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.potm:Zone%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptm:Zone%')))
  AND (procName LIKE '%\\RuntimeBroker.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\thunderbird.exe' OR procName LIKE '%\\brave.exe' OR procName LIKE '%\\chrome.exe' OR procName LIKE '%\\firefox.exe' OR procName LIKE '%\\iexplore.exe' OR procName LIKE '%\\maxthon.exe' OR procName LIKE '%\\MicrosoftEdge.exe' OR procName LIKE '%\\msedge.exe' OR procName LIKE '%\\msedgewebview2.exe' OR procName LIKE '%\\opera.exe' OR procName LIKE '%\\safari.exe' OR procName LIKE '%\\seamonkey.exe' OR procName LIKE '%\\vivaldi.exe' OR procName LIKE '%\\whale.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate macro files downloaded from the internet; Legitimate macro files sent as attachments via emails

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
- https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference

---

## Office Macro File Creation From Suspicious Process

| Field | Value |
|---|---|
| **Sigma ID** | `b1c50487-1967-4315-a026-6491686d860e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1566.001 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_from_susp_process.yml)**

> Detects the creation of a office macro file from a a suspicious process

```sql
-- ============================================================
-- Title:        Office Macro File Creation From Suspicious Process
-- Sigma ID:     b1c50487-1967-4315-a026-6491686d860e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1566.001
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_from_susp_process.yml
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
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((procName LIKE '%\\cscript.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\regsvr32.exe' OR procName LIKE '%\\rundll32.exe' OR procName LIKE '%\\wscript.exe'))
  OR ((indexOf(metrics_string.name, 'parentProcName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%\\cscript.exe' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%\\mshta.exe' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%\\regsvr32.exe' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%\\rundll32.exe' OR metrics_string.value[indexOf(metrics_string.name,'parentProcName')] LIKE '%\\wscript.exe')))
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dotm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xltm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.potm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptm')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
- https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference

---

## OneNote Attachment File Dropped In Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `7fd164ba-126a-4d9c-9392-0d4f7c243df0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_onenote_files_in_susp_locations.yml)**

> Detects creation of files with the ".one"/".onepkg" extension in suspicious or uncommon locations. This could be a sign of attackers abusing OneNote attachments

```sql
-- ============================================================
-- Title:        OneNote Attachment File Dropped In Suspicious Location
-- Sigma ID:     7fd164ba-126a-4d9c-9392-0d4f7c243df0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_onenote_files_in_susp_locations.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of ".one" or ".onepkg" files from those locations
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Temp\\%'))
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.one' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.onepkg')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of ".one" or ".onepkg" files from those locations

**References:**
- https://www.bleepingcomputer.com/news/security/hackers-now-use-microsoft-onenote-attachments-to-spread-malware/
- https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/

---

## Suspicious File Created Via OneNote Application

| Field | Value |
|---|---|
| **Sigma ID** | `fcc6d700-68d9-4241-9a1a-06874d621b06` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_onenote_susp_dropped_files.yml)**

> Detects suspicious files created via the OneNote application. This could indicate a potential malicious ".one"/".onepkg" file was executed as seen being used in malware activity in the wild

```sql
-- ============================================================
-- Title:        Suspicious File Created Via OneNote Application
-- Sigma ID:     fcc6d700-68d9-4241-9a1a-06874d621b06
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_onenote_susp_dropped_files.yml
-- Unmapped:     (none)
-- False Pos:    False positives should be very low with the extensions list cited. Especially if you don't heavily utilize OneNote.; Occasional FPs might occur if OneNote is used internally to share different embedded documents
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\onenote.exe' OR procName LIKE '%\\onenotem.exe' OR procName LIKE '%\\onenoteim.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\OneNote\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.chm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.htm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.html' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives should be very low with the extensions list cited. Especially if you don't heavily utilize OneNote.; Occasional FPs might occur if OneNote is used internally to share different embedded documents

**References:**
- https://www.bleepingcomputer.com/news/security/hackers-now-use-microsoft-onenote-attachments-to-spread-malware/
- https://blog.osarmor.com/319/onenote-attachment-delivers-asyncrat-malware/
- https://twitter.com/MaD_c4t/status/1623414582382567424
- https://labs.withsecure.com/publications/detecting-onenote-abuse
- https://www.trustedsec.com/blog/new-attacks-old-tricks-how-onenote-malware-is-evolving/
- https://app.any.run/tasks/17f2d378-6d11-4d6f-8340-954b04f35e83/

---

## New Outlook Macro Created

| Field | Value |
|---|---|
| **Sigma ID** | `8c31f563-f9a7-450c-bfa8-35f8f32f1f61` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137, T1008, T1546 |
| **Author** | @ScoubiMtl |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_macro_creation.yml)**

> Detects the creation of a macro file for Outlook.

```sql
-- ============================================================
-- Title:        New Outlook Macro Created
-- Sigma ID:     8c31f563-f9a7-450c-bfa8-35f8f32f1f61
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1137, T1008, T1546
-- Author:       @ScoubiMtl
-- Date:         2021-04-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_macro_creation.yml
-- Unmapped:     (none)
-- False Pos:    User genuinely creates a VB Macro for their email
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\outlook.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Outlook\\VbaProject.OTM'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User genuinely creates a VB Macro for their email

**References:**
- https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/

---

## Potential Persistence Via Outlook Form

| Field | Value |
|---|---|
| **Sigma ID** | `c3edc6a5-d9d4-48d8-930e-aab518390917` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137.003 |
| **Author** | Tobias Michalski (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_newform.yml)**

> Detects the creation of a new Outlook form which can contain malicious code

```sql
-- ============================================================
-- Title:        Potential Persistence Via Outlook Form
-- Sigma ID:     c3edc6a5-d9d4-48d8-930e-aab518390917
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137.003
-- Author:       Tobias Michalski (Nextron Systems)
-- Date:         2021-06-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_newform.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of outlook forms
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\outlook.exe'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft\\FORMS\\IPM%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Local Settings\\Application Data\\Microsoft\\Forms%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of outlook forms

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=76
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=79
- https://learn.microsoft.com/en-us/office/vba/outlook/concepts/outlook-forms/create-an-outlook-form
- https://www.slipstick.com/developer/custom-form/clean-outlooks-forms-cache/

---

## Suspicious File Created in Outlook Temporary Directory

| Field | Value |
|---|---|
| **Sigma ID** | `fabb0e80-030c-4e3e-a104-d09676991ac3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1566.001 |
| **Author** | Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_susp_file_creation_in_temp_dir.yml)**

> Detects the creation of files with suspicious file extensions in the temporary directory that Outlook uses when opening attachments.
This can be used to detect spear-phishing campaigns that use suspicious files as attachments, which may contain malicious code.


```sql
-- ============================================================
-- Title:        Suspicious File Created in Outlook Temporary Directory
-- Sigma ID:     fabb0e80-030c-4e3e-a104-d09676991ac3
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1566.001
-- Author:       Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_susp_file_creation_in_temp_dir.yml
-- Unmapped:     (none)
-- False Pos:    Opening of headers or footers in email signatures that include SVG images or legitimate SVG attachments
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cpl' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.iso' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rdp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.svg' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vba' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs'))
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Packages\\Microsoft.Outlook\_%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft\\Olk\\Attachments\\%')))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Microsoft\\Windows\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Content.Outlook\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Opening of headers or footers in email signatures that include SVG images or legitimate SVG attachments

**References:**
- https://vipre.com/blog/svg-phishing-attacks-the-new-trick-in-the-cybercriminals-playbook/
- https://thecyberexpress.com/rogue-rdp-files-used-in-ukraine-cyberattacks/
- https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/

---

## Suspicious Outlook Macro Created

| Field | Value |
|---|---|
| **Sigma ID** | `117d3d3a-755c-4a61-b23e-9171146d094c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137, T1008, T1546 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_susp_macro_creation.yml)**

> Detects the creation of a macro file for Outlook.

```sql
-- ============================================================
-- Title:        Suspicious Outlook Macro Created
-- Sigma ID:     117d3d3a-755c-4a61-b23e-9171146d094c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137, T1008, T1546
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_outlook_susp_macro_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Outlook\\VbaProject.OTM')
  AND NOT (procName LIKE '%\\outlook.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53
- https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/

---

## Publisher Attachment File Dropped In Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `3d2a2d59-929c-4b78-8c1a-145dfe9e07b1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_publisher_files_in_susp_locations.yml)**

> Detects creation of files with the ".pub" extension in suspicious or uncommon locations. This could be a sign of attackers abusing Publisher documents

```sql
-- ============================================================
-- Title:        Publisher Attachment File Dropped In Suspicious Location
-- Sigma ID:     3d2a2d59-929c-4b78-8c1a-145dfe9e07b1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_publisher_files_in_susp_locations.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of ".pub" files from those locations
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\Temp\\%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pub'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of ".pub" files from those locations

**References:**
- https://twitter.com/EmericNasi/status/1623224526220804098

---

## Potential Persistence Via Microsoft Office Startup Folder

| Field | Value |
|---|---|
| **Sigma ID** | `0e20c89d-2264-44ae-8238-aeeaba609ece` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137 |
| **Author** | Max Altgelt (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_startup_persistence.yml)**

> Detects creation of Microsoft Office files inside of one of the default startup folders in order to achieve persistence.

```sql
-- ============================================================
-- Title:        Potential Persistence Via Microsoft Office Startup Folder
-- Sigma ID:     0e20c89d-2264-44ae-8238-aeeaba609ece
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137
-- Author:       Max Altgelt (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_startup_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Loading a user environment from a backup or a domain controller; Synchronization of templates
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND NOT ((procName LIKE '%\\WINWORD.exe' OR procName LIKE '%\\EXCEL.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Loading a user environment from a backup or a domain controller; Synchronization of templates

**References:**
- https://insight-jp.nttsecurity.com/post/102hojk/operation-restylink-apt-campaign-targeting-japanese-companies
- https://learn.microsoft.com/en-us/office/troubleshoot/excel/use-startup-folders

---

## File With Uncommon Extension Created By An Office Application

| Field | Value |
|---|---|
| **Sigma ID** | `c7a74c80-ba5a-486e-9974-ab9e682bc5e4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_susp_file_extension.yml)**

> Detects the creation of files with an executable or script extension by an Office application.

```sql
-- ============================================================
-- Title:        File With Uncommon Extension Created By An Office Application
-- Sigma ID:     c7a74c80-ba5a-486e-9974-ab9e682bc5e4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_susp_file_extension.yml
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
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
- https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml

---

## Uncommon File Created In Office Startup Folder

| Field | Value |
|---|---|
| **Sigma ID** | `a10a2c40-2c4d-49f8-b557-1a946bc55d9d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1587.001 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_uncommon_file_startup.yml)**

> Detects the creation of a file with an uncommon extension in an Office application startup folder

```sql
-- ============================================================
-- Title:        Uncommon File Created In Office Startup Folder
-- Sigma ID:     a10a2c40-2c4d-49f8-b557-1a946bc55d9d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1587.001
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_uncommon_file_startup.yml
-- Unmapped:     (none)
-- False Pos:    False positive might stem from rare extensions used by other Office utilities.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Word\\STARTUP%'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Office%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Program Files%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\STARTUP%'))
  AND NOT ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docb' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dotm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.mdb' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.mdw' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pdf' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wwl'))))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Excel\\XLSTART%'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Office%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Program Files%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\XLSTART%'))
  AND NOT ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xls' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlt' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xltm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlw'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positive might stem from rare extensions used by other Office utilities.

**References:**
- https://app.any.run/tasks/d6fe6624-6ef8-485d-aa75-3d1bdda2a08c/
- http://addbalance.com/word/startup.htm
- https://answers.microsoft.com/en-us/msoffice/forum/all/document-in-word-startup-folder-doesnt-open-when/44ab0932-2917-4150-8cdc-2f2cf39e86f3
- https://en.wikipedia.org/wiki/List_of_Microsoft_Office_filename_extensions

---

## PCRE.NET Package Temp Files

| Field | Value |
|---|---|
| **Sigma ID** | `6e90ae7a-7cd3-473f-a035-4ebb72d961da` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_pcre_net_temp_file.yml)**

> Detects processes creating temp files related to PCRE.NET package

```sql
-- ============================================================
-- Title:        PCRE.NET Package Temp Files
-- Sigma ID:     6e90ae7a-7cd3-473f-a035-4ebb72d961da
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_pcre_net_temp_file.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/rbmaslen/status/1321859647091970051
- https://twitter.com/tifkin_/status/1321916444557365248

---

## Suspicious File Created In PerfLogs

| Field | Value |
|---|---|
| **Sigma ID** | `bbb7e38c-0b41-4a11-b306-d2a457b7ac2b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_perflogs_susp_files.yml)**

> Detects suspicious file based on their extension being created in "C:\PerfLogs\". Note that this directory mostly contains ".etl" files

```sql
-- ============================================================
-- Title:        Suspicious File Created In PerfLogs
-- Sigma ID:     bbb7e38c-0b41-4a11-b306-d2a457b7ac2b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_perflogs_susp_files.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\PerfLogs\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.7z' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bin' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.chm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.psm1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.py' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sys' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research
- https://labs.withsecure.com/publications/fin7-target-veeam-servers

---

## Potential Binary Or Script Dropper Via PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `7047d730-036f-4f40-b9d8-1c63e36d5e62` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_drop_binary_or_script.yml)**

> Detects PowerShell creating a binary executable or a script file.

```sql
-- ============================================================
-- Title:        Potential Binary Or Script Dropper Via PowerShell
-- Sigma ID:     7047d730-036f-4f40-b9d8-1c63e36d5e62
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_drop_binary_or_script.yml
-- Unmapped:     (none)
-- False Pos:    False positives will differ depending on the environment and scripts used. Apply additional filters accordingly.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\powershell.exe' OR procName LIKE '%\\powershell\_ise.exe' OR procName LIKE '%\\pwsh.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.chm' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.com' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jar' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ocx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sys' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives will differ depending on the environment and scripts used. Apply additional filters accordingly.

**References:**
- https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

---

## PowerShell Script Dropped Via PowerShell.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `576426ad-0131-4001-ae01-be175da0c108` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_drop_powershell.yml)**

> Detects PowerShell creating a PowerShell file (.ps1). While often times this behavior is benign, sometimes it can be a sign of a dropper script trying to achieve persistence.

```sql
-- ============================================================
-- Title:        PowerShell Script Dropped Via PowerShell.EXE
-- Sigma ID:     576426ad-0131-4001-ae01-be175da0c108
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence
-- Author:       frack113
-- Date:         2023-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_drop_powershell.yml
-- Unmapped:     (none)
-- False Pos:    False positives will differ depending on the environment and scripts used. Apply additional filters accordingly.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives will differ depending on the environment and scripts used. Apply additional filters accordingly.

**References:**
- https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

---

## Malicious PowerShell Scripts - FileCreation

| Field | Value |
|---|---|
| **Sigma ID** | `f331aa1f-8c53-4fc3-b083-cc159bc971cb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Markus Neis, Nasreddine Bencherchali (Nextron Systems), Mustafa Kaan Demir, Georg Lauenstein |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_exploit_scripts.yml)**

> Detects the creation of known offensive powershell scripts used for exploitation

```sql
-- ============================================================
-- Title:        Malicious PowerShell Scripts - FileCreation
-- Sigma ID:     f331aa1f-8c53-4fc3-b083-cc159bc971cb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Markus Neis, Nasreddine Bencherchali (Nextron Systems), Mustafa Kaan Demir, Georg Lauenstein
-- Date:         2018-04-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_exploit_scripts.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Add-ConstrainedDelegationBackdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Add-Exfiltration.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Add-Persistence.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Add-RegBackdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Add-RemoteRegBackdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Add-ScrnSaveBackdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ADRecon.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AzureADRecon.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\BadSuccessor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Check-VM.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ConvertTo-ROT13.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Copy-VSS.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Create-MultipleSessions.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\DNS\_TXT\_Pwnage.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\dnscat2.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Do-Exfiltration.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\DomainPasswordSpray.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Download\_Execute.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Download-Execute-PS.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Enable-DuplicateToken.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Enabled-DuplicateToken.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Execute-Command-MSSQL.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Execute-DNSTXT-Code.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Execute-OnTime.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ExetoText.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Exploit-Jboss.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Find-AVSignature.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Find-Fruit.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Find-GPOLocation.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Find-TrustedDocuments.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\FireBuster.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\FireListener.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ApplicationHost.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ChromeDump.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ClipboardContents.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ComputerDetail.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-FoxDump.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-GPPAutologon.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-GPPPassword.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-IndexedItem.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-Keystrokes.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-LSASecret.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-MicrophoneAudio.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-PassHashes.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-PassHints.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-RegAlwaysInstallElevated.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-RegAutoLogon.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-RickAstley.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-Screenshot.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-SecurityPackages.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ServiceFilePermission.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ServicePermission.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-ServiceUnquoted.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-SiteListPassword.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-System.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-TimedScreenshot.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-UnattendedInstallFile.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-Unconstrained.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-USBKeystrokes.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-VaultCredential.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-VulnAutoRun.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-VulnSchTask.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-WebConfig.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-WebCredentials.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Get-WLAN-Keys.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Gupt-Backdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\HTTP-Backdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\HTTP-Login.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Install-ServiceBinary.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Install-SSP.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ACLScanner.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ADSBackdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-AmsiBypass.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ARPScan.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-BackdoorLNK.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-BadPotato.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-BetterSafetyKatz.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-BruteForce.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-BypassUAC.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Carbuncle.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Certify.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ConPtyShell.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-CredentialInjection.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-CredentialsPhish.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DAFT.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DCSync.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Decode.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DinvokeKatz.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DllInjection.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DNSExfiltrator.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DNSUpdate.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-DowngradeAccount.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-EgressCheck.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Encode.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-EventViewer.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Eyewitness.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-FakeLogonScreen.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Farmer.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Get-RBCD-Threaded.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Gopher.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Grouper2.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Grouper3.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-HandleKatz.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Interceptor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Internalmonologue.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Inveigh.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-InveighRelay.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-JSRatRegsvr.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-JSRatRundll.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-KrbRelay.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-KrbRelayUp.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-LdapSignCheck.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Lockless.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-MalSCCM.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Mimikatz.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-MimikatzWDigestDowngrade.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Mimikittenz.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-MITM6.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-NanoDump.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-NetRipper.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-NetworkRelay.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-NinjaCopy.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-OxidResolver.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-P0wnedshell.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-P0wnedshellx86.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Paranoia.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PortScan.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PoshRatHttp.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PoshRatHttps.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PostExfil.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerDump.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerDPAPI.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellIcmp.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellTCP.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellTcpOneLine.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellTcpOneLineBind.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellUdp.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellUdpOneLine.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerShellWMI.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PowerThIEf.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PPLDump.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Prasadhak.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PsExec.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PsGcat.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PsGcatAgent.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PSInject.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-PsUaCme.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ReflectivePEInjection.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ReverseDNSLookup.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Rubeus.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-RunAs.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SafetyKatz.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SauronEye.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SCShell.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Seatbelt.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ServiceAbuse.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SessionGopher.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ShellCode.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SMBScanner.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Snaffler.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Spoolsample.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SSHCommand.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-SSIDExfil.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-StandIn.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-StickyNotesExtract.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Tater.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Thunderfox.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-ThunderStruck.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-TokenManipulation.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Tokenvator.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-TotalExec.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-UrbanBishop.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-UserHunter.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-VoiceTroll.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Whisker.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-WinEnum.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-winPEAS.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-WireTap.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-WmiCommand.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-WScriptBypassUAC.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Invoke-Zerologon.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Keylogger.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\MailRaider.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\New-HoneyHash.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\OfficeMemScraper.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Offline\_Winpwn.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-CHM.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-DnsTxt.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-Excel.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-HTA.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-Java.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-JS.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-Minidump.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-RundllCommand.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-SCF.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-SCT.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-Shortcut.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-WebQuery.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Out-Word.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Parse\_Keys.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Port-Scan.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerBreach.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\powercat.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Powermad.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerRunAsSystem.psm1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerSharpPack.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerUp.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerUpSQL.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerView.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PSAsyncShell.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\RemoteHashRetrieval.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Remove-Persistence.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Remove-PoshRat.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Remove-Update.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Run-EXEonRemote.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Schtasks-Backdoor.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Set-DCShadowPermissions.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Set-MacAttribute.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Set-RemotePSRemoting.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Set-RemoteWMI.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Set-Wallpaper.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Show-TargetScreen.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Speak.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Start-CaptureServer.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Start-WebcamRecorder.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\StringToBase64.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TexttoExe.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Veeam-Get-Creds.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\VolumeShadowCopyTools.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WinPwn.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WSUSpendu.ps1'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Invoke-Sharp%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/PowerShellMafia/PowerSploit
- https://github.com/NetSPI/PowerUpSQL
- https://github.com/CsEnox/EventViewer-UACBypass
- https://web.archive.org/web/20210511204621/https://github.com/AlsidOfficial/WSUSpendu
- https://github.com/nettitude/Invoke-PowerThIEf
- https://github.com/S3cur3Th1sSh1t/WinPwn
- https://github.com/S3cur3Th1sSh1t/PowerSharpPack/tree/master/PowerSharpBinaries
- https://github.com/BC-SECURITY/Invoke-ZeroLogon/blob/111d17c7fec486d9bb23387e2e828b09a26075e4/Invoke-ZeroLogon.ps1
- https://github.com/xorrior/RandomPS-Scripts/blob/848c919bfce4e2d67b626cbcf4404341cfe3d3b6/Get-DXWebcamVideo.ps1
- https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/6f23bb41f9675d7e2d32bacccff75e931ae00554/OfficeMemScraper.ps1
- https://github.com/dafthack/DomainPasswordSpray/blob/b13d64a5834694aa73fd2aea9911a83027c465a7/DomainPasswordSpray.ps1
- https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/
- https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/
- https://github.com/HarmJ0y/DAMP
- https://github.com/samratashok/nishang
- https://github.com/DarkCoderSc/PowerRunAsSystem/
- https://github.com/besimorhino/powercat
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/adrecon/ADRecon
- https://github.com/adrecon/AzureADRecon
- https://github.com/sadshade/veeam-creds/blob/6010eaf31ba41011b58d6af3950cffbf6f5cea32/Veeam-Get-Creds.ps1
- https://github.com/The-Viper-One/Invoke-PowerDPAPI/
- https://github.com/Arno0x/DNSExfiltrator/

---

## PowerShell Module File Created

| Field | Value |
|---|---|
| **Sigma ID** | `e36941d0-c0f0-443f-bc6f-cb2952eb69ea` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_module_creation.yml)**

> Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc.

```sql
-- ============================================================
-- Title:        PowerShell Module File Created
-- Sigma ID:     e36941d0-c0f0-443f-bc6f-cb2952eb69ea
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_module_creation.yml
-- Unmapped:     (none)
-- False Pos:    Likely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WindowsPowerShell\\Modules\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerShell\\7\\Modules\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- Internal Research
- https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3

---

## Potential Suspicious PowerShell Module File Created

| Field | Value |
|---|---|
| **Sigma ID** | `e8a52bbd-bced-459f-bd93-64db45ce7657` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_module_susp_creation.yml)**

> Detects the creation of a new PowerShell module in the first folder of the module directory structure "\WindowsPowerShell\Modules\malware\malware.psm1". This is somewhat an uncommon practice as legitimate modules often includes a version folder.

```sql
-- ============================================================
-- Title:        Potential Suspicious PowerShell Module File Created
-- Sigma ID:     e8a52bbd-bced-459f-bd93-64db45ce7657
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_module_susp_creation.yml
-- Unmapped:     (none)
-- False Pos:    False positive rate will vary depending on the environments. Additional filters might be required to make this logic usable in production.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\\\WindowsPowerShell\\\\Modules\\\\*\\.ps' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\\\WindowsPowerShell\\\\Modules\\\\*\\.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positive rate will vary depending on the environments. Additional filters might be required to make this logic usable in production.

**References:**
- Internal Research
- https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3

---

## PowerShell Module File Created By Non-PowerShell Process

| Field | Value |
|---|---|
| **Sigma ID** | `e3845023-ca9a-4024-b2b2-5422156d5527` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_module_uncommon_creation.yml)**

> Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc. by a non-PowerShell process

```sql
-- ============================================================
-- Title:        PowerShell Module File Created By Non-PowerShell Process
-- Sigma ID:     e3845023-ca9a-4024-b2b2-5422156d5527
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_module_uncommon_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WindowsPowerShell\\Modules\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerShell\\7\\Modules\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research
- https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3

---

## Potential Startup Shortcut Persistence Via PowerShell.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `92fa78e7-4d39-45f1-91a3-8b23f3f1088d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Christopher Peacock '@securepeacock', SCYTHE |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_startup_shortcuts.yml)**

> Detects PowerShell writing startup shortcuts.
This procedure was highlighted in Red Canary Intel Insights Oct. 2021, "We frequently observe adversaries using PowerShell to write malicious .lnk files into the startup directory to establish persistence.
Accordingly, this detection opportunity is likely to identify persistence mechanisms in multiple threats.
In the context of Yellow Cockatoo, this persistence mechanism eventually launches the command-line script that leads to the installation of a malicious DLL"


```sql
-- ============================================================
-- Title:        Potential Startup Shortcut Persistence Via PowerShell.EXE
-- Sigma ID:     92fa78e7-4d39-45f1-91a3-8b23f3f1088d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Christopher Peacock '@securepeacock', SCYTHE
-- Date:         2021-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_startup_shortcuts.yml
-- Unmapped:     (none)
-- False Pos:    Depending on your environment accepted applications may leverage this at times. It is recommended to search for anomalies inidicative of malware.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\start menu\\programs\\startup\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Depending on your environment accepted applications may leverage this at times. It is recommended to search for anomalies inidicative of malware.

**References:**
- https://redcanary.com/blog/intelligence-insights-october-2021/
- https://github.com/redcanaryco/atomic-red-team/blob/36d49de4c8b00bf36054294b4a1fcbab3917d7c5/atomics/T1547.001/T1547.001.md#atomic-test-7---add-executable-shortcut-link-to-user-startup-folder

---

## PSScriptPolicyTest Creation By Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `1027d292-dd87-4a1a-8701-2abe04d7783c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ps_script_policy_test_creation_by_uncommon_process.yml)**

> Detects the creation of the "PSScriptPolicyTest" PowerShell script by an uncommon process. This file is usually generated by Microsoft Powershell to test against Applocker.

```sql
-- ============================================================
-- Title:        PSScriptPolicyTest Creation By Uncommon Process
-- Sigma ID:     1027d292-dd87-4a1a-8701-2abe04d7783c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ps_script_policy_test_creation_by_uncommon_process.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_\_PSScriptPolicyTest\_%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.paloaltonetworks.com/blog/security-operations/stopping-powershell-without-powershell/

---

## Rclone Config File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `34986307-b7f4-49be-92f3-e7a4d01ac5db` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Aaron Greetham (@beardofbinary) - NCC Group |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_rclone_config_files.yml)**

> Detects Rclone config files being created

```sql
-- ============================================================
-- Title:        Rclone Config File Creation
-- Sigma ID:     34986307-b7f4-49be-92f3-e7a4d01ac5db
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Aaron Greetham (@beardofbinary) - NCC Group
-- Date:         2021-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_rclone_config_files.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Rclone usage
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Users\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\.config\\rclone\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Rclone usage

**References:**
- https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/

---

## .RDP File Created By Uncommon Application

| Field | Value |
|---|---|
| **Sigma ID** | `fccfb43e-09a7-4bd2-8b37-a5a7df33386d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_rdp_file_susp_creation.yml)**

> Detects creation of a file with an ".rdp" extension by an application that doesn't commonly create such files.


```sql
-- ============================================================
-- Title:        .RDP File Created By Uncommon Application
-- Sigma ID:     fccfb43e-09a7-4bd2-8b37-a5a7df33386d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_rdp_file_susp_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rdp')
    AND (procName LIKE '%\\brave.exe' OR procName LIKE '%\\CCleaner Browser\\Application\\CCleanerBrowser.exe' OR procName LIKE '%\\chromium.exe' OR procName LIKE '%\\firefox.exe' OR procName LIKE '%\\Google\\Chrome\\Application\\chrome.exe' OR procName LIKE '%\\iexplore.exe' OR procName LIKE '%\\microsoftedge.exe' OR procName LIKE '%\\msedge.exe' OR procName LIKE '%\\Opera.exe' OR procName LIKE '%\\Vivaldi.exe' OR procName LIKE '%\\Whale.exe' OR procName LIKE '%\\olk.exe' OR procName LIKE '%\\Outlook.exe' OR procName LIKE '%\\RuntimeBroker.exe' OR procName LIKE '%\\Thunderbird.exe' OR procName LIKE '%\\Discord.exe' OR procName LIKE '%\\Keybase.exe' OR procName LIKE '%\\msteams.exe' OR procName LIKE '%\\Slack.exe' OR procName LIKE '%\\teams.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
- https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/

---

## Potential Winnti Dropper Activity

| Field | Value |
|---|---|
| **Sigma ID** | `130c9e58-28ac-4f83-8574-0a4cc913b97e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027 |
| **Author** | Alexander Rausch |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_redmimicry_winnti_filedrop.yml)**

> Detects files dropped by Winnti as described in RedMimicry Winnti playbook

```sql
-- ============================================================
-- Title:        Potential Winnti Dropper Activity
-- Sigma ID:     130c9e58-28ac-4f83-8574-0a4cc913b97e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027
-- Author:       Alexander Rausch
-- Date:         2020-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_redmimicry_winnti_filedrop.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\gthread-3.6.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sigcmm-2.4.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\Temp\\tmp.bat'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redmimicry.com/posts/redmimicry-winnti/#dropper

---

## PDF File Created By RegEdit.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `145095eb-e273-443b-83d0-f9b519b7867b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.yml)**

> Detects the creation of a file with the ".pdf" extension by the "RegEdit.exe" process.
This indicates that a user is trying to print/save a registry key as a PDF in order to potentially extract sensitive information and bypass defenses.


```sql
-- ============================================================
-- Title:        PDF File Created By RegEdit.EXE
-- Sigma ID:     145095eb-e273-443b-83d0-f9b519b7867b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\regedit.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pdf'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://sensepost.com/blog/2024/dumping-lsa-secrets-a-story-about-task-decorrelation/

---

## RemCom Service File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `7eff1a7f-dd45-4c20-877a-f21e342a7611` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_remcom_service.yml)**

> Detects default RemCom service filename which indicates RemCom service installation and execution

```sql
-- ============================================================
-- Title:        RemCom Service File Creation
-- Sigma ID:     7eff1a7f-dd45-4c20-877a-f21e342a7611
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_remcom_service.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\RemComSvc.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/kavika13/RemCom/

---

## ScreenConnect Temporary Installation Artefact

| Field | Value |
|---|---|
| **Sigma ID** | `fec96f39-988b-4586-b746-b93d59fd1922` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_remote_access_tools_screenconnect_artefact.yml)**

> An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


```sql
-- ============================================================
-- Title:        ScreenConnect Temporary Installation Artefact
-- Sigma ID:     fec96f39-988b-4586-b746-b93d59fd1922
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       frack113
-- Date:         2022-02-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_remote_access_tools_screenconnect_artefact.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Bin\\ScreenConnect.%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-5---screenconnect-application-download-and-install-on-windows

---

## Remote Access Tool - ScreenConnect Temporary File

| Field | Value |
|---|---|
| **Sigma ID** | `0afecb6e-6223-4a82-99fb-bf5b981e92a5` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.003 |
| **Author** | Ali Alwashali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_remote_access_tools_screenconnect_remote_file.yml)**

> Detects the creation of files in a specific location by ScreenConnect RMM.
ScreenConnect has feature to remotely execute binaries on a target machine. These binaries will be dropped to ":\Users\<username>\Documents\ConnectWiseControl\Temp\" before execution.


```sql
-- ============================================================
-- Title:        Remote Access Tool - ScreenConnect Temporary File
-- Sigma ID:     0afecb6e-6223-4a82-99fb-bf5b981e92a5
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1059.003
-- Author:       Ali Alwashali
-- Date:         2023-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_remote_access_tools_screenconnect_remote_file.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of ScreenConnect
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\ScreenConnect.WindowsClient.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Documents\\ConnectWiseControl\\Temp\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of ScreenConnect

**References:**
- https://github.com/SigmaHQ/sigma/pull/4467

---

## Potential RipZip Attack on Startup Folder

| Field | Value |
|---|---|
| **Sigma ID** | `a6976974-ea6f-4e97-818e-ea08625c52cb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547 |
| **Author** | Greg (rule) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ripzip_attack.yml)**

> Detects a phishing attack which expands a ZIP file containing a malicious shortcut.
If the victim expands the ZIP file via the explorer process, then the explorer process expands the malicious ZIP file and drops a malicious shortcut redirected to a backdoor into the Startup folder.
Additionally, the file name of the malicious shortcut in Startup folder contains {0AFACED1-E828-11D1-9187-B532F1E9575D} meaning the folder shortcut operation.


```sql
-- ============================================================
-- Title:        Potential RipZip Attack on Startup Folder
-- Sigma ID:     a6976974-ea6f-4e97-818e-ea08625c52cb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547
-- Author:       Greg (rule)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_ripzip_attack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk.{0AFACED1-E828-11D1-9187-B532F1E9575D}%')
    AND procName LIKE '%\\explorer.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/jonasLyk/status/1549338335243534336?t=CrmPocBGLbDyE4p6zTX1cg&s=19

---

## Potential SAM Database Dump

| Field | Value |
|---|---|
| **Sigma ID** | `4e87b8e2-2ee9-4b2a-a715-4727d297ece0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sam_dump.yml)**

> Detects the creation of files that look like exports of the local SAM (Security Account Manager)

```sql
-- ============================================================
-- Title:        Potential SAM Database Dump
-- Sigma ID:     4e87b8e2-2ee9-4b2a-a715-4727d297ece0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sam_dump.yml
-- Unmapped:     (none)
-- False Pos:    Rare cases of administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Temp\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam.sav' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Intel\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam.hive' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Perflogs\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ProgramData\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\Public\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Roaming\\sam' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_ShadowSteal.zip' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Documents\\SAM.export' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\sam')))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\hive\_sam\_%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam.save%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam.export%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\~reg\_sam.save%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam\_backup%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam.bck%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\sam.backup%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare cases of administrative activity

**References:**
- https://github.com/search?q=CVE-2021-36934
- https://web.archive.org/web/20210725081645/https://github.com/cube0x0/CVE-2021-36934
- https://www.google.com/search?q=%22reg.exe+save%22+sam
- https://github.com/HuskyHacks/ShadowSteal
- https://github.com/FireFart/hivenightmare

---

## Self Extraction Directive File Created In Potentially Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `760e75d8-c3b5-409b-a9bf-6130b4c4603f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sed_file_creation.yml)**

> Detects the creation of Self Extraction Directive files (.sed) in a potentially suspicious location.
These files are used by the "iexpress.exe" utility in order to create self extracting packages.
Attackers were seen abusing this utility and creating PE files with embedded ".sed" entries.


```sql
-- ============================================================
-- Title:        Self Extraction Directive File Created In Potentially Suspicious Location
-- Sigma ID:     760e75d8-c3b5-409b-a9bf-6130b4c4603f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2024-02-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sed_file_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\System32\\Tasks\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\Tasks\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sed'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://strontic.github.io/xcyclopedia/library/iexpress.exe-D594B2A33EFAFD0EABF09E3FDC05FCEA.html
- https://en.wikipedia.org/wiki/IExpress
- https://www.virustotal.com/gui/file/602f4ae507fa8de57ada079adff25a6c2a899bd25cd092d0af7e62cdb619c93c/behavior

---

## Windows Shell/Scripting Application File Write to Suspicious Folder

| Field | Value |
|---|---|
| **Sigma ID** | `1277f594-a7d1-4f28-a2d3-73af5cbeab43` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_shell_write_susp_directory.yml)**

> Detects Windows shells and scripting applications that write files to suspicious folders

```sql
-- ============================================================
-- Title:        Windows Shell/Scripting Application File Write to Suspicious Folder
-- Sigma ID:     1277f594-a7d1-4f28-a2d3-73af5cbeab43
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-11-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_shell_write_susp_directory.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\bash.exe' OR procName LIKE '%\\cmd.exe' OR procName LIKE '%\\cscript.exe' OR procName LIKE '%\\msbuild.exe' OR procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe' OR procName LIKE '%\\sh.exe' OR procName LIKE '%\\wscript.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\Public\\%')))
  OR ((procName LIKE '%\\certutil.exe' OR procName LIKE '%\\forfiles.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\schtasks.exe' OR procName LIKE '%\\scriptrunner.exe' OR procName LIKE '%\\wmic.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\Windows\\Temp\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Windows Binaries Write Suspicious Extensions

| Field | Value |
|---|---|
| **Sigma ID** | `b8fd0e93-ff58-4cbd-8f48-1c114e342e62` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1036 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_shell_write_susp_files_extensions.yml)**

> Detects Windows executables that write files with suspicious extensions

```sql
-- ============================================================
-- Title:        Windows Binaries Write Suspicious Extensions
-- Sigma ID:     b8fd0e93-ff58-4cbd-8f48-1c114e342e62
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1036
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_shell_write_susp_files_extensions.yml
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
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Startup Folder File Write

| Field | Value |
|---|---|
| **Sigma ID** | `2aa0a6b4-a865-495b-ab51-c28249537b75` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_startup_folder_file_write.yml)**

> A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.

```sql
-- ============================================================
-- Title:        Startup Folder File Write
-- Sigma ID:     2aa0a6b4-a865-495b-ab51-c28249537b75
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_startup_folder_file_write.yml
-- Unmapped:     (none)
-- False Pos:    FP could be caused by legitimate application writing shortcuts for example. This folder should always be inspected to make sure that all the files in there are legitimate
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** FP could be caused by legitimate application writing shortcuts for example. This folder should always be inspected to make sure that all the files in there are legitimate

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/12
- https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/5.B.1_611FCA99-97D0-4873-9E51-1C1BA2DBB40D.md

---

## Suspicious Creation with Colorcpl

| Field | Value |
|---|---|
| **Sigma ID** | `e15b518d-b4ce-4410-a9cd-501f23ce4a18` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_colorcpl.yml)**

> Once executed, colorcpl.exe will copy the arbitrary file to c:\windows\system32\spool\drivers\color\

```sql
-- ============================================================
-- Title:        Suspicious Creation with Colorcpl
-- Sigma ID:     e15b518d-b4ce-4410-a9cd-501f23ce4a18
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564
-- Author:       frack113
-- Date:         2022-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_colorcpl.yml
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
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\colorcpl.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/eral4m/status/1480468728324231172?s=20

---

## Created Files by Microsoft Sync Center

| Field | Value |
|---|---|
| **Sigma ID** | `409f8a98-4496-4aaa-818a-c931c0a8b832` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1055, T1218 |
| **Author** | elhoim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_creation_by_mobsync.yml)**

> This rule detects suspicious files created by Microsoft Sync Center (mobsync)

```sql
-- ============================================================
-- Title:        Created Files by Microsoft Sync Center
-- Sigma ID:     409f8a98-4496-4aaa-818a-c931c0a8b832
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1055, T1218
-- Author:       elhoim
-- Date:         2022-04-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_creation_by_mobsync.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\mobsync.exe'
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/intelligence-insights-november-2021/

---

## Suspicious Files in Default GPO Folder

| Field | Value |
|---|---|
| **Sigma ID** | `5f87308a-0a5b-4623-ae15-d8fa1809bc60` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.005 |
| **Author** | elhoim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_default_gpo_dir_write.yml)**

> Detects the creation of copy of suspicious files (EXE/DLL) to the default GPO storage folder

```sql
-- ============================================================
-- Title:        Suspicious Files in Default GPO Folder
-- Sigma ID:     5f87308a-0a5b-4623-ae15-d8fa1809bc60
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.005
-- Author:       elhoim
-- Date:         2022-04-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_default_gpo_dir_write.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/intelligence-insights-november-2021/

---

## Suspicious Creation TXT File in User Desktop

| Field | Value |
|---|---|
| **Sigma ID** | `caf02a0a-1e1c-4552-9b48-5e070bd88d11` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_desktop_txt.yml)**

> Ransomware create txt file in the user Desktop

```sql
-- ============================================================
-- Title:        Suspicious Creation TXT File in User Desktop
-- Sigma ID:     caf02a0a-1e1c-4552-9b48-5e070bd88d11
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1486
-- Author:       frack113
-- Date:         2021-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_desktop_txt.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\cmd.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Desktop\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.txt'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1486/T1486.md#atomic-test-5---purelocker-ransom-note

---

## Suspicious Desktopimgdownldr Target File

| Field | Value |
|---|---|
| **Sigma ID** | `fc4f4817-0c53-4683-a4ee-b17a64bc1039` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_desktopimgdownldr_file.yml)**

> Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension

```sql
-- ============================================================
-- Title:        Suspicious Desktopimgdownldr Target File
-- Sigma ID:     fc4f4817-0c53-4683-a4ee-b17a64bc1039
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2020-07-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_desktopimgdownldr_file.yml
-- Unmapped:     (none)
-- False Pos:    False positives depend on scripts and administrative tools used in the monitored environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\svchost.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Personalization\\LockScreenImage\\%'))
  AND NOT (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%C:\\Windows\\%'))
  AND NOT ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpg%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpeg%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.png%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives depend on scripts and administrative tools used in the monitored environment

**References:**
- https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
- https://twitter.com/SBousseaden/status/1278977301745741825

---

## Creation of a Diagcab

| Field | Value |
|---|---|
| **Sigma ID** | `3d0ed417-3d94-4963-a562-4a92c940656a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_diagcab.yml)**

> Detects the creation of diagcab file, which could be caused by some legitimate installer or is a sign of exploitation (review the filename and its location)

```sql
-- ============================================================
-- Title:        Creation of a Diagcab
-- Sigma ID:     3d0ed417-3d94-4963-a562-4a92c940656a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2022-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_diagcab.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate microsoft diagcab
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.diagcab')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate microsoft diagcab

**References:**
- https://threadreaderapp.com/thread/1533879688141086720.html

---

## Suspicious Double Extension Files

| Field | Value |
|---|---|
| **Sigma ID** | `b4926b47-a9d7-434c-b3a0-adc3fa0bd13e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1036.007 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_double_extension.yml)**

> Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default.

```sql
-- ============================================================
-- Title:        Suspicious Double Extension Files
-- Sigma ID:     b4926b47-a9d7-434c-b3a0-adc3fa0bd13e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1036.007
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2022-06-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_double_extension.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rar.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip.exe'))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.iso' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rar' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.svg' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip'))
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.doc.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.gif.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpeg.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpg.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.mp3.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.mp4.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pdf.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.png.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ppt.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rtf.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.svg.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.txt.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xls.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsx.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-june-mustang-panda/
- https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
- https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles
- https://twitter.com/malwrhunterteam/status/1235135745611960321
- https://twitter.com/luc4m/status/1073181154126254080
- https://cloud.google.com/blog/topics/threat-intelligence/cybercriminals-weaponize-fake-ai-websites
- https://vipre.com/blog/svg-phishing-attacks-the-new-trick-in-the-cybercriminals-playbook/

---

## DPAPI Backup Keys And Certificate Export Activity IOC

| Field | Value |
|---|---|
| **Sigma ID** | `7892ec59-c5bb-496d-8968-e5d210ca3ac4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1555, T1552.004 |
| **Author** | Nounou Mbeiri, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_dpapi_backup_and_cert_export_ioc.yml)**

> Detects file names with specific patterns seen generated and used by tools such as Mimikatz and DSInternals related to exported or stolen DPAPI backup keys and certificates.


```sql
-- ============================================================
-- Title:        DPAPI Backup Keys And Certificate Export Activity IOC
-- Sigma ID:     7892ec59-c5bb-496d-8968-e5d210ca3ac4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1555, T1552.004
-- Author:       Nounou Mbeiri, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-06-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_dpapi_backup_and_cert_export_ioc.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ntds\_capi\_%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ntds\_legacy\_%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ntds\_unknown\_%'))
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cer' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.key' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pfx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pvk')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.dsinternals.com/en/dpapi-backup-key-theft-auditing/
- https://github.com/MichaelGrafnetter/DSInternals/blob/39ee8a69bbdc1cfd12c9afdd7513b4788c4895d4/Src/DSInternals.Common/Data/DPAPI/DPAPIBackupKey.cs#L28-L32

---

## Suspicious MSExchangeMailboxReplication ASPX Write

| Field | Value |
|---|---|
| **Sigma ID** | `7280c9f3-a5af-45d0-916a-bc01cb4151c9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1190, T1505.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_exchange_aspx_write.yml)**

> Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation

```sql
-- ============================================================
-- Title:        Suspicious MSExchangeMailboxReplication ASPX Write
-- Sigma ID:     7280c9f3-a5af-45d0-916a-bc01cb4151c9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1190, T1505.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_exchange_aspx_write.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\MSExchangeMailboxReplication.exe'
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.aspx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.asp')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/blackbyte-ransomware/

---

## Suspicious Executable File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `74babdd6-a758-4549-9632-26535279e654` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_executable_creation.yml)**

> Detect creation of suspicious executable file names.
Some strings look for suspicious file extensions, others look for filenames that exploit unquoted service paths.


```sql
-- ============================================================
-- Title:        Suspicious Executable File Creation
-- Sigma ID:     74babdd6-a758-4549-9632-26535279e654
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564
-- Author:       frack113
-- Date:         2022-09-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_executable_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\$Recycle.Bin.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Documents and Settings.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\MSOCache.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\PerfLogs.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Recovery.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sys.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
- https://app.any.run/tasks/76c69e2d-01e8-49d9-9aea-fb7cc0c4d3ad/

---

## Suspicious File Write to Webapps Root Directory

| Field | Value |
|---|---|
| **Sigma ID** | `89c42960-f244-4dad-9151-ae9b1a3287a2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003, T1190 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_file_write_in_webapps_root.yml)**

> Detects suspicious file writes to the root directory of web applications, particularly Apache web servers or Tomcat servers.
This may indicate an attempt to deploy malicious files such as web shells or other unauthorized scripts.


```sql
-- ============================================================
-- Title:        Suspicious File Write to Webapps Root Directory
-- Sigma ID:     89c42960-f244-4dad-9151-ae9b1a3287a2
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1505.003, T1190
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_file_write_in_webapps_root.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\webapps\\ROOT\\%')
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\apache%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\tomcat%'))
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jsp')
  AND (procName LIKE '%\\dotnet.exe' OR procName LIKE '%\\w3wp.exe' OR procName LIKE '%\\java.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/

---

## Suspicious File Write to SharePoint Layouts Directory

| Field | Value |
|---|---|
| **Sigma ID** | `1f0489be-b496-4ddf-b3a9-5900f2044e9c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1190, T1505.003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_filewrite_in_sharepoint_layouts_dir.yml)**

> Detects suspicious file writes to SharePoint layouts directory which could indicate webshell activity or post-exploitation.
This behavior has been observed in the exploitation of SharePoint vulnerabilities such as CVE-2025-49704, CVE-2025-49706 or CVE-2025-53770.


```sql
-- ============================================================
-- Title:        Suspicious File Write to SharePoint Layouts Directory
-- Sigma ID:     1f0489be-b496-4ddf-b3a9-5900f2044e9c
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1190, T1505.003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_filewrite_in_sharepoint_layouts_dir.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\cmd.exe' OR procName LIKE '%\\powershell\_ise.exe' OR procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe' OR procName LIKE '%\\w3wp.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\Web Server Extensions\\%'))
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\15\\TEMPLATE\\LAYOUTS\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\16\\TEMPLATE\\LAYOUTS\\%'))
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.asax' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ascx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ashx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.asmx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.asp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.aspx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cer' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.config' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jsp' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jspx' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.php' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/
- https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/

---

## Suspicious Get-Variable.exe Creation

| Field | Value |
|---|---|
| **Sigma ID** | `0c3fac91-5627-46e8-a6a8-a0d7b9b8ae1b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546, T1027 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_get_variable.yml)**

> Get-Variable is a valid PowerShell cmdlet
WindowsApps is by default in the path where PowerShell is executed.
So when the Get-Variable command is issued on PowerShell execution, the system first looks for the Get-Variable executable in the path and executes the malicious binary instead of looking for the PowerShell cmdlet.


```sql
-- ============================================================
-- Title:        Suspicious Get-Variable.exe Creation
-- Sigma ID:     0c3fac91-5627-46e8-a6a8-a0d7b9b8ae1b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546, T1027
-- Author:       frack113
-- Date:         2022-04-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_get_variable.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Local\\Microsoft\\WindowsApps\\Get-Variable.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.malwarebytes.com/threat-intelligence/2022/04/colibri-loader-combines-task-scheduler-and-powershell-in-clever-persistence-technique/
- https://www.joesandbox.com/analysis/465533/0/html

---

## Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream

| Field | Value |
|---|---|
| **Sigma ID** | `a8f866e1-bdd4-425e-a27a-37619238d9c7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.004 |
| **Author** | Scoubi (@ScoubiMtl) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_hidden_dir_index_allocation.yml)**

> Detects the creation of hidden file/folder with the "::$index_allocation" stream. Which can be used as a technique to prevent access to folder and files from tooling such as "explorer.exe" and "powershell.exe"


```sql
-- ============================================================
-- Title:        Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream
-- Sigma ID:     a8f866e1-bdd4-425e-a27a-37619238d9c7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.004
-- Author:       Scoubi (@ScoubiMtl)
-- Date:         2023-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_hidden_dir_index_allocation.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%::$index\_allocation%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/pfiatde/status/1681977680688738305
- https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
- https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/
- https://github.com/redcanaryco/atomic-red-team/blob/5c3b23002d2bbede3c07e7307165fc2a235a427d/atomics/T1564.004/T1564.004.md#atomic-test-5---create-hidden-directory-via-index_allocation
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3

---

## Potential Homoglyph Attack Using Lookalike Characters in Filename

| Field | Value |
|---|---|
| **Sigma ID** | `4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036, T1036.003 |
| **Author** | Micah Babinski, @micahbabinski |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_homoglyph_filename.yml)**

> Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters.
This is used as an obfuscation and masquerading techniques. Only "perfect" homoglyphs are included; these are characters that
are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters.


```sql
-- ============================================================
-- Title:        Potential Homoglyph Attack Using Lookalike Characters in Filename
-- Sigma ID:     4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036, T1036.003
-- Author:       Micah Babinski, @micahbabinski
-- Date:         2023-05-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_homoglyph_filename.yml
-- Unmapped:     (none)
-- False Pos:    File names with legitimate Cyrillic text. Will likely require tuning (or not be usable) in countries where these alphabets are in use.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%а%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%е%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%о%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%р%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%с%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%х%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ѕ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%і%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ӏ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ј%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%һ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ԁ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ԛ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ԝ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ο%'))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%А%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%В%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Е%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%К%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%М%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Н%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%О%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Р%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%С%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Т%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Х%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ѕ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%І%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ј%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ү%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ӏ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ԍ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ԛ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ԝ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Α%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Β%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ε%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ζ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Η%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ι%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Κ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Μ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ν%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ο%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Ρ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Τ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Υ%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%Χ%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** File names with legitimate Cyrillic text. Will likely require tuning (or not be usable) in countries where these alphabets are in use.

**References:**
- https://redcanary.com/threat-detection-report/threats/socgholish/#threat-socgholish
- http://www.irongeek.com/homoglyph-attack-generator.php

---

## Legitimate Application Dropped Archive

| Field | Value |
|---|---|
| **Sigma ID** | `654fcc6d-840d-4844-9b07-2c3300e54a26` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | frack113, Florian Roth |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_archive.yml)**

> Detects programs on a Windows system that should not write an archive to disk

```sql
-- ============================================================
-- Title:        Legitimate Application Dropped Archive
-- Sigma ID:     654fcc6d-840d-4844-9b07-2c3300e54a26
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       frack113, Florian Roth
-- Date:         2022-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_archive.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\winword.exe' OR procName LIKE '%\\excel.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\msaccess.exe' OR procName LIKE '%\\mspub.exe' OR procName LIKE '%\\eqnedt32.exe' OR procName LIKE '%\\visio.exe' OR procName LIKE '%\\wordpad.exe' OR procName LIKE '%\\wordview.exe' OR procName LIKE '%\\certutil.exe' OR procName LIKE '%\\certoc.exe' OR procName LIKE '%\\CertReq.exe' OR procName LIKE '%\\Desktopimgdownldr.exe' OR procName LIKE '%\\esentutl.exe' OR procName LIKE '%\\finger.exe' OR procName LIKE '%\\notepad.exe' OR procName LIKE '%\\AcroRd32.exe' OR procName LIKE '%\\RdrCEF.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\hh.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.zip' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rar' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.7z' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.diagcab' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.appx')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Neo23x0/sysmon-config/blob/3f808d9c022c507aae21a9346afba4a59dd533b9/sysmonconfig-export-block.xml#L1326

---

## Legitimate Application Dropped Executable

| Field | Value |
|---|---|
| **Sigma ID** | `f0540f7e-2db3-4432-b9e0-3965486744bc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | frack113, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_exe.yml)**

> Detects programs on a Windows system that should not write executables to disk

```sql
-- ============================================================
-- Title:        Legitimate Application Dropped Executable
-- Sigma ID:     f0540f7e-2db3-4432-b9e0-3965486744bc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       frack113, Florian Roth (Nextron Systems)
-- Date:         2022-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_exe.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\eqnedt32.exe' OR procName LIKE '%\\wordpad.exe' OR procName LIKE '%\\wordview.exe' OR procName LIKE '%\\certutil.exe' OR procName LIKE '%\\certoc.exe' OR procName LIKE '%\\CertReq.exe' OR procName LIKE '%\\Desktopimgdownldr.exe' OR procName LIKE '%\\esentutl.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\AcroRd32.exe' OR procName LIKE '%\\RdrCEF.exe' OR procName LIKE '%\\hh.exe' OR procName LIKE '%\\finger.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ocx')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Neo23x0/sysmon-config/blob/3f808d9c022c507aae21a9346afba4a59dd533b9/sysmonconfig-export-block.xml#L1326

---

## Legitimate Application Writing Files In Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `1cf465a1-2609-4c15-9b66-c32dbe4bfd67` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218, T1105 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_in_uncommon_location.yml)**

> Detects legitimate applications writing any type of file to uncommon or suspicious locations that are not typical for application data storage or execution.
Adversaries may leverage legitimate applications (Living off the Land Binaries - LOLBins) to drop or download malicious files to uncommon locations on the system to evade detection by security solutions.


```sql
-- ============================================================
-- Title:        Legitimate Application Writing Files In Uncommon Location
-- Sigma ID:     1cf465a1-2609-4c15-9b66-c32dbe4bfd67
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1218, T1105
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-12-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_in_uncommon_location.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\eqnedt32.exe' OR procName LIKE '%\\wordpad.exe' OR procName LIKE '%\\wordview.exe' OR procName LIKE '%\\cmdl32.exe' OR procName LIKE '%\\certutil.exe' OR procName LIKE '%\\certoc.exe' OR procName LIKE '%\\CertReq.exe' OR procName LIKE '%\\bitsadmin.exe' OR procName LIKE '%\\Desktopimgdownldr.exe' OR procName LIKE '%\\esentutl.exe' OR procName LIKE '%\\expand.exe' OR procName LIKE '%\\extrac32.exe' OR procName LIKE '%\\replace.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\ftp.exe' OR procName LIKE '%\\Ldifde.exe' OR procName LIKE '%\\RdrCEF.exe' OR procName LIKE '%\\hh.exe' OR procName LIKE '%\\finger.exe' OR procName LIKE '%\\findstr.exe')
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Perflogs%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Windows\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\$Recycle.Bin\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Roaming\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Contacts\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Desktop\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Favorites\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Favourites\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\inetpub\\wwwroot\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Music\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Pictures\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Start Menu\\Programs\\Startup\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Users\\Default\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Videos\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lolbas-project.github.io/#/download

---

## Legitimate Application Dropped Script

| Field | Value |
|---|---|
| **Sigma ID** | `7d604714-e071-49ff-8726-edeb95a70679` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | frack113, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_script.yml)**

> Detects programs on a Windows system that should not write scripts to disk

```sql
-- ============================================================
-- Title:        Legitimate Application Dropped Script
-- Sigma ID:     7d604714-e071-49ff-8726-edeb95a70679
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       frack113, Florian Roth (Nextron Systems)
-- Date:         2022-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_script.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\eqnedt32.exe' OR procName LIKE '%\\wordpad.exe' OR procName LIKE '%\\wordview.exe' OR procName LIKE '%\\certutil.exe' OR procName LIKE '%\\certoc.exe' OR procName LIKE '%\\CertReq.exe' OR procName LIKE '%\\Desktopimgdownldr.exe' OR procName LIKE '%\\esentutl.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\AcroRd32.exe' OR procName LIKE '%\\RdrCEF.exe' OR procName LIKE '%\\hh.exe' OR procName LIKE '%\\finger.exe')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scf' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsh')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Neo23x0/sysmon-config/blob/3f808d9c022c507aae21a9346afba4a59dd533b9/sysmonconfig-export-block.xml#L1326

---

## Suspicious LNK Double Extension File Created

| Field | Value |
|---|---|
| **Sigma ID** | `3215aa19-f060-4332-86d5-5602511f3ca8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.007 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_lnk_double_extension.yml)**

> Detects the creation of files with an "LNK" as a second extension. This is sometimes used by malware as a method to abuse the fact that Windows hides the "LNK" extension by default.


```sql
-- ============================================================
-- Title:        Suspicious LNK Double Extension File Created
-- Sigma ID:     3215aa19-f060-4332-86d5-5602511f3ca8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.007
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2022-11-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_lnk_double_extension.yml
-- Unmapped:     (none)
-- False Pos:    Some tuning is required for other general purpose directories of third party apps
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.doc.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpg.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pdf.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ppt.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pptx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xls.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsx.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some tuning is required for other general purpose directories of third party apps

**References:**
- https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-june-mustang-panda/
- https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
- https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles
- https://twitter.com/malwrhunterteam/status/1235135745611960321
- https://twitter.com/luc4m/status/1073181154126254080

---

## PowerShell Profile Modification

| Field | Value |
|---|---|
| **Sigma ID** | `b5b78988-486d-4a80-b991-930eff3ff8bf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.013 |
| **Author** | HieuTT35, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml)**

> Detects the creation or modification of a powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence

```sql
-- ============================================================
-- Title:        PowerShell Profile Modification
-- Sigma ID:     b5b78988-486d-4a80-b991-930eff3ff8bf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.013
-- Author:       HieuTT35, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml
-- Unmapped:     (none)
-- False Pos:    System administrator creating Powershell profile manually
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft.PowerShell\_profile.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PowerShell\\profile.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Program Files\\PowerShell\\7-preview\\profile.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Program Files\\PowerShell\\7\\profile.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WindowsPowerShell\\profile.ps1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System administrator creating Powershell profile manually

**References:**
- https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
- https://persistence-info.github.io/Data/powershellprofile.html

---

## Suspicious PROCEXP152.sys File Created In TMP

| Field | Value |
|---|---|
| **Sigma ID** | `3da70954-0f2c-4103-adff-b7440368f50e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | xknow (@xknow_infosec), xorxes (@xor_xes) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_procexplorer_driver_created_in_tmp_folder.yml)**

> Detects the creation of the PROCEXP152.sys file in the application-data local temporary folder.
This driver is used by Sysinternals Process Explorer but also by KDU (https://github.com/hfiref0x/KDU) or Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU.


```sql
-- ============================================================
-- Title:        Suspicious PROCEXP152.sys File Created In TMP
-- Sigma ID:     3da70954-0f2c-4103-adff-b7440368f50e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       xknow (@xknow_infosec), xorxes (@xor_xes)
-- Date:         2019-04-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_procexplorer_driver_created_in_tmp_folder.yml
-- Unmapped:     (none)
-- False Pos:    Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%PROCEXP152.sys'))
  AND NOT ((procName LIKE '%\\procexp64.exe%' OR procName LIKE '%\\procexp.exe%' OR procName LIKE '%\\procmon64.exe%' OR procName LIKE '%\\procmon.exe%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legimate tools using this driver and filename (like Sysinternals). Note - Clever attackers may easily bypass this detection by just renaming the driver filename. Therefore just Medium-level and don't rely on it.

**References:**
- https://web.archive.org/web/20230331181619/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/

---

## Suspicious Binaries and Scripts in Public Folder

| Field | Value |
|---|---|
| **Sigma ID** | `b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204 |
| **Author** | The DFIR Report |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_public_folder_extension.yml)**

> Detects the creation of a file with a suspicious extension in the public folder, which could indicate potential malicious activity.

```sql
-- ============================================================
-- Title:        Suspicious Binaries and Scripts in Public Folder
-- Sigma ID:     b447f7de-1e53-4cbf-bfb4-f1f6d0b04e4e
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1204
-- Author:       The DFIR Report
-- Date:         2025-01-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_public_folder_extension.yml
-- Unmapped:     (none)
-- False Pos:    Administrators deploying legitimate binaries to public folders.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%:\\Users\\Public\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators deploying legitimate binaries to public folders.

**References:**
- https://intel.thedfirreport.com/events/view/30032
- https://intel.thedfirreport.com/eventReports/view/70
- https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/

---

## Suspicious File Creation Activity From Fake Recycle.Bin Folder

| Field | Value |
|---|---|
| **Sigma ID** | `cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_recycle_bin_fake_exec.yml)**

> Detects file write event from/to a fake recycle bin folder that is often used as a staging directory for malware

```sql
-- ============================================================
-- Title:        Suspicious File Creation Activity From Fake Recycle.Bin Folder
-- Sigma ID:     cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-07-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_recycle_bin_fake_exec.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%RECYCLERS.BIN\\%' OR procName LIKE '%RECYCLER.BIN\\%'))
  OR ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%RECYCLERS.BIN\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%RECYCLER.BIN\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.mandiant.com/resources/blog/infected-usb-steal-secrets
- https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/

---

## Potential File Extension Spoofing Using Right-to-Left Override

| Field | Value |
|---|---|
| **Sigma ID** | `979baf41-ca44-4540-9d0c-4fcef3b5a3a4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1036.002 |
| **Author** | Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_right_to_left_override_extension_spoofing.yml)**

> Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions.


```sql
-- ============================================================
-- Title:        Potential File Extension Spoofing Using Right-to-Left Override
-- Sigma ID:     979baf41-ca44-4540-9d0c-4fcef3b5a3a4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1036.002
-- Author:       Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2024-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_right_to_left_override_extension_spoofing.yml
-- Unmapped:     (none)
-- False Pos:    Filenames that contains scriptures such as arabic or hebrew might make use of this character
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%3pm.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%4pm.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%cod.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%fdp.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ftr.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%gepj.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%gnp.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%gpj.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%ism.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%lmth.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%nls.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%piz.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%slx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%tdo.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%vsc.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%vwm.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%xcod.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%xslx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%xtpp.%'))
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\u202e%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%[U+202E]%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Filenames that contains scriptures such as arabic or hebrew might make use of this character

**References:**
- https://redcanary.com/blog/right-to-left-override/
- https://www.malwarebytes.com/blog/news/2014/01/the-rtlo-method
- https://tria.ge/241015-l98snsyeje/behavioral2
- https://www.unicode.org/versions/Unicode5.2.0/ch02.pdf

---

## Drop Binaries Into Spool Drivers Color Folder

| Field | Value |
|---|---|
| **Sigma ID** | `ce7066a6-508a-42d3-995b-2952c65dc2ce` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_spool_drivers_color_drop.yml)**

> Detects the creation of suspcious binary files inside the "\windows\system32\spool\drivers\color\" as seen in the blog referenced below

```sql
-- ============================================================
-- Title:        Drop Binaries Into Spool Drivers Color Folder
-- Sigma ID:     ce7066a6-508a-42d3-995b-2952c65dc2ce
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_spool_drivers_color_drop.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\spool\\drivers\\color\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sys')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/

---

## Suspicious Startup Folder Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `28208707-fe31-437f-9a7f-4b1108b94d2e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1204.002, T1547.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml)**

> Detects the creation of potentially malicious script and executable files in Windows startup folders, which is a common persistence technique used by threat actors.
These files (.ps1, .vbs, .js, .bat, etc.) are automatically executed when a user logs in, making the Startup folder an attractive target for attackers.
This technique is frequently observed in malvertising campaigns and malware distribution where attackers attempt to maintain long-term access to compromised systems.


```sql
-- ============================================================
-- Title:        Suspicious Startup Folder Persistence
-- Sigma ID:     28208707-fe31-437f-9a7f-4b1108b94d2e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1204.002, T1547.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Rare legitimate usage of some of the extensions mentioned in the rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\Start Menu\\Programs\\Startup\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.bat' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.cmd' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.hta' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jar' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.js' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jse' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.msi' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.ps1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.psd1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.psm1' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.scr' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.url' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vba' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vbs' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.wsf')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate usage of some of the extensions mentioned in the rule

**References:**
- https://github.com/last-byte/PersistenceSniper
- https://www.microsoft.com/en-us/security/blog/2025/03/06/malvertising-campaign-leads-to-info-stealers-hosted-on-github/
- https://github.com/redcanaryco/atomic-red-team/blob/5ede8f21e42ebe37e0a6eff757dba60bcfa85859/atomics/T1547.001/T1547.001.md

---

## Suspicious Interactive PowerShell as SYSTEM

| Field | Value |
|---|---|
| **Sigma ID** | `5b40a734-99b6-4b98-a1d0-1cea51a08ab2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_system_interactive_powershell.yml)**

> Detects the creation of files that indicator an interactive use of PowerShell in the SYSTEM user context

```sql
-- ============================================================
-- Title:        Suspicious Interactive PowerShell as SYSTEM
-- Sigma ID:     5b40a734-99b6-4b98-a1d0-1cea51a08ab2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-12-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_system_interactive_powershell.yml
-- Unmapped:     (none)
-- False Pos:    Administrative activity; PowerShell scripts running as SYSTEM user
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] IN ('C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt', 'C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative activity; PowerShell scripts running as SYSTEM user

**References:**
- https://jpcertcc.github.io/ToolAnalysisResultSheet/details/PowerSploit_Invoke-Mimikatz.htm

---

## Suspicious Scheduled Task Write to System32 Tasks

| Field | Value |
|---|---|
| **Sigma ID** | `80e1f67a-4596-4351-98f5-a9c3efabac95` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1053 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_task_write.yml)**

> Detects the creation of tasks from processes executed from suspicious locations

```sql
-- ============================================================
-- Title:        Suspicious Scheduled Task Write to System32 Tasks
-- Sigma ID:     80e1f67a-4596-4351-98f5-a9c3efabac95
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1053
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-11-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_task_write.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\System32\\Tasks%')
    AND (procName LIKE '%\\AppData\\%' OR procName LIKE '%C:\\PerfLogs%' OR procName LIKE '%\\Windows\\System32\\config\\systemprofile%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## TeamViewer Remote Session

| Field | Value |
|---|---|
| **Sigma ID** | `162ab1e4-6874-4564-853c-53ec3ab8be01` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_teamviewer_remote_session.yml)**

> Detects the creation of log files during a TeamViewer remote session

```sql
-- ============================================================
-- Title:        TeamViewer Remote Session
-- Sigma ID:     162ab1e4-6874-4564-853c-53ec3ab8be01
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-01-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_teamviewer_remote_session.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate uses of TeamViewer in an organisation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TeamViewer\\RemotePrinting\\tvprint.db' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TeamViewer\\TVNetwork.log'))
  OR indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\TeamViewer%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\_Logfile.log%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate uses of TeamViewer in an organisation

**References:**
- https://www.teamviewer.com/en-us/

---

## VsCode Powershell Profile Modification

| Field | Value |
|---|---|
| **Sigma ID** | `3a9fa2ec-30bc-4ebd-b49e-7c9cff225502` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.013 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml)**

> Detects the creation or modification of a vscode related powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence

```sql
-- ============================================================
-- Title:        VsCode Powershell Profile Modification
-- Sigma ID:     3a9fa2ec-30bc-4ebd-b49e-7c9cff225502
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.013
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the profile by developers or administrators
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft.VSCode\_profile.ps1')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the profile by developers or administrators

**References:**
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.2

---

## Potentially Suspicious WDAC Policy File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `1d2de8a6-4803-4fde-b85b-f58f3aa7a705` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | X__Junior |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_wdac_policy_creation.yml)**

> Detects suspicious Windows Defender Application Control (WDAC) policy file creation from abnormal processes that could be abused by attacker to block EDR/AV components while allowing their own malicious code to run on the system.


```sql
-- ============================================================
-- Title:        Potentially Suspicious WDAC Policy File Creation
-- Sigma ID:     1d2de8a6-4803-4fde-b85b-f58f3aa7a705
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        (none)
-- Author:       X__Junior
-- Date:         2025-02-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_wdac_policy_creation.yml
-- Unmapped:     (none)
-- False Pos:    Administrators and security vendors could leverage WDAC, apply additional filters as needed.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Windows\\System32\\CodeIntegrity\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators and security vendors could leverage WDAC, apply additional filters as needed.

**References:**
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-group-policy
- https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/
- https://github.com/logangoins/Krueger/tree/main
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-script
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-memcm

---

## Windows Terminal Profile Settings Modification By Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `9b64de98-9db3-4033-bd7a-f51430105f00` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.015 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_windows_terminal_profile.yml)**

> Detects the creation or modification of the Windows Terminal Profile settings file "settings.json" by an uncommon process.

```sql
-- ============================================================
-- Title:        Windows Terminal Profile Settings Modification By Uncommon Process
-- Sigma ID:     9b64de98-9db3-4033-bd7a-f51430105f00
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.015
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_windows_terminal_profile.yml
-- Unmapped:     (none)
-- False Pos:    Some false positives may occur with admin scripts that set WT settings.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\cmd.exe' OR procName LIKE '%\\cscript.exe' OR procName LIKE '%\\mshta.exe' OR procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe' OR procName LIKE '%\\wscript.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal\_8wekyb3d8bbwe\\LocalState\\settings.json'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives may occur with admin scripts that set WT settings.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/74438b0237d141ee9c99747976447dc884cb1a39/atomics/T1547.015/T1547.015.md#atomic-test-1---persistence-by-modifying-windows-terminal-profile
- https://twitter.com/nas_bench/status/1550836225652686848

---

## WinSxS Executable File Creation By Non-System Process

| Field | Value |
|---|---|
| **Sigma ID** | `34746e8c-5fb8-415a-b135-0abc167e912a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_winsxs_binary_creation.yml)**

> Detects the creation of binaries in the WinSxS folder by non-system processes

```sql
-- ============================================================
-- Title:        WinSxS Executable File Creation By Non-System Process
-- Sigma ID:     34746e8c-5fb8-415a-b135-0abc167e912a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_susp_winsxs_binary_creation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\WinSxS\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF

---

## ADExplorer Writing Complete AD Snapshot Into .dat File

| Field | Value |
|---|---|
| **Sigma ID** | `0a1255c5-d732-4b62-ac02-b5152d34fb83` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.002, T1069.002, T1482 |
| **Author** | Arnim Rupp (Nextron Systems), Thomas Patzke |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_adexplorer_dump_written.yml)**

> Detects the dual use tool ADExplorer writing a complete AD snapshot into a .dat file. This can be used by attackers to extract data for Bloodhound, usernames for password spraying or use the meta data for social engineering. The snapshot doesn't contain password hashes but there have been cases, where administrators put passwords in the comment field.

```sql
-- ============================================================
-- Title:        ADExplorer Writing Complete AD Snapshot Into .dat File
-- Sigma ID:     0a1255c5-d732-4b62-ac02-b5152d34fb83
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        discovery | T1087.002, T1069.002, T1482
-- Author:       Arnim Rupp (Nextron Systems), Thomas Patzke
-- Date:         2025-07-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_adexplorer_dump_written.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of ADExplorer by administrators creating .dat snapshots
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\ADExp.exe' OR procName LIKE '%\\ADExplorer.exe' OR procName LIKE '%\\ADExplorer64.exe' OR procName LIKE '%\\ADExplorer64a.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dat'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of ADExplorer by administrators creating .dat snapshots

**References:**
- https://learn.microsoft.com/de-de/sysinternals/downloads/adexplorer
- https://github.com/c3c/ADExplorerSnapshot.py/tree/f700904defac330802bbfedd1d8ffd9248f4ee24
- https://www.packetlabs.net/posts/scattered-spider-is-a-young-ransomware-gang-exploiting-large-corporations/
- https://www.nccgroup.com/us/research-blog/lapsus-recent-techniques-tactics-and-procedures/
- https://trustedsec.com/blog/adexplorer-on-engagements

---

## LiveKD Kernel Memory Dump File Created

| Field | Value |
|---|---|
| **Sigma ID** | `814ddeca-3d31-4265-8e07-8cc54fb44903` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_livekd_default_dump_name.yml)**

> Detects the creation of a file that has the same name as the default LiveKD kernel memory dump.

```sql
-- ============================================================
-- Title:        LiveKD Kernel Memory Dump File Created
-- Sigma ID:     814ddeca-3d31-4265-8e07-8cc54fb44903
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_livekd_default_dump_name.yml
-- Unmapped:     (none)
-- False Pos:    In rare occasions administrators might leverage LiveKD to perform live kernel debugging. This should not be allowed on production systems. Investigate and apply additional filters where necessary.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\Windows\livekd.dmp')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** In rare occasions administrators might leverage LiveKD to perform live kernel debugging. This should not be allowed on production systems. Investigate and apply additional filters where necessary.

**References:**
- Internal Research

---

## LiveKD Driver Creation

| Field | Value |
|---|---|
| **Sigma ID** | `16fe46bb-4f64-46aa-817d-ff7bec4a2352` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver.yml)**

> Detects the creation of the LiveKD driver, which is used for live kernel debugging

```sql
-- ============================================================
-- Title:        LiveKD Driver Creation
-- Sigma ID:     16fe46bb-4f64-46aa-817d-ff7bec4a2352
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of LiveKD for debugging purposes will also trigger this
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\Windows\System32\drivers\LiveKdD.SYS')
    AND (procName LIKE '%\\livekd.exe' OR procName LIKE '%\\livek64.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of LiveKD for debugging purposes will also trigger this

**References:**
- Internal Research

---

## LiveKD Driver Creation By Uncommon Process

| Field | Value |
|---|---|
| **Sigma ID** | `059c5af9-5131-4d8d-92b2-de4ad6146712` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver_susp_creation.yml)**

> Detects the creation of the LiveKD driver by a process image other than "livekd.exe".

```sql
-- ============================================================
-- Title:        LiveKD Driver Creation By Uncommon Process
-- Sigma ID:     059c5af9-5131-4d8d-92b2-de4ad6146712
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver_susp_creation.yml
-- Unmapped:     (none)
-- False Pos:    Administrators might rename LiveKD before its usage which could trigger this. Add additional names you use to the filter
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\Windows\System32\drivers\LiveKdD.SYS')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators might rename LiveKD before its usage which could trigger this. Add additional names you use to the filter

**References:**
- Internal Research

---

## Process Explorer Driver Creation By Non-Sysinternals Binary

| Field | Value |
|---|---|
| **Sigma ID** | `de46c52b-0bf8-4936-a327-aace94f94ac6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1068 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_procexp_driver_susp_creation.yml)**

> Detects creation of the Process Explorer drivers by processes other than Process Explorer (procexp) itself.
Hack tools or malware may use the Process Explorer driver to elevate privileges, drops it to disk for a few moments, runs a service using that driver and removes it afterwards.


```sql
-- ============================================================
-- Title:        Process Explorer Driver Creation By Non-Sysinternals Binary
-- Sigma ID:     de46c52b-0bf8-4936-a327-aace94f94ac6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1068
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2023-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_procexp_driver_susp_creation.yml
-- Unmapped:     (none)
-- False Pos:    Some false positives may occur with legitimate renamed process explorer binaries
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PROCEXP%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sys'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives may occur with legitimate renamed process explorer binaries

**References:**
- https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- https://github.com/Yaxser/Backstab
- https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks
- https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/

---

## Process Monitor Driver Creation By Non-Sysinternals Binary

| Field | Value |
|---|---|
| **Sigma ID** | `a05baa88-e922-4001-bc4d-8738135f27de` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1068 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_procmon_driver_susp_creation.yml)**

> Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself.

```sql
-- ============================================================
-- Title:        Process Monitor Driver Creation By Non-Sysinternals Binary
-- Sigma ID:     a05baa88-e922-4001-bc4d-8738135f27de
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1068
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_procmon_driver_susp_creation.yml
-- Unmapped:     (none)
-- False Pos:    Some false positives may occur with legitimate renamed process monitor binaries
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\procmon%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sys'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some false positives may occur with legitimate renamed process monitor binaries

**References:**
- Internal Research

---

## PsExec Service File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `259e5a6a-b8d2-4c38-86e2-26c5e651361d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml)**

> Detects default PsExec service filename which indicates PsExec service installation and execution

```sql
-- ============================================================
-- Title:        PsExec Service File Creation
-- Sigma ID:     259e5a6a-b8d2-4c38-86e2-26c5e651361d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Thomas Patzke
-- Date:         2017-06-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\PSEXESVC.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.jpcert.or.jp/english/pub/sr/ir_research.html
- https://jpcertcc.github.io/ToolAnalysisResultSheet

---

## PSEXEC Remote Execution File Artefact

| Field | Value |
|---|---|
| **Sigma ID** | `304afd73-55a5-4bb9-8c21-0b1fc84ea9e4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1136.002, T1543.003, T1570 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_psexec_service_key.yml)**

> Detects creation of the PSEXEC key file. Which is created anytime a PsExec command is executed. It gets written to the file system and will be recorded in the USN Journal on the target system

```sql
-- ============================================================
-- Title:        PSEXEC Remote Execution File Artefact
-- Sigma ID:     304afd73-55a5-4bb9-8c21-0b1fc84ea9e4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1136.002, T1543.003, T1570
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_psexec_service_key.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\PSEXEC-%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.key'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://aboutdfir.com/the-key-to-identify-psexec/
- https://twitter.com/davisrichardg/status/1616518800584704028

---

## Potential Privilege Escalation Attempt Via .Exe.Local Technique

| Field | Value |
|---|---|
| **Sigma ID** | `07a99744-56ac-40d2-97b7-2095967b0e03` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Subhash P (@pbssubhash) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_system32_local_folder_privilege_escalation.yml)**

> Detects potential privilege escalation attempt via the creation of the "*.Exe.Local" folder inside the "System32" directory in order to sideload "comctl32.dll"

```sql
-- ============================================================
-- Title:        Potential Privilege Escalation Attempt Via .Exe.Local Technique
-- Sigma ID:     07a99744-56ac-40d2-97b7-2095967b0e03
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems), Subhash P (@pbssubhash)
-- Date:         2022-12-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_system32_local_folder_privilege_escalation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\logonUI.exe.local%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\werFault.exe.local%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\consent.exe.local%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\narrator.exe.local%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\wermgr.exe.local%'))
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\comctl32.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/binderlabs/DirCreate2System
- https://github.com/sailay1996/awesome_windows_logical_bugs/blob/60cbb23a801f4c3195deac1cc46df27c225c3d07/dir_create2system.txt

---

## LSASS Process Memory Dump Creation Via Taskmgr.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `69ca12af-119d-44ed-b50f-a47af0ebc364` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_taskmgr_lsass_dump.yml)**

> Detects the creation of an "lsass.dmp" file by the taskmgr process. This indicates a manual dumping of the LSASS.exe process memory using Windows Task Manager.

```sql
-- ============================================================
-- Title:        LSASS Process Memory Dump Creation Via Taskmgr.EXE
-- Sigma ID:     69ca12af-119d-44ed-b50f-a47af0ebc364
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       Swachchhanda Shrawan Poudel
-- Date:         2023-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_taskmgr_lsass_dump.yml
-- Unmapped:     (none)
-- False Pos:    Rare case of troubleshooting by an administrator or support that has to be investigated regardless
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%:\\Windows\\system32\\taskmgr.exe' OR procName LIKE '%:\\Windows\\SysWOW64\\taskmgr.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\lsass%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.DMP%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare case of troubleshooting by an administrator or support that has to be investigated regardless

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/987e3ca988ae3cff4b9f6e388c139c05bf44bbb8/atomics/T1003.001/T1003.001.md#L1

---

## Hijack Legit RDP Session to Move Laterally

| Field | Value |
|---|---|
| **Sigma ID** | `52753ea4-b3a0-4365-910d-36cff487b789` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_tsclient_filewrite_startup.yml)**

> Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder

```sql
-- ============================================================
-- Title:        Hijack Legit RDP Session to Move Laterally
-- Sigma ID:     52753ea4-b3a0-4365-910d-36cff487b789
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Samir Bousseaden
-- Date:         2019-02-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_tsclient_filewrite_startup.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\mstsc.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research

---

## UAC Bypass Using Consent and Comctl32 - File

| Field | Value |
|---|---|
| **Sigma ID** | `62ed5b55-f991-406a-85d9-e8e8fdf18789` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_consent_comctl32.yml)**

> Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)

```sql
-- ============================================================
-- Title:        UAC Bypass Using Consent and Comctl32 - File
-- Sigma ID:     62ed5b55-f991-406a-85d9-e8e8fdf18789
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_consent_comctl32.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\consent.exe.@%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\comctl32.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Using .NET Code Profiler on MMC

| Field | Value |
|---|---|
| **Sigma ID** | `93a19907-d4f9-4deb-9f91-aac4692776a6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_dotnet_profiler.yml)**

> Detects the pattern of UAC Bypass using .NET Code Profiler and mmc.exe DLL hijacking (UACMe 39)

```sql
-- ============================================================
-- Title:        UAC Bypass Using .NET Code Profiler on MMC
-- Sigma ID:     93a19907-d4f9-4deb-9f91-aac4692776a6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_dotnet_profiler.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\pe386.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Using EventVwr

| Field | Value |
|---|---|
| **Sigma ID** | `63e4f530-65dc-49cc-8f80-ccfa95c69d43` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Antonio Cocomazzi (idea), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_eventvwr.yml)**

> Detects the pattern of a UAC bypass using Windows Event Viewer

```sql
-- ============================================================
-- Title:        UAC Bypass Using EventVwr
-- Sigma ID:     63e4f530-65dc-49cc-8f80-ccfa95c69d43
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Antonio Cocomazzi (idea), Florian Roth (Nextron Systems)
-- Date:         2022-04-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_eventvwr.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\Event Viewer\\RecentViews' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Microsoft\\EventV~1\\RecentViews'))
  AND NOT ((procName LIKE 'C:\\Windows\\System32\\%' OR procName LIKE 'C:\\Windows\\SysWOW64\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/orange_8361/status/1518970259868626944?s=20&t=RFXqZjtA7tWM3HxqEH78Aw
- https://twitter.com/splinter_code/status/1519075134296006662?s=12&t=DLUXH86WtcmG_AZ5gY3C6g
- https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#execute

---

## UAC Bypass Using IDiagnostic Profile - File

| Field | Value |
|---|---|
| **Sigma ID** | `48ea844d-19b1-4642-944e-fe39c2cc1fec` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1548.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_idiagnostic_profile.yml)**

> Detects the creation of a file by "dllhost.exe" in System32 directory part of "IDiagnosticProfileUAC" UAC bypass technique

```sql
-- ============================================================
-- Title:        UAC Bypass Using IDiagnostic Profile - File
-- Sigma ID:     48ea844d-19b1-4642-944e-fe39c2cc1fec
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1548.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_idiagnostic_profile.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\DllHost.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Wh04m1001/IDiagnosticProfileUAC

---

## UAC Bypass Using IEInstal - File

| Field | Value |
|---|---|
| **Sigma ID** | `bdd8157d-8e85-4397-bb82-f06cc9c71dbb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_ieinstal.yml)**

> Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)

```sql
-- ============================================================
-- Title:        UAC Bypass Using IEInstal - File
-- Sigma ID:     bdd8157d-8e85-4397-bb82-f06cc9c71dbb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_ieinstal.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = 'C:\Program Files\Internet Explorer\IEInstal.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%consent.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Using MSConfig Token Modification - File

| Field | Value |
|---|---|
| **Sigma ID** | `41bb431f-56d8-4691-bb56-ed34e390906f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_msconfig_gui.yml)**

> Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)

```sql
-- ============================================================
-- Title:        UAC Bypass Using MSConfig Token Modification - File
-- Sigma ID:     41bb431f-56d8-4691-bb56-ed34e390906f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_msconfig_gui.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\pkgmgr.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Using NTFS Reparse Point - File

| Field | Value |
|---|---|
| **Sigma ID** | `7fff6773-2baa-46de-a24a-b6eec1aba2d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_ntfs_reparse_point.yml)**

> Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)

```sql
-- ============================================================
-- Title:        UAC Bypass Using NTFS Reparse Point - File
-- Sigma ID:     7fff6773-2baa-46de-a24a-b6eec1aba2d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_ntfs_reparse_point.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\api-ms-win-core-kernel32-legacy-l1.DLL'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Abusing Winsat Path Parsing - File

| Field | Value |
|---|---|
| **Sigma ID** | `155dbf56-e0a4-4dd0-8905-8a98705045e8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_winsat.yml)**

> Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

```sql
-- ============================================================
-- Title:        UAC Bypass Abusing Winsat Path Parsing - File
-- Sigma ID:     155dbf56-e0a4-4dd0-8905-8a98705045e8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_winsat.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\system32\\winsat.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\system32\\winmm.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Using Windows Media Player - File

| Field | Value |
|---|---|
| **Sigma ID** | `68578b43-65df-4f81-9a9b-92f32711a951` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_wmp.yml)**

> Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)

```sql
-- ============================================================
-- Title:        UAC Bypass Using Windows Media Player - File
-- Sigma ID:     68578b43-65df-4f81-9a9b-92f32711a951
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_uac_bypass_wmp.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Users\\%')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\AppData\\Local\\Temp\\OskSupport.dll'))
  OR (procName = 'C:\Windows\system32\DllHost.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\Program Files\Windows Media Player\osk.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## VHD Image Download Via Browser

| Field | Value |
|---|---|
| **Sigma ID** | `8468111a-ef07-4654-903b-b863a80bbc95` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1587.001 |
| **Author** | frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_vhd_download_via_browsers.yml)**

> Detects creation of ".vhd"/".vhdx" files by browser processes.
Malware can use mountable Virtual Hard Disk ".vhd" files to encapsulate payloads and evade security controls.


```sql
-- ============================================================
-- Title:        VHD Image Download Via Browser
-- Sigma ID:     8468111a-ef07-4654-903b-b863a80bbc95
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1587.001
-- Author:       frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
-- Date:         2021-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_vhd_download_via_browsers.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate downloads of ".vhd" files would also trigger this
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\brave.exe' OR procName LIKE '%\\chrome.exe' OR procName LIKE '%\\firefox.exe' OR procName LIKE '%\\iexplore.exe' OR procName LIKE '%\\maxthon.exe' OR procName LIKE '%\\MicrosoftEdge.exe' OR procName LIKE '%\\msedge.exe' OR procName LIKE '%\\msedgewebview2.exe' OR procName LIKE '%\\opera.exe' OR procName LIKE '%\\safari.exe' OR procName LIKE '%\\seamonkey.exe' OR procName LIKE '%\\vivaldi.exe' OR procName LIKE '%\\whale.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.vhd%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate downloads of ".vhd" files would also trigger this

**References:**
- https://redcanary.com/blog/intelligence-insights-october-2021/
- https://www.kaspersky.com/blog/lazarus-vhd-ransomware/36559/
- https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/

---

## Visual Studio Code Tunnel Remote File Creation

| Field | Value |
|---|---|
| **Sigma ID** | `56e05d41-ce99-4ecd-912d-93f019ee0b71` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_vscode_tunnel_remote_creation_artefacts.yml)**

> Detects the creation of file by the "node.exe" process in the ".vscode-server" directory. Could be a sign of remote file creation via VsCode tunnel feature


```sql
-- ============================================================
-- Title:        Visual Studio Code Tunnel Remote File Creation
-- Sigma ID:     56e05d41-ce99-4ecd-912d-93f019ee0b71
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_vscode_tunnel_remote_creation_artefacts.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\servers\\Stable-%'
    AND procName LIKE '%\\server\\node.exe'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\.vscode-server\\data\\User\\History\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Renamed VsCode Code Tunnel Execution - File Indicator

| Field | Value |
|---|---|
| **Sigma ID** | `d102b8f5-61dc-4e68-bd83-9a3187c67377` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_vscode_tunnel_renamed_execution.yml)**

> Detects the creation of a file with the name "code_tunnel.json" which indicate execution and usage of VsCode tunneling utility by an "Image" or "Process" other than VsCode.


```sql
-- ============================================================
-- Title:        Renamed VsCode Code Tunnel Execution - File Indicator
-- Sigma ID:     d102b8f5-61dc-4e68-bd83-9a3187c67377
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_vscode_tunnel_renamed_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\code\_tunnel.json')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://ipfyx.fr/post/visual-studio-code-tunnel/
- https://badoption.eu/blog/2023/01/31/code_c2.html

---

## Potential Webshell Creation On Static Website

| Field | Value |
|---|---|
| **Sigma ID** | `39f1f9f2-9636-45de-98f6-a4046aa8e4b9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Beyu Denis, oscd.community, Tim Shelton, Thurein Oo |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_webshell_creation_detect.yml)**

> Detects the creation of files with certain extensions on a static web site. This can be indicative of potential uploads of a web shell.

```sql
-- ============================================================
-- Title:        Potential Webshell Creation On Static Website
-- Sigma ID:     39f1f9f2-9636-45de-98f6-a4046aa8e4b9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Beyu Denis, oscd.community, Tim Shelton, Thurein Oo
-- Date:         2019-10-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_webshell_creation_detect.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrator or developer creating legitimate executable files in a web application folder
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator or developer creating legitimate executable files in a web application folder

**References:**
- PT ESC rule and personal experience
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/c95a0a1a2855dc0cd7f7327614545fe30482a636/Upload%20Insecure%20Files/README.md

---

## Creation of WerFault.exe/Wer.dll in Unusual Folder

| Field | Value |
|---|---|
| **Sigma ID** | `28a452f3-786c-4fd8-b8f2-bddbe9d616d1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_werfault_dll_hijacking.yml)**

> Detects the creation of a file named "WerFault.exe" or "wer.dll" in an uncommon folder, which could be a sign of WerFault DLL hijacking.

```sql
-- ============================================================
-- Title:        Creation of WerFault.exe/Wer.dll in Unusual Folder
-- Sigma ID:     28a452f3-786c-4fd8-b8f2-bddbe9d616d1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       frack113
-- Date:         2022-05-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_werfault_dll_hijacking.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\WerFault.exe' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wer.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.bleepingcomputer.com/news/security/hackers-are-now-hiding-malware-in-windows-event-logs/

---

## WinRAR Creating Files in Startup Locations

| Field | Value |
|---|---|
| **Sigma ID** | `74a2b37d-fea4-41e0-9ac7-c9fbcf1f60cc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_winrar_file_creation_in_startup_folder.yml)**

> Detects WinRAR creating files in Windows startup locations, which may indicate an attempt to establish persistence by adding malicious files to the Startup folder.
This kind of behaviour has been associated with exploitation of WinRAR path traversal vulnerability CVE-2025-6218 or CVE-2025-8088.


```sql
-- ============================================================
-- Title:        WinRAR Creating Files in Startup Locations
-- Sigma ID:     74a2b37d-fea4-41e0-9ac7-c9fbcf1f60cc
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1547.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_winrar_file_creation_in_startup_folder.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\WinRAR.exe' OR procName LIKE '%\\Rar.exe')
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\Start Menu\\Programs\\Startup\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/mulwareX/CVE-2025-6218-POC
- https://x.com/0x534c/status/1944694507787710685
- https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/

---

## AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File

| Field | Value |
|---|---|
| **Sigma ID** | `d353dac0-1b41-46c2-820c-d7d2561fc6ed` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1216 |
| **Author** | Julia Fomina, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_winrm_awl_bypass.yml)**

> Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)

```sql
-- ============================================================
-- Title:        AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File
-- Sigma ID:     d353dac0-1b41-46c2-820c-d7d2561fc6ed
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1216
-- Author:       Julia Fomina, oscd.community
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_winrm_awl_bypass.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%WsmPty.xsl' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%WsmTxt.xsl'))
  AND NOT ((indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\System32\\%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE 'C:\\Windows\\SysWOW64\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404

---

## WMI Persistence - Script Event Consumer File Write

| Field | Value |
|---|---|
| **Sigma ID** | `33f41cdd-35ac-4ba8-814b-c6a4244a1ad4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wmi_persistence_script_event_consumer_write.yml)**

> Detects file writes of WMI script event consumer

```sql
-- ============================================================
-- Title:        WMI Persistence - Script Event Consumer File Write
-- Sigma ID:     33f41cdd-35ac-4ba8-814b-c6a4244a1ad4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       Thomas Patzke
-- Date:         2018-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wmi_persistence_script_event_consumer_write.yml
-- Unmapped:     (none)
-- False Pos:    Dell Power Manager (C:\Program Files\Dell\PowerManager\DpmPowerPlanSetup.exe)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName = 'C:\WINDOWS\system32\wbem\scrcons.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Dell Power Manager (C:\Program Files\Dell\PowerManager\DpmPowerPlanSetup.exe)

**References:**
- https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/

---

## Wmiexec Default Output File

| Field | Value |
|---|---|
| **Sigma ID** | `8d5aca11-22b3-4f22-b7ba-90e60533e1fb` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wmiexec_default_filename.yml)**

> Detects the creation of the default output filename used by the wmiexec tool

```sql
-- ============================================================
-- Title:        Wmiexec Default Output File
-- Sigma ID:     8d5aca11-22b3-4f22-b7ba-90e60533e1fb
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        execution | T1047
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wmiexec_default_filename.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'fileName')], '\\Windows\\__1\d{9}\.\d{1,7}$')))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'fileName')], 'C:\\__1\d{9}\.\d{1,7}$')))
  OR (indexOf(metrics_string.name, 'fileName') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'fileName')], 'D:\\__1\d{9}\.\d{1,7}$')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.crowdstrike.com/blog/how-to-detect-and-prevent-impackets-wmiexec/
- https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py

---

## Wmiprvse Wbemcomn DLL Hijack - File

| Field | Value |
|---|---|
| **Sigma ID** | `614a7e17-5643-4d89-b6fe-f9df1a79641c` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1047, T1021.002 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.yml)**

> Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.

```sql
-- ============================================================
-- Title:        Wmiprvse Wbemcomn DLL Hijack - File
-- Sigma ID:     614a7e17-5643-4d89-b6fe-f9df1a79641c
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        execution | T1047, T1021.002
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName = 'System'
    AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\wbem\\wbemcomn.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html

---

## UEFI Persistence Via Wpbbin - FileCreation

| Field | Value |
|---|---|
| **Sigma ID** | `e94b9ddc-eec5-4bb8-8a58-b9dc5f4e185f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1542.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wpbbin_persistence.yml)**

> Detects creation of a file named "wpbbin" in the "%systemroot%\system32\" directory. Which could be indicative of UEFI based persistence method

```sql
-- ============================================================
-- Title:        UEFI Persistence Via Wpbbin - FileCreation
-- Sigma ID:     e94b9ddc-eec5-4bb8-8a58-b9dc5f4e185f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1542.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_wpbbin_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] = 'C:\Windows\System32\wpbbin.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)

**References:**
- https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
- https://persistence-info.github.io/Data/wpbbin.html

---

## Writing Local Admin Share

| Field | Value |
|---|---|
| **Sigma ID** | `4aafb0fa-bff5-4b9d-b99e-8093e659c65f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_writing_local_admin_share.yml)**

> Aversaries may use to interact with a remote network share using Server Message Block (SMB).
This technique is used by post-exploitation frameworks.


```sql
-- ============================================================
-- Title:        Writing Local Admin Share
-- Sigma ID:     4aafb0fa-bff5-4b9d-b99e-8093e659c65f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.002
-- Author:       frack113
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_writing_local_admin_share.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\\\\\\\127.0.0%' AND metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%\\ADMIN$\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.002/T1021.002.md#atomic-test-4---execute-command-writing-output-to-local-admin-share

---
