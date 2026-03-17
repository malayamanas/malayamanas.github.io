# Sigma → FortiSIEM: Windows Registry Set

> 204 rules · Generated 2026-03-17

## Table of Contents

- [Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback](#enable-remote-connection-between-anonymous-computer-allowanonymouscallback)
- [Registry Persistence via Service in Safe Mode](#registry-persistence-via-service-in-safe-mode)
- [Add Port Monitor Persistence in Registry](#add-port-monitor-persistence-in-registry)
- [Add Debugger Entry To AeDebug For Persistence](#add-debugger-entry-to-aedebug-for-persistence)
- [Allow RDP Remote Assistance Feature](#allow-rdp-remote-assistance-feature)
- [Potential AMSI COM Server Hijacking](#potential-amsi-com-server-hijacking)
- [AMSI Disabled via Registry Modification](#amsi-disabled-via-registry-modification)
- [Classes Autorun Keys Modification](#classes-autorun-keys-modification)
- [Common Autorun Keys Modification](#common-autorun-keys-modification)
- [CurrentControlSet Autorun Keys Modification](#currentcontrolset-autorun-keys-modification)
- [CurrentVersion Autorun Keys Modification](#currentversion-autorun-keys-modification)
- [CurrentVersion NT Autorun Keys Modification](#currentversion-nt-autorun-keys-modification)
- [Internet Explorer Autorun Keys Modification](#internet-explorer-autorun-keys-modification)
- [Office Autorun Keys Modification](#office-autorun-keys-modification)
- [Session Manager Autorun Keys Modification](#session-manager-autorun-keys-modification)
- [System Scripts Autorun Keys Modification](#system-scripts-autorun-keys-modification)
- [WinSock2 Autorun Keys Modification](#winsock2-autorun-keys-modification)
- [Wow6432Node CurrentVersion Autorun Keys Modification](#wow6432node-currentversion-autorun-keys-modification)
- [Wow6432Node Classes Autorun Keys Modification](#wow6432node-classes-autorun-keys-modification)
- [Wow6432Node Windows NT CurrentVersion Autorun Keys Modification](#wow6432node-windows-nt-currentversion-autorun-keys-modification)
- [New BgInfo.EXE Custom DB Path Registry Configuration](#new-bginfoexe-custom-db-path-registry-configuration)
- [New BgInfo.EXE Custom VBScript Registry Configuration](#new-bginfoexe-custom-vbscript-registry-configuration)
- [New BgInfo.EXE Custom WMI Query Registry Configuration](#new-bginfoexe-custom-wmi-query-registry-configuration)
- [Bypass UAC Using DelegateExecute](#bypass-uac-using-delegateexecute)
- [Bypass UAC Using Event Viewer](#bypass-uac-using-event-viewer)
- [Bypass UAC Using SilentCleanup Task](#bypass-uac-using-silentcleanup-task)
- [Default RDP Port Changed to Non Standard Port](#default-rdp-port-changed-to-non-standard-port)
- [IE Change Domain Zone](#ie-change-domain-zone)
- [Sysmon Driver Altitude Change](#sysmon-driver-altitude-change)
- [Change Winevt Channel Access Permission Via Registry](#change-winevt-channel-access-permission-via-registry)
- [Running Chrome VPN Extensions via the Registry 2 VPN Extension](#running-chrome-vpn-extensions-via-the-registry-2-vpn-extension)
- [ClickOnce Trust Prompt Tampering](#clickonce-trust-prompt-tampering)
- [Potential CobaltStrike Service Installations - Registry](#potential-cobaltstrike-service-installations-registry)
- [COM Hijack via Sdclt](#com-hijack-via-sdclt)
- [CrashControl CrashDump Disabled](#crashcontrol-crashdump-disabled)
- [Security Event Logging Disabled via MiniNt Registry Key - Registry Set](#security-event-logging-disabled-via-minint-registry-key-registry-set)
- [Service Binary in Suspicious Folder](#service-binary-in-suspicious-folder)
- [Windows Credential Guard Disabled - Registry](#windows-credential-guard-disabled-registry)
- [Custom File Open Handler Executes PowerShell](#custom-file-open-handler-executes-powershell)
- [Potential Registry Persistence Attempt Via DbgManagedDebugger](#potential-registry-persistence-attempt-via-dbgmanageddebugger)
- [Windows Defender Exclusions Added - Registry](#windows-defender-exclusions-added-registry)
- [Potentially Suspicious Desktop Background Change Via Registry](#potentially-suspicious-desktop-background-change-via-registry)
- [Antivirus Filter Driver Disallowed On Dev Drive - Registry](#antivirus-filter-driver-disallowed-on-dev-drive-registry)
- [Windows Hypervisor Enforced Code Integrity Disabled](#windows-hypervisor-enforced-code-integrity-disabled)
- [Hypervisor Enforced Paging Translation Disabled](#hypervisor-enforced-paging-translation-disabled)
- [DHCP Callout DLL Installation](#dhcp-callout-dll-installation)
- [Disable Administrative Share Creation at Startup](#disable-administrative-share-creation-at-startup)
- [Potential AutoLogger Sessions Tampering](#potential-autologger-sessions-tampering)
- [Disable Microsoft Defender Firewall via Registry](#disable-microsoft-defender-firewall-via-registry)
- [Disable Internal Tools or Feature in Registry](#disable-internal-tools-or-feature-in-registry)
- [Disable Macro Runtime Scan Scope](#disable-macro-runtime-scan-scope)
- [Disable Privacy Settings Experience in Registry](#disable-privacy-settings-experience-in-registry)
- [Disable Windows Security Center Notifications](#disable-windows-security-center-notifications)
- [Registry Disable System Restore](#registry-disable-system-restore)
- [Windows Defender Service Disabled - Registry](#windows-defender-service-disabled-registry)
- [Windows Event Log Access Tampering Via Registry](#windows-event-log-access-tampering-via-registry)
- [Disable Windows Firewall by Registry](#disable-windows-firewall-by-registry)
- [Disable Windows Event Logging Via Registry](#disable-windows-event-logging-via-registry)
- [Disable Exploit Guard Network Protection on Windows Defender](#disable-exploit-guard-network-protection-on-windows-defender)
- [Disabled Windows Defender Eventlog](#disabled-windows-defender-eventlog)
- [Disable PUA Protection on Windows Defender](#disable-pua-protection-on-windows-defender)
- [Disable Tamper Protection on Windows Defender](#disable-tamper-protection-on-windows-defender)
- [Add DisallowRun Execution to Registry](#add-disallowrun-execution-to-registry)
- [Persistence Via Disk Cleanup Handler - Autorun](#persistence-via-disk-cleanup-handler-autorun)
- [DNS-over-HTTPS Enabled by Registry](#dns-over-https-enabled-by-registry)
- [New DNS ServerLevelPluginDll Installed](#new-dns-serverlevelplugindll-installed)
- [ETW Logging Disabled In .NET Processes - Sysmon Registry](#etw-logging-disabled-in-net-processes-sysmon-registry)
- [Directory Service Restore Mode(DSRM) Registry Value Tampering](#directory-service-restore-modedsrm-registry-value-tampering)
- [Periodic Backup For System Registry Hives Enabled](#periodic-backup-for-system-registry-hives-enabled)
- [Windows Recall Feature Enabled - Registry](#windows-recall-feature-enabled-registry)
- [Enabling COR Profiler Environment Variables](#enabling-cor-profiler-environment-variables)
- [Scripted Diagnostics Turn Off Check Enabled - Registry](#scripted-diagnostics-turn-off-check-enabled-registry)
- [Potential EventLog File Location Tampering](#potential-eventlog-file-location-tampering)
- [Suspicious Application Allowed Through Exploit Guard](#suspicious-application-allowed-through-exploit-guard)
- [Change User Account Associated with the FAX Service](#change-user-account-associated-with-the-fax-service)
- [Change the Fax Dll](#change-the-fax-dll)
- [New File Association Using Exefile](#new-file-association-using-exefile)
- [FileFix - Command Evidence in TypedPaths](#filefix-command-evidence-in-typedpaths)
- [Add Debugger Entry To Hangs Key For Persistence](#add-debugger-entry-to-hangs-key-for-persistence)
- [Persistence Via Hhctrl.ocx](#persistence-via-hhctrlocx)
- [Registry Modification to Hidden File Extension](#registry-modification-to-hidden-file-extension)
- [Displaying Hidden Files Feature Disabled](#displaying-hidden-files-feature-disabled)
- [Registry Hide Function from User](#registry-hide-function-from-user)
- [Hide Schedule Task Via Index Value Tamper](#hide-schedule-task-via-index-value-tamper)
- [Driver Added To Disallowed Images In HVCI - Registry](#driver-added-to-disallowed-images-in-hvci-registry)
- [IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols](#ie-zonemap-setting-downgraded-to-mycomputer-zone-for-http-protocols)
- [Uncommon Extension In Keyboard Layout IME File Registry Value](#uncommon-extension-in-keyboard-layout-ime-file-registry-value)
- [Suspicious Path In Keyboard Layout IME File Registry Value](#suspicious-path-in-keyboard-layout-ime-file-registry-value)
- [New Root or CA or AuthRoot Certificate to Store](#new-root-or-ca-or-authroot-certificate-to-store)
- [Internet Explorer DisableFirstRunCustomize Enabled](#internet-explorer-disablefirstruncustomize-enabled)
- [Potential Ransomware Activity Using LegalNotice Message](#potential-ransomware-activity-using-legalnotice-message)
- [Lolbas OneDriveStandaloneUpdater.exe Proxy Download](#lolbas-onedrivestandaloneupdaterexe-proxy-download)
- [RestrictedAdminMode Registry Value Tampering](#restrictedadminmode-registry-value-tampering)
- [Lsass Full Dump Request Via DumpType Registry Settings](#lsass-full-dump-request-via-dumptype-registry-settings)
- [NET NGenAssemblyUsageLog Registry Key Tamper](#net-ngenassemblyusagelog-registry-key-tamper)
- [New Netsh Helper DLL Registered From A Suspicious Location](#new-netsh-helper-dll-registered-from-a-suspicious-location)
- [Potential Persistence Via Netsh Helper DLL - Registry](#potential-persistence-via-netsh-helper-dll-registry)
- [New Application in AppCompat](#new-application-in-appcompat)
- [Potential Credential Dumping Attempt Using New NetworkProvider - REG](#potential-credential-dumping-attempt-using-new-networkprovider-reg)
- [New ODBC Driver Registered](#new-odbc-driver-registered)
- [Potentially Suspicious ODBC Driver Registered](#potentially-suspicious-odbc-driver-registered)
- [Trust Access Disable For VBApplications](#trust-access-disable-for-vbapplications)
- [Microsoft Office Protected View Disabled](#microsoft-office-protected-view-disabled)
- [Python Function Execution Security Warning Disabled In Excel - Registry](#python-function-execution-security-warning-disabled-in-excel-registry)
- [Enable Microsoft Dynamic Data Exchange](#enable-microsoft-dynamic-data-exchange)
- [Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting](#potential-persistence-via-outlook-loadmacroprovideronboot-setting)
- [Outlook Macro Execution Without Warning Setting Enabled](#outlook-macro-execution-without-warning-setting-enabled)
- [Outlook EnableUnsafeClientMailRules Setting Enabled - Registry](#outlook-enableunsafeclientmailrules-setting-enabled-registry)
- [Outlook Security Settings Updated - Registry](#outlook-security-settings-updated-registry)
- [Macro Enabled In A Potentially Suspicious Document](#macro-enabled-in-a-potentially-suspicious-document)
- [Uncommon Microsoft Office Trusted Location Added](#uncommon-microsoft-office-trusted-location-added)
- [Office Macros Warning Disabled](#office-macros-warning-disabled)
- [MaxMpxCt Registry Value Changed](#maxmpxct-registry-value-changed)
- [Potential Persistence Via New AMSI Providers - Registry](#potential-persistence-via-new-amsi-providers-registry)
- [Potential Persistence Via AppCompat RegisterAppRestart Layer](#potential-persistence-via-appcompat-registerapprestart-layer)
- [Potential Persistence Via App Paths Default Property](#potential-persistence-via-app-paths-default-property)
- [Potential Persistence Using DebugPath](#potential-persistence-using-debugpath)
- [Potential Persistence Via AutodialDLL](#potential-persistence-via-autodialdll)
- [Potential Persistence Via CHM Helper DLL](#potential-persistence-via-chm-helper-dll)
- [COM Object Hijacking Via Modification Of Default System CLSID Default Value](#com-object-hijacking-via-modification-of-default-system-clsid-default-value)
- [Potential COM Object Hijacking Via TreatAs Subkey - Registry](#potential-com-object-hijacking-via-treatas-subkey-registry)
- [Potential PSFactoryBuffer COM Hijacking](#potential-psfactorybuffer-com-hijacking)
- [Potential Persistence Via Custom Protocol Handler](#potential-persistence-via-custom-protocol-handler)
- [Potential Persistence Via Event Viewer Events.asp](#potential-persistence-via-event-viewer-eventsasp)
- [Potential Persistence Via GlobalFlags](#potential-persistence-via-globalflags)
- [Modification of IE Registry Settings](#modification-of-ie-registry-settings)
- [Register New IFiltre For Persistence](#register-new-ifiltre-for-persistence)
- [Potential Persistence Via Logon Scripts - Registry](#potential-persistence-via-logon-scripts-registry)
- [Potential Persistence Via LSA Extensions](#potential-persistence-via-lsa-extensions)
- [Potential Persistence Via Mpnotify](#potential-persistence-via-mpnotify)
- [Potential Persistence Via MyComputer Registry Keys](#potential-persistence-via-mycomputer-registry-keys)
- [Potential Persistence Via DLLPathOverride](#potential-persistence-via-dllpathoverride)
- [Potential Persistence Via Visual Studio Tools for Office](#potential-persistence-via-visual-studio-tools-for-office)
- [Potential Persistence Via Outlook Home Page](#potential-persistence-via-outlook-home-page)
- [Potential Persistence Via Outlook Today Page](#potential-persistence-via-outlook-today-page)
- [Potential WerFault ReflectDebugger Registry Value Abuse](#potential-werfault-reflectdebugger-registry-value-abuse)
- [Potential Persistence Via Scrobj.dll COM Hijacking](#potential-persistence-via-scrobjdll-com-hijacking)
- [Potential Persistence Via Shim Database Modification](#potential-persistence-via-shim-database-modification)
- [Suspicious Shim Database Patching Activity](#suspicious-shim-database-patching-activity)
- [Potential Persistence Via Shim Database In Uncommon Location](#potential-persistence-via-shim-database-in-uncommon-location)
- [Potential Persistence Via TypedPaths](#potential-persistence-via-typedpaths)
- [Potential Persistence Via Excel Add-in - Registry](#potential-persistence-via-excel-add-in-registry)
- [Potential Attachment Manager Settings Associations Tamper](#potential-attachment-manager-settings-associations-tamper)
- [Potential Attachment Manager Settings Attachments Tamper](#potential-attachment-manager-settings-attachments-tamper)
- [Potential ClickFix Execution Pattern - Registry](#potential-clickfix-execution-pattern-registry)
- [Registry Modification for OCI DLL Redirection](#registry-modification-for-oci-dll-redirection)
- [PowerShell as a Service in Registry](#powershell-as-a-service-in-registry)
- [PowerShell Script Execution Policy Enabled](#powershell-script-execution-policy-enabled)
- [Potential PowerShell Execution Policy Tampering](#potential-powershell-execution-policy-tampering)
- [Suspicious PowerShell In Registry Run Keys](#suspicious-powershell-in-registry-run-keys)
- [PowerShell Logging Disabled Via Registry Key Tampering](#powershell-logging-disabled-via-registry-key-tampering)
- [Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG](#potential-provisioning-registry-key-abuse-for-binary-proxy-execution-reg)
- [PUA - Sysinternal Tool Execution - Registry](#pua-sysinternal-tool-execution-registry)
- [Suspicious Execution Of Renamed Sysinternals Tools - Registry](#suspicious-execution-of-renamed-sysinternals-tools-registry)
- [PUA - Sysinternals Tools Execution - Registry](#pua-sysinternals-tools-execution-registry)
- [Usage of Renamed Sysinternals Tools - RegistrySet](#usage-of-renamed-sysinternals-tools-registryset)
- [ETW Logging Disabled For rpcrt4.dll](#etw-logging-disabled-for-rpcrt4dll)
- [Potentially Suspicious Command Executed Via Run Dialog Box - Registry](#potentially-suspicious-command-executed-via-run-dialog-box-registry)
- [ScreenSaver Registry Key Set](#screensaver-registry-key-set)
- [Potential SentinelOne Shell Context Menu Scan Command Tampering](#potential-sentinelone-shell-context-menu-scan-command-tampering)
- [ServiceDll Hijack](#servicedll-hijack)
- [ETW Logging Disabled For SCM](#etw-logging-disabled-for-scm)
- [Registry Explorer Policy Modification](#registry-explorer-policy-modification)
- [Persistence Via New SIP Provider](#persistence-via-new-sip-provider)
- [Tamper With Sophos AV Registry Keys](#tamper-with-sophos-av-registry-keys)
- [Hiding User Account Via SpecialAccounts Registry Key](#hiding-user-account-via-specialaccounts-registry-key)
- [Activate Suppression of Windows Security Center Notifications](#activate-suppression-of-windows-security-center-notifications)
- [Suspicious Keyboard Layout Load](#suspicious-keyboard-layout-load)
- [Potential PendingFileRenameOperations Tampering](#potential-pendingfilerenameoperations-tampering)
- [Suspicious Printer Driver Empty Manufacturer](#suspicious-printer-driver-empty-manufacturer)
- [Registry Persistence via Explorer Run Key](#registry-persistence-via-explorer-run-key)
- [New RUN Key Pointing to Suspicious Folder](#new-run-key-pointing-to-suspicious-folder)
- [Suspicious Space Characters in RunMRU Registry Path - ClickFix](#suspicious-space-characters-in-runmru-registry-path-clickfix)
- [Suspicious Service Installed](#suspicious-service-installed)
- [Suspicious Shell Open Command Registry Modification](#suspicious-shell-open-command-registry-modification)
- [Suspicious Space Characters in TypedPaths Registry Path - FileFix](#suspicious-space-characters-in-typedpaths-registry-path-filefix)
- [Modify User Shell Folders Startup Value](#modify-user-shell-folders-startup-value)
- [WFP Filter Added via Registry](#wfp-filter-added-via-registry)
- [Suspicious Environment Variable Has Been Registered](#suspicious-environment-variable-has-been-registered)
- [Enable LM Hash Storage](#enable-lm-hash-storage)
- [Scheduled TaskCache Change by Uncommon Program](#scheduled-taskcache-change-by-uncommon-program)
- [Potential Registry Persistence Attempt Via Windows Telemetry](#potential-registry-persistence-attempt-via-windows-telemetry)
- [RDP Sensitive Settings Changed to Zero](#rdp-sensitive-settings-changed-to-zero)
- [RDP Sensitive Settings Changed](#rdp-sensitive-settings-changed)
- [New TimeProviders Registered With Uncommon DLL Name](#new-timeproviders-registered-with-uncommon-dll-name)
- [Old TLS1.0/TLS1.1 Protocol Version Enabled](#old-tls10tls11-protocol-version-enabled)
- [COM Hijacking via TreatAs](#com-hijacking-via-treatas)
- [Potential Signing Bypass Via Windows Developer Features - Registry](#potential-signing-bypass-via-windows-developer-features-registry)
- [UAC Bypass via Event Viewer](#uac-bypass-via-event-viewer)
- [UAC Bypass via Sdclt](#uac-bypass-via-sdclt)
- [UAC Bypass Abusing Winsat Path Parsing - Registry](#uac-bypass-abusing-winsat-path-parsing-registry)
- [UAC Bypass Using Windows Media Player - Registry](#uac-bypass-using-windows-media-player-registry)
- [UAC Disabled](#uac-disabled)
- [UAC Notification Disabled](#uac-notification-disabled)
- [UAC Secure Desktop Prompt Disabled](#uac-secure-desktop-prompt-disabled)
- [VBScript Payload Stored in Registry](#vbscript-payload-stored-in-registry)
- [Windows Vulnerable Driver Blocklist Disabled](#windows-vulnerable-driver-blocklist-disabled)
- [Execution DLL of Choice Using WAB.EXE](#execution-dll-of-choice-using-wabexe)
- [Wdigest Enable UseLogonCredential](#wdigest-enable-uselogoncredential)
- [Disable Windows Defender Functionalities Via Registry Keys](#disable-windows-defender-functionalities-via-registry-keys)
- [Winget Admin Settings Modification](#winget-admin-settings-modification)
- [Enable Local Manifest Installation With Winget](#enable-local-manifest-installation-with-winget)
- [Winlogon AllowMultipleTSSessions Enable](#winlogon-allowmultipletssessions-enable)
- [Winlogon Notify Key Logon Persistence](#winlogon-notify-key-logon-persistence)

## Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback

| Field | Value |
|---|---|
| **Sigma ID** | `4d431012-2ab5-4db7-a84e-b29809da2172` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_set_enable_anonymous_connection.yml)**

> Detects enabling of the "AllowAnonymousCallback" registry value, which allows a remote connection between computers that do not have a trust relationship.

```sql
-- ============================================================
-- Title:        Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback
-- Sigma ID:     4d431012-2ab5-4db7-a84e-b29809da2172
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-11-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_set_enable_anonymous_connection.yml
-- Unmapped:     (none)
-- False Pos:    Administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\WBEM\\CIMOM\\AllowAnonymousCallback%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative activity

**References:**
- https://learn.microsoft.com/en-us/windows/win32/wmisdk/connecting-to-wmi-remotely-starting-with-vista

---

## Registry Persistence via Service in Safe Mode

| Field | Value |
|---|---|
| **Sigma ID** | `1547e27c-3974-43e2-a7d7-7f484fb928ec` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml)**

> Detects the modification of the registry to allow a driver or service to persist in Safe Mode.

```sql
-- ============================================================
-- Title:        Registry Persistence via Service in Safe Mode
-- Sigma ID:     1547e27c-3974-43e2-a7d7-7f484fb928ec
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564.001
-- Author:       frack113
-- Date:         2022-04-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\SafeBoot\\Minimal\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\SafeBoot\\Network\\%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\(Default)')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'Service'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-33---windows-add-registry-value-to-load-service-in-safe-mode-without-network
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-34---windows-add-registry-value-to-load-service-in-safe-mode-with-network

---

## Add Port Monitor Persistence in Registry

| Field | Value |
|---|---|
| **Sigma ID** | `944e8941-f6f6-4ee8-ac05-1c224e923c0e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.010 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_add_port_monitor.yml)**

> Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation.
A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup.


```sql
-- ============================================================
-- Title:        Add Port Monitor Persistence in Registry
-- Sigma ID:     944e8941-f6f6-4ee8-ac05-1c224e923c0e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.010
-- Author:       frack113
-- Date:         2021-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_add_port_monitor.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Print\\Monitors\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.010/T1547.010.md

---

## Add Debugger Entry To AeDebug For Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `092af964-4233-4373-b4ba-d86ea2890288` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_aedebug_persistence.yml)**

> Detects when an attacker adds a new "Debugger" value to the "AeDebug" key in order to achieve persistence which will get invoked when an application crashes

```sql
-- ============================================================
-- Title:        Add Debugger Entry To AeDebug For Persistence
-- Sigma ID:     092af964-4233-4373-b4ba-d86ea2890288
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_aedebug_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the key to setup a debugger. Which is often the case on developers machines
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dll'))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '"C:\WINDOWS\system32\vsjitdebugger.exe" -p %ld -e %ld -j 0x%p')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the key to setup a debugger. Which is often the case on developers machines

**References:**
- https://persistence-info.github.io/Data/aedebug.html
- https://learn.microsoft.com/en-us/windows/win32/debug/configuring-automatic-debugging

---

## Allow RDP Remote Assistance Feature

| Field | Value |
|---|---|
| **Sigma ID** | `37b437cf-3fc5-4c8e-9c94-1d7c9aff842b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_allow_rdp_remote_assistance_feature.yml)**

> Detect enable rdp feature to allow specific user to rdp connect on the targeted machine

```sql
-- ============================================================
-- Title:        Allow RDP Remote Assistance Feature
-- Sigma ID:     37b437cf-3fc5-4c8e-9c94-1d7c9aff842b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_allow_rdp_remote_assistance_feature.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the feature (alerts should be investigated either way)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%System\\CurrentControlSet\\Control\\Terminal Server\\fAllowToGetHelp')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the feature (alerts should be investigated either way)

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

---

## Potential AMSI COM Server Hijacking

| Field | Value |
|---|---|
| **Sigma ID** | `160d2780-31f7-4922-8b3a-efce30e63e96` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_amsi_com_hijack.yml)**

> Detects changes to the AMSI come server registry key in order disable AMSI scanning functionalities. When AMSI attempts to starts its COM component, it will query its registered CLSID and return a non-existent COM server. This causes a load failure and prevents any scanning methods from being accessed, ultimately rendering AMSI useless

```sql
-- ============================================================
-- Title:        Potential AMSI COM Server Hijacking
-- Sigma ID:     160d2780-31f7-4922-8b3a-efce30e63e96
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_amsi_com_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32\\(Default)')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '%windir%\system32\amsi.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/
- https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-comreg-bypass

---

## AMSI Disabled via Registry Modification

| Field | Value |
|---|---|
| **Sigma ID** | `aa37cbb0-da36-42cb-a90f-fdf216fc7467` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001, T1562.006 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_amsi_disable.yml)**

> Detects attempts to disable AMSI (Anti-Malware Scan Interface) by modifying the AmsiEnable registry value.
Anti-Malware Scan Interface (AMSI) is a security feature in Windows that allows applications and services to integrate with anti-malware products for enhanced protection against malicious content.
Adversaries may attempt to disable AMSI to evade detection by security software, allowing them to execute malicious scripts or code without being scanned.


```sql
-- ============================================================
-- Title:        AMSI Disabled via Registry Modification
-- Sigma ID:     aa37cbb0-da36-42cb-a90f-fdf216fc7467
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001, T1562.006
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-12-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_amsi_disable.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://mostafayahiax.medium.com/hunting-for-amsi-bypassing-methods-9886dda0bf9d
- https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- https://www.mdsec.co.uk/2019/02/macros-and-more-with-sharpshooter-v2-0/

---

## Classes Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `9df5f547-c86a-433e-b533-f2794357e242` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_classes.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Classes Autorun Keys Modification
-- Sigma ID:     9df5f547-c86a-433e-b533-f2794357e242
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_classes.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## Common Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `f59c3faf-50f3-464b-9f4c-1b67ab512d99` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split), wagga (name) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_common.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Common Autorun Keys Modification
-- Sigma ID:     f59c3faf-50f3-464b-9f4c-1b67ab512d99
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split), wagga (name)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_common.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows CE Services\\AutoStart%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Wow6432Node\\Microsoft\\Command Processor\\Autorun%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnDisconnect%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnConnect%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SYSTEM\\Setup\\CmdLine%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Ctf\\LangBarAddin%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Command Processor\\Autorun%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Classes\\Protocols\\Handler%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Classes\\Protocols\\Filter%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Classes\\Htmlfile\\Shell\\Open\\Command\\(Default)%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Environment\\UserInitMprLogonScript%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\Scrnsave.exe%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Internet Explorer\\UrlSearchHooks%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Internet Explorer\\Desktop\\Components%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Classes\\Clsid\\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\\Inprocserver32%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control Panel\\Desktop\\Scrnsave.exe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d
- https://persistence-info.github.io/Data/userinitmprlogonscript.html

---

## CurrentControlSet Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `f674e36a-4b91-431e-8aef-f8a96c2aca35` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentcontrolset.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        CurrentControlSet Autorun Keys Modification
-- Sigma ID:     f674e36a-4b91-431e-8aef-f8a96c2aca35
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentcontrolset.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## CurrentVersion Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `20f0ee37-5942-4e45-b7d5-c5b5db9df5cd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        CurrentVersion Autorun Keys Modification
-- Sigma ID:     20f0ee37-5942-4e45-b7d5-c5b5db9df5cd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d
- https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/

---

## CurrentVersion NT Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `cbf93e5d-ca6c-4722-8bea-e9119007c248` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        CurrentVersion NT Autorun Keys Modification
-- Sigma ID:     cbf93e5d-ca6c-4722-8bea-e9119007c248
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## Internet Explorer Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `a80f662f-022f-4429-9b8c-b1a41aaa6688` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_internet_explorer.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Internet Explorer Autorun Keys Modification
-- Sigma ID:     a80f662f-022f-4429-9b8c-b1a41aaa6688
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_internet_explorer.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Wow6432Node\\Microsoft\\Internet Explorer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Internet Explorer%'))
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Toolbar%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Extensions%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Explorer Bars%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## Office Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `baecf8fb-edbf-429f-9ade-31fc3f22b970` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_office.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Office Autorun Keys Modification
-- Sigma ID:     baecf8fb-edbf-429f-9ade-31fc3f22b970
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_office.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## Session Manager Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `046218bd-e0d8-4113-a3c3-895a12b2b298` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001, T1546.009 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_session_manager.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Session Manager Autorun Keys Modification
-- Sigma ID:     046218bd-e0d8-4113-a3c3-895a12b2b298
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001, T1546.009
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_session_manager.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\System\\CurrentControlSet\\Control\\Session Manager%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SetupExecute%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\S0InitialCommand%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\KnownDlls%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Execute%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\BootExecute%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppCertDlls%'))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## System Scripts Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `e7a2fd40-3ae1-4a85-bf80-15cf624fb1b1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_system_scripts.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        System Scripts Autorun Keys Modification
-- Sigma ID:     e7a2fd40-3ae1-4a85-bf80-15cf624fb1b1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_system_scripts.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Startup%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Shutdown%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Logon%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Logoff%'))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## WinSock2 Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `d6c2ce7e-afb5-4337-9ca4-4b5254ed0565` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_winsock2.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        WinSock2 Autorun Keys Modification
-- Sigma ID:     d6c2ce7e-afb5-4337-9ca4-4b5254ed0565
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_winsock2.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Protocol\_Catalog9\\Catalog\_Entries%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\NameSpace\_Catalog5\\Catalog\_Entries%'))
  AND NOT ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)'))
  OR (procName = 'C:\Windows\System32\MsiExec.exe')
  OR (procName = 'C:\Windows\syswow64\MsiExec.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## Wow6432Node CurrentVersion Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `b29aed60-ebd1-442b-9cb5-16a1d0324adb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Wow6432Node CurrentVersion Autorun Keys Modification
-- Sigma ID:     b29aed60-ebd1-442b-9cb5-16a1d0324adb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d
- https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/

---

## Wow6432Node Classes Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `18f2065c-d36c-464a-a748-bcf909acb2e3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node_classes.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Wow6432Node Classes Autorun Keys Modification
-- Sigma ID:     18f2065c-d36c-464a-a748-bcf909acb2e3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node_classes.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Wow6432Node\\Classes%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Folder\\ShellEx\\ExtShellFolderViews%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Folder\\ShellEx\\DragDropHandlers%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Folder\\ShellEx\\ColumnHandlers%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Directory\\Shellex\\DragDropHandlers%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Directory\\Shellex\\CopyHookHandlers%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{AC757296-3522-4E11-9862-C17BE5A1767E}\\Instance%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\\Instance%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{7ED96837-96F0-4812-B211-F13C24117ED3}\\Instance%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{083863F1-70DE-11d0-BD40-00A0C911CE86}\\Instance%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AllFileSystemObjects\\ShellEx\\DragDropHandlers%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ShellEx\\PropertySheetHandlers%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ShellEx\\ContextMenuHandlers%'))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## Wow6432Node Windows NT CurrentVersion Autorun Keys Modification

| Field | Value |
|---|---|
| **Sigma ID** | `480421f9-417f-4d3b-9552-fd2728443ec8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node_currentversion.yml)**

> Detects modification of autostart extensibility point (ASEP) in registry.

```sql
-- ============================================================
-- Title:        Wow6432Node Windows NT CurrentVersion Autorun Keys Modification
-- Sigma ID:     480421f9-417f-4d3b-9552-fd2728443ec8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_wow6432node_currentversion.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason; Legitimate administrator sets up autorun keys for legitimate reason

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

---

## New BgInfo.EXE Custom DB Path Registry Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `53330955-dc52-487f-a3a2-da24dcff99b5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bginfo_custom_db.yml)**

> Detects setting of a new registry database value related to BgInfo configuration. Attackers can for example set this value to save the results of the commands executed by BgInfo in order to exfiltrate information.

```sql
-- ============================================================
-- Title:        New BgInfo.EXE Custom DB Path Registry Configuration
-- Sigma ID:     53330955-dc52-487f-a3a2-da24dcff99b5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bginfo_custom_db.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of external DB to save the results
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Winternals\\BGInfo\\Database')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of external DB to save the results

**References:**
- Internal Research

---

## New BgInfo.EXE Custom VBScript Registry Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `992dd79f-dde8-4bb0-9085-6350ba97cfb3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bginfo_custom_vbscript.yml)**

> Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom VBScript via "BgInfo.exe"

```sql
-- ============================================================
-- Title:        New BgInfo.EXE Custom VBScript Registry Configuration
-- Sigma ID:     992dd79f-dde8-4bb0-9085-6350ba97cfb3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bginfo_custom_vbscript.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate VBScript
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Winternals\\BGInfo\\UserFields\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '4%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate VBScript

**References:**
- Internal Research

---

## New BgInfo.EXE Custom WMI Query Registry Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `cd277474-5c52-4423-a52b-ac2d7969902f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bginfo_custom_wmi_query.yml)**

> Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom WMI query via "BgInfo.exe"

```sql
-- ============================================================
-- Title:        New BgInfo.EXE Custom WMI Query Registry Configuration
-- Sigma ID:     cd277474-5c52-4423-a52b-ac2d7969902f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bginfo_custom_wmi_query.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate WMI query
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Winternals\\BGInfo\\UserFields\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '6%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate WMI query

**References:**
- Internal Research

---

## Bypass UAC Using DelegateExecute

| Field | Value |
|---|---|
| **Sigma ID** | `46dd5308-4572-4d12-aa43-8938f0184d4f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_delegateexecute.yml)**

> Bypasses User Account Control using a fileless method

```sql
-- ============================================================
-- Title:        Bypass UAC Using DelegateExecute
-- Sigma ID:     46dd5308-4572-4d12-aa43-8938f0184d4f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       frack113
-- Date:         2022-01-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_delegateexecute.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\open\\command\\DelegateExecute')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iexecutecommand
- https://devblogs.microsoft.com/oldnewthing/20100312-01/?p=14623
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-7---bypass-uac-using-sdclt-delegateexecute

---

## Bypass UAC Using Event Viewer

| Field | Value |
|---|---|
| **Sigma ID** | `674202d0-b22a-4af4-ae5f-2eda1f3da1af` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.010 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.yml)**

> Bypasses User Account Control using Event Viewer and a relevant Windows Registry modification

```sql
-- ============================================================
-- Title:        Bypass UAC Using Event Viewer
-- Sigma ID:     674202d0-b22a-4af4-ae5f-2eda1f3da1af
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.010
-- Author:       frack113
-- Date:         2022-01-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\_Classes\\mscfile\\shell\\open\\command\\(Default)')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '\%SystemRoot\%\\system32\\mmc.exe "\%1" \%%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-1---bypass-uac-using-event-viewer-cmd

---

## Bypass UAC Using SilentCleanup Task

| Field | Value |
|---|---|
| **Sigma ID** | `724ea201-6514-4f38-9739-e5973c34f49a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | frack113, Nextron Systems |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task.yml)**

> Detects the setting of the environement variable "windir" to a non default value.
Attackers often abuse this variable in order to trigger a UAC bypass via the "SilentCleanup" task.
The SilentCleanup task located in %windir%\system32\cleanmgr.exe is an auto-elevated task that can be abused to elevate any file with administrator privileges without prompting UAC.


```sql
-- ============================================================
-- Title:        Bypass UAC Using SilentCleanup Task
-- Sigma ID:     724ea201-6514-4f38-9739-e5973c34f49a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       frack113, Nextron Systems
-- Date:         2022-01-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Environment\\windir')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-9---bypass-uac-using-silentcleanup-task
- https://www.reddit.com/r/hacking/comments/ajtrws/bypassing_highest_uac_level_windows_810/
- https://www.fortinet.com/blog/threat-research/enter-the-darkgate-new-cryptocurrency-mining-and-ransomware-campaign

---

## Default RDP Port Changed to Non Standard Port

| Field | Value |
|---|---|
| **Sigma ID** | `509e84b9-a71a-40e0-834f-05470369bd1e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.010 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_rdp_port.yml)**

> Detects changes to the default RDP port.
Remote desktop is a common feature in operating systems. It allows a user to log into a remote system using an interactive session with a graphical user interface.
Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).


```sql
-- ============================================================
-- Title:        Default RDP Port Changed to Non Standard Port
-- Sigma ID:     509e84b9-a71a-40e0-834f-05470369bd1e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.010
-- Author:       frack113
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_rdp_port.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.001/T1021.001.md

---

## IE Change Domain Zone

| Field | Value |
|---|---|
| **Sigma ID** | `45e112d0-7759-4c2a-aa36-9f8fb79d3393` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_security_zones.yml)**

> Hides the file extension through modification of the registry

```sql
-- ============================================================
-- Title:        IE Change Domain Zone
-- Sigma ID:     45e112d0-7759-4c2a-aa36-9f8fb79d3393
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1137
-- Author:       frack113
-- Date:         2022-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_security_zones.yml
-- Unmapped:     (none)
-- False Pos:    Administrative scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('DWORD (0x00000000)', 'DWORD (0x00000001)', '(Empty)'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
- https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries

---

## Sysmon Driver Altitude Change

| Field | Value |
|---|---|
| **Sigma ID** | `4916a35e-bfc4-47d0-8e25-a003d7067061` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | B.Talebi |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_sysmon_driver_altitude.yml)**

> Detects changes in Sysmon driver altitude value.
If the Sysmon driver is configured to load at an altitude of another registered service, it will fail to load at boot.


```sql
-- ============================================================
-- Title:        Sysmon Driver Altitude Change
-- Sigma ID:     4916a35e-bfc4-47d0-8e25-a003d7067061
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       B.Talebi
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_sysmon_driver_altitude.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate driver altitude change to hide sysmon
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Instances\\Sysmon Instance\\Altitude'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate driver altitude change to hide sysmon

**References:**
- https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650
- https://youtu.be/zSihR3lTf7g

---

## Change Winevt Channel Access Permission Via Registry

| Field | Value |
|---|---|
| **Sigma ID** | `7d9263bd-dc47-4a58-bc92-5474abab390c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_winevt_channelaccess.yml)**

> Detects tampering with the "ChannelAccess" registry key in order to change access to Windows event channel.

```sql
-- ============================================================
-- Title:        Change Winevt Channel Access Permission Via Registry
-- Sigma ID:     7d9263bd-dc47-4a58-bc92-5474abab390c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       frack113
-- Date:         2022-09-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_change_winevt_channelaccess.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ChannelAccess')
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%(A;;0x1;;;LA)%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%(A;;0x1;;;SY)%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%(A;;0x5;;;BA)%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://app.any.run/tasks/77b2e328-8f36-46b2-b2e2-8a80398217ab/
- https://learn.microsoft.com/en-us/windows/win32/api/winevt/
- https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/

---

## Running Chrome VPN Extensions via the Registry 2 VPN Extension

| Field | Value |
|---|---|
| **Sigma ID** | `b64a026b-8deb-4c1d-92fd-98893209dff1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_chrome_extension.yml)**

> Running Chrome VPN Extensions via the Registry install 2 vpn extension

```sql
-- ============================================================
-- Title:        Running Chrome VPN Extensions via the Registry 2 VPN Extension
-- Sigma ID:     b64a026b-8deb-4c1d-92fd-98893209dff1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Wow6432Node\\Google\\Chrome\\Extensions%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%update\_url'))
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%fdcgdnkidjaadafnichfpabhfomcebme%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%fcfhplploccackoneaefokcmbjfbkenj%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bihmplhobchoageeokmgbdihknkjbknd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%gkojfkhlekighikafcpjkiklfbnlmeio%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jajilbjjinjmgcibalaakngmkilboobh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%gjknjjomckknofjidppipffbpoekiipm%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%nabbmpekekjknlbkgpodfndbodhijjem%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%kpiecbcckbofpmkkkdibbllpinceiihk%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%nlbejmccbhkncgokjcmghpfloaajcffj%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%omghfjlpggmjjaagoclmmobgdodcjboh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bibjcjfmgapbfoljiojpipaooddpkpai%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%mpcaainmfjjigeicjnlkdfajbioopjko%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jljopmgdobloagejpohpldgkiellmfnc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%lochiccbgeohimldjooaakjllnafhaid%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%nhnfcgpcbfclhfafjlooihdfghaeinfc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ookhnhpkphagefgdiemllfajmkdkcaim%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%namfblliamklmeodpcelkokjbffgmeoo%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%nbcojefnccbanplpoffopkoepjmhgdgh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%majdfhpaihoncoakbjgbdhglocklcgno%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%lnfdmdhmfbimhhpaeocncdlhiodoblbd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%eppiocemhmnlbhjplcgkofciiegomcon%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%cocfojppfigjeefejbpfmedgjbpchcng%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%foiopecknacmiihiocgdjgbjokkpkohc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%hhdobjgopfphlmjbmnpglhfcgppchgje%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jgbaghohigdbgbolncodkdlpenhcmcge%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%inligpkjkhbpifecbdjhmdpcfhnlelja%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%higioemojdadgdbhbbbkfbebbdlfjbip%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%hipncndjamdcmphkgngojegjblibadbe%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%iolonopooapdagdemdoaihahlfkncfgg%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%nhfjkakglbnnpkpldhjmpmmfefifedcj%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jpgljfpmoofbmlieejglhonfofmahini%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%fgddmllnllkalaagkghckoinaemmogpe%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ejkaocphofnobjdedneohbbiilggdlbi%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%keodbianoliadkoelloecbhllnpiocoi%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%hoapmlpnmpaehilehggglehfdlnoegck%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%poeojclicodamonabcabmapamjkkmnnk%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%dfkdflfgjdajbhocmfjolpjbebdkcjog%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%kcdahmgmaagjhocpipbodaokikjkampi%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%klnkiajpmpkkkgpgbogmcgfjhdoljacg%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%lneaocagcijjdpkcabeanfpdbmapcjjg%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%pgfpignfckbloagkfnamnolkeaecfgfh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jplnlifepflhkbkgonidnobkakhmpnmh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jliodmnojccaloajphkingdnpljdhdok%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%hnmpcagpplmpfojmgmnngilcnanddlhb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ffbkglfijbcbgblgflchnbphjdllaogb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%kcndmbbelllkmioekdagahekgimemejo%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jdgilggpfmjpbodmhndmhojklgfdlhob%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bihhflimonbpcfagfadcnbbdngpopnjb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ppajinakbfocjfnijggfndbdmjggcmde%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%oofgbpoabipfcfjapgnbbjjaenockbdp%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bhnhkdgoefpmekcgnccpnhjfdgicfebm%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%knmmpciebaoojcpjjoeonlcjacjopcpf%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%dhadilbmmjiooceioladdphemaliiobo%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jedieiamjmoflcknjdjhpieklepfglin%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%mhngpdlhojliikfknhfaglpnddniijfh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%omdakjcmkglenbhjadbccaookpfjihpa%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%npgimkapccfidfkfoklhpkgmhgfejhbj%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%akeehkgglkmpapdnanoochpfmeghfdln%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%gbmdmipapolaohpinhblmcnpmmlgfgje%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%aigmfoeogfnljhnofglledbhhfegannp%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%cgojmfochfikphincbhokimmmjenhhgk%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ficajfeojakddincjafebjmfiefcmanc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ifnaibldjfdmaipaddffmgcmekjhiloa%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%jbnmpdkcfkochpanomnkhnafobppmccn%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%apcfdffemoinopelidncddjbhkiblecc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%mjolnodfokkkaichkcjipfgblbfgojpa%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%oifjbnnafapeiknapihcmpeodaeblbkn%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%plpmggfglncceinmilojdkiijhmajkjh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%mjnbclmflcpookeapghfhapeffmpodij%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bblcccknbdbplgmdjnnikffefhdlobhp%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%aojlhgbkmkahabcmcpifbolnoichfeep%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%lcmammnjlbmlbcaniggmlejfjpjagiia%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%knajdeaocbpmfghhmijicidfcmdgbdpm%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bdlcnpceagnkjnjlbbbcepohejbheilk%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%edknjdjielmpdlnllkdmaghlbpnmjmgb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%eidnihaadmmancegllknfbliaijfmkgo%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ckiahbcmlmkpfiijecbpflfahoimklke%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%macdlemfnignjhclfcfichcdhiomgjjb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%chioafkonnhbpajpengbalkececleldf%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%amnoibeflfphhplmckdbiajkjaoomgnj%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%llbhddikeonkpbhpncnhialfbpnilcnc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%pcienlhnoficegnepejpfiklggkioccm%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%iocnglnmfkgfedpcemdflhkchokkfeii%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%igahhbkcppaollcjeaaoapkijbnphfhb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%njpmifchgidinihmijhcfpbdmglecdlb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ggackgngljinccllcmbgnpgpllcjepgc%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%kchocjcihdgkoplngjemhpplmmloanja%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bnijmipndnicefcdbhgcjoognndbgkep%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%lklekjodgannjcccdlbicoamibgbdnmi%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%dbdbnchagbkhknegmhgikkleoogjcfge%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%egblhcjfjmbjajhjhpmnlekffgaemgfh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ehbhfpfdkmhcpaehaooegfdflljcnfec%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bkkgdjpomdnfemhhkalfkogckjdkcjkg%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%almalgbpmcfpdaopimbdchdliminoign%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%akkbkhnikoeojlhiiomohpdnkhbkhieh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%gbfgfbopcfokdpkdigfmoeaajfmpkbnh%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bniikohfmajhdcffljgfeiklcbgffppl%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%lejgfmmlngaigdmmikblappdafcmkndb%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ffhhkmlgedgcliajaedapkdfigdobcif%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%gcknhkkoolaabfmlnjonogaaifnjlfnp%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%pooljnboifbodgifngpppfklhifechoe%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%fjoaledfpmneenckfbpdfhkmimnjocfa%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%aakchaleigkohafkfjfjbblobjifikek%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%dpplabbmogkhghncfbfdeeokoefdjegm%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%padekgcemlokbadohgkifijomclgjgif%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%bfidboloedlamgdmenmlbipfnccokknp%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1133/T1133.md#atomic-test-1---running-chrome-vpn-extensions-via-the-registry-2-vpn-extension

---

## ClickOnce Trust Prompt Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `ac9159cc-c364-4304-8f0a-d63fc1a0aabb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | @SerkinValery, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_clickonce_trust_prompt.yml)**

> Detects changes to the ClickOnce trust prompt registry key in order to enable an installation from different locations such as the Internet.

```sql
-- ============================================================
-- Title:        ClickOnce Trust Prompt Tampering
-- Sigma ID:     ac9159cc-c364-4304-8f0a-d63fc1a0aabb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       @SerkinValery, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_clickonce_trust_prompt.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate internal requirements.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Internet' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\LocalIntranet' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\MyComputer' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\TrustedSites' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\UntrustedSites'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'Enabled'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate internal requirements.

**References:**
- https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
- https://learn.microsoft.com/en-us/visualstudio/deployment/how-to-configure-the-clickonce-trust-prompt-behavior

---

## Potential CobaltStrike Service Installations - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `61a7697c-cb79-42a8-a2ff-5f0cdfae0130` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1021.002, T1543.003, T1569.002 |
| **Author** | Wojciech Lesicki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml)**

> Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.


```sql
-- ============================================================
-- Title:        Potential CobaltStrike Service Installations - Registry
-- Sigma ID:     61a7697c-cb79-42a8-a2ff-5f0cdfae0130
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1021.002, T1543.003, T1569.002
-- Author:       Wojciech Lesicki
-- Date:         2021-06-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%ADMIN$%' AND metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.exe%'))
  OR (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%COMSPEC\%%' AND metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%start%' AND metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%powershell%'))
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\System\\CurrentControlSet\\Services%'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\System\\ControlSet%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395

---

## COM Hijack via Sdclt

| Field | Value |
|---|---|
| **Sigma ID** | `07743f65-7ec9-404a-a519-913db7118a8d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546, T1548 |
| **Author** | Omkar Gudhate |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_comhijack_sdclt.yml)**

> Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'

```sql
-- ============================================================
-- Title:        COM Hijack via Sdclt
-- Sigma ID:     07743f65-7ec9-404a-a519-913db7118a8d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546, T1548
-- Author:       Omkar Gudhate
-- Date:         2020-09-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_comhijack_sdclt.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Classes\\Folder\\shell\\open\\command\\DelegateExecute%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
- https://www.exploit-db.com/exploits/47696

---

## CrashControl CrashDump Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `2ff692c2-4594-41ec-8fcb-46587de769e0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1564, T1112 |
| **Author** | Tobias Michalski (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_crashdump_disabled.yml)**

> Detects disabling the CrashDump per registry (as used by HermeticWiper)

```sql
-- ============================================================
-- Title:        CrashControl CrashDump Disabled
-- Sigma ID:     2ff692c2-4594-41ec-8fcb-46587de769e0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1564, T1112
-- Author:       Tobias Michalski (Nextron Systems)
-- Date:         2022-02-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_crashdump_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate disabling of crashdumps
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SYSTEM\\CurrentControlSet\\Control\\CrashControl%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate disabling of crashdumps

**References:**
- https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/

---

## Security Event Logging Disabled via MiniNt Registry Key - Registry Set

| Field | Value |
|---|---|
| **Sigma ID** | `8839e550-52d7-4958-9f2f-e13c1e736838` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1562.002, T1112 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_create_minint_key.yml)**

> Detects the addition of the 'MiniNt' key to the registry. Upon a reboot, Windows Event Log service will stop writing events.
Windows Event Log is a service that collects and stores event logs from the operating system and applications. It is an important component of Windows security and auditing.
Adversary may want to disable this service to disable logging of security events which could be used to detect their activities.


```sql
-- ============================================================
-- Title:        Security Event Logging Disabled via MiniNt Registry Key - Registry Set
-- Sigma ID:     8839e550-52d7-4958-9f2f-e13c1e736838
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1562.002, T1112
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-04-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_create_minint_key.yml
-- Unmapped:     (none)
-- False Pos:    Highly Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] = 'HKLM\System\CurrentControlSet\Control\MiniNt\(Default)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Highly Unlikely

**References:**
- https://www.hackingarticles.in/defense-evasion-windows-event-logging-t1562-002/

---

## Service Binary in Suspicious Folder

| Field | Value |
|---|---|
| **Sigma ID** | `a07f0359-4c90-4dc4-a681-8ffea40b4f47` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Florian Roth (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_creation_service_susp_folder.yml)**

> Detect the creation of a service with a service binary located in a suspicious directory

```sql
-- ============================================================
-- Title:        Service Binary in Suspicious Folder
-- Sigma ID:     a07f0359-4c90-4dc4-a681-8ffea40b4f47
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Florian Roth (Nextron Systems), frack113
-- Date:         2022-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_creation_service_susp_folder.yml
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
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

---

## Windows Credential Guard Disabled - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `73921b9c-cafd-4446-b0c6-fdb0ace42bc0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_credential_guard_disabled.yml)**

> Detects attempts to disable Windows Credential Guard by setting registry values to 0. Credential Guard uses virtualization-based security to isolate secrets so that only privileged system software can access them.
Adversaries may disable Credential Guard to gain access to sensitive credentials stored in the system, such as NTLM hashes and Kerberos tickets, which can be used for lateral movement and privilege escalation.


```sql
-- ============================================================
-- Title:        Windows Credential Guard Disabled - Registry
-- Sigma ID:     73921b9c-cafd-4446-b0c6-fdb0ace42bc0
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-12-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_credential_guard_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DeviceGuard\\EnableVirtualizationBasedSecurity' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DeviceGuard\\LsaCfgFlags' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Lsa\\LsaCfgFlags'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://woshub.com/disable-credential-guard-windows/

---

## Custom File Open Handler Executes PowerShell

| Field | Value |
|---|---|
| **Sigma ID** | `7530b96f-ad8e-431d-a04d-ac85cc461fdc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1202 |
| **Author** | CD_R0M_ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_custom_file_open_handler_powershell_execution.yml)**

> Detects the abuse of custom file open handler, executing powershell

```sql
-- ============================================================
-- Title:        Custom File Open Handler Executes PowerShell
-- Sigma ID:     7530b96f-ad8e-431d-a04d-ac85cc461fdc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1202
-- Author:       CD_R0M_
-- Date:         2022-06-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_custom_file_open_handler_powershell_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%shell\\open\\command\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%powershell%' AND metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%-command%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://news.sophos.com/en-us/2022/02/01/solarmarker-campaign-used-novel-registry-changes-to-establish-persistence/?cmp=30728

---

## Potential Registry Persistence Attempt Via DbgManagedDebugger

| Field | Value |
|---|---|
| **Sigma ID** | `9827ae57-3802-418f-994b-d5ecf5cd974b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dbgmanageddebugger_persistence.yml)**

> Detects the addition of the "Debugger" value to the "DbgManagedDebugger" key in order to achieve persistence. Which will get invoked when an application crashes

```sql
-- ============================================================
-- Title:        Potential Registry Persistence Attempt Via DbgManagedDebugger
-- Sigma ID:     9827ae57-3802-418f-994b-d5ecf5cd974b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574
-- Author:       frack113
-- Date:         2022-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dbgmanageddebugger_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the key to setup a debugger. Which is often the case on developers machines
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\.NETFramework\\DbgManagedDebugger')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '"C:\Windows\system32\vsjitdebugger.exe" PID %d APPDOM %d EXTEXT "%s" EVTHDL %d')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the key to setup a debugger. Which is often the case on developers machines

**References:**
- https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/
- https://github.com/last-byte/PersistenceSniper

---

## Windows Defender Exclusions Added - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `a982fc9c-6333-4ffb-a51d-addb04e8b529` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_defender_exclusions.yml)**

> Detects the Setting of Windows Defender Exclusions

```sql
-- ============================================================
-- Title:        Windows Defender Exclusions Added - Registry
-- Sigma ID:     a982fc9c-6333-4ffb-a51d-addb04e8b529
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-07-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_defender_exclusions.yml
-- Unmapped:     (none)
-- False Pos:    Administrator actions
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows Defender\\Exclusions%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions

**References:**
- https://twitter.com/_nullbind/status/1204923340810543109

---

## Potentially Suspicious Desktop Background Change Via Registry

| Field | Value |
|---|---|
| **Sigma ID** | `85b88e05-dadc-430b-8a9e-53ff1cd30aae` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, impact |
| **MITRE Techniques** | T1112, T1491.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Stephen Lincoln @slincoln-aiq (AttackIQ) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_desktop_background_change.yml)**

> Detects registry value settings that would replace the user's desktop background.
This is a common technique used by malware to change the desktop background to a ransom note or other image.


```sql
-- ============================================================
-- Title:        Potentially Suspicious Desktop Background Change Via Registry
-- Sigma ID:     85b88e05-dadc-430b-8a9e-53ff1cd30aae
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, impact | T1112, T1491.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Stephen Lincoln @slincoln-aiq (AttackIQ)
-- Date:         2023-12-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_desktop_background_change.yml
-- Unmapped:     (none)
-- False Pos:    Administrative scripts that change the desktop background to a company logo or other image.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Control Panel\\Desktop%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%CurrentVersion\\Policies\\ActiveDesktop%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%CurrentVersion\\Policies\\System%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts that change the desktop background to a company logo or other image.

**References:**
- https://www.attackiq.com/2023/09/20/emulating-rhysida/
- https://research.checkpoint.com/2023/the-rhysida-ransomware-activity-analysis-and-ties-to-vice-society/
- https://www.trendmicro.com/en_us/research/23/h/an-overview-of-the-new-rhysida-ransomware.html
- https://www.virustotal.com/gui/file/a864282fea5a536510ae86c77ce46f7827687783628e4f2ceb5bf2c41b8cd3c6/behavior
- https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsDesktop::Wallpaper
- https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.ControlPanelDisplay::CPL_Personalization_NoDesktopBackgroundUI

---

## Antivirus Filter Driver Disallowed On Dev Drive - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `31e124fb-5dc4-42a0-83b3-44a69c77b271` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | @kostastsale, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_devdrv_disallow_antivirus_filter.yml)**

> Detects activity that indicates a user disabling the ability for Antivirus mini filter to inspect a "Dev Drive".


```sql
-- ============================================================
-- Title:        Antivirus Filter Driver Disallowed On Dev Drive - Registry
-- Sigma ID:     31e124fb-5dc4-42a0-83b3-44a69c77b271
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       @kostastsale, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-11-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_devdrv_disallow_antivirus_filter.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\FilterManager\\FltmgrDevDriveAllowAntivirusFilter')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/0gtweet/status/1720419490519752955

---

## Windows Hypervisor Enforced Code Integrity Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `8b7273a4-ba5d-4d8a-b04f-11f2900d043a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Anish Bogati |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedcodeintegrity_disabled.yml)**

> Detects changes to the HypervisorEnforcedCodeIntegrity registry key and the "Enabled" value being set to 0 in order to disable the Hypervisor Enforced Code Integrity feature. This allows an attacker to load unsigned and untrusted code to be run in the kernel


```sql
-- ============================================================
-- Title:        Windows Hypervisor Enforced Code Integrity Disabled
-- Sigma ID:     8b7273a4-ba5d-4d8a-b04f-11f2900d043a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), Anish Bogati
-- Date:         2023-03-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedcodeintegrity_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate system administration tasks that require disabling HVCI for troubleshooting purposes when certain drivers or applications are incompatible with it.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\DeviceGuard\\HypervisorEnforcedCodeIntegrity' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\DeviceGuard\\HypervisorEnforcedCodeIntegrity'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate system administration tasks that require disabling HVCI for troubleshooting purposes when certain drivers or applications are incompatible with it.

**References:**
- https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/
- https://github.com/redcanaryco/atomic-red-team/blob/04e487c1828d76df3e834621f4f893ea756d5232/atomics/T1562.001/T1562.001.md#atomic-test-43---disable-hypervisor-enforced-code-integrity-hvci

---

## Hypervisor Enforced Paging Translation Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `7f2954d2-99c2-4d42-a065-ca36740f187b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedpagingtranslation_disabled.yml)**

> Detects changes to the "DisableHypervisorEnforcedPagingTranslation" registry value. Where the it is set to "1" in order to disable the Hypervisor Enforced Paging Translation feature.


```sql
-- ============================================================
-- Title:        Hypervisor Enforced Paging Translation Disabled
-- Sigma ID:     7f2954d2-99c2-4d42-a065-ca36740f187b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedpagingtranslation_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DisableHypervisorEnforcedPagingTranslation')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/standa_t/status/1808868985678803222
- https://github.com/AaLl86/WindowsInternals/blob/070dc4f317726dfb6ffd2b7a7c121a33a8659b5e/Slides/Hypervisor-enforced%20Paging%20Translation%20-%20The%20end%20of%20non%20data-driven%20Kernel%20Exploits%20(Recon2024).pdf

---

## DHCP Callout DLL Installation

| Field | Value |
|---|---|
| **Sigma ID** | `9d3436ef-9476-4c43-acca-90ce06bdf33a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001, T1112 |
| **Author** | Dimitrios Slamaris |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dhcp_calloutdll.yml)**

> Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)

```sql
-- ============================================================
-- Title:        DHCP Callout DLL Installation
-- Sigma ID:     9d3436ef-9476-4c43-acca-90ce06bdf33a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001, T1112
-- Author:       Dimitrios Slamaris
-- Date:         2017-05-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dhcp_calloutdll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\DHCPServer\\Parameters\\CalloutDlls' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\DHCPServer\\Parameters\\CalloutEnabled'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
- https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
- https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx

---

## Disable Administrative Share Creation at Startup

| Field | Value |
|---|---|
| **Sigma ID** | `c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.005 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_administrative_share.yml)**

> Administrative shares are hidden network shares created by Microsoft Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system

```sql
-- ============================================================
-- Title:        Disable Administrative Share Creation at Startup
-- Sigma ID:     c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.005
-- Author:       frack113
-- Date:         2022-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_administrative_share.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\LanmanServer\\Parameters\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AutoShareWks' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AutoShareServer'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md#atomic-test-4---disable-administrative-share-creation-at-startup

---

## Potential AutoLogger Sessions Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `f37b4bce-49d0-4087-9f5b-58bffda77316` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_autologger_sessions.yml)**

> Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging

```sql
-- ============================================================
-- Title:        Potential AutoLogger Sessions Tampering
-- Sigma ID:     f37b4bce-49d0-4087-9f5b-58bffda77316
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_autologger_sessions.yml
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
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/MichalKoczwara/status/1553634816016498688
- https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
- https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf

---

## Disable Microsoft Defender Firewall via Registry

| Field | Value |
|---|---|
| **Sigma ID** | `974515da-6cc5-4c95-ae65-f97f9150ec7f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_defender_firewall.yml)**

> Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage

```sql
-- ============================================================
-- Title:        Disable Microsoft Defender Firewall via Registry
-- Sigma ID:     974515da-6cc5-4c95-ae65-f97f9150ec7f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2022-01-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_defender_firewall.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\EnableFirewall')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md#atomic-test-2---disable-microsoft-defender-firewall-via-registry

---

## Disable Internal Tools or Feature in Registry

| Field | Value |
|---|---|
| **Sigma ID** | `e2482f8d-3443-4237-b906-cc145d87a076` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems), CrimpSec |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_function_user.yml)**

> Detects registry modifications that change features of internal Windows tools (malware like Agent Tesla uses this technique)

```sql
-- ============================================================
-- Title:        Disable Internal Tools or Feature in Registry
-- Sigma ID:     e2482f8d-3443-4237-b906-cc145d87a076
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems), CrimpSec
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_function_user.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\shutdownwithoutlogon' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\ToastEnabled' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SYSTEM\\CurrentControlSet\\Control\\Storage\\Write Protection' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
  OR ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisableCMD' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\StartMenuLogOff' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableChangePassword' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableLockWorkstation' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskmgr' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\NoDispBackgroundPage' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\NoDispCPL' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\DisableNotificationCenter' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Policies\\Microsoft\\Windows\\System\\DisableCMD'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md
- https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions
- https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
- https://www.malwarebytes.com/blog/detections/pum-optional-nodispbackgroundpage
- https://www.malwarebytes.com/blog/detections/pum-optional-nodispcpl
- https://bazaar.abuse.ch/sample/7bde840c7e8c36dce4c3bac937bcf39f36a6f118001b406bfbbc25451ce44fb4/

---

## Disable Macro Runtime Scan Scope

| Field | Value |
|---|---|
| **Sigma ID** | `ab871450-37dc-4a3a-997f-6662aa8ae0f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_macroruntimescanscope.yml)**

> Detects tampering with the MacroRuntimeScanScope registry key to disable runtime scanning of enabled macros

```sql
-- ============================================================
-- Title:        Disable Macro Runtime Scan Scope
-- Sigma ID:     ab871450-37dc-4a3a-997f-6662aa8ae0f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_macroruntimescanscope.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Office\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Common\\Security%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\MacroRuntimeScanScope')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.microsoft.com/en-us/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/
- https://admx.help/?Category=Office2016&Policy=office16.Office.Microsoft.Policies.Windows::L_MacroRuntimeScanScope
- https://github.com/S3cur3Th1sSh1t/OffensiveVBA/blob/28cc6a2802d8176195ac19b3c8e9a749009a82a3/src/AMSIbypasses.vba

---

## Disable Privacy Settings Experience in Registry

| Field | Value |
|---|---|
| **Sigma ID** | `0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_privacy_settings_experience.yml)**

> Detects registry modifications that disable Privacy Settings Experience

```sql
-- ============================================================
-- Title:        Disable Privacy Settings Experience in Registry
-- Sigma ID:     0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       frack113
-- Date:         2022-10-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_privacy_settings_experience.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows\\OOBE\\DisablePrivacyExperience')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1562.001/T1562.001.md

---

## Disable Windows Security Center Notifications

| Field | Value |
|---|---|
| **Sigma ID** | `3ae1a046-f7db-439d-b7ce-b8b366b81fa6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_security_center_notifications.yml)**

> Detect set UseActionCenterExperience to 0 to disable the Windows security center notification

```sql
-- ============================================================
-- Title:        Disable Windows Security Center Notifications
-- Sigma ID:     3ae1a046-f7db-439d-b7ce-b8b366b81fa6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_security_center_notifications.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Windows\\CurrentVersion\\ImmersiveShell\\UseActionCenterExperience')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

---

## Registry Disable System Restore

| Field | Value |
|---|---|
| **Sigma ID** | `5de03871-5d46-4539-a82d-3aa992a69a83` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_system_restore.yml)**

> Detects the modification of the registry to disable a system restore on the computer

```sql
-- ============================================================
-- Title:        Registry Disable System Restore
-- Sigma ID:     5de03871-5d46-4539-a82d-3aa992a69a83
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       frack113
-- Date:         2022-04-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_system_restore.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Policies\\Microsoft\\Windows NT\\SystemRestore%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore%'))
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%DisableConfig' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%DisableSR'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry

---

## Windows Defender Service Disabled - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `e1aa95de-610a-427d-b9e7-9b46cfafbe6a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Ján Trenčanský, frack113, AlertIQ, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_defender_service.yml)**

> Detects when an attacker or tool disables the  Windows Defender service (WinDefend) via the registry

```sql
-- ============================================================
-- Title:        Windows Defender Service Disabled - Registry
-- Sigma ID:     e1aa95de-610a-427d-b9e7-9b46cfafbe6a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Ján Trenčanský, frack113, AlertIQ, Nasreddine Bencherchali
-- Date:         2022-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_defender_service.yml
-- Unmapped:     (none)
-- False Pos:    Administrator actions
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\WinDefend\\Start')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000004)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions

**References:**
- https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
- https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105

---

## Windows Event Log Access Tampering Via Registry

| Field | Value |
|---|---|
| **Sigma ID** | `ba226dcf-d390-4642-b9af-b534872f1156` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001, T1112 |
| **Author** | X__Junior |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_event_log_access.yml)**

> Detects changes to the Windows EventLog channel permission values. It focuses on changes to the Security Descriptor Definition Language (SDDL) string, as modifications to these values can restrict access to specific users or groups, potentially aiding in defense evasion by controlling who can view or modify a event log channel. Upon execution, the user shouldn't be able to access the event log channel via the event viewer or via utilities such as "Get-EventLog" or "wevtutil".


```sql
-- ============================================================
-- Title:        Windows Event Log Access Tampering Via Registry
-- Sigma ID:     ba226dcf-d390-4642-b9af-b534872f1156
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1547.001, T1112
-- Author:       X__Junior
-- Date:         2025-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_event_log_access.yml
-- Unmapped:     (none)
-- False Pos:    Administrative activity, still unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%D:(D;%'))
  OR (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%D:(%' AND metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%)(D;%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative activity, still unlikely

**References:**
- https://www.atomicredteam.io/atomic-red-team/atomics/T1562.002#atomic-test-8---modify-event-log-channel-access-permissions-via-registry---powershell
- https://www.youtube.com/watch?v=uSYvHUVU8xY
- https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language

---

## Disable Windows Firewall by Registry

| Field | Value |
|---|---|
| **Sigma ID** | `e78c408a-e2ea-43cd-b5ea-51975cf358c0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_firewall.yml)**

> Detect set EnableFirewall to 0 to disable the Windows firewall

```sql
-- ============================================================
-- Title:        Disable Windows Firewall by Registry
-- Sigma ID:     e78c408a-e2ea-43cd-b5ea-51975cf358c0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       frack113
-- Date:         2022-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_firewall.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile\\EnableFirewall' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\EnableFirewall'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1562.004/T1562.004.md

---

## Disable Windows Event Logging Via Registry

| Field | Value |
|---|---|
| **Sigma ID** | `2f78da12-f7c7-430b-8b19-a28f269b77a3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_winevt_logging.yml)**

> Detects tampering with the "Enabled" registry key in order to disable Windows logging of a Windows event channel

```sql
-- ============================================================
-- Title:        Disable Windows Event Logging Via Registry
-- Sigma ID:     2f78da12-f7c7-430b-8b19-a28f269b77a3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_winevt_logging.yml
-- Unmapped:     (none)
-- False Pos:    Rare falsepositives may occur from legitimate administrators disabling specific event log for troubleshooting
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Enabled')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare falsepositives may occur from legitimate administrators disabling specific event log for troubleshooting

**References:**
- https://twitter.com/WhichbufferArda/status/1543900539280293889
- https://github.com/DebugPrivilege/CPP/blob/c39d365617dbfbcb01fffad200d52b6239b2918c/Windows%20Defender/RestoreDefenderConfig.cpp

---

## Disable Exploit Guard Network Protection on Windows Defender

| Field | Value |
|---|---|
| **Sigma ID** | `bf9e1387-b040-4393-9851-1598f8ecfae9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_exploit_guard_net_protection_on_ms_defender.yml)**

> Detects disabling Windows Defender Exploit Guard Network Protection

```sql
-- ============================================================
-- Title:        Disable Exploit Guard Network Protection on Windows Defender
-- Sigma ID:     bf9e1387-b040-4393-9851-1598f8ecfae9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_exploit_guard_net_protection_on_ms_defender.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection\\DisallowExploitProtectionOverride%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.html

---

## Disabled Windows Defender Eventlog

| Field | Value |
|---|---|
| **Sigma ID** | `fcddca7c-b9c0-4ddf-98da-e1e2d18b0157` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_microsoft_defender_eventlog.yml)**

> Detects the disabling of the Windows Defender eventlog as seen in relation to Lockbit 3.0 infections

```sql
-- ============================================================
-- Title:        Disabled Windows Defender Eventlog
-- Sigma ID:     fcddca7c-b9c0-4ddf-98da-e1e2d18b0157
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-07-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_microsoft_defender_eventlog.yml
-- Unmapped:     (none)
-- False Pos:    Other Antivirus software installations could cause Windows to disable that eventlog (unknown)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/Operational\\Enabled%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other Antivirus software installations could cause Windows to disable that eventlog (unknown)

**References:**
- https://twitter.com/WhichbufferArda/status/1543900539280293889/photo/2

---

## Disable PUA Protection on Windows Defender

| Field | Value |
|---|---|
| **Sigma ID** | `8ffc5407-52e3-478f-9596-0a7371eafe13` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_pua_protection_on_microsoft_defender.yml)**

> Detects disabling Windows Defender PUA protection

```sql
-- ============================================================
-- Title:        Disable PUA Protection on Windows Defender
-- Sigma ID:     8ffc5407-52e3-478f-9596-0a7371eafe13
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_pua_protection_on_microsoft_defender.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Policies\\Microsoft\\Windows Defender\\PUAProtection%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html

---

## Disable Tamper Protection on Windows Defender

| Field | Value |
|---|---|
| **Sigma ID** | `93d298a1-d28f-47f1-a468-d971e7796679` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_tamper_protection_on_microsoft_defender.yml)**

> Detects disabling Windows Defender Tamper Protection

```sql
-- ============================================================
-- Title:        Disable Tamper Protection on Windows Defender
-- Sigma ID:     93d298a1-d28f-47f1-a468-d971e7796679
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disabled_tamper_protection_on_microsoft_defender.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows Defender\\Features\\TamperProtection%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html

---

## Add DisallowRun Execution to Registry

| Field | Value |
|---|---|
| **Sigma ID** | `275641a5-a492-45e2-a817-7c81e9d9d3e9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disallowrun_execution.yml)**

> Detect set DisallowRun to 1 to prevent user running specific computer program

```sql
-- ============================================================
-- Title:        Add DisallowRun Execution to Registry
-- Sigma ID:     275641a5-a492-45e2-a817-7c81e9d9d3e9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disallowrun_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

---

## Persistence Via Disk Cleanup Handler - Autorun

| Field | Value |
|---|---|
| **Sigma ID** | `d4e2745c-f0c6-4bde-a3ab-b553b3f693cc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disk_cleanup_handler_autorun_persistence.yml)**

> Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence via autorun.
The disk cleanup manager is part of the operating system.
It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI.
Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications.
Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler.
Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler.


```sql
-- ============================================================
-- Title:        Persistence Via Disk Cleanup Handler - Autorun
-- Sigma ID:     d4e2745c-f0c6-4bde-a3ab-b553b3f693cc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disk_cleanup_handler_autorun_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://persistence-info.github.io/Data/diskcleanuphandler.html
- https://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/

---

## DNS-over-HTTPS Enabled by Registry

| Field | Value |
|---|---|
| **Sigma ID** | `04b45a8a-d11d-49e4-9acc-4a1b524407a5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1140, T1112 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.yml)**

> Detects when a user enables DNS-over-HTTPS.
This can be used to hide internet activity or be used to hide the process of exfiltrating data.
With this enabled organization will lose visibility into data such as query type, response and originating IP that are used to determine bad actors.


```sql
-- ============================================================
-- Title:        DNS-over-HTTPS Enabled by Registry
-- Sigma ID:     04b45a8a-d11d-49e4-9acc-4a1b524407a5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1140, T1112
-- Author:       Austin Songer
-- Date:         2021-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'secure'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS\\Enabled')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html
- https://github.com/elastic/detection-rules/issues/1371
- https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode
- https://admx.help/HKLM/Software/Policies/Mozilla/Firefox/DNSOverHTTPS

---

## New DNS ServerLevelPluginDll Installed

| Field | Value |
|---|---|
| **Sigma ID** | `e61e8a88-59a9-451c-874e-70fcc9740d67` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001, T1112 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dns_server_level_plugin_dll.yml)**

> Detects the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry, which can be used to execute code in context of the DNS server (restart required)

```sql
-- ============================================================
-- Title:        New DNS ServerLevelPluginDll Installed
-- Sigma ID:     e61e8a88-59a9-451c-874e-70fcc9740d67
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001, T1112
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-05-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dns_server_level_plugin_dll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\services\\DNS\\Parameters\\ServerLevelPluginDll')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
- https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html

---

## ETW Logging Disabled In .NET Processes - Sysmon Registry

| Field | Value |
|---|---|
| **Sigma ID** | `bf4fc428-dcc3-4bbd-99fe-2422aeee2544` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112, T1562 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dot_net_etw_tamper.yml)**

> Potential adversaries stopping ETW providers recording loaded .NET assemblies.

```sql
-- ============================================================
-- Title:        ETW Logging Disabled In .NET Processes - Sysmon Registry
-- Sigma ID:     bf4fc428-dcc3-4bbd-99fe-2422aeee2544
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112, T1562
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-06-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dot_net_etw_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\COMPlus\_ETWEnabled' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\COMPlus\_ETWFlags'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('0', 'DWORD (0x00000000)')))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\.NETFramework\\ETWEnabled')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/_xpn_/status/1268712093928378368
- https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
- https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
- https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
- https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
- https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
- https://bunnyinside.com/?term=f71e8cb9c76a
- http://managed670.rssing.com/chan-5590147/all_p1.html
- https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code
- https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/
- https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf

---

## Directory Service Restore Mode(DSRM) Registry Value Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `b61e87c0-50db-4b2e-8986-6a2be94b33b0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | Nischal Khadgi |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dsrm_tampering.yml)**

> Detects changes to "DsrmAdminLogonBehavior" registry value.
During a Domain Controller (DC) promotion, administrators create a Directory Services Restore Mode (DSRM) local administrator account with a password that rarely changes. The DSRM account is an “Administrator” account that logs in with the DSRM mode when the server is booting up to restore AD backups or recover the server from a failure.
Attackers could abuse DSRM account to maintain their persistence and access to the organization's Active Directory.
If the "DsrmAdminLogonBehavior" value is set to "0", the administrator account can only be used if the DC starts in DSRM.
If the "DsrmAdminLogonBehavior" value is set to "1", the administrator account can only be used if the local AD DS service is stopped.
If the "DsrmAdminLogonBehavior" value is set to "2", the administrator account can always be used.


```sql
-- ============================================================
-- Title:        Directory Service Restore Mode(DSRM) Registry Value Tampering
-- Sigma ID:     b61e87c0-50db-4b2e-8986-6a2be94b33b0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       Nischal Khadgi
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_dsrm_tampering.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Lsa\\DsrmAdminLogonBehavior')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://adsecurity.org/?p=1785
- https://www.sentinelone.com/blog/detecting-dsrm-account-misconfigurations/
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dsrm-credentials

---

## Periodic Backup For System Registry Hives Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `973ef012-8f1a-4c40-93b4-7e659a5cd17f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enable_periodic_backup.yml)**

> Detects the enabling of the "EnablePeriodicBackup" registry value. Once enabled, The OS will backup System registry hives on restarts to the "C:\Windows\System32\config\RegBack" folder. Windows creates a "RegIdleBackup" task to manage subsequent backups.
Registry backup was a default behavior on Windows and was disabled as of "Windows 10, version 1803".


```sql
-- ============================================================
-- Title:        Periodic Backup For System Registry Hives Enabled
-- Sigma ID:     973ef012-8f1a-4c40-93b4-7e659a5cd17f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-07-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enable_periodic_backup.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate need for RegBack feature by administrators.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Session Manager\\Configuration Manager\\EnablePeriodicBackup')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate need for RegBack feature by administrators.

**References:**
- https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder

---

## Windows Recall Feature Enabled - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `75180c5f-4ea1-461a-a4f6-6e4700c065d4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1113 |
| **Author** | Sajid Nawaz Khan |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enable_windows_recall.yml)**

> Detects the enabling of the Windows Recall feature via registry manipulation. Windows Recall can be enabled by setting the value of "DisableAIDataAnalysis" to "0".
Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities.
This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary.


```sql
-- ============================================================
-- Title:        Windows Recall Feature Enabled - Registry
-- Sigma ID:     75180c5f-4ea1-461a-a4f6-6e4700c065d4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1113
-- Author:       Sajid Nawaz Khan
-- Date:         2024-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enable_windows_recall.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use/activation of Windows Recall
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use/activation of Windows Recall

**References:**
- https://learn.microsoft.com/en-us/windows/client-management/manage-recall
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis

---

## Enabling COR Profiler Environment Variables

| Field | Value |
|---|---|
| **Sigma ID** | `ad89044a-8f49-4673-9a55-cbd88a1b374f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.012 |
| **Author** | Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research), Jimmy Bayne (@bohops) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enabling_cor_profiler_env_variables.yml)**

> Detects .NET Framework CLR and .NET Core CLR "cor_enable_profiling" and "cor_profiler" variables being set and configured.

```sql
-- ============================================================
-- Title:        Enabling COR Profiler Environment Variables
-- Sigma ID:     ad89044a-8f49-4673-9a55-cbd88a1b374f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1574.012
-- Author:       Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research), Jimmy Bayne (@bohops)
-- Date:         2020-09-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enabling_cor_profiler_env_variables.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\COR\_ENABLE\_PROFILING' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\COR\_PROFILER' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CORECLR\_ENABLE\_PROFILING'))
  OR indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CORECLR\_PROFILER\_PATH%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://twitter.com/jamieantisocial/status/1304520651248668673
- https://www.slideshare.net/JamieWilliams130/started-from-the-bottom-exploiting-data-sources-to-uncover-attck-behaviors
- https://www.sans.org/cyber-security-summit/archives
- https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling

---

## Scripted Diagnostics Turn Off Check Enabled - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `7d995e63-ec83-4aa3-89d5-8a17b5c87c86` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Christopher Peacock @securepeacock, SCYTHE @scythe_io |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enabling_turnoffcheck.yml)**

> Detects enabling TurnOffCheck which can be used to bypass defense of MSDT Follina vulnerability

```sql
-- ============================================================
-- Title:        Scripted Diagnostics Turn Off Check Enabled - Registry
-- Sigma ID:     7d995e63-ec83-4aa3-89d5-8a17b5c87c86
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Christopher Peacock @securepeacock, SCYTHE @scythe_io
-- Date:         2022-06-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enabling_turnoffcheck.yml
-- Unmapped:     (none)
-- False Pos:    Administrator actions
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics\\TurnOffCheck')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions

**References:**
- https://twitter.com/wdormann/status/1537075968568877057?s=20&t=0lr18OAnmAGoGpma6grLUw

---

## Potential EventLog File Location Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `0cb8d736-995d-4ce7-a31e-1e8d452a1459` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.002 |
| **Author** | D3F7A5105 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_evtx_file_key_tamper.yml)**

> Detects tampering with EventLog service "file" key. In order to change the default location of an Evtx file. This technique is used to tamper with log collection and alerting

```sql
-- ============================================================
-- Title:        Potential EventLog File Location Tampering
-- Sigma ID:     0cb8d736-995d-4ce7-a31e-1e8d452a1459
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.002
-- Author:       D3F7A5105
-- Date:         2023-01-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_evtx_file_key_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\File'))
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\System32\\Winevt\\Logs\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key

---

## Suspicious Application Allowed Through Exploit Guard

| Field | Value |
|---|---|
| **Sigma ID** | `42205c73-75c8-4a63-9db1-e3782e06fda0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_exploit_guard_susp_allowed_apps.yml)**

> Detects applications being added to the "allowed applications" list of exploit guard in order to bypass controlled folder settings

```sql
-- ============================================================
-- Title:        Suspicious Application Allowed Through Exploit Guard
-- Sigma ID:     42205c73-75c8-4a63-9db1-e3782e06fda0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_exploit_guard_susp_allowed_apps.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\AllowedApplications%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Desktop\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Windows\\Temp\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.microsoft.com/security/blog/2017/10/23/windows-defender-exploit-guard-reduce-the-attack-surface-against-next-generation-malware/

---

## Change User Account Associated with the FAX Service

| Field | Value |
|---|---|
| **Sigma ID** | `e3fdf743-f05b-4051-990a-b66919be1743` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_fax_change_service_user.yml)**

> Detect change of the user account associated with the FAX service to avoid the escalation problem.

```sql
-- ============================================================
-- Title:        Change User Account Associated with the FAX Service
-- Sigma ID:     e3fdf743-f05b-4051-990a-b66919be1743
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-07-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_fax_change_service_user.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] = 'HKLM\System\CurrentControlSet\Services\Fax\ObjectName')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%NetworkService%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/dottor_morte/status/1544652325570191361
- https://raw.githubusercontent.com/RiccardoAncarani/talks/master/F-Secure/unorthodox-lateral-movement.pdf

---

## Change the Fax Dll

| Field | Value |
|---|---|
| **Sigma ID** | `9e3357ba-09d4-4fbd-a7c5-ad6386314513` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_fax_dll_persistance.yml)**

> Detect possible persistence using Fax DLL load when service restart

```sql
-- ============================================================
-- Title:        Change the Fax Dll
-- Sigma ID:     9e3357ba-09d4-4fbd-a7c5-ad6386314513
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-07-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_fax_dll_persistance.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Fax\\Device Providers\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ImageName%')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '%systemroot%\system32\fxst30.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/dottor_morte/status/1544652325570191361
- https://raw.githubusercontent.com/RiccardoAncarani/talks/master/F-Secure/unorthodox-lateral-movement.pdf

---

## New File Association Using Exefile

| Field | Value |
|---|---|
| **Sigma ID** | `44a22d59-b175-4f13-8c16-cbaef5b581ff` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Andreas Hunkeler (@Karneades) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_file_association_exefile.yml)**

> Detects the abuse of the exefile handler in new file association. Used for bypass of security products.

```sql
-- ============================================================
-- Title:        New File Association Using Exefile
-- Sigma ID:     44a22d59-b175-4f13-8c16-cbaef5b581ff
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Andreas Hunkeler (@Karneades)
-- Date:         2021-11-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_file_association_exefile.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\.%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'exefile'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/mrd0x/status/1461041276514623491

---

## FileFix - Command Evidence in TypedPaths

| Field | Value |
|---|---|
| **Sigma ID** | `4fee3d51-8069-4a4c-a0f7-924fcaff2c70` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.004 |
| **Author** | Alfie Champion (delivr.to), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_filefix_typedpath_commands.yml)**

> Detects commonly-used chained commands and strings in the most recent 'url' value of the 'TypedPaths' key, which could be indicative of a user being targeted by the FileFix technique.


```sql
-- ============================================================
-- Title:        FileFix - Command Evidence in TypedPaths
-- Sigma ID:     4fee3d51-8069-4a4c-a0f7-924fcaff2c70
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1204.004
-- Author:       Alfie Champion (delivr.to), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_filefix_typedpath_commands.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%#%' AND metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%http%'))
  AND ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%account%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%anti-bot%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%botcheck%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%captcha%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%challenge%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%confirmation%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%fraud%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%human%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%identification%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%identificator%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%identity%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%robot%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%validation%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%verification%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%verify%')))
  OR ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%comspec\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%bitsadmin%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%certutil%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%cmd%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%cscript%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%curl%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%finger%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%mshta%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%powershell%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%pwsh%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%regsvr32%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%rundll32%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%schtasks%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%wget%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%wscript%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://x.com/russianpanda9xx/status/1940831134759506029
- https://mrd0x.com/filefix-clickfix-alternative/
- https://www.scpx.com.au/2025/11/16/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/

---

## Add Debugger Entry To Hangs Key For Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `833ef470-fa01-4631-a79b-6f291c9ac498` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hangs_debugger_persistence.yml)**

> Detects when an attacker adds a new "Debugger" value to the "Hangs" key in order to achieve persistence which will get invoked when an application crashes

```sql
-- ============================================================
-- Title:        Add Debugger Entry To Hangs Key For Persistence
-- Sigma ID:     833ef470-fa01-4631-a79b-6f291c9ac498
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hangs_debugger_persistence.yml
-- Unmapped:     (none)
-- False Pos:    This value is not set by default but could be rarly used by administrators
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\Debugger%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This value is not set by default but could be rarly used by administrators

**References:**
- https://persistence-info.github.io/Data/wer_debugger.html
- https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/

---

## Persistence Via Hhctrl.ocx

| Field | Value |
|---|---|
| **Sigma ID** | `f10ed525-97fe-4fed-be7c-2feecca941b1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hhctrl_persistence.yml)**

> Detects when an attacker modifies the registry value of the "hhctrl" to point to a custom binary

```sql
-- ============================================================
-- Title:        Persistence Via Hhctrl.ocx
-- Sigma ID:     f10ed525-97fe-4fed-be7c-2feecca941b1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hhctrl_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{52A2AAAE-085D-4187-97EA-8C30DB990436}\\InprocServer32\\(Default)%')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'C:\Windows\System32\hhctrl.ocx')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://persistence-info.github.io/Data/hhctrl.html
- https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/

---

## Registry Modification to Hidden File Extension

| Field | Value |
|---|---|
| **Sigma ID** | `5df86130-4e95-4a54-90f7-26541b40aec2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hidden_extention.yml)**

> Hides the file extension through modification of the registry

```sql
-- ============================================================
-- Title:        Registry Modification to Hidden File Extension
-- Sigma ID:     5df86130-4e95-4a54-90f7-26541b40aec2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1137
-- Author:       frack113
-- Date:         2022-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hidden_extention.yml
-- Unmapped:     (none)
-- False Pos:    Administrative scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000002)'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-1---modify-registry-of-current-user-profile---cmd
- https://unit42.paloaltonetworks.com/ransomware-families/
- https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=TrojanSpy%3aMSIL%2fHakey.A

---

## Displaying Hidden Files Feature Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `5a5152f1-463f-436b-b2f5-8eceb3964b42` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1564.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hide_file.yml)**

> Detects modifications to the "Hidden" and "ShowSuperHidden" explorer registry values in order to disable showing of hidden files and system files.
This technique is abused by several malware families to hide their files from normal users.


```sql
-- ============================================================
-- Title:        Displaying Hidden Files Feature Disabled
-- Sigma ID:     5a5152f1-463f-436b-b2f5-8eceb3964b42
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1564.001
-- Author:       frack113
-- Date:         2022-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hide_file.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md#atomic-test-8---hide-files-through-registry

---

## Registry Hide Function from User

| Field | Value |
|---|---|
| **Sigma ID** | `5a93eb65-dffa-4543-b761-94aa60098fb6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hide_function_user.yml)**

> Detects registry modifications that hide internal tools or functions from the user (malware like Agent Tesla, Hermetic Wiper uses this technique)

```sql
-- ============================================================
-- Title:        Registry Hide Function from User
-- Sigma ID:     5a93eb65-dffa-4543-b761-94aa60098fb6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hide_function_user.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowInfoTip' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowCompColor'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
  OR ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideClock' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAHealth' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCANetwork' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAPower' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAVolume'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md

---

## Hide Schedule Task Via Index Value Tamper

| Field | Value |
|---|---|
| **Sigma ID** | `5b16df71-8615-4f7f-ac9b-6c43c0509e61` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hide_scheduled_task_via_index_tamper.yml)**

> Detects when the "index" value of a scheduled task is modified from the registry
Which effectively hides it from any tooling such as "schtasks /query" (Read the referenced link for more information about the effects of this technique)


```sql
-- ============================================================
-- Title:        Hide Schedule Task Via Index Value Tamper
-- Sigma ID:     5b16df71-8615-4f7f-ac9b-6c43c0509e61
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hide_scheduled_task_via_index_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Index%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments

---

## Driver Added To Disallowed Images In HVCI - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `555155a2-03bf-4fe7-af74-d176b3fdbe16` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Omar Khaled (@beacon_exe) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hvci_disallowed_images.yml)**

> Detects changes to the "HVCIDisallowedImages" registry value to potentially add a driver to the list, in order to prevent it from loading.


```sql
-- ============================================================
-- Title:        Driver Added To Disallowed Images In HVCI - Registry
-- Sigma ID:     555155a2-03bf-4fe7-af74-d176b3fdbe16
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems), Omar Khaled (@beacon_exe)
-- Date:         2023-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hvci_disallowed_images.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate usage of this key would also trigger this. Investigate the driver being added and make sure its intended
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\CI\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\HVCIDisallowedImages%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of this key would also trigger this. Investigate the driver being added and make sure its intended

**References:**
- https://github.com/yardenshafir/conference_talks/blob/3de1f5d7c02656c35117f067fbff0a219c304b09/OffensiveCon_2023_Your_Mitigations_are_My_Opportunities.pdf
- https://x.com/yarden_shafir/status/1822667605175324787

---

## IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols

| Field | Value |
|---|---|
| **Sigma ID** | `3fd4c8d7-8362-4557-a8e6-83b29cc0d724` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Michael Haag (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_ie_security_zone_protocol_defaults_downgrade.yml)**

> Detects changes to Internet Explorer's (IE / Windows Internet properties) ZoneMap configuration of the "HTTP" and "HTTPS" protocols to point to the "My Computer" zone. This allows downloaded files from the Internet to be granted the same level of trust as files stored locally.


```sql
-- ============================================================
-- Title:        IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols
-- Sigma ID:     3fd4c8d7-8362-4557-a8e6-83b29cc0d724
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems), Michael Haag (idea)
-- Date:         2023-09-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_ie_security_zone_protocol_defaults_downgrade.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\http' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\https'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%DWORD (0x00000000)%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/M_haggis/status/1699056847154725107
- https://twitter.com/JAMESWT_MHT/status/1699042827261391247
- https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries
- https://www.virustotal.com/gui/file/339ff720c74dc44265b917b6d3e3ba0411d61f3cd3c328e9a2bae81592c8a6e5/content

---

## Uncommon Extension In Keyboard Layout IME File Registry Value

| Field | Value |
|---|---|
| **Sigma ID** | `b888e3f2-224d-4435-b00b-9dd66e9ea1f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_ime_non_default_extension.yml)**

> Detects usage of Windows Input Method Editor (IME) keyboard layout feature, which allows an attacker to load a DLL into the process after sending the WM_INPUTLANGCHANGEREQUEST message.
Before doing this, the client needs to register the DLL in a special registry key that is assumed to implement this keyboard layout. This registry key should store a value named "Ime File" with a DLL path.
IMEs are essential for languages that have more characters than can be represented on a standard keyboard, such as Chinese, Japanese, and Korean.


```sql
-- ============================================================
-- Title:        Uncommon Extension In Keyboard Layout IME File Registry Value
-- Sigma ID:     b888e3f2-224d-4435-b00b-9dd66e9ea1f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-11-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_ime_non_default_extension.yml
-- Unmapped:     (none)
-- False Pos:    IMEs are essential for languages that have more characters than can be represented on a standard keyboard, such as Chinese, Japanese, and Korean.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Keyboard Layouts\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Ime File%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** IMEs are essential for languages that have more characters than can be represented on a standard keyboard, such as Chinese, Japanese, and Korean.

**References:**
- https://www.linkedin.com/pulse/guntior-story-advanced-bootkit-doesnt-rely-windows-disk-baranov-wue8e/

---

## Suspicious Path In Keyboard Layout IME File Registry Value

| Field | Value |
|---|---|
| **Sigma ID** | `9d8f9bb8-01af-4e15-a3a2-349071530530` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_ime_suspicious_paths.yml)**

> Detects usage of Windows Input Method Editor (IME) keyboard layout feature, which allows an attacker to load a DLL into the process after sending the WM_INPUTLANGCHANGEREQUEST message.
Before doing this, the client needs to register the DLL in a special registry key that is assumed to implement this keyboard layout. This registry key should store a value named "Ime File" with a DLL path.
IMEs are essential for languages that have more characters than can be represented on a standard keyboard, such as Chinese, Japanese, and Korean.


```sql
-- ============================================================
-- Title:        Suspicious Path In Keyboard Layout IME File Registry Value
-- Sigma ID:     9d8f9bb8-01af-4e15-a3a2-349071530530
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-11-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_ime_suspicious_paths.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Keyboard Layouts\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Ime File%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.linkedin.com/pulse/guntior-story-advanced-bootkit-doesnt-rely-windows-disk-baranov-wue8e/

---

## New Root or CA or AuthRoot Certificate to Store

| Field | Value |
|---|---|
| **Sigma ID** | `d223b46b-5621-4037-88fe-fda32eead684` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_install_root_or_ca_certificat.yml)**

> Detects the addition of new root, CA or AuthRoot certificates to the Windows registry

```sql
-- ============================================================
-- Title:        New Root or CA or AuthRoot Certificate to Store
-- Sigma ID:     d223b46b-5621-4037-88fe-fda32eead684
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       frack113
-- Date:         2022-04-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_install_root_or_ca_certificat.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\CA\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\CA\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\AuthRoot\\Certificates\\%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Blob')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'Binary Data'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md#atomic-test-6---add-root-certificate-to-currentuser-certificate-store
- https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec

---

## Internet Explorer DisableFirstRunCustomize Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `ab567429-1dfb-4674-b6d2-979fd2f9d125` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_internet_explorer_disable_first_run_customize.yml)**

> Detects changes to the Internet Explorer "DisableFirstRunCustomize" value, which prevents Internet Explorer from running the first run wizard the first time a user starts the browser after installing Internet Explorer or Windows.


```sql
-- ============================================================
-- Title:        Internet Explorer DisableFirstRunCustomize Enabled
-- Sigma ID:     ab567429-1dfb-4674-b6d2-979fd2f9d125
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_internet_explorer_disable_first_run_customize.yml
-- Unmapped:     (none)
-- False Pos:    As this is controlled by group policy as well as user settings. Some false positives may occur.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Internet Explorer\\Main\\DisableFirstRunCustomize')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('DWORD (0x00000001)', 'DWORD (0x00000002)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** As this is controlled by group policy as well as user settings. Some false positives may occur.

**References:**
- https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/devil-bait/NCSC-MAR-Devil-Bait.pdf
- https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
- https://admx.help/?Category=InternetExplorer&Policy=Microsoft.Policies.InternetExplorer::NoFirstRunCustomise

---

## Potential Ransomware Activity Using LegalNotice Message

| Field | Value |
|---|---|
| **Sigma ID** | `8b9606c9-28be-4a38-b146-0e313cc232c1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1491.001 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_legalnotice_susp_message.yml)**

> Detect changes to the "LegalNoticeCaption" or "LegalNoticeText" registry values where the message set contains keywords often used in ransomware ransom messages

```sql
-- ============================================================
-- Title:        Potential Ransomware Activity Using LegalNotice Message
-- Sigma ID:     8b9606c9-28be-4a38-b146-0e313cc232c1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1491.001
-- Author:       frack113
-- Date:         2022-12-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_legalnotice_susp_message.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText%'))
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%encrypted%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Unlock-Password%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%paying%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/5c1e6f1b4fafd01c8d1ece85f510160fc1275fbf/atomics/T1491.001/T1491.001.md

---

## Lolbas OneDriveStandaloneUpdater.exe Proxy Download

| Field | Value |
|---|---|
| **Sigma ID** | `3aff0be0-7802-4a7e-a4fa-c60c74bc5e1d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lolbin_onedrivestandaloneupdater.yml)**

> Detects setting a custom URL for OneDriveStandaloneUpdater.exe to download a file from the Internet without executing any
anomalous executables with suspicious arguments. The downloaded file will be in C:\Users\redacted\AppData\Local\Microsoft\OneDrive\StandaloneUpdaterreSignInSettingsConfig.json


```sql
-- ============================================================
-- Title:        Lolbas OneDriveStandaloneUpdater.exe Proxy Download
-- Sigma ID:     3aff0be0-7802-4a7e-a4fa-c60c74bc5e1d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113
-- Date:         2022-05-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lolbin_onedrivestandaloneupdater.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\OneDrive\\UpdateOfficeConfig\\UpdateRingSettingURLFromOC%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/OneDriveStandaloneUpdater/

---

## RestrictedAdminMode Registry Value Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `d6ce7ebd-260b-4323-9768-a9631c8d4db2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lsa_disablerestrictedadmin.yml)**

> Detects changes to the "DisableRestrictedAdmin" registry value in order to disable or enable RestrictedAdmin mode.
RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop.
This prevents your credentials from being harvested during the initial connection process if the remote server has been compromise


```sql
-- ============================================================
-- Title:        RestrictedAdminMode Registry Value Tampering
-- Sigma ID:     d6ce7ebd-260b-4323-9768-a9631c8d4db2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2023-01-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lsa_disablerestrictedadmin.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/a8e3cf63e97b973a25903d3df9fd55da6252e564/atomics/T1112/T1112.md
- https://social.technet.microsoft.com/wiki/contents/articles/32905.remote-desktop-services-enable-restricted-admin-mode.aspx

---

## Lsass Full Dump Request Via DumpType Registry Settings

| Field | Value |
|---|---|
| **Sigma ID** | `33efc23c-6ea2-4503-8cfe-bdf82ce8f719` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.001 |
| **Author** | @pbssubhash |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lsass_usermode_dumping.yml)**

> Detects the setting of the "DumpType" registry value to "2" which stands for a "Full Dump". Technique such as LSASS Shtinkering requires this value to be "2" in order to dump LSASS.

```sql
-- ============================================================
-- Title:        Lsass Full Dump Request Via DumpType Registry Settings
-- Sigma ID:     33efc23c-6ea2-4503-8cfe-bdf82ce8f719
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.001
-- Author:       @pbssubhash
-- Date:         2022-12-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_lsass_usermode_dumping.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate application that needs to do a full dump of their process
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe\\DumpType%'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000002)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate application that needs to do a full dump of their process

**References:**
- https://github.com/deepinstinct/Lsass-Shtinkering
- https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
- https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf

---

## NET NGenAssemblyUsageLog Registry Key Tamper

| Field | Value |
|---|---|
| **Sigma ID** | `28036918-04d3-423d-91c0-55ecf99fb892` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_net_cli_ngenassemblyusagelog.yml)**

> Detects changes to the NGenAssemblyUsageLog registry key.
.NET Usage Log output location can be controlled by setting the NGenAssemblyUsageLog CLR configuration knob in the Registry or by configuring an environment variable (as described in the next section).
By simplify specifying an arbitrary value (e.g. fake output location or junk data) for the expected value, a Usage Log file for the .NET execution context will not be created.


```sql
-- ============================================================
-- Title:        NET NGenAssemblyUsageLog Registry Key Tamper
-- Sigma ID:     28036918-04d3-423d-91c0-55ecf99fb892
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-11-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_net_cli_ngenassemblyusagelog.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\.NETFramework\\NGenAssemblyUsageLog')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/

---

## New Netsh Helper DLL Registered From A Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `e7b18879-676e-4a0e-ae18-27039185a8e7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.007 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_netsh_help_dll_persistence_susp_location.yml)**

> Detects changes to the Netsh registry key to add a new DLL value that is located on a suspicious location. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper


```sql
-- ============================================================
-- Title:        New Netsh Helper DLL Registered From A Suspicious Location
-- Sigma ID:     e7b18879-676e-4a0e-ae18-27039185a8e7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.007
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_netsh_help_dll_persistence_susp_location.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\NetSh%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll
- https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/

---

## Potential Persistence Via Netsh Helper DLL - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `c90362e0-2df3-4e61-94fe-b37615814cb1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.007 |
| **Author** | Anish Bogati |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_netsh_helper_dll_potential_persistence.yml)**

> Detects changes to the Netsh registry key to add a new DLL value. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper


```sql
-- ============================================================
-- Title:        Potential Persistence Via Netsh Helper DLL - Registry
-- Sigma ID:     c90362e0-2df3-4e61-94fe-b37615814cb1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.007
-- Author:       Anish Bogati
-- Date:         2023-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_netsh_helper_dll_potential_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate helper added by different programs and the OS
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\NetSh%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dll%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate helper added by different programs and the OS

**References:**
- https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll
- https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/

---

## New Application in AppCompat

| Field | Value |
|---|---|
| **Sigma ID** | `60936b49-fca0-4f32-993d-7415edcf9a5d` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_new_application_appcompat.yml)**

> A General detection for a new application in AppCompat. This indicates an application executing for the first time on an endpoint.

```sql
-- ============================================================
-- Title:        New Application in AppCompat
-- Sigma ID:     60936b49-fca0-4f32-993d-7415edcf9a5d
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1204.002
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_new_application_appcompat.yml
-- Unmapped:     (none)
-- False Pos:    This rule is to explore new applications on an endpoint. False positives depends on the organization.; Newly setup system.; Legitimate installation of new application.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppCompatFlags\\Compatibility Assistant\\Store\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This rule is to explore new applications on an endpoint. False positives depends on the organization.; Newly setup system.; Legitimate installation of new application.

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/1
- https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/1.A.1_DFD6A782-9BDB-4550-AB6B-525E825B095E.md

---

## Potential Credential Dumping Attempt Using New NetworkProvider - REG

| Field | Value |
|---|---|
| **Sigma ID** | `0442defa-b4a2-41c9-ae2c-ea7042fc4701` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_new_network_provider.yml)**

> Detects when an attacker tries to add a new network provider in order to dump clear text credentials, similar to how the NPPSpy tool does it

```sql
-- ============================================================
-- Title:        Potential Credential Dumping Attempt Using New NetworkProvider - REG
-- Sigma ID:     0442defa-b4a2-41c9-ae2c-ea7042fc4701
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_new_network_provider.yml
-- Unmapped:     (none)
-- False Pos:    Other legitimate network providers used and not filtred in this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\System\\CurrentControlSet\\Services\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\NetworkProvider%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legitimate network providers used and not filtred in this rule

**References:**
- https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/network-provider-settings-removed-in-place-upgrade
- https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy

---

## New ODBC Driver Registered

| Field | Value |
|---|---|
| **Sigma ID** | `3390fbef-c98d-4bdd-a863-d65ed7c610dd` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_odbc_driver_registered.yml)**

> Detects the registration of a new ODBC driver.

```sql
-- ============================================================
-- Title:        New ODBC Driver Registered
-- Sigma ID:     3390fbef-c98d-4bdd-a863-d65ed7c610dd
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_odbc_driver_registered.yml
-- Unmapped:     (none)
-- False Pos:    Likely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\ODBC\\ODBCINST.INI\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Driver'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

---

## Potentially Suspicious ODBC Driver Registered

| Field | Value |
|---|---|
| **Sigma ID** | `e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_odbc_driver_registered_susp.yml)**

> Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location

```sql
-- ============================================================
-- Title:        Potentially Suspicious ODBC Driver Registered
-- Sigma ID:     e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_odbc_driver_registered_susp.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\ODBC\\ODBCINST.INI\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Driver' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Setup'))
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\Registration\\CRMLog%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\com\\dmp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\FxsTmp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\spool\\drivers\\color\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\spool\\PRINTERS\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\spool\\SERVERS\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\Tasks\_Migrated\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\SysWOW64\\com\\dmp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\SysWOW64\\FxsTmp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\Tasks\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\Tracing\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Roaming\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

---

## Trust Access Disable For VBApplications

| Field | Value |
|---|---|
| **Sigma ID** | `1a5c46e9-f32f-42f7-b2bc-6e9084db7fbf` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_access_vbom_tamper.yml)**

> Detects registry changes to Microsoft Office "AccessVBOM" to a value of "1" which disables trust access for VBA on the victim machine and lets attackers execute malicious macros without any Microsoft Office warnings.

```sql
-- ============================================================
-- Title:        Trust Access Disable For VBApplications
-- Sigma ID:     1a5c46e9-f32f-42f7-b2bc-6e9084db7fbf
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2020-05-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_access_vbom_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Security\\AccessVBOM')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/inversecos/status/1494174785621819397
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
- https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/

---

## Microsoft Office Protected View Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `a5c7a43f-6009-4a8c-80c5-32abf1c53ecc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_disable_protected_view_features.yml)**

> Detects changes to Microsoft Office protected view registry keys with which the attacker disables this feature.

```sql
-- ============================================================
-- Title:        Microsoft Office Protected View Disabled
-- Sigma ID:     a5c7a43f-6009-4a8c-80c5-32abf1c53ecc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_disable_protected_view_features.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Office\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Security\\ProtectedView\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
- https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
- https://yoroi.company/research/cyber-criminal-espionage-operation-insists-on-italian-manufacturing/
- https://admx.help/HKCU/software/policies/microsoft/office/16.0/excel/security/protectedview

---

## Python Function Execution Security Warning Disabled In Excel - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `17e53739-a1fc-4a62-b1b9-87711c2d5e44` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), @Kostastsale |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_disable_python_security_warnings.yml)**

> Detects changes to the registry value "PythonFunctionWarnings" that would prevent any warnings or alerts from showing when Python functions are about to be executed.
Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet.


```sql
-- ============================================================
-- Title:        Python Function Execution Security Warning Disabled In Excel - Registry
-- Sigma ID:     17e53739-a1fc-4a62-b1b9-87711c2d5e44
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems), @Kostastsale
-- Date:         2024-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_disable_python_security_warnings.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Office\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Excel\\Security\\PythonFunctionWarnings')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327

---

## Enable Microsoft Dynamic Data Exchange

| Field | Value |
|---|---|
| **Sigma ID** | `63647769-326d-4dde-a419-b925cc0caf42` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1559.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_enable_dde.yml)**

> Enable Dynamic Data Exchange protocol (DDE) in all supported editions of Microsoft Word or Excel.

```sql
-- ============================================================
-- Title:        Enable Microsoft Dynamic Data Exchange
-- Sigma ID:     63647769-326d-4dde-a419-b925cc0caf42
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1559.002
-- Author:       frack113
-- Date:         2022-02-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_enable_dde.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Excel\\Security\\DisableDDEServerLaunch' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Excel\\Security\\DisableDDEServerLookup'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Word\\Security\\AllowDDE')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('DWORD (0x00000001)', 'DWORD (0x00000002)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://msrc.microsoft.com/update-guide/vulnerability/ADV170021

---

## Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting

| Field | Value |
|---|---|
| **Sigma ID** | `396ae3eb-4174-4b9b-880e-dc0364d78a19` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137, T1008, T1546 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_enable_load_macro_provider_on_boot.yml)**

> Detects the modification of Outlook setting "LoadMacroProviderOnBoot" which if enabled allows the automatic loading of any configured VBA project/module

```sql
-- ============================================================
-- Title:        Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting
-- Sigma ID:     396ae3eb-4174-4b9b-880e-dc0364d78a19
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137, T1008, T1546
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-04-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_enable_load_macro_provider_on_boot.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Outlook\\LoadMacroProviderOnBoot')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%0x00000001%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53
- https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/

---

## Outlook Macro Execution Without Warning Setting Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `e3b50fa5-3c3f-444e-937b-0a99d33731cd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137, T1008, T1546 |
| **Author** | @ScoubiMtl |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_enable_macro_execution.yml)**

> Detects the modification of Outlook security setting to allow unprompted execution of macros.

```sql
-- ============================================================
-- Title:        Outlook Macro Execution Without Warning Setting Enabled
-- Sigma ID:     e3b50fa5-3c3f-444e-937b-0a99d33731cd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137, T1008, T1546
-- Author:       @ScoubiMtl
-- Date:         2021-04-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_enable_macro_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Outlook\\Security\\Level')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%0x00000001%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53

---

## Outlook EnableUnsafeClientMailRules Setting Enabled - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `6763c6c8-bd01-4687-bc8d-4fa52cf8ba08` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_enable_unsafe_client_mail_rules.yml)**

> Detects an attacker trying to enable the outlook security setting "EnableUnsafeClientMailRules" which allows outlook to run applications or execute macros

```sql
-- ============================================================
-- Title:        Outlook EnableUnsafeClientMailRules Setting Enabled - Registry
-- Sigma ID:     6763c6c8-bd01-4687-bc8d-4fa52cf8ba08
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_enable_unsafe_client_mail_rules.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Outlook\\Security\\EnableUnsafeClientMailRules')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://support.microsoft.com/en-us/topic/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro-in-outlook-2016-and-outlook-2013-e4964b72-173c-959d-5d7b-ead562979048
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=44

---

## Outlook Security Settings Updated - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `c3cefdf4-6703-4e1c-bad8-bf422fc5015a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_security_settings.yml)**

> Detects changes to the registry values related to outlook security settings

```sql
-- ============================================================
-- Title:        Outlook Security Settings Updated - Registry
-- Sigma ID:     c3cefdf4-6703-4e1c-bad8-bf422fc5015a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1137
-- Author:       frack113
-- Date:         2021-12-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_security_settings.yml
-- Unmapped:     (none)
-- False Pos:    Administrative activity
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Office\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Outlook\\Security\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative activity

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1137/T1137.md
- https://learn.microsoft.com/en-us/outlook/troubleshoot/security/information-about-email-security-settings

---

## Macro Enabled In A Potentially Suspicious Document

| Field | Value |
|---|---|
| **Sigma ID** | `a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_trust_record_susp_location.yml)**

> Detects registry changes to Office trust records where the path is located in a potentially suspicious location

```sql
-- ============================================================
-- Title:        Macro Enabled In A Potentially Suspicious Document
-- Sigma ID:     a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_trust_record_susp_location.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%/AppData/Local/Microsoft/Windows/INetCache/%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%/AppData/Local/Temp/%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%/PerfLogs/%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%C:/Users/Public/%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%file:///D:/%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%file:///E:/%'))
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Security\\Trusted Documents\\TrustRecords%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/inversecos/status/1494174785621819397
- Internal Research

---

## Uncommon Microsoft Office Trusted Location Added

| Field | Value |
|---|---|
| **Sigma ID** | `f742bde7-9528-42e5-bd82-84f51a8387d2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_trusted_location_uncommon.yml)**

> Detects changes to registry keys related to "Trusted Location" of Microsoft Office where the path is set to something uncommon. Attackers might add additional trusted locations to avoid macro security restrictions.

```sql
-- ============================================================
-- Title:        Uncommon Microsoft Office Trusted Location Added
-- Sigma ID:     f742bde7-9528-42e5-bd82-84f51a8387d2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-06-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_trusted_location_uncommon.yml
-- Unmapped:     (none)
-- False Pos:    Other unknown legitimate or custom paths need to be filtered to avoid false positives
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Security\\Trusted Locations\\Location%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Path'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other unknown legitimate or custom paths need to be filtered to avoid false positives

**References:**
- Internal Research
- https://admx.help/?Category=Office2016&Policy=excel16.Office.Microsoft.Policies.Windows::L_TrustedLoc01

---

## Office Macros Warning Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `91239011-fe3c-4b54-9f24-15c86bb65913` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_vba_warnings_tamper.yml)**

> Detects registry changes to Microsoft Office "VBAWarning" to a value of "1" which enables the execution of all macros, whether signed or unsigned.

```sql
-- ============================================================
-- Title:        Office Macros Warning Disabled
-- Sigma ID:     91239011-fe3c-4b54-9f24-15c86bb65913
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Trent Liffick (@tliffick), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2020-05-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_vba_warnings_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Security\\VBAWarnings')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/inversecos/status/1494174785621819397
- https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
- https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/

---

## MaxMpxCt Registry Value Changed

| Field | Value |
|---|---|
| **Sigma ID** | `0e6a9e62-627e-496c-aef5-bfa39da29b5e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1070.005 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_optimize_file_sharing_network.yml)**

> Detects changes to the "MaxMpxCt" registry value.
MaxMpxCt specifies the maximum outstanding network requests for the server per client, which is used when negotiating a Server Message Block (SMB) connection with a client. Note if the value is set beyond 125 older Windows 9x clients will fail to negotiate.
Ransomware threat actors and operators (specifically BlackCat) were seen increasing this value in order to handle a higher volume of traffic.


```sql
-- ============================================================
-- Title:        MaxMpxCt Registry Value Changed
-- Sigma ID:     0e6a9e62-627e-496c-aef5-bfa39da29b5e
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1070.005
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_optimize_file_sharing_network.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\LanmanServer\\Parameters\\MaxMpxCt')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.huntress.com/blog/blackcat-ransomware-affiliate-ttps
- https://securityscorecard.com/research/deep-dive-into-alphv-blackcat-ransomware
- https://www.intrinsec.com/alphv-ransomware-gang-analysis/?cn-reloaded=1
- https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/

---

## Potential Persistence Via New AMSI Providers - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `33efc23c-6ea2-4503-8cfe-bdf82ce8f705` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_amsi_providers.yml)**

> Detects when an attacker adds a new AMSI provider via the Windows Registry to bypass AMSI (Antimalware Scan Interface) protections.
Attackers may add custom AMSI providers to persist on the system and evade detection by security software that relies on AMSI for scanning scripts and other content.
This technique is often used in conjunction with fileless malware and script-based attacks to maintain persistence while avoiding detection.


```sql
-- ============================================================
-- Title:        Potential Persistence Via New AMSI Providers - Registry
-- Sigma ID:     33efc23c-6ea2-4503-8cfe-bdf82ce8f705
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_amsi_providers.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate security products adding their own AMSI providers. Filter these according to your environment.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\AMSI\\Providers\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\WOW6432Node\\Microsoft\\AMSI\\Providers\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate security products adding their own AMSI providers. Filter these according to your environment.

**References:**
- https://persistence-info.github.io/Data/amsi.html
- https://github.com/gtworek/PSBits/blob/8d767892f3b17eefa4d0668f5d2df78e844f01d8/FakeAMSI/FakeAMSI.c

---

## Potential Persistence Via AppCompat RegisterAppRestart Layer

| Field | Value |
|---|---|
| **Sigma ID** | `b86852fb-4c77-48f9-8519-eb1b2c308b59` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.011 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_app_cpmpat_layer_registerapprestart.yml)**

> Detects the setting of the REGISTERAPPRESTART compatibility layer on an application.
This compatibility layer allows an application to register for restart using the "RegisterApplicationRestart" API.
This can be potentially abused as a persistence mechanism.


```sql
-- ============================================================
-- Title:        Potential Persistence Via AppCompat RegisterAppRestart Layer
-- Sigma ID:     b86852fb-4c77-48f9-8519-eb1b2c308b59
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.011
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_app_cpmpat_layer_registerapprestart.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications making use of this feature for compatibility reasons
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%REGISTERAPPRESTART%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications making use of this feature for compatibility reasons

**References:**
- https://github.com/nasbench/Misc-Research/blob/d114d6a5e0a437d3818e492ef9864367152543e7/Other/Persistence-Via-RegisterAppRestart-Shim.md

---

## Potential Persistence Via App Paths Default Property

| Field | Value |
|---|---|
| **Sigma ID** | `707e097c-e20f-4f67-8807-1f72ff4500d6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.012 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_app_paths.yml)**

> Detects changes to the "Default" property for keys located in the \Software\Microsoft\Windows\CurrentVersion\App Paths\ registry. Which might be used as a method of persistence
The entries found under App Paths are used primarily for the following purposes.
First, to map an application's executable file name to that file's fully qualified path.
Second, to prepend information to the PATH environment variable on a per-application, per-process basis.


```sql
-- ============================================================
-- Title:        Potential Persistence Via App Paths Default Property
-- Sigma ID:     707e097c-e20f-4f67-8807-1f72ff4500d6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.012
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_app_paths.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications registering their binary from on of the suspicious locations mentioned above (tune it)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%(Default)' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Path'))
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Users\\Public%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Desktop\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Downloads\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%temp\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%tmp\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%iex%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Invoke-%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%rundll32%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%regsvr32%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%mshta%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%cscript%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%wscript%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.bat%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.hta%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dll%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.ps1%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications registering their binary from on of the suspicious locations mentioned above (tune it)

**References:**
- https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
- https://learn.microsoft.com/en-us/windows/win32/shell/app-registration

---

## Potential Persistence Using DebugPath

| Field | Value |
|---|---|
| **Sigma ID** | `df4dc653-1029-47ba-8231-3c44238cc0ae` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_appx_debugger.yml)**

> Detects potential persistence using Appx DebugPath

```sql
-- ============================================================
-- Title:        Potential Persistence Using DebugPath
-- Sigma ID:     df4dc653-1029-47ba-8231-3c44238cc0ae
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.015
-- Author:       frack113
-- Date:         2022-07-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_appx_debugger.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\ActivatableClasses\\Package\\Microsoft.%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DebugPath'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\Microsoft.%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\(Default)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/
- https://github.com/rootm0s/WinPwnage

---

## Potential Persistence Via AutodialDLL

| Field | Value |
|---|---|
| **Sigma ID** | `e6fe26ee-d063-4f5b-b007-39e90aaf50e3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_autodial_dll.yml)**

> Detects change the the "AutodialDLL" key which could be used as a persistence method to load custom DLL via the "ws2_32" library

```sql
-- ============================================================
-- Title:        Potential Persistence Via AutodialDLL
-- Sigma ID:     e6fe26ee-d063-4f5b-b007-39e90aaf50e3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_autodial_dll.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\WinSock2\\Parameters\\AutodialDLL%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/
- https://persistence-info.github.io/Data/autodialdll.html

---

## Potential Persistence Via CHM Helper DLL

| Field | Value |
|---|---|
| **Sigma ID** | `976dd1f2-a484-45ec-aa1d-0e87e882262b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_chm.yml)**

> Detects when an attacker modifies the registry key "HtmlHelp Author" to achieve persistence

```sql
-- ============================================================
-- Title:        Potential Persistence Via CHM Helper DLL
-- Sigma ID:     976dd1f2-a484-45ec-aa1d-0e87e882262b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_chm.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\HtmlHelp Author\\Location%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\WOW6432Node\\Microsoft\\HtmlHelp Author\\Location%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://persistence-info.github.io/Data/htmlhelpauthor.html
- https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/

---

## COM Object Hijacking Via Modification Of Default System CLSID Default Value

| Field | Value |
|---|---|
| **Sigma ID** | `790317c0-0a36-4a6a-a105-6e576bf99a14` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_com_hijacking_builtin.yml)**

> Detects potential COM object hijacking via modification of default system CLSID.

```sql
-- ============================================================
-- Title:        COM Object Hijacking Via Modification Of Default System CLSID Default Value
-- Sigma ID:     790317c0-0a36-4a6a-a105-6e576bf99a14
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1546.015
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_com_hijacking_builtin.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/ (idea)
- https://unit42.paloaltonetworks.com/snipbot-romcom-malware-variant/
- https://blog.talosintelligence.com/uat-5647-romcom/
- https://global.ptsecurity.com/analytics/pt-esc-threat-intelligence/darkhotel-a-cluster-of-groups-united-by-common-techniques
- https://threatbook.io/blog/Analysis-of-APT-C-60-Attack-on-South-Korea
- https://catalyst.prodaft.com/public/report/inside-the-latest-espionage-campaign-of-nebulous-mantis
- https://github.com/rtecCyberSec/BitlockMove
- https://cert.gov.ua/article/6284080
- https://securelist.com/forumtroll-apt-hacking-team-dante-spyware/117851/

---

## Potential COM Object Hijacking Via TreatAs Subkey - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `9b0f8a61-91b2-464f-aceb-0527e0a45020` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | Kutepov Anton, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_com_key_linking.yml)**

> Detects COM object hijacking via TreatAs subkey

```sql
-- ============================================================
-- Title:        Potential COM Object Hijacking Via TreatAs Subkey - Registry
-- Sigma ID:     9b0f8a61-91b2-464f-aceb-0527e0a45020
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.015
-- Author:       Kutepov Anton, oscd.community
-- Date:         2019-10-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_com_key_linking.yml
-- Unmapped:     (none)
-- False Pos:    Maybe some system utilities in rare cases use linking keys for backward compatibility
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%HKU\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Classes\\CLSID\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\TreatAs%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Maybe some system utilities in rare cases use linking keys for backward compatibility

**References:**
- https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/

---

## Potential PSFactoryBuffer COM Hijacking

| Field | Value |
|---|---|
| **Sigma ID** | `243380fa-11eb-4141-af92-e14925e77c1b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | BlackBerry Threat Research and Intelligence Team - @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_comhijack_psfactorybuffer.yml)**

> Detects changes to the PSFactory COM InProcServer32 registry. This technique was used by RomCom to create persistence storing a malicious DLL.

```sql
-- ============================================================
-- Title:        Potential PSFactoryBuffer COM Hijacking
-- Sigma ID:     243380fa-11eb-4141-af92-e14925e77c1b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.015
-- Author:       BlackBerry Threat Research and Intelligence Team - @Joseliyo_Jstnk
-- Date:         2023-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_comhijack_psfactorybuffer.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CLSID\\{c90250f3-4d7d-4991-9b69-a5c5bc1c2ae6}\\InProcServer32\\(Default)')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('%windir%\System32\ActXPrxy.dll', 'C:\Windows\System32\ActXPrxy.dll'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.blackberry.com/en/2023/06/romcom-resurfaces-targeting-ukraine
- https://strontic.github.io/xcyclopedia/library/clsid_C90250F3-4D7D-4991-9B69-A5C5BC1C2AE6.html
- https://www.virustotal.com/gui/file/6d3ab9e729bb03ae8ae3fcd824474c5052a165de6cb4c27334969a542c7b261d/detection
- https://www.trendmicro.com/en_us/research/23/e/void-rabisu-s-use-of-romcom-backdoor-shows-a-growing-shift-in-th.html

---

## Potential Persistence Via Custom Protocol Handler

| Field | Value |
|---|---|
| **Sigma ID** | `fdbf0b9d-0182-4c43-893b-a1eaab92d085` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_custom_protocol_handler.yml)**

> Detects potential persistence activity via the registering of a new custom protocole handlers. While legitimate applications register protocole handlers often times during installation. And attacker can abuse this by setting a custom handler to be used as a persistence mechanism.

```sql
-- ============================================================
-- Title:        Potential Persistence Via Custom Protocol Handler
-- Sigma ID:     fdbf0b9d-0182-4c43-893b-a1eaab92d085
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-05-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_custom_protocol_handler.yml
-- Unmapped:     (none)
-- False Pos:    Many legitimate applications can register a new custom protocol handler. Additional filters needs to applied according to your environment.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE 'HKCR\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'URL:%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Many legitimate applications can register a new custom protocol handler. Additional filters needs to applied according to your environment.

**References:**
- https://ladydebug.com/blog/2019/06/21/custom-protocol-handler-cph/

---

## Potential Persistence Via Event Viewer Events.asp

| Field | Value |
|---|---|
| **Sigma ID** | `a1e11042-a74a-46e6-b07c-c4ce8ecc239b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_event_viewer_events_asp.yml)**

> Detects potential registry persistence technique using the Event Viewer "Events.asp" technique

```sql
-- ============================================================
-- Title:        Potential Persistence Via Event Viewer Events.asp
-- Sigma ID:     a1e11042-a74a-46e6-b07c-c4ce8ecc239b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-02-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_event_viewer_events_asp.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionURL%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/nas_bench/status/1626648985824788480
- https://admx.help/?Category=Windows_7_2008R2&Policy=Microsoft.Policies.InternetCommunicationManagement::EventViewer_DisableLinks
- https://www.hexacorn.com/blog/2019/02/15/beyond-good-ol-run-key-part-103/
- https://github.com/redcanaryco/atomic-red-team/blob/f296668303c29d3f4c07e42bdd2b28d8dd6625f9/atomics/T1112/T1112.md

---

## Potential Persistence Via GlobalFlags

| Field | Value |
|---|---|
| **Sigma ID** | `36803969-5421-41ec-b92f-8500f79c23b0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.012 |
| **Author** | Karneades, Jonhnathan Ribeiro, Florian Roth |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_globalflags.yml)**

> Detects registry persistence technique using the GlobalFlags and SilentProcessExit keys

```sql
-- ============================================================
-- Title:        Potential Persistence Via GlobalFlags
-- Sigma ID:     36803969-5421-41ec-b92f-8500f79c23b0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.012
-- Author:       Karneades, Jonhnathan Ribeiro, Florian Roth
-- Date:         2018-04-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_globalflags.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Image File Execution Options\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\GlobalFlag%')
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SilentProcessExit\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ReportingMode%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\MonitorProcess%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
- https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/

---

## Modification of IE Registry Settings

| Field | Value |
|---|---|
| **Sigma ID** | `d88d0ab2-e696-4d40-a2ed-9790064e66b3` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_ie.yml)**

> Detects modification of the registry settings used for Internet Explorer and other Windows components that use these settings. An attacker can abuse this registry key to add a domain to the trusted sites Zone or insert JavaScript for persistence

```sql
-- ============================================================
-- Title:        Modification of IE Registry Settings
-- Sigma ID:     d88d0ab2-e696-4d40-a2ed-9790064e66b3
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_ie.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-5---javascript-in-registry

---

## Register New IFiltre For Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `b23818c7-e575-4d13-8012-332075ec0a2b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_ifilter.yml)**

> Detects when an attacker registers a new IFilter for an extension. Microsoft Windows Search uses filters to extract the content of items for inclusion in a full-text index.
You can extend Windows Search to index new or proprietary file types by writing filters to extract the content, and property handlers to extract the properties of files.


```sql
-- ============================================================
-- Title:        Register New IFiltre For Persistence
-- Sigma ID:     b23818c7-e575-4d13-8012-332075ec0a2b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_ifilter.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate registration of IFilters by the OS or software
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate registration of IFilters by the OS or software

**References:**
- https://persistence-info.github.io/Data/ifilters.html
- https://twitter.com/0gtweet/status/1468548924600459267
- https://github.com/gtworek/PSBits/tree/master/IFilter
- https://github.com/gtworek/PSBits/blob/8d767892f3b17eefa4d0668f5d2df78e844f01d8/IFilter/Dll.cpp#L281-L308

---

## Potential Persistence Via Logon Scripts - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `9ace0707-b560-49b8-b6ca-5148b42f39fb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1037.001 |
| **Author** | Tom Ueltschi (@c_APT_ure) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_logon_scripts_userinitmprlogonscript.yml)**

> Detects creation of "UserInitMprLogonScript" registry value which can be used as a persistence method by malicious actors

```sql
-- ============================================================
-- Title:        Potential Persistence Via Logon Scripts - Registry
-- Sigma ID:     9ace0707-b560-49b8-b6ca-5148b42f39fb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1037.001
-- Author:       Tom Ueltschi (@c_APT_ure)
-- Date:         2019-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_logon_scripts_userinitmprlogonscript.yml
-- Unmapped:     (none)
-- False Pos:    Investigate the contents of the "UserInitMprLogonScript" value to determine of the added script is legitimate
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%UserInitMprLogonScript%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate the contents of the "UserInitMprLogonScript" value to determine of the added script is legitimate

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.001/T1037.001.md

---

## Potential Persistence Via LSA Extensions

| Field | Value |
|---|---|
| **Sigma ID** | `41f6531d-af6e-4c6e-918f-b946f2b85a36` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_lsa_extension.yml)**

> Detects when an attacker modifies the "REG_MULTI_SZ" value named "Extensions" to include a custom DLL to achieve persistence via lsass.
The "Extensions" list contains filenames of DLLs being automatically loaded by lsass.exe. Each DLL has its InitializeLsaExtension() method called after loading.


```sql
-- ============================================================
-- Title:        Potential Persistence Via LSA Extensions
-- Sigma ID:     41f6531d-af6e-4c6e-918f-b946f2b85a36
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_lsa_extension.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SYSTEM\\CurrentControlSet\\Control\\LsaExtensionConfig\\LsaSrv\\Extensions%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://persistence-info.github.io/Data/lsaaextension.html
- https://twitter.com/0gtweet/status/1476286368385019906

---

## Potential Persistence Via Mpnotify

| Field | Value |
|---|---|
| **Sigma ID** | `92772523-d9c1-4c93-9547-b0ca500baba3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_mpnotify.yml)**

> Detects when an attacker register a new SIP provider for persistence and defense evasion

```sql
-- ============================================================
-- Title:        Potential Persistence Via Mpnotify
-- Sigma ID:     92772523-d9c1-4c93-9547-b0ca500baba3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_mpnotify.yml
-- Unmapped:     (none)
-- False Pos:    Might trigger if a legitimate new SIP provider is registered. But this is not a common occurrence in an environment and should be investigated either way
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\mpnotify%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Might trigger if a legitimate new SIP provider is registered. But this is not a common occurrence in an environment and should be investigated either way

**References:**
- https://persistence-info.github.io/Data/mpnotify.html
- https://www.youtube.com/watch?v=ggY3srD9dYs&ab_channel=GrzegorzTworek

---

## Potential Persistence Via MyComputer Registry Keys

| Field | Value |
|---|---|
| **Sigma ID** | `8fbe98a8-8f9d-44f8-aa71-8c572e29ef06` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_mycomputer.yml)**

> Detects modification to the "Default" value of the "MyComputer" key and subkeys to point to a custom binary that will be launched whenever the associated action is executed (see reference section for example)

```sql
-- ============================================================
-- Title:        Potential Persistence Via MyComputer Registry Keys
-- Sigma ID:     8fbe98a8-8f9d-44f8-aa71-8c572e29ef06
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_mycomputer.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely but if you experience FPs add specific processes and locations you would like to monitor for
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%(Default)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely but if you experience FPs add specific processes and locations you would like to monitor for

**References:**
- https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/

---

## Potential Persistence Via DLLPathOverride

| Field | Value |
|---|---|
| **Sigma ID** | `a1b1fd53-9c4a-444c-bae0-34a330fc7aa8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_natural_language.yml)**

> Detects when an attacker adds a new "DLLPathOverride" value to the "Natural Language" key in order to achieve persistence which will get invoked by "SearchIndexer.exe" process

```sql
-- ============================================================
-- Title:        Potential Persistence Via DLLPathOverride
-- Sigma ID:     a1b1fd53-9c4a-444c-bae0-34a330fc7aa8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_natural_language.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Language\\%')
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\StemmerDLLPathOverride%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\WBDLLPathOverride%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\StemmerClass%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\WBreakerClass%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://persistence-info.github.io/Data/naturallanguage6.html
- https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/

---

## Potential Persistence Via Visual Studio Tools for Office

| Field | Value |
|---|---|
| **Sigma ID** | `9d15044a-7cfe-4d23-8085-6ebc11df7685` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137.006 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_office_vsto.yml)**

> Detects persistence via Visual Studio Tools for Office (VSTO) add-ins in Office applications.

```sql
-- ============================================================
-- Title:        Potential Persistence Via Visual Studio Tools for Office
-- Sigma ID:     9d15044a-7cfe-4d23-8085-6ebc11df7685
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1137.006
-- Author:       Bhabesh Raj
-- Date:         2021-01-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_office_vsto.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate Addin Installation
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Office\\Outlook\\Addins\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Office\\Word\\Addins\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Office\\Excel\\Addins\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Office\\Powerpoint\\Addins\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\VSTO\\Security\\Inclusion\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Addin Installation

**References:**
- https://twitter.com/_vivami/status/1347925307643355138
- https://vanmieghem.io/stealth-outlook-persistence/

---

## Potential Persistence Via Outlook Home Page

| Field | Value |
|---|---|
| **Sigma ID** | `ddd171b5-2cc6-4975-9e78-f0eccd08cc76` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.yml)**

> Detects potential persistence activity via outlook home page.
An attacker can set a home page to achieve code execution and persistence by editing the WebView registry keys.


```sql
-- ============================================================
-- Title:        Potential Persistence Via Outlook Home Page
-- Sigma ID:     ddd171b5-2cc6-4975-9e78-f0eccd08cc76
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand
-- Date:         2021-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Office\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Outlook\\WebView\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\URL'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=70
- https://support.microsoft.com/en-us/topic/outlook-home-page-feature-is-missing-in-folder-properties-d207edb7-aa02-46c5-b608-5d9dbed9bd04?ui=en-us&rs=en-us&ad=us
- https://trustedsec.com/blog/specula-turning-outlook-into-a-c2-with-one-registry-change

---

## Potential Persistence Via Outlook Today Page

| Field | Value |
|---|---|
| **Sigma ID** | `487bb375-12ef-41f6-baae-c6a1572b4dd1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_outlook_todaypage.yml)**

> Detects potential persistence activity via outlook today page.
An attacker can set a custom page to execute arbitrary code and link to it via the registry values "URL" and "UserDefinedUrl".


```sql
-- ============================================================
-- Title:        Potential Persistence Via Outlook Today Page
-- Sigma ID:     487bb375-12ef-41f6-baae-c6a1572b4dd1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand
-- Date:         2021-06-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_outlook_todaypage.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Office\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Outlook\\Today\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=74
- https://trustedsec.com/blog/specula-turning-outlook-into-a-c2-with-one-registry-change

---

## Potential WerFault ReflectDebugger Registry Value Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `0cf2e1c6-8d10-4273-8059-738778f981ad` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1036.003 |
| **Author** | X__Junior |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_reflectdebugger.yml)**

> Detects potential WerFault "ReflectDebugger" registry value abuse for persistence.

```sql
-- ============================================================
-- Title:        Potential WerFault ReflectDebugger Registry Value Abuse
-- Sigma ID:     0cf2e1c6-8d10-4273-8059-738778f981ad
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1036.003
-- Author:       X__Junior
-- Date:         2023-05-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_reflectdebugger.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
- https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/

---

## Potential Persistence Via Scrobj.dll COM Hijacking

| Field | Value |
|---|---|
| **Sigma ID** | `fe20dda1-6f37-4379-bbe0-a98d400cae90` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_scrobj_dll.yml)**

> Detect use of scrobj.dll as this DLL looks for the ScriptletURL key to get the location of the script to execute

```sql
-- ============================================================
-- Title:        Potential Persistence Via Scrobj.dll COM Hijacking
-- Sigma ID:     fe20dda1-6f37-4379-bbe0-a98d400cae90
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.015
-- Author:       frack113
-- Date:         2022-08-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_scrobj_dll.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the dll.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%InprocServer32\\(Default)')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'C:\WINDOWS\system32\scrobj.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the dll.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md

---

## Potential Persistence Via Shim Database Modification

| Field | Value |
|---|---|
| **Sigma ID** | `dfb5b4e8-91d0-4291-b40a-e3b0d3942c45` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.011 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database.yml)**

> Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time


```sql
-- ============================================================
-- Title:        Potential Persistence Via Shim Database Modification
-- Sigma ID:     dfb5b4e8-91d0-4291-b40a-e3b0d3942c45
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.011
-- Author:       frack113
-- Date:         2021-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate custom SHIM installations will also trigger this rule
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate custom SHIM installations will also trigger this rule

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.011/T1546.011.md#atomic-test-3---registry-key-creation-andor-modification-events-for-sdb
- https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
- https://andreafortuna.org/2018/11/12/process-injection-and-persistence-using-application-shimming/

---

## Suspicious Shim Database Patching Activity

| Field | Value |
|---|---|
| **Sigma ID** | `bf344fea-d947-4ef4-9192-34d008315d3a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.011 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database_susp_application.yml)**

> Detects installation of new shim databases that try to patch sections of known processes for potential process injection or persistence.

```sql
-- ============================================================
-- Title:        Suspicious Shim Database Patching Activity
-- Sigma ID:     bf344fea-d947-4ef4-9192-34d008315d3a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.011
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database_susp_application.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\%')
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\csrss.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\dllhost.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\explorer.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\RuntimeBroker.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\services.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\sihost.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\svchost.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\taskhostw.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\winlogon.exe' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\WmiPrvSe.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/pillowmint-fin7s-monkey-thief/
- https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html

---

## Potential Persistence Via Shim Database In Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `6b6976a3-b0e6-4723-ac24-ae38a737af41` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.011 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database_uncommon_location.yml)**

> Detects the installation of a new shim database where the file is located in a non-default location

```sql
-- ============================================================
-- Title:        Potential Persistence Via Shim Database In Uncommon Location
-- Sigma ID:     6b6976a3-b0e6-4723-ac24-ae38a737af41
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1546.011
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database_uncommon_location.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DatabasePath%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
- https://andreafortuna.org/2018/11/12/process-injection-and-persistence-using-application-shimming/
- https://www.blackhat.com/docs/asia-14/materials/Erickson/Asia-14-Erickson-Persist-It-Using-And-Abusing-Microsofts-Fix-It-Patches.pdf

---

## Potential Persistence Via TypedPaths

| Field | Value |
|---|---|
| **Sigma ID** | `086ae989-9ca6-4fe7-895a-759c5544f247` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_typed_paths.yml)**

> Detects modification addition to the 'TypedPaths' key in the user or admin registry from a non standard application. Which might indicate persistence attempt

```sql
-- ============================================================
-- Title:        Potential Persistence Via TypedPaths
-- Sigma ID:     086ae989-9ca6-4fe7-895a-759c5544f247
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_typed_paths.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\%')
  AND NOT (procName IN ('C:\Windows\explorer.exe', 'C:\Windows\SysWOW64\explorer.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/dez_/status/1560101453150257154
- https://forensafe.com/blogs/typedpaths.html

---

## Potential Persistence Via Excel Add-in - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `961e33d1-4f86-4fcf-80ab-930a708b2f82` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1137.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_xll.yml)**

> Detect potential persistence via the creation of an excel add-in (XLL) file to make it run automatically when Excel is started.

```sql
-- ============================================================
-- Title:        Potential Persistence Via Excel Add-in - Registry
-- Sigma ID:     961e33d1-4f86-4fcf-80ab-930a708b2f82
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1137.006
-- Author:       frack113
-- Date:         2023-01-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_xll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Office\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Excel\\Options')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '/R %')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.xll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/4ae9580a1a8772db87a1b6cdb0d03e5af231e966/atomics/T1137.006/T1137.006.md
- https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence

---

## Potential Attachment Manager Settings Associations Tamper

| Field | Value |
|---|---|
| **Sigma ID** | `a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_policies_associations_tamper.yml)**

> Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information)

```sql
-- ============================================================
-- Title:        Potential Attachment Manager Settings Associations Tamper
-- Sigma ID:     a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_policies_associations_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://support.microsoft.com/en-us/topic/information-about-the-attachment-manager-in-microsoft-windows-c48a4dcd-8de5-2af5-ee9b-cd795ae42738
- https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465

---

## Potential Attachment Manager Settings Attachments Tamper

| Field | Value |
|---|---|
| **Sigma ID** | `ee77a5db-b0f3-4be2-bfd4-b58be1c6b15a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_policies_attachments_tamper.yml)**

> Detects tampering with attachment manager settings policies attachments (See reference for more information)

```sql
-- ============================================================
-- Title:        Potential Attachment Manager Settings Attachments Tamper
-- Sigma ID:     ee77a5db-b0f3-4be2-bfd4-b58be1c6b15a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_policies_attachments_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://support.microsoft.com/en-us/topic/information-about-the-attachment-manager-in-microsoft-windows-c48a4dcd-8de5-2af5-ee9b-cd795ae42738
- https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465

---

## Potential ClickFix Execution Pattern - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `f5fe36cf-f1ec-4c23-903d-09a3110f6bbb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_potential_clickfix_execution.yml)**

> Detects potential ClickFix malware execution patterns by monitoring registry modifications in RunMRU keys containing HTTP/HTTPS links.
ClickFix is known to be distributed through phishing campaigns and uses techniques like clipboard hijacking and fake CAPTCHA pages.
Through the fakecaptcha pages, the adversary tricks users into opening the Run dialog box and pasting clipboard-hijacked content,
such as one-liners that execute remotely hosted malicious files or scripts.


```sql
-- ============================================================
-- Title:        Potential ClickFix Execution Pattern - Registry
-- Sigma ID:     f5fe36cf-f1ec-4c23-903d-09a3110f6bbb
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1204.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-03-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_potential_clickfix_execution.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications using RunMRU with HTTP links
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%http://%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%https://%'))
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\%')
  AND ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%account%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%anti-bot%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%botcheck%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%captcha%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%challenge%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%confirmation%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%fraud%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%human%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%identification%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%identificator%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%identity%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%robot%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%validation%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%verification%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%verify%')))
  OR ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%comspec\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%bitsadmin%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%certutil%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%cmd%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%cscript%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%curl%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%finger%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%mshta%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%powershell%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%pwsh%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%regsvr32%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%rundll32%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%schtasks%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%wget%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%wscript%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications using RunMRU with HTTP links

**References:**
- https://github.com/JohnHammond/recaptcha-phish
- https://www.zscaler.com/blogs/security-research/deepseek-lure-using-captchas-spread-malware
- https://www.threatdown.com/blog/clipboard-hijacker-tries-to-install-a-trojan/
- https://app.any.run/tasks/5c16b4db-4b36-4039-a0ed-9b09abff8be2
- https://www.esentire.com/security-advisories/netsupport-rat-clickfix-distribution
- https://medium.com/@boutnaru/the-windows-foreniscs-journey-run-mru-run-dialog-box-most-recently-used-57375a02d724
- https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/
- https://medium.com/@poudelswachchhanda123/preventing-lnk-and-fakecaptcha-threats-a-system-hardening-approach-2f7b7ed2e493
- https://www.scpx.com.au/2025/11/16/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/

---

## Registry Modification for OCI DLL Redirection

| Field | Value |
|---|---|
| **Sigma ID** | `c0e0bdec-3e3d-47aa-9974-05539c999c89` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112, T1574.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_potential_oci_dll_redirection.yml)**

> Detects registry modifications related to 'OracleOciLib' and 'OracleOciLibPath' under 'MSDTC' settings.
Threat actors may modify these registry keys to redirect the loading of 'oci.dll' to a malicious DLL, facilitating phantom DLL hijacking via the MSDTC service.


```sql
-- ============================================================
-- Title:        Registry Modification for OCI DLL Redirection
-- Sigma ID:     c0e0bdec-3e3d-47aa-9974-05539c999c89
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1112, T1574.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2026-01-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_potential_oci_dll_redirection.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI\\OracleOciLib')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%oci.dll%')))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI\\OracleOciLibPath')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%SystemRoot\%\\System32\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.crowdstrike.com/en-us/blog/4-ways-adversaries-hijack-dlls/

---

## PowerShell as a Service in Registry

| Field | Value |
|---|---|
| **Sigma ID** | `4a5f5a5e-ac01-474b-9b4e-d61298c9df1d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | oscd.community, Natalia Shornikova |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_as_service.yml)**

> Detects that a powershell code is written to the registry as a service.

```sql
-- ============================================================
-- Title:        PowerShell as a Service in Registry
-- Sigma ID:     4a5f5a5e-ac01-474b-9b4e-d61298c9df1d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       oscd.community, Natalia Shornikova
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_as_service.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ImagePath')
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%powershell%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%pwsh%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

---

## PowerShell Script Execution Policy Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `8218c875-90b9-42e2-b60d-0b0069816d10` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Thurein Oo |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_enablescripts_enabled.yml)**

> Detects the enabling of the PowerShell script execution policy. Once enabled, this policy allows scripts to be executed.

```sql
-- ============================================================
-- Title:        PowerShell Script Execution Policy Enabled
-- Sigma ID:     8218c875-90b9-42e2-b60d-0b0069816d10
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems), Thurein Oo
-- Date:         2023-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_enablescripts_enabled.yml
-- Unmapped:     (none)
-- False Pos:    Likely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Policies\\Microsoft\\Windows\\PowerShell\\EnableScripts')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerShell::EnableScripts

---

## Potential PowerShell Execution Policy Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `fad91067-08c5-4d1a-8d8c-d96a21b37814` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_execution_policy.yml)**

> Detects changes to the PowerShell execution policy in order to bypass signing requirements for script execution

```sql
-- ============================================================
-- Title:        Potential PowerShell Execution Policy Tampering
-- Sigma ID:     fad91067-08c5-4d1a-8d8c-d96a21b37814
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_execution_policy.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy'))
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Bypass%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Unrestricted%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3

---

## Suspicious PowerShell In Registry Run Keys

| Field | Value |
|---|---|
| **Sigma ID** | `8d85cf08-bf97-4260-ba49-986a2a65129c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | frack113, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_in_run_keys.yml)**

> Detects potential PowerShell commands or code within registry run keys

```sql
-- ============================================================
-- Title:        Suspicious PowerShell In Registry Run Keys
-- Sigma ID:     8d85cf08-bf97-4260-ba49-986a2a65129c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       frack113, Florian Roth (Nextron Systems)
-- Date:         2022-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_in_run_keys.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin or third party scripts. Baseline according to your environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%'))
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%powershell%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%pwsh %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%FromBase64String%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.DownloadFile(%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.DownloadString(%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '% -w hidden %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '% -w 1 %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%-windowstyle hidden%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%-window hidden%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '% -nop %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '% -encodedcommand %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%-ExecutionPolicy Bypass%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Invoke-Expression%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%IEX (%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Invoke-Command%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%ICM -%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Invoke-WebRequest%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%IWR %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Invoke-RestMethod%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%IRM %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '% -noni %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '% -noninteractive %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin or third party scripts. Baseline according to your environment

**References:**
- https://github.com/frack113/atomic-red-team/blob/a9051c38de8a5320b31c7039efcbd3b56cf2d65a/atomics/T1547.001/T1547.001.md#atomic-test-9---systembc-malware-as-a-service-registry
- https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-exploits-proxyshell-in-attack.html
- https://github.com/HackTricks-wiki/hacktricks/blob/e4c7b21b8f36c97c35b7c622732b38a189ce18f7/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md

---

## PowerShell Logging Disabled Via Registry Key Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1564.001, T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.yml)**

> Detects changes to the registry for the currently logged-in user. In order to disable PowerShell module logging, script block logging or transcription and script execution logging

```sql
-- ============================================================
-- Title:        PowerShell Logging Disabled Via Registry Key Tampering
-- Sigma ID:     fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1564.001, T1112
-- Author:       frack113
-- Date:         2022-04-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\PowerShell\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\PowerShellCore\\%'))
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ModuleLogging\\EnableModuleLogging' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ScriptBlockLogging\\EnableScriptBlockLogging' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ScriptBlockLogging\\EnableScriptBlockInvocationLogging' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Transcription\\EnableTranscripting' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Transcription\\EnableInvocationHeader' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\EnableScripts'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-32---windows-powershell-logging-disabled

---

## Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG

| Field | Value |
|---|---|
| **Sigma ID** | `7021255e-5db3-4946-a8b9-0ba7a4644a69` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.yml)**

> Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".

```sql
-- ============================================================
-- Title:        Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG
-- Sigma ID:     7021255e-5db3-4946-a8b9-0ba7a4644a69
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       Swachchhanda Shrawan Poudel
-- Date:         2023-08-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Provisioning\\Commands\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
- https://twitter.com/0gtweet/status/1674399582162153472

---

## PUA - Sysinternal Tool Execution - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `25ffa65d-76d8-4da5-a832-3f2b0136e133` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1588.002 |
| **Author** | Markus Neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_pua_sysinternals_execution_via_eula.yml)**

> Detects the execution of a Sysinternals Tool via the creation of the "accepteula" registry key

```sql
-- ============================================================
-- Title:        PUA - Sysinternal Tool Execution - Registry
-- Sigma ID:     25ffa65d-76d8-4da5-a832-3f2b0136e133
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1588.002
-- Author:       Markus Neis
-- Date:         2017-08-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_pua_sysinternals_execution_via_eula.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of SysInternals tools; Programs that use the same Registry Key
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\EulaAccepted')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of SysInternals tools; Programs that use the same Registry Key

**References:**
- https://twitter.com/Moti_B/status/1008587936735035392

---

## Suspicious Execution Of Renamed Sysinternals Tools - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `f50f3c09-557d-492d-81db-9064a8d4e211` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1588.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_pua_sysinternals_renamed_execution_via_eula.yml)**

> Detects the creation of the "accepteula" key related to the Sysinternals tools being created from executables with the wrong name (e.g. a renamed Sysinternals tool)

```sql
-- ============================================================
-- Title:        Suspicious Execution Of Renamed Sysinternals Tools - Registry
-- Sigma ID:     f50f3c09-557d-492d-81db-9064a8d4e211
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1588.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_pua_sysinternals_renamed_execution_via_eula.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Active Directory Explorer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Handle%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\LiveKd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ProcDump%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Process Explorer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsExec%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsLoggedon%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsLoglist%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsPasswd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsPing%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsService%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SDelete%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\EulaAccepted'))
  AND NOT ((procName LIKE '%\\ADExplorer.exe' OR procName LIKE '%\\ADExplorer64.exe' OR procName LIKE '%\\handle.exe' OR procName LIKE '%\\handle64.exe' OR procName LIKE '%\\livekd.exe' OR procName LIKE '%\\livekd64.exe' OR procName LIKE '%\\procdump.exe' OR procName LIKE '%\\procdump64.exe' OR procName LIKE '%\\procexp.exe' OR procName LIKE '%\\procexp64.exe' OR procName LIKE '%\\PsExec.exe' OR procName LIKE '%\\PsExec64.exe' OR procName LIKE '%\\PsLoggedon.exe' OR procName LIKE '%\\PsLoggedon64.exe' OR procName LIKE '%\\psloglist.exe' OR procName LIKE '%\\psloglist64.exe' OR procName LIKE '%\\pspasswd.exe' OR procName LIKE '%\\pspasswd64.exe' OR procName LIKE '%\\PsPing.exe' OR procName LIKE '%\\PsPing64.exe' OR procName LIKE '%\\PsService.exe' OR procName LIKE '%\\PsService64.exe' OR procName LIKE '%\\sdelete.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research

---

## PUA - Sysinternals Tools Execution - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `c7da8edc-49ae-45a2-9e61-9fd860e4e73d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1588.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_pua_sysinternals_susp_execution_via_eula.yml)**

> Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.

```sql
-- ============================================================
-- Title:        PUA - Sysinternals Tools Execution - Registry
-- Sigma ID:     c7da8edc-49ae-45a2-9e61-9fd860e4e73d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1588.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_pua_sysinternals_susp_execution_via_eula.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of SysInternals tools. Filter the legitimate paths used in your environment
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Active Directory Explorer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Handle%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\LiveKd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Process Explorer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ProcDump%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsExec%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsLoglist%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsPasswd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SDelete%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Sysinternals%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\EulaAccepted'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of SysInternals tools. Filter the legitimate paths used in your environment

**References:**
- https://twitter.com/Moti_B/status/1008587936735035392

---

## Usage of Renamed Sysinternals Tools - RegistrySet

| Field | Value |
|---|---|
| **Sigma ID** | `8023f872-3f1d-4301-a384-801889917ab4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1588.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_renamed_sysinternals_eula_accepted.yml)**

> Detects non-sysinternals tools setting the "accepteula" key which normally is set on sysinternals tool execution

```sql
-- ============================================================
-- Title:        Usage of Renamed Sysinternals Tools - RegistrySet
-- Sigma ID:     8023f872-3f1d-4301-a384-801889917ab4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1588.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_renamed_sysinternals_eula_accepted.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsExec%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\ProcDump%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Handle%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\LiveKd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Process Explorer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsLoglist%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\PsPasswd%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Active Directory Explorer%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\EulaAccepted'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- Internal Research

---

## ETW Logging Disabled For rpcrt4.dll

| Field | Value |
|---|---|
| **Sigma ID** | `90f342e1-1aaa-4e43-b092-39fda57ed11e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112, T1562 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_rpcrt4_etw_tamper.yml)**

> Detects changes to the "ExtErrorInformation" key in order to disable ETW logging for rpcrt4.dll

```sql
-- ============================================================
-- Title:        ETW Logging Disabled For rpcrt4.dll
-- Sigma ID:     90f342e1-1aaa-4e43-b092-39fda57ed11e
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1112, T1562
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_rpcrt4_etw_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\Rpc\\ExtErrorInformation')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('DWORD (0x00000000)', 'DWORD (0x00000002)')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://redplait.blogspot.com/2020/07/whats-wrong-with-etw.html

---

## Potentially Suspicious Command Executed Via Run Dialog Box - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `a7df0e9e-91a5-459a-a003-4cde67c2ff5d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001 |
| **Author** | Ahmed Farouk, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.yml)**

> Detects execution of commands via the run dialog box on Windows by checking values of the "RunMRU" registry key.
This technique was seen being abused by threat actors to deceive users into pasting and executing malicious commands, often disguised as CAPTCHA verification steps.


```sql
-- ============================================================
-- Title:        Potentially Suspicious Command Executed Via Run Dialog Box - Registry
-- Sigma ID:     a7df0e9e-91a5-459a-a003-4cde67c2ff5d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001
-- Author:       Ahmed Farouk, Nasreddine Bencherchali
-- Date:         2024-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/@ahmed.moh.farou2/fake-captcha-campaign-on-arabic-pirated-movie-sites-delivers-lumma-stealer-4f203f7adabf
- https://medium.com/@shaherzakaria8/downloading-trojan-lumma-infostealer-through-capatcha-1f25255a0e71
- https://www.forensafe.com/blogs/runmrukey.html
- https://redcanary.com/blog/threat-intelligence/intelligence-insights-october-2024/

---

## ScreenSaver Registry Key Set

| Field | Value |
|---|---|
| **Sigma ID** | `40b6e656-4e11-4c0c-8772-c1cc6dae34ce` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218.011 |
| **Author** | Jose Luis Sanchez Martinez (@Joseliyo_Jstnk) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_scr_file_executed_by_rundll32.yml)**

> Detects registry key established after masqueraded .scr file execution using Rundll32 through desk.cpl

```sql
-- ============================================================
-- Title:        ScreenSaver Registry Key Set
-- Sigma ID:     40b6e656-4e11-4c0c-8772-c1cc6dae34ce
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218.011
-- Author:       Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)
-- Date:         2022-05-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_scr_file_executed_by_rundll32.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of screen saver
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\rundll32.exe'
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control Panel\\Desktop\\SCRNSAVE.EXE%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.scr'))
  AND NOT ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%C:\\Windows\\System32\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%C:\\Windows\\SysWOW64\\%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of screen saver

**References:**
- https://twitter.com/VakninHai/status/1517027824984547329
- https://twitter.com/pabraeken/status/998627081360695297
- https://jstnk9.github.io/jstnk9/research/InstallScreenSaver-SCR-files

---

## Potential SentinelOne Shell Context Menu Scan Command Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `6c304b02-06e6-402d-8be4-d5833cdf8198` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml)**

> Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne.

```sql
-- ============================================================
-- Title:        Potential SentinelOne Shell Context Menu Scan Command Tampering
-- Sigma ID:     6c304b02-06e6-402d-8be4-d5833cdf8198
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-03-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\shell\\SentinelOneScan\\command\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://mrd0x.com/sentinelone-persistence-via-menu-context/

---

## ServiceDll Hijack

| Field | Value |
|---|---|
| **Sigma ID** | `612e47e9-8a59-43a6-b404-f48683f45bd6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_servicedll_hijack.yml)**

> Detects changes to the "ServiceDLL" value related to a service in the registry.
This is often used as a method of persistence.


```sql
-- ============================================================
-- Title:        ServiceDll Hijack
-- Sigma ID:     612e47e9-8a59-43a6-b404-f48683f45bd6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       frack113
-- Date:         2022-02-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_servicedll_hijack.yml
-- Unmapped:     (none)
-- False Pos:    Administrative scripts; Installation of a service
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\System\\%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%ControlSet%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Parameters\\ServiceDll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts; Installation of a service

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md#atomic-test-4---tinyturla-backdoor-service-w64time
- https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/

---

## ETW Logging Disabled For SCM

| Field | Value |
|---|---|
| **Sigma ID** | `4f281b83-0200-4b34-bf35-d24687ea57c2` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112, T1562 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_services_etw_tamper.yml)**

> Detects changes to the "TracingDisabled" key in order to disable ETW logging for services.exe (SCM)

```sql
-- ============================================================
-- Title:        ETW Logging Disabled For SCM
-- Sigma ID:     4f281b83-0200-4b34-bf35-d24687ea57c2
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1112, T1562
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_services_etw_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows NT\\CurrentVersion\\Tracing\\SCM\\Regular\\TracingDisabled')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://redplait.blogspot.com/2020/07/whats-wrong-with-etw.html

---

## Registry Explorer Policy Modification

| Field | Value |
|---|---|
| **Sigma ID** | `1c3121ed-041b-4d97-a075-07f54f20fb4a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_set_nopolicies_user.yml)**

> Detects registry modifications that disable internal tools or functions in explorer (malware like Agent Tesla uses this technique)

```sql
-- ============================================================
-- Title:        Registry Explorer Policy Modification
-- Sigma ID:     1c3121ed-041b-4d97-a075-07f54f20fb4a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_set_nopolicies_user.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate admin script
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoLogOff' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDesktop' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFind' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFileMenu' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoClose' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSetTaskbar' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoPropertiesMyDocuments' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoTrayContextMenu'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate admin script

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md

---

## Persistence Via New SIP Provider

| Field | Value |
|---|---|
| **Sigma ID** | `5a2b21ee-6aaa-4234-ac9d-59a59edf90a1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1553.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sip_persistence.yml)**

> Detects when an attacker register a new SIP provider for persistence and defense evasion

```sql
-- ============================================================
-- Title:        Persistence Via New SIP Provider
-- Sigma ID:     5a2b21ee-6aaa-4234-ac9d-59a59edf90a1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1553.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sip_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate SIP being registered by the OS or different software.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate SIP being registered by the OS or different software.

**References:**
- https://persistence-info.github.io/Data/codesigning.html
- https://github.com/gtworek/PSBits/tree/master/SIP
- https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf

---

## Tamper With Sophos AV Registry Keys

| Field | Value |
|---|---|
| **Sigma ID** | `9f4662ac-17ca-43aa-8f12-5d7b989d0101` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml)**

> Detects tamper attempts to sophos av functionality via registry key modification

```sql
-- ============================================================
-- Title:        Tamper With Sophos AV Registry Keys
-- Sigma ID:     9f4662ac-17ca-43aa-8f12-5d7b989d0101
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Some FP may occur when the feature is disabled by the AV itself, you should always investigate if the action was legitimate
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Sophos Endpoint Defense\\TamperProtection\\Config\\SAVEnabled%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Sophos Endpoint Defense\\TamperProtection\\Config\\SEDEnabled%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Sophos\\SAVService\\TamperProtection\\Enabled%'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some FP may occur when the feature is disabled by the AV itself, you should always investigate if the action was legitimate

**References:**
- https://redacted.com/blog/bianlian-ransomware-gang-gives-it-a-go/

---

## Hiding User Account Via SpecialAccounts Registry Key

| Field | Value |
|---|---|
| **Sigma ID** | `f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1564.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_special_accounts.yml)**

> Detects modifications to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.

```sql
-- ============================================================
-- Title:        Hiding User Account Via SpecialAccounts Registry Key
-- Sigma ID:     f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1564.002
-- Author:       Nasreddine Bencherchali (Nextron Systems), frack113
-- Date:         2022-07-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_special_accounts.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1564.002/T1564.002.md#atomic-test-3---create-hidden-user-in-registry

---

## Activate Suppression of Windows Security Center Notifications

| Field | Value |
|---|---|
| **Sigma ID** | `0c93308a-3f1b-40a9-b649-57ea1a1c1d63` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_suppress_defender_notifications.yml)**

> Detect set Notification_Suppress to 1 to disable the Windows security center notification

```sql
-- ============================================================
-- Title:        Activate Suppression of Windows Security Center Notifications
-- Sigma ID:     0c93308a-3f1b-40a9-b649-57ea1a1c1d63
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       frack113
-- Date:         2022-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_suppress_defender_notifications.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration\\Notification\_Suppress')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md

---

## Suspicious Keyboard Layout Load

| Field | Value |
|---|---|
| **Sigma ID** | `34aa0252-6039-40ff-951f-939fd6ce47d8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1588.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.yml)**

> Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only

```sql
-- ============================================================
-- Title:        Suspicious Keyboard Layout Load
-- Sigma ID:     34aa0252-6039-40ff-951f-939fd6ce47d8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1588.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.yml
-- Unmapped:     (none)
-- False Pos:    Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Keyboard Layout\\Preload\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Keyboard Layout\\Substitutes\\%'))
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%00000429%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%00050429%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%0000042a%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)

**References:**
- https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
- https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files

---

## Potential PendingFileRenameOperations Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `4eec988f-7bf0-49f1-8675-1e6a510b3a2a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_pendingfilerenameoperations.yml)**

> Detect changes to the "PendingFileRenameOperations" registry key from uncommon or suspicious images locations to stage currently used files for rename or deletion after reboot.


```sql
-- ============================================================
-- Title:        Potential PendingFileRenameOperations Tampering
-- Sigma ID:     4eec988f-7bf0-49f1-8675-1e6a510b3a2a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.003
-- Author:       frack113
-- Date:         2023-01-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_pendingfilerenameoperations.yml
-- Unmapped:     (none)
-- False Pos:    Installers and updaters may set currently in use files for rename or deletion after a reboot.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Installers and updaters may set currently in use files for rename or deletion after a reboot.

**References:**
- https://any.run/report/3ecd4763ffc944fdc67a9027e459cd4f448b1a8d1b36147977afaf86bbf2a261/64b0ba45-e7ce-423b-9a1d-5b4ea59521e6
- https://devblogs.microsoft.com/scripting/determine-pending-reboot-statuspowershell-style-part-1/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960241(v=technet.10)?redirectedfrom=MSDN
- https://www.trendmicro.com/en_us/research/21/j/purplefox-adds-new-backdoor-that-uses-websockets.html
- https://www.trendmicro.com/en_us/research/19/i/purple-fox-fileless-malware-with-rookit-component-delivered-by-rig-exploit-kit-now-abuses-powershell.html

---

## Suspicious Printer Driver Empty Manufacturer

| Field | Value |
|---|---|
| **Sigma ID** | `e0813366-0407-449a-9869-a2db1119dc41` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_printer_driver.yml)**

> Detects a suspicious printer driver installation with an empty Manufacturer value

```sql
-- ============================================================
-- Title:        Suspicious Printer Driver Empty Manufacturer
-- Sigma ID:     e0813366-0407-449a-9869-a2db1119dc41
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2020-07-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_printer_driver.yml
-- Unmapped:     (none)
-- False Pos:    Alerts on legitimate printer drivers that do not set any more details in the Manufacturer value
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Print\\Environments\\Windows x64\\Drivers%' AND metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Manufacturer%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '(Empty)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Alerts on legitimate printer drivers that do not set any more details in the Manufacturer value

**References:**
- https://twitter.com/SBousseaden/status/1410545674773467140

---

## Registry Persistence via Explorer Run Key

| Field | Value |
|---|---|
| **Sigma ID** | `b7916c2a-fa2f-4795-9477-32b731f70f11` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Florian Roth (Nextron Systems), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml)**

> Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder

```sql
-- ============================================================
-- Title:        Registry Persistence via Explorer Run Key
-- Sigma ID:     b7916c2a-fa2f-4795-9477-32b731f70f11
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Florian Roth (Nextron Systems), oscd.community
-- Date:         2018-07-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run')
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\$Recycle.bin\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\ProgramData\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Users\\Default\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Local\\Temp\\%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/

---

## New RUN Key Pointing to Suspicious Folder

| Field | Value |
|---|---|
| **Sigma ID** | `02ee49e2-e294-4d0f-9278-f5b3212fc588` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Florian Roth (Nextron Systems), Markus Neis, Sander Wiebing, Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_run_key_img_folder.yml)**

> Detects suspicious new RUN key element pointing to an executable in a suspicious folder

```sql
-- ============================================================
-- Title:        New RUN Key Pointing to Suspicious Folder
-- Sigma ID:     02ee49e2-e294-4d0f-9278-f5b3212fc588
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1547.001
-- Author:       Florian Roth (Nextron Systems), Markus Neis, Sander Wiebing, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2018-08-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_run_key_img_folder.yml
-- Unmapped:     (none)
-- False Pos:    Software using weird folders for updates
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%'))
  AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Perflogs%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\ProgramData'%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Windows\\Temp%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Temp%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Local\\Temp%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Roaming%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\$Recycle.bin%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Users\\Default%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%:\\Users\\public%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%temp\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%tmp\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%Public\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%AppData\%%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Software using weird folders for updates

**References:**
- https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
- https://github.com/HackTricks-wiki/hacktricks/blob/e4c7b21b8f36c97c35b7c622732b38a189ce18f7/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md

---

## Suspicious Space Characters in RunMRU Registry Path - ClickFix

| Field | Value |
|---|---|
| **Sigma ID** | `7a1b4c5e-8f3d-4b9a-7c2e-1f4a5b8c6d9e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.004, T1027.010 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_runmru_space_character.yml)**

> Detects the occurrence of numerous space characters in RunMRU registry paths, which may indicate execution via phishing lures using clickfix techniques to hide malicious commands in the Windows Run dialog box from naked eyes.


```sql
-- ============================================================
-- Title:        Suspicious Space Characters in RunMRU Registry Path - ClickFix
-- Sigma ID:     7a1b4c5e-8f3d-4b9a-7c2e-1f4a5b8c6d9e
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1204.004, T1027.010
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_runmru_space_character.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%#%'))
  AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://expel.com/blog/cache-smuggling-when-a-picture-isnt-a-thousand-words/
- https://github.com/JohnHammond/recaptcha-phish

---

## Suspicious Service Installed

| Field | Value |
|---|---|
| **Sigma ID** | `f2485272-a156-4773-82d7-1d178bc4905b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | xknow (@xknow_infosec), xorxes (@xor_xes) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_service_installed.yml)**

> Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders.
Both services are used in the tool Ghost-In-The-Logs (https://github.com/bats3c/Ghost-In-The-Logs), which uses KDU (https://github.com/hfiref0x/KDU)


```sql
-- ============================================================
-- Title:        Suspicious Service Installed
-- Sigma ID:     f2485272-a156-4773-82d7-1d178bc4905b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       xknow (@xknow_infosec), xorxes (@xor_xes)
-- Date:         2019-04-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_service_installed.yml
-- Unmapped:     (none)
-- False Pos:    Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] IN ('HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath', 'HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath'))
  AND NOT (((procName LIKE '%\\procexp64.exe' OR procName LIKE '%\\procexp.exe' OR procName LIKE '%\\procmon64.exe' OR procName LIKE '%\\procmon.exe' OR procName LIKE '%\\handle.exe' OR procName LIKE '%\\handle64.exe')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS%'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other legimate tools using this service names and drivers. Note - clever attackers may easily bypass this detection by just renaming the services. Therefore just Medium-level and don't rely on it.

**References:**
- https://web.archive.org/web/20200419024230/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/

---

## Suspicious Shell Open Command Registry Modification

| Field | Value |
|---|---|
| **Sigma ID** | `9e8894c0-0ae0-11ef-9d85-1f2942bec57c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548.002, T1546.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_shell_open_keys_modification_patterns.yml)**

> Detects modifications to shell open registry keys that point to suspicious locations typically used by malware for persistence.
Generally, modifications to the `*\shell\open\command` registry key can indicate an attempt to change the default action for opening files,
and various UAC bypass or persistence techniques involve modifying these keys to execute malicious scripts or binaries.


```sql
-- ============================================================
-- Title:        Suspicious Shell Open Command Registry Modification
-- Sigma ID:     9e8894c0-0ae0-11ef-9d85-1f2942bec57c
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1548.002, T1546.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2026-01-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_shell_open_keys_modification_patterns.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate software installations or updates that modify the shell open command registry keys to these locations.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\shell\\open\\command\\%')
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\$Recycle.Bin\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Contacts\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Music\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\PerfLogs\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Photos\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Pictures\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Videos\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\Windows\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%AppData\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%LocalAppData\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%Temp\%%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\%tmp\%%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software installations or updates that modify the shell open command registry keys to these locations.

**References:**
- https://www.trendmicro.com/en_us/research/25/f/water-curse.html

---

## Suspicious Space Characters in TypedPaths Registry Path - FileFix

| Field | Value |
|---|---|
| **Sigma ID** | `8f2a5c3d-9e4b-4a7c-8d1f-2e5a6b9c3d7e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.004, T1027.010 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_typedpaths_space_characters.yml)**

> Detects the occurrence of numerous space characters in TypedPaths registry paths, which may indicate execution via phishing lures using file-fix techniques to hide malicious commands.


```sql
-- ============================================================
-- Title:        Suspicious Space Characters in TypedPaths Registry Path - FileFix
-- Sigma ID:     8f2a5c3d-9e4b-4a7c-8d1f-2e5a6b9c3d7e
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1204.004, T1027.010
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_typedpaths_space_characters.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\url1')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%#%'))
  AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%            %')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://expel.com/blog/cache-smuggling-when-a-picture-isnt-a-thousand-words/
- https://mrd0x.com/filefix-clickfix-alternative/

---

## Modify User Shell Folders Startup Value

| Field | Value |
|---|---|
| **Sigma ID** | `9c226817-8dc9-46c2-a58d-66655aafd7dc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | frack113, Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.yml)**

> Detect modification of the User Shell Folders registry values for Startup or Common Startup which could indicate persistence attempts.
Attackers may modify User Shell Folders registry keys to point to malicious executables or scripts that will be executed during startup.
This technique is often used to maintain persistence on a compromised system by ensuring that the malicious payload is executed automatically.


```sql
-- ============================================================
-- Title:        Modify User Shell Folders Startup Value
-- Sigma ID:     9c226817-8dc9-46c2-a58d-66655aafd7dc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       frack113, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2022-10-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders%'))
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Common Startup' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Startup')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1547.001/T1547.001.md
- https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/

---

## WFP Filter Added via Registry

| Field | Value |
|---|---|
| **Sigma ID** | `1f1d8209-636e-4c6c-a137-781cca8b82f9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1562, T1569.002 |
| **Author** | Frack113 |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_wfp_filter_added.yml)**

> Detects registry modifications that add Windows Filtering Platform (WFP) filters, which may be used to block security tools and EDR agents from reporting events.


```sql
-- ============================================================
-- Title:        WFP Filter Added via Registry
-- Sigma ID:     1f1d8209-636e-4c6c-a137-781cca8b82f9
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution | T1562, T1569.002
-- Author:       Frack113
-- Date:         2025-10-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_wfp_filter_added.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\BFE\\Parameters\\Policy\\Persistent\\Filter\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/netero1010/EDRSilencer/blob/0e73a7037ec65c52894d8208e6f605a7da0a34a6/EDRSilencer.c
- https://www.huntress.com/blog/silencing-the-edr-silencers
- https://www.trendmicro.com/en_us/research/24/j/edrsilencer-disrupting-endpoint-security-solutions.html

---

## Suspicious Environment Variable Has Been Registered

| Field | Value |
|---|---|
| **Sigma ID** | `966315ef-c5e1-4767-ba25-fce9c8de3660` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_suspicious_env_variables.yml)**

> Detects the creation of user-specific or system-wide environment variables via the registry. Which contains suspicious commands and strings

```sql
-- ============================================================
-- Title:        Suspicious Environment Variable Has Been Registered
-- Sigma ID:     966315ef-c5e1-4767-ba25-fce9c8de3660
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_suspicious_env_variables.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('powershell', 'pwsh')))
  OR ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\AppData\\Local\\Temp\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%C:\\Users\\Public\\%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%TVqQAAMAAAAEAAAA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%TVpQAAIAAAAEAA8A%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%TVqAAAEAAAAEABAA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%TVoAAAAAAAAAAAAA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%TVpTAQEAAAAEAAAA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%SW52b2tlL%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%ludm9rZS%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%JbnZva2Ut%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%SQBuAHYAbwBrAGUALQ%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%kAbgB2AG8AawBlAC0A%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%JAG4AdgBvAGsAZQAtA%')))
  OR ((indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'SUVY%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'SQBFAF%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'SQBuAH%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'cwBhA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'aWV4%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'aQBlA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'R2V0%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'dmFy%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'dgBhA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'dXNpbm%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'H4sIA%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'Y21k%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'cABhAH%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'Qzpc%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'Yzpc%')))
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Environment\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://infosec.exchange/@sbousseaden/109542254124022664

---

## Enable LM Hash Storage

| Field | Value |
|---|---|
| **Sigma ID** | `c420410f-c2d8-4010-856b-dffe21866437` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_system_lsa_nolmhash.yml)**

> Detects changes to the "NoLMHash" registry value in order to allow Windows to store LM Hashes.
By setting this registry value to "0" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases.


```sql
-- ============================================================
-- Title:        Enable LM Hash Storage
-- Sigma ID:     c420410f-c2d8-4010-856b-dffe21866437
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-12-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_system_lsa_nolmhash.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%System\\CurrentControlSet\\Control\\Lsa\\NoLMHash')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
- https://www.sans.org/blog/protecting-privileged-domain-accounts-lm-hashes-the-good-the-bad-and-the-ugly/

---

## Scheduled TaskCache Change by Uncommon Program

| Field | Value |
|---|---|
| **Sigma ID** | `4720b7df-40c3-48fd-bbdf-fd4b3c464f0d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053, T1053.005 |
| **Author** | Syed Hasan (@syedhasan009) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_taskcache_entry.yml)**

> Monitor the creation of a new key under 'TaskCache' when a new scheduled task is registered by a process that is not svchost.exe, which is suspicious

```sql
-- ============================================================
-- Title:        Scheduled TaskCache Change by Uncommon Program
-- Sigma ID:     4720b7df-40c3-48fd-bbdf-fd4b3c464f0d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053, T1053.005
-- Author:       Syed Hasan (@syedhasan009)
-- Date:         2021-06-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_taskcache_entry.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
- https://labs.f-secure.com/blog/scheduled-task-tampering/

---

## Potential Registry Persistence Attempt Via Windows Telemetry

| Field | Value |
|---|---|
| **Sigma ID** | `73a883d0-0348-4be4-a8d8-51031c2564f8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053.005 |
| **Author** | Lednyov Alexey, oscd.community, Sreeman |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_telemetry_persistence.yml)**

> Detects potential persistence behavior using the windows telemetry registry key.
Windows telemetry makes use of the binary CompatTelRunner.exe to run a variety of commands and perform the actual telemetry collections.
This binary was created to be easily extensible, and to that end, it relies on the registry to instruct on which commands to run.
The problem is, it will run any arbitrary command without restriction of location or type.


```sql
-- ============================================================
-- Title:        Potential Registry Persistence Attempt Via Windows Telemetry
-- Sigma ID:     73a883d0-0348-4be4-a8d8-51031c2564f8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053.005
-- Author:       Lednyov Alexey, oscd.community, Sreeman
-- Date:         2020-10-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_telemetry_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Command')
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.bat%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.bin%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.cmd%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dat%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dll%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.exe%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.hta%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.jar%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.js%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.msi%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.ps%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.sh%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.vb%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/

---

## RDP Sensitive Settings Changed to Zero

| Field | Value |
|---|---|
| **Sigma ID** | `a2863fbc-d5cb-48d5-83fb-d976d4b1743b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_terminal_server_suspicious.yml)**

> Detects tampering of RDP Terminal Service/Server sensitive settings.
Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections', etc.


```sql
-- ============================================================
-- Title:        RDP Sensitive Settings Changed to Zero
-- Sigma ID:     a2863fbc-d5cb-48d5-83fb-d976d4b1743b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali
-- Date:         2022-09-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_terminal_server_suspicious.yml
-- Unmapped:     (none)
-- False Pos:    Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\fDenyTSConnections' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\fSingleSessionPerUser' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\UserAuthentication'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)

**References:**
- https://web.archive.org/web/20200929062532/https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
- http://woshub.com/rds-shadow-how-to-connect-to-a-user-session-in-windows-server-2012-r2/
- https://twitter.com/SagieSec/status/1469001618863624194?t=HRf0eA0W1YYzkTSHb-Ky1A&s=03
- https://threathunterplaybook.com/hunts/windows/190407-RegModEnableRDPConnections/notebook.html
- https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
- http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/
- https://admx.help/HKLM/SOFTWARE/Policies/Microsoft/Windows%20NT/Terminal%20Services

---

## RDP Sensitive Settings Changed

| Field | Value |
|---|---|
| **Sigma ID** | `3f6b7b62-61aa-45db-96bd-9c31b36b653c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_terminal_server_tampering.yml)**

> Detects tampering of RDP Terminal Service/Server sensitive settings.
Such as allowing unauthorized users access to a system via the 'fAllowUnsolicited' or enabling RDP via 'fDenyTSConnections', etc.

Below is a list of registry keys/values that are monitored by this rule:

- Shadow: Used to enable Remote Desktop shadowing, which allows an administrator to view or control a user's session.
- DisableRemoteDesktopAntiAlias: Disables anti-aliasing for remote desktop sessions.
- DisableSecuritySettings: Disables certain security settings for Remote Desktop connections.
- fAllowUnsolicited: Allows unsolicited remote assistance offers.
- fAllowUnsolicitedFullControl: Allows unsolicited remote assistance offers with full control.
- InitialProgram: Specifies a program to run automatically when a user logs on to a remote computer.
- ServiceDll: Used in RDP hijacking techniques to specify a custom DLL to be loaded by the Terminal Services service.
- SecurityLayer: Specifies the security layer used for RDP connections.


```sql
-- ============================================================
-- Title:        RDP Sensitive Settings Changed
-- Sigma ID:     3f6b7b62-61aa-45db-96bd-9c31b36b653c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Samir Bousseaden, David ANDRE, Roberto Rodriguez @Cyb3rWard0g, Nasreddine Bencherchali
-- Date:         2022-08-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_terminal_server_tampering.yml
-- Unmapped:     (none)
-- False Pos:    Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Terminal Server\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Windows NT\\Terminal Services\\%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Shadow')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] IN ('DWORD (0x00000001)', 'DWORD (0x00000002)', 'DWORD (0x00000003)', 'DWORD (0x00000004)')))
  OR ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Terminal Server\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Windows NT\\Terminal Services\\%'))
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DisableRemoteDesktopAntiAlias' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DisableSecuritySettings' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\fAllowUnsolicited' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\fAllowUnsolicitedFullControl'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Terminal Server\\InitialProgram%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\services\\TermService\\Parameters\\ServiceDll%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Terminal Server\\WinStations\\RDP-Tcp\\SecurityLayer%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Windows NT\\Terminal Services\\InitialProgram%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some of the keys mentioned here could be modified by an administrator while setting group policy (it should be investigated either way)

**References:**
- http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/
- http://woshub.com/rds-shadow-how-to-connect-to-a-user-session-in-windows-server-2012-r2/
- https://admx.help/HKLM/SOFTWARE/Policies/Microsoft/Windows%20NT/Terminal%20Services
- https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
- https://blog.sekoia.io/darkgate-internals/
- https://blog.talosintelligence.com/understanding-the-phobos-affiliate-structure/
- https://github.com/redcanaryco/atomic-red-team/blob/02c7d02fe1f1feb0fc7944550408ea8224273994/atomics/T1112/T1112.md#atomic-test-63---disable-remote-desktop-anti-alias-setting-through-registry
- https://github.com/redcanaryco/atomic-red-team/blob/02c7d02fe1f1feb0fc7944550408ea8224273994/atomics/T1112/T1112.md#atomic-test-64---disable-remote-desktop-security-settings-through-registry
- https://github.com/redcanaryco/atomic-red-team/blob/dd526047b8c399c312fee47d1e6fb531164da54d/atomics/T1112/T1112.yaml#L790
- https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
- https://threathunterplaybook.com/hunts/windows/190407-RegModEnableRDPConnections/notebook.html
- https://twitter.com/SagieSec/status/1469001618863624194?t=HRf0eA0W1YYzkTSHb-Ky1A&s=03
- https://web.archive.org/web/20200929062532/https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
- https://www.trendmicro.com/en_us/research/25/i/unmasking-the-gentlemen-ransomware.html

---

## New TimeProviders Registered With Uncommon DLL Name

| Field | Value |
|---|---|
| **Sigma ID** | `e88a6ddc-74f7-463b-9b26-f69fc0d2ce85` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_timeproviders_dllname.yml)**

> Detects processes setting a new DLL in DllName in under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProvider.
Adversaries may abuse time providers to execute DLLs when the system boots.
The Windows Time service (W32Time) enables time synchronization across and within domains.


```sql
-- ============================================================
-- Title:        New TimeProviders Registered With Uncommon DLL Name
-- Sigma ID:     e88a6ddc-74f7-463b-9b26-f69fc0d2ce85
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.003
-- Author:       frack113
-- Date:         2022-06-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_timeproviders_dllname.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Services\\W32Time\\TimeProviders%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\DllName'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.003/T1547.003.md

---

## Old TLS1.0/TLS1.1 Protocol Version Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `439957a7-ad86-4a8f-9705-a28131c6821b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_tls_protocol_old_version_enabled.yml)**

> Detects applications or users re-enabling old TLS versions by setting the "Enabled" value to "1" for the "Protocols" registry key.

```sql
-- ============================================================
-- Title:        Old TLS1.0/TLS1.1 Protocol Version Enabled
-- Sigma ID:     439957a7-ad86-4a8f-9705-a28131c6821b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-09-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_tls_protocol_old_version_enabled.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate enabling of the old tls versions due to incompatibility
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\%'))
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Enabled')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate enabling of the old tls versions due to incompatibility

**References:**
- https://techcommunity.microsoft.com/t5/windows-it-pro-blog/tls-1-0-and-tls-1-1-soon-to-be-disabled-in-windows/ba-p/3887947

---

## COM Hijacking via TreatAs

| Field | Value |
|---|---|
| **Sigma ID** | `dc5c24af-6995-49b2-86eb-a9ff62199e82` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.015 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_treatas_persistence.yml)**

> Detect modification of TreatAs key to enable "rundll32.exe -sta" command

```sql
-- ============================================================
-- Title:        COM Hijacking via TreatAs
-- Sigma ID:     dc5c24af-6995-49b2-86eb-a9ff62199e82
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.015
-- Author:       frack113
-- Date:         2022-08-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_treatas_persistence.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%TreatAs\\(Default)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md
- https://www.youtube.com/watch?v=3gz1QmiMhss&t=1251s

---

## Potential Signing Bypass Via Windows Developer Features - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `b110ebaf-697f-4da1-afd5-b536fa27a2c1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_turn_on_dev_features.yml)**

> Detects when the enablement of developer features such as "Developer Mode" or "Application Sideloading". Which allows the user to install untrusted packages.

```sql
-- ============================================================
-- Title:        Potential Signing Bypass Via Windows Developer Features - Registry
-- Sigma ID:     b110ebaf-697f-4da1-afd5-b536fa27a2c1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_turn_on_dev_features.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Policies\\Microsoft\\Windows\\Appx\\%'))
    AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AllowAllTrustedApps' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AllowDevelopmentWithoutDevLicense'))
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/malmoeb/status/1560536653709598721
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/

---

## UAC Bypass via Event Viewer

| Field | Value |
|---|---|
| **Sigma ID** | `7c81fec3-1c1d-43b0-996a-46753041b1b6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_eventvwr.yml)**

> Detects UAC bypass method using Windows event viewer

```sql
-- ============================================================
-- Title:        UAC Bypass via Event Viewer
-- Sigma ID:     7c81fec3-1c1d-43b0-996a-46753041b1b6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_eventvwr.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\mscfile\\shell\\open\\command')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
- https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100

---

## UAC Bypass via Sdclt

| Field | Value |
|---|---|
| **Sigma ID** | `5b872a46-3b90-45c1-8419-f675db8053aa` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Omer Yampel, Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.yml)**

> Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe (e.g. UACMe 53)

```sql
-- ============================================================
-- Title:        UAC Bypass via Sdclt
-- Sigma ID:     5b872a46-3b90-45c1-8419-f675db8053aa
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Omer Yampel, Christian Burkard (Nextron Systems)
-- Date:         2017-03-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand')
  OR (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Classes\\Folder\\shell\\open\\command\\SymbolicLinkValue')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (match(metrics_string.value[indexOf(metrics_string.name,'regValue')], '-1[0-9]{3}\\Software\\Classes\\')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Abusing Winsat Path Parsing - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `6597be7b-ac61-4ac8-bef4-d3ec88174853` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_winsat.yml)**

> Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

```sql
-- ============================================================
-- Title:        UAC Bypass Abusing Winsat Path Parsing - Registry
-- Sigma ID:     6597be7b-ac61-4ac8-bef4-d3ec88174853
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_winsat.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Root\\InventoryApplicationFile\\winsat.exe|%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\LowerCaseLongPath')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE 'c:\\users\\%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%\\appdata\\local\\temp\\system32\\winsat.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Bypass Using Windows Media Player - Registry

| Field | Value |
|---|---|
| **Sigma ID** | `5f9db380-ea57-4d1e-beab-8a2d33397e93` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548.002 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_wmp.yml)**

> Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)

```sql
-- ============================================================
-- Title:        UAC Bypass Using Windows Media Player - Registry
-- Sigma ID:     5f9db380-ea57-4d1e-beab-8a2d33397e93
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548.002
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_wmp.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store\\C:\\Program Files\\Windows Media Player\\osk.exe')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'Binary Data'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/hfiref0x/UACME

---

## UAC Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `48437c39-9e5f-47fb-af95-3d663c3f2919` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548.002 |
| **Author** | frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable.yml)**

> Detects when an attacker tries to disable User Account Control (UAC) by setting the registry value "EnableLUA" to 0.


```sql
-- ============================================================
-- Title:        UAC Disabled
-- Sigma ID:     48437c39-9e5f-47fb-af95-3d663c3f2919
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1548.002
-- Author:       frack113
-- Date:         2022-01-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md

---

## UAC Notification Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `c5f6a85d-b647-40f7-bbad-c10b66bab038` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548.002 |
| **Author** | frack113, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable_notification.yml)**

> Detects when an attacker tries to disable User Account Control (UAC) notification by tampering with the "UACDisableNotify" value.
UAC is a critical security feature in Windows that prevents unauthorized changes to the operating system. It prompts the user for permission or an administrator password before allowing actions that could affect the system's operation or change settings that affect other users.
When "UACDisableNotify" is set to 1, UAC prompts are suppressed.


```sql
-- ============================================================
-- Title:        UAC Notification Disabled
-- Sigma ID:     c5f6a85d-b647-40f7-bbad-c10b66bab038
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1548.002
-- Author:       frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable_notification.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Security Center\\UACDisableNotify%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md
- https://securityintelligence.com/x-force/x-force-hive0129-targeting-financial-institutions-latam-banking-trojan/

---

## UAC Secure Desktop Prompt Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `0d7ceeef-3539-4392-8953-3dc664912714` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548.002 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable_secure_desktop_prompt.yml)**

> Detects when an attacker tries to change User Account Control (UAC) elevation request destination via the "PromptOnSecureDesktop" value.
The "PromptOnSecureDesktop" setting specifically determines whether UAC prompts are displayed on the secure desktop. The secure desktop is a separate desktop environment that's isolated from other processes running on the system. It's designed to prevent malicious software from intercepting or tampering with UAC prompts.
When "PromptOnSecureDesktop" is set to 0, UAC prompts are displayed on the user's current desktop instead of the secure desktop. This reduces the level of security because it potentially exposes the prompts to manipulation by malicious software.


```sql
-- ============================================================
-- Title:        UAC Secure Desktop Prompt Disabled
-- Sigma ID:     0d7ceeef-3539-4392-8953-3dc664912714
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1548.002
-- Author:       frack113
-- Date:         2024-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable_secure_desktop_prompt.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop%')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md

---

## VBScript Payload Stored in Registry

| Field | Value |
|---|---|
| **Sigma ID** | `46490193-1b22-4c29-bdd6-5bf63907216f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_vbs_payload_stored.yml)**

> Detects VBScript content stored into registry keys as seen being used by UNC2452 group

```sql
-- ============================================================
-- Title:        VBScript Payload Stored in Registry
-- Sigma ID:     46490193-1b22-4c29-bdd6-5bf63907216f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_vbs_payload_stored.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%Software\\Microsoft\\Windows\\CurrentVersion%')
    AND (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%vbscript:%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%jscript:%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%mshtml,%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%RunHTMLApplication%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%Execute(%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%CreateObject%' OR metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%window.close%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/

---

## Windows Vulnerable Driver Blocklist Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `d526c60a-e236-4011-b165-831ffa52ab70` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_vulnerable_driver_blocklist_disable.yml)**

> Detects when the Windows Vulnerable Driver Blocklist is set to disabled. This setting is crucial for preventing the loading of known vulnerable drivers,
and its modification may indicate an attempt to bypass security controls. It is often targeted by threat actors to facilitate the installation of malicious or vulnerable drivers,
particularly in scenarios involving Endpoint Detection and Response (EDR) bypass techniques.
This rule applies to systems that support the Vulnerable Driver Blocklist feature, including Windows 10 version 1903 and later, and Windows Server 2022 and later.
Note that this change will require a reboot to take effect, and this rule only detects the registry modification action.


```sql
-- ============================================================
-- Title:        Windows Vulnerable Driver Blocklist Disabled
-- Sigma ID:     d526c60a-e236-4011-b165-831ffa52ab70
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2026-01-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_vulnerable_driver_blocklist_disable.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely and should be investigated immediately.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Control\\CI\\Config\\VulnerableDriverBlocklistEnable')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000000)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely and should be investigated immediately.

**References:**
- https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
- https://www.sophos.com/en-us/blog/sharpening-the-knife-gold-blades-strategic-evolution
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

---

## Execution DLL of Choice Using WAB.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `fc014922-5def-4da9-a0fc-28c973f41bfb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | oscd.community, Natalia Shornikova |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_wab_dllpath_reg_change.yml)**

> This rule detects that the path to the DLL written in the registry is different from the default one. Launched WAB.exe tries to load the DLL from Registry.

```sql
-- ============================================================
-- Title:        Execution DLL of Choice Using WAB.EXE
-- Sigma ID:     fc014922-5def-4da9-a0fc-28c973f41bfb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       oscd.community, Natalia Shornikova
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_wab_dllpath_reg_change.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Software\\Microsoft\\WAB\\DLLPath')
  AND NOT (indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = '%CommonProgramFiles%\System\wab32.dll')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/LOLBAS-Project/LOLBAS/blob/8283d8d91552213ded165fd36deb6cb9534cb443/yml/OSBinaries/Wab.yml
- https://twitter.com/Hexacorn/status/991447379864932352
- http://www.hexacorn.com/blog/2018/05/01/wab-exe-as-a-lolbin/

---

## Wdigest Enable UseLogonCredential

| Field | Value |
|---|---|
| **Sigma ID** | `d6a9b252-c666-4de6-8806-5561bbbd3bdc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml)**

> Detects potential malicious modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to enable clear-text credentials

```sql
-- ============================================================
-- Title:        Wdigest Enable UseLogonCredential
-- Sigma ID:     d6a9b252-c666-4de6-8806-5561bbbd3bdc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2019-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%WDigest\\UseLogonCredential')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://threathunterplaybook.com/hunts/windows/190510-RegModWDigestDowngrade/notebook.html
- https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649
- https://github.com/redcanaryco/atomic-red-team/blob/73fcfa1d4863f6a4e17f90e54401de6e30a312bb/atomics/T1112/T1112.md#atomic-test-3---modify-registry-to-store-logon-credentials

---

## Disable Windows Defender Functionalities Via Registry Keys

| Field | Value |
|---|---|
| **Sigma ID** | `0eb46774-f1ab-4a74-8238-1155855f2263` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | AlertIQ, Ján Trenčanský, frack113, Nasreddine Bencherchali, Swachchhanda Shrawan Poudel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_windows_defender_tamper.yml)**

> Detects when attackers or tools disable Windows Defender functionalities via the Windows registry

```sql
-- ============================================================
-- Title:        Disable Windows Defender Functionalities Via Registry Keys
-- Sigma ID:     0eb46774-f1ab-4a74-8238-1155855f2263
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       AlertIQ, Ján Trenčanský, frack113, Nasreddine Bencherchali, Swachchhanda Shrawan Poudel
-- Date:         2022-08-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_windows_defender_tamper.yml
-- Unmapped:     (none)
-- False Pos:    Administrator actions via the Windows Defender interface; Third party Antivirus
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows Defender\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\%' OR metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions via the Windows Defender interface; Third party Antivirus

**References:**
- https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
- https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105
- https://admx.help/?Category=Windows_7_2008R2&Policy=Microsoft.Policies.WindowsDefender::SpyNetReporting
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
- https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html
- https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.html
- https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html
- https://securelist.com/key-group-ransomware-samples-and-telegram-schemes/114025/

---

## Winget Admin Settings Modification

| Field | Value |
|---|---|
| **Sigma ID** | `6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winget_admin_settings_tampering.yml)**

> Detects changes to the AppInstaller (winget) admin settings. Such as enabling local manifest installations or disabling installer hash checks

```sql
-- ============================================================
-- Title:        Winget Admin Settings Modification
-- Sigma ID:     6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winget_admin_settings_tampering.yml
-- Unmapped:     (none)
-- False Pos:    The event doesn't contain information about the type of change. False positives are expected with legitimate changes
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\winget.exe'
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '\\REGISTRY\\A\\%')
    AND indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\LocalState\\admin\_settings'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The event doesn't contain information about the type of change. False positives are expected with legitimate changes

**References:**
- https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
- https://github.com/microsoft/winget-cli/blob/02d2f93807c9851d73eaacb4d8811a76b64b7b01/src/AppInstallerCommonCore/Public/winget/AdminSettings.h#L13

---

## Enable Local Manifest Installation With Winget

| Field | Value |
|---|---|
| **Sigma ID** | `fa277e82-9b78-42dd-b05c-05555c7b6015` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winget_enable_local_manifest.yml)**

> Detects changes to the AppInstaller (winget) policy. Specifically the activation of the local manifest installation, which allows a user to install new packages via custom manifests.

```sql
-- ============================================================
-- Title:        Enable Local Manifest Installation With Winget
-- Sigma ID:     fa277e82-9b78-42dd-b05c-05555c7b6015
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winget_enable_local_manifest.yml
-- Unmapped:     (none)
-- False Pos:    Administrators or developers might enable this for testing purposes or to install custom private packages
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\AppInstaller\\EnableLocalManifestFiles')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] = 'DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators or developers might enable this for testing purposes or to install custom private packages

**References:**
- https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

---

## Winlogon AllowMultipleTSSessions Enable

| Field | Value |
|---|---|
| **Sigma ID** | `f7997770-92c3-4ec9-b112-774c4ef96f96` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winlogon_allow_multiple_tssessions.yml)**

> Detects when the 'AllowMultipleTSSessions' value is enabled.
Which allows for multiple Remote Desktop connection sessions to be opened at once.
This is often used by attacker as a way to connect to an RDP session without disconnecting the other users


```sql
-- ============================================================
-- Title:        Winlogon AllowMultipleTSSessions Enable
-- Sigma ID:     f7997770-92c3-4ec9-b112-774c4ef96f96
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-09-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winlogon_allow_multiple_tssessions.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the multi session functionality
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllowMultipleTSSessions')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%DWORD (0x00000001)'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the multi session functionality

**References:**
- http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html

---

## Winlogon Notify Key Logon Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `bbf59793-6efb-4fa1-95ca-a7d288e52c88` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.004 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winlogon_notify_key.yml)**

> Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in.
Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.


```sql
-- ============================================================
-- Title:        Winlogon Notify Key Logon Persistence
-- Sigma ID:     bbf59793-6efb-4fa1-95ca-a7d288e52c88
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1547.004
-- Author:       frack113
-- Date:         2021-12-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winlogon_notify_key.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'regKey')] AS targetObject,
  metrics_string.value[indexOf(metrics_string.name,'regValue')] AS details,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-12-Reg-Create-Delete', 'Win-Sysmon-13-Reg-Value-Set')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'regKey') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regKey')] LIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\logon')
    AND indexOf(metrics_string.name, 'regValue') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'regValue')] LIKE '%.dll'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.004/T1547.004.md#atomic-test-3---winlogon-notify-key-logon-persistence---powershell

---
