# Sigma → FortiSIEM: Windows System

> 63 rules · Generated 2026-03-17

## Table of Contents

- [Sysmon Application Crashed](#sysmon-application-crashed)
- [NTLMv1 Logon Between Client and Server](#ntlmv1-logon-between-client-and-server)
- [ISATAP Router Address Was Set](#isatap-router-address-was-set)
- [Active Directory Certificate Services Denied Certificate Enrollment Request](#active-directory-certificate-services-denied-certificate-enrollment-request)
- [DHCP Server Loaded the CallOut DLL](#dhcp-server-loaded-the-callout-dll)
- [DHCP Server Error Failed Loading the CallOut DLL](#dhcp-server-error-failed-loading-the-callout-dll)
- [Local Privilege Escalation Indicator TabTip](#local-privilege-escalation-indicator-tabtip)
- [Eventlog Cleared](#eventlog-cleared)
- [Important Windows Eventlog Cleared](#important-windows-eventlog-cleared)
- [Certificate Use With No Strong Mapping](#certificate-use-with-no-strong-mapping)
- [No Suitable Encryption Key Found For Generating Kerberos Ticket](#no-suitable-encryption-key-found-for-generating-kerberos-ticket)
- [Critical Hive In Suspicious Location Access Bits Cleared](#critical-hive-in-suspicious-location-access-bits-cleared)
- [Volume Shadow Copy Mount](#volume-shadow-copy-mount)
- [Crash Dump Created By Operating System](#crash-dump-created-by-operating-system)
- [Windows Update Error](#windows-update-error)
- [Zerologon Exploitation Using Well-known Tools](#zerologon-exploitation-using-well-known-tools)
- [Vulnerable Netlogon Secure Channel Connection Allowed](#vulnerable-netlogon-secure-channel-connection-allowed)
- [NTFS Vulnerability Exploitation](#ntfs-vulnerability-exploitation)
- [CobaltStrike Service Installations - System](#cobaltstrike-service-installations-system)
- [Windows Defender Threat Detection Service Disabled](#windows-defender-threat-detection-service-disabled)
- [smbexec.py Service Installation](#smbexecpy-service-installation)
- [Invoke-Obfuscation CLIP+ Launcher - System](#invoke-obfuscation-clip-launcher-system)
- [Invoke-Obfuscation Obfuscated IEX Invocation - System](#invoke-obfuscation-obfuscated-iex-invocation-system)
- [Invoke-Obfuscation STDIN+ Launcher - System](#invoke-obfuscation-stdin-launcher-system)
- [Invoke-Obfuscation VAR+ Launcher - System](#invoke-obfuscation-var-launcher-system)
- [Invoke-Obfuscation COMPRESS OBFUSCATION - System](#invoke-obfuscation-compress-obfuscation-system)
- [Invoke-Obfuscation RUNDLL LAUNCHER - System](#invoke-obfuscation-rundll-launcher-system)
- [Invoke-Obfuscation Via Stdin - System](#invoke-obfuscation-via-stdin-system)
- [Invoke-Obfuscation Via Use Clip - System](#invoke-obfuscation-via-use-clip-system)
- [Invoke-Obfuscation Via Use MSHTA - System](#invoke-obfuscation-via-use-mshta-system)
- [Invoke-Obfuscation Via Use Rundll32 - System](#invoke-obfuscation-via-use-rundll32-system)
- [Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System](#invoke-obfuscation-var-launcher-obfuscation-system)
- [KrbRelayUp Service Installation](#krbrelayup-service-installation)
- [Credential Dumping Tools Service Execution - System](#credential-dumping-tools-service-execution-system)
- [Meterpreter or Cobalt Strike Getsystem Service Installation - System](#meterpreter-or-cobalt-strike-getsystem-service-installation-system)
- [Moriya Rootkit - System](#moriya-rootkit-system)
- [PowerShell Scripts Installed as Services](#powershell-scripts-installed-as-services)
- [Anydesk Remote Access Software Service Installation](#anydesk-remote-access-software-service-installation)
- [CSExec Service Installation](#csexec-service-installation)
- [HackTool Service Registration or Execution](#hacktool-service-registration-or-execution)
- [Mesh Agent Service Installation](#mesh-agent-service-installation)
- [NetSupport Manager Service Install](#netsupport-manager-service-install)
- [PAExec Service Installation](#paexec-service-installation)
- [New PDQDeploy Service - Server Side](#new-pdqdeploy-service-server-side)
- [New PDQDeploy Service - Client Side](#new-pdqdeploy-service-client-side)
- [ProcessHacker Privilege Elevation](#processhacker-privilege-elevation)
- [RemCom Service Installation](#remcom-service-installation)
- [Remote Access Tool Services Have Been Installed - System](#remote-access-tool-services-have-been-installed-system)
- [Remote Utilities Host Service Install](#remote-utilities-host-service-install)
- [Sliver C2 Default Service Installation](#sliver-c2-default-service-installation)
- [Service Installed By Unusual Client - System](#service-installed-by-unusual-client-system)
- [Suspicious Service Installation](#suspicious-service-installation)
- [PsExec Service Installation](#psexec-service-installation)
- [TacticalRMM Service Installation](#tacticalrmm-service-installation)
- [Tap Driver Installation](#tap-driver-installation)
- [Uncommon Service Installation Image Path](#uncommon-service-installation-image-path)
- [Windows Service Terminated With Error](#windows-service-terminated-with-error)
- [Important Windows Service Terminated With Error](#important-windows-service-terminated-with-error)
- [Important Windows Service Terminated Unexpectedly](#important-windows-service-terminated-unexpectedly)
- [RTCore Suspicious Service Installation](#rtcore-suspicious-service-installation)
- [Service Installation in Suspicious Folder](#service-installation-in-suspicious-folder)
- [Service Installation with Suspicious Folder Pattern](#service-installation-with-suspicious-folder-pattern)
- [Suspicious Service Installation Script](#suspicious-service-installation-script)

## Sysmon Application Crashed

| Field | Value |
|---|---|
| **Sigma ID** | `4d7f1827-1637-4def-8d8a-fd254f9454df` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562 |
| **Author** | Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/application_popup/win_system_application_sysmon_crash.yml)**

> Detects application popup reporting a failure of the Sysmon service

```sql
-- ============================================================
-- Title:        Sysmon Application Crashed
-- Sigma ID:     4d7f1827-1637-4def-8d8a-fd254f9454df
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562
-- Author:       Tim Shelton
-- Date:         2022-04-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/application_popup/win_system_application_sysmon_crash.yml
-- Unmapped:     Caption
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Caption

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-26')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Application Popup')
    AND winEventId = '26'
    AND rawEventMsg IN ('sysmon64.exe - Application Error', 'sysmon.exe - Application Error'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nasbench/EVTX-ETW-Resources/blob/f1b010ce0ee1b71e3024180de1a3e67f99701fe4/ETWProvidersManifests/Windows10/1803/W10_1803_Pro_19700101_17134.1/WEPExplorer/Application%20Popup.xml#L36

---

## NTLMv1 Logon Between Client and Server

| Field | Value |
|---|---|
| **Sigma ID** | `e9d4ab66-a532-4ef7-a502-66a9e4a34f5d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1550.002 |
| **Author** | Tim Shelton, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/lsasrv/win_system_lsasrv_ntlmv1.yml)**

> Detects the reporting of NTLMv1 being used between a client and server. NTLMv1 is insecure as the underlying encryption algorithms can be brute-forced by modern hardware.

```sql
-- ============================================================
-- Title:        NTLMv1 Logon Between Client and Server
-- Sigma ID:     e9d4ab66-a532-4ef7-a502-66a9e4a34f5d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1550.002
-- Author:       Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-04-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/lsasrv/win_system_lsasrv_ntlmv1.yml
-- Unmapped:     (none)
-- False Pos:    Environments that use NTLMv1
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
WHERE eventType IN ('Win-System-6038', 'Win-System-6039')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'LsaSrv')
    AND winEventId IN ('6038', '6039'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Environments that use NTLMv1

**References:**
- https://github.com/nasbench/EVTX-ETW-Resources/blob/f1b010ce0ee1b71e3024180de1a3e67f99701fe4/ETWProvidersManifests/Windows10/22H2/W10_22H2_Pro_20230321_19045.2728/WEPExplorer/LsaSrv.xml

---

## ISATAP Router Address Was Set

| Field | Value |
|---|---|
| **Sigma ID** | `d22df9cd-2aee-4089-93c7-9dc4eae77f2c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact, collection, execution |
| **MITRE Techniques** | T1557, T1565.002 |
| **Author** | hamid |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_Iphlpsvc/win_system_isatap_router_address_set.yml)**

> Detects the configuration of a new ISATAP router on a Windows host. While ISATAP is a legitimate Microsoft technology for IPv6 transition, unexpected or unauthorized ISATAP router configurations could indicate a potential IPv6 DNS Takeover attack using tools like mitm6.
In such attacks, adversaries advertise themselves as DHCPv6 servers and set malicious ISATAP routers to intercept traffic.
This detection should be correlated with network baselines and known legitimate ISATAP deployments in your environment.


```sql
-- ============================================================
-- Title:        ISATAP Router Address Was Set
-- Sigma ID:     d22df9cd-2aee-4089-93c7-9dc4eae77f2c
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        impact, collection, execution | T1557, T1565.002
-- Author:       hamid
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_Iphlpsvc/win_system_isatap_router_address_set.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate ISATAP router configuration in enterprise environments; IPv6 transition projects and network infrastructure changes; Network administrators configuring dual-stack networking; Automatic ISATAP configuration in some Windows deployments
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
WHERE eventType IN ('Win-System-4100')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '4100'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Iphlpsvc'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate ISATAP router configuration in enterprise environments; IPv6 transition projects and network infrastructure changes; Network administrators configuring dual-stack networking; Automatic ISATAP configuration in some Windows deployments

**References:**
- https://www.blackhillsinfosec.com/mitm6-strikes-again-the-dark-side-of-ipv6/
- https://redfoxsec.com/blog/ipv6-dns-takeover/
- https://www.securityhq.com/blog/malicious-isatap-tunneling-unearthed-on-windows-server/
- https://medium.com/@ninnesoturan/detecting-ipv6-dns-takeover-a54a6a88be1f

---

## Active Directory Certificate Services Denied Certificate Enrollment Request

| Field | Value |
|---|---|
| **Sigma ID** | `994bfd6d-0a2e-481e-a861-934069fcf5f5` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1553.004 |
| **Author** | @SerkinValery |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml)**

> Detects denied requests by Active Directory Certificate Services.
Example of these requests denial include issues with permissions on the certificate template or invalid signatures.


```sql
-- ============================================================
-- Title:        Active Directory Certificate Services Denied Certificate Enrollment Request
-- Sigma ID:     994bfd6d-0a2e-481e-a861-934069fcf5f5
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1553.004
-- Author:       @SerkinValery
-- Date:         2024-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml
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
WHERE eventType IN ('Win-System-53')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-CertificationAuthority')
    AND winEventId = '53')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd299871(v=ws.10)
- https://www.gradenegger.eu/en/details-of-the-event-with-id-53-of-the-source-microsoft-windows-certificationauthority/

---

## DHCP Server Loaded the CallOut DLL

| Field | Value |
|---|---|
| **Sigma ID** | `13fc89a9-971e-4ca6-b9dc-aa53a445bf40` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Dimitrios Slamaris |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config.yml)**

> This rule detects a DHCP server in which a specified Callout DLL (in registry) was loaded

```sql
-- ============================================================
-- Title:        DHCP Server Loaded the CallOut DLL
-- Sigma ID:     13fc89a9-971e-4ca6-b9dc-aa53a445bf40
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Dimitrios Slamaris
-- Date:         2017-05-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config.yml
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
WHERE eventType IN ('Win-System-1033')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '1033'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-DHCP-Server'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
- https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
- https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx

---

## DHCP Server Error Failed Loading the CallOut DLL

| Field | Value |
|---|---|
| **Sigma ID** | `75edd3fd-7146-48e5-9848-3013d7f0282c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Dimitrios Slamaris, @atc_project (fix) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config_failed.yml)**

> This rule detects a DHCP server error in which a specified Callout DLL (in registry) could not be loaded

```sql
-- ============================================================
-- Title:        DHCP Server Error Failed Loading the CallOut DLL
-- Sigma ID:     75edd3fd-7146-48e5-9848-3013d7f0282c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Dimitrios Slamaris, @atc_project (fix)
-- Date:         2017-05-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config_failed.yml
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
WHERE eventType IN ('Win-System-1031', 'Win-System-1032', 'Win-System-1034')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('1031', '1032', '1034')
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-DHCP-Server'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
- https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
- https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx

---

## Local Privilege Escalation Indicator TabTip

| Field | Value |
|---|---|
| **Sigma ID** | `bc2e25ed-b92b-4daa-b074-b502bdd1982b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection, execution |
| **MITRE Techniques** | T1557.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_distributed_com/win_system_lpe_indicators_tabtip.yml)**

> Detects the invocation of TabTip via CLSID as seen when JuicyPotatoNG is used on a system in brute force mode

```sql
-- ============================================================
-- Title:        Local Privilege Escalation Indicator TabTip
-- Sigma ID:     bc2e25ed-b92b-4daa-b074-b502bdd1982b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection, execution | T1557.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-10-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_distributed_com/win_system_lpe_indicators_tabtip.yml
-- Unmapped:     param1, param2, param3
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: param1
-- UNMAPPED_FIELD: param2
-- UNMAPPED_FIELD: param3

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-10001')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-DistributedCOM')
    AND winEventId = '10001'
    AND rawEventMsg = 'C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe'
    AND rawEventMsg = '2147943140'
    AND rawEventMsg = '{054AAE20-4BEA-4347-8A35-64A533254A9D}')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/antonioCoco/JuicyPotatoNG

---

## Eventlog Cleared

| Field | Value |
|---|---|
| **Sigma ID** | `a62b37e0-45d3-48d9-a517-90c1a1b0186b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml)**

> One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution

```sql
-- ============================================================
-- Title:        Eventlog Cleared
-- Sigma ID:     a62b37e0-45d3-48d9-a517-90c1a1b0186b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-01-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml
-- Unmapped:     (none)
-- False Pos:    Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)
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
WHERE eventType IN ('Win-System-104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '104'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Eventlog'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)

**References:**
- https://twitter.com/deviouspolack/status/832535435960209408
- https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100

---

## Important Windows Eventlog Cleared

| Field | Value |
|---|---|
| **Sigma ID** | `100ef69e-3327-481c-8e5c-6d80d9507556` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.001 |
| **Author** | Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml)**

> Detects the clearing of one of the Windows Core Eventlogs. e.g. caused by "wevtutil cl" command execution

```sql
-- ============================================================
-- Title:        Important Windows Eventlog Cleared
-- Sigma ID:     100ef69e-3327-481c-8e5c-6d80d9507556
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.001
-- Author:       Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-05-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml
-- Unmapped:     (none)
-- False Pos:    Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  metrics_string.value[indexOf(metrics_string.name,'channel')] AS channel,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-104')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '104'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Eventlog')
    AND indexOf(metrics_string.name, 'channel') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'channel')] IN ('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational', 'PowerShellCore/Operational', 'Security', 'System', 'Windows PowerShell')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog); System provisioning (system reset before the golden image creation)

**References:**
- https://twitter.com/deviouspolack/status/832535435960209408
- https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100

---

## Certificate Use With No Strong Mapping

| Field | Value |
|---|---|
| **Sigma ID** | `993c2665-e6ef-40e3-a62a-e1a97686af79` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | @br4dy5 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_cert_use_no_strong_mapping.yml)**

> Detects a user certificate that was valid but could not be mapped to a user in a strong way (such as via explicit mapping, key trust mapping, or a SID)
This could be a sign of exploitation of the elevation of privilege vulnerabilities (CVE-2022-34691, CVE-2022-26931, CVE-2022-26923) that can occur when the KDC allows certificate spoofing by not requiring a strong mapping.
Events where the AccountName and CN of the Subject do not match, or where the CN ends in a dollar sign indicating a machine, may indicate certificate spoofing.


```sql
-- ============================================================
-- Title:        Certificate Use With No Strong Mapping
-- Sigma ID:     993c2665-e6ef-40e3-a62a-e1a97686af79
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       @br4dy5
-- Date:         2023-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_cert_use_no_strong_mapping.yml
-- Unmapped:     (none)
-- False Pos:    If prevalent in the environment, filter on events where the AccountName and CN of the Subject do not reference the same user; If prevalent in the environment, filter on CNs that end in a dollar sign indicating it is a machine name
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
WHERE eventType IN ('Win-System-39', 'Win-System-41')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] IN ('Kerberos-Key-Distribution-Center', 'Microsoft-Windows-Kerberos-Key-Distribution-Center'))
    AND winEventId IN ('39', '41'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If prevalent in the environment, filter on events where the AccountName and CN of the Subject do not reference the same user; If prevalent in the environment, filter on CNs that end in a dollar sign indicating it is a machine name

**References:**
- https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

---

## No Suitable Encryption Key Found For Generating Kerberos Ticket

| Field | Value |
|---|---|
| **Sigma ID** | `b1e0b3f5-b62e-41be-886a-daffde446ad4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1558.003 |
| **Author** | @SerkinValery |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_tgs_no_suitable_encryption_key_found.yml)**

> Detects errors when a target server doesn't have suitable keys for generating kerberos tickets.
This issue can occur for example when a service uses a user account or a computer account that is configured for only DES encryption on a computer that is running Windows 7 which has DES encryption for Kerberos authentication disabled.


```sql
-- ============================================================
-- Title:        No Suitable Encryption Key Found For Generating Kerberos Ticket
-- Sigma ID:     b1e0b3f5-b62e-41be-886a-daffde446ad4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1558.003
-- Author:       @SerkinValery
-- Date:         2024-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_tgs_no_suitable_encryption_key_found.yml
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
WHERE eventType IN ('Win-System-16', 'Win-System-27')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] IN ('Kerberos-Key-Distribution-Center', 'Microsoft-Windows-Kerberos-Key-Distribution-Center'))
    AND winEventId IN ('16', '27'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd348773(v=ws.10)
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kdc-event-16-27-des-encryption-disabled

---

## Critical Hive In Suspicious Location Access Bits Cleared

| Field | Value |
|---|---|
| **Sigma ID** | `39f919f3-980b-4e6f-a975-8af7e507ef2b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_kernel_general/win_system_susp_critical_hive_location_access_bits_cleared.yml)**

> Detects events from the Kernel-General ETW indicating that the access bits of a hive with a system like hive name located in the temp directory have been reset.
This occurs when an application tries to access a hive and the hive has not be recognized since the last 7 days (by default).
Registry hive dumping utilities such as QuarksPwDump were seen emitting this behavior.


```sql
-- ============================================================
-- Title:        Critical Hive In Suspicious Location Access Bits Cleared
-- Sigma ID:     39f919f3-980b-4e6f-a975-8af7e507ef2b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-05-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_kernel_general/win_system_susp_critical_hive_location_access_bits_cleared.yml
-- Unmapped:     HiveName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: HiveName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-16')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '16'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Kernel-General')
    AND (rawEventMsg LIKE '%\\Temp\\SAM%' OR rawEventMsg LIKE '%\\Temp\\SECURITY%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nasbench/Misc-Research/blob/b20da2336de0f342d31ef4794959d28c8d3ba5ba/ETW/Microsoft-Windows-Kernel-General.md

---

## Volume Shadow Copy Mount

| Field | Value |
|---|---|
| **Sigma ID** | `f512acbf-e662-4903-843e-97ce4652b740` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1003.002 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml)**

> Detects volume shadow copy mount via Windows event log

```sql
-- ============================================================
-- Title:        Volume Shadow Copy Mount
-- Sigma ID:     f512acbf-e662-4903-843e-97ce4652b740
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1003.002
-- Author:       Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
-- Date:         2020-10-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml
-- Unmapped:     DeviceName
-- False Pos:    Legitimate use of volume shadow copy mounts (backups maybe).
-- ============================================================
-- UNMAPPED_FIELD: DeviceName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-98')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-Ntfs')
    AND winEventId = '98'
    AND rawEventMsg LIKE '%HarddiskVolumeShadowCopy%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of volume shadow copy mounts (backups maybe).

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy

---

## Crash Dump Created By Operating System

| Field | Value |
|---|---|
| **Sigma ID** | `882fbe50-d8d7-4e29-ae80-0648a8556866` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1003.002, T1005 |
| **Author** | Jason Mull |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_wer_systemerrorreporting/win_system_crash_dump_created.yml)**

> Detects "BugCheck" errors indicating the system rebooted due to a crash, capturing the bugcheck code, dump file path, and report ID.

```sql
-- ============================================================
-- Title:        Crash Dump Created By Operating System
-- Sigma ID:     882fbe50-d8d7-4e29-ae80-0648a8556866
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        collection | T1003.002, T1005
-- Author:       Jason Mull
-- Date:         2025-05-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_wer_systemerrorreporting/win_system_crash_dump_created.yml
-- Unmapped:     (none)
-- False Pos:    (none)
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
WHERE eventType IN ('Win-System-1001')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-WER-SystemErrorReporting')
    AND winEventId = '1001')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://www.sans.edu/cyber-research/from-crash-compromise-unlocking-potential-windows-crash-dumps-offensive-security/
- https://jasonmull.com/articles/offensive/2025-05-12-windows-crash-dumps-offensive-security/

---

## Windows Update Error

| Field | Value |
|---|---|
| **Sigma ID** | `13cfeb75-9e33-4d04-b0f7-ab8faaa95a59` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1584 |
| **Author** | frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_windows_update_client/win_system_susp_system_update_error.yml)**

> Detects Windows update errors including installation failures and connection issues. Defenders should observe this in case critical update KBs aren't installed.


```sql
-- ============================================================
-- Title:        Windows Update Error
-- Sigma ID:     13cfeb75-9e33-4d04-b0f7-ab8faaa95a59
-- Level:        informational  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        impact | T1584
-- Author:       frack113
-- Date:         2021-12-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_windows_update_client/win_system_susp_system_update_error.yml
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
WHERE eventType IN ('Win-System-16', 'Win-System-20', 'Win-System-24', 'Win-System-213', 'Win-System-217')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Microsoft-Windows-WindowsUpdateClient')
    AND winEventId IN ('16', '20', '24', '213', '217'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nasbench/EVTX-ETW-Resources/blob/f1b010ce0ee1b71e3024180de1a3e67f99701fe4/ETWProvidersManifests/Windows10/1903/W10_1903_Pro_20200714_18362.959/WEPExplorer/Microsoft-Windows-WindowsUpdateClient.xml

---

## Zerologon Exploitation Using Well-known Tools

| Field | Value |
|---|---|
| **Sigma ID** | `18f37338-b9bd-4117-a039-280c81f7a596` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1210 |
| **Author** | Demyan Sokolin @_drd0c, Teymur Kheirkhabarov @HeirhabarovT, oscd.community |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml)**

> This rule is designed to detect attempts to exploit Zerologon (CVE-2020-1472) vulnerability using mimikatz zerologon module or other exploits from machine with "kali" hostname.

```sql
-- ============================================================
-- Title:        Zerologon Exploitation Using Well-known Tools
-- Sigma ID:     18f37338-b9bd-4117-a039-280c81f7a596
-- Level:        critical  |  FSM Severity: 9
-- Status:       stable
-- MITRE:        T1210
-- Author:       Demyan Sokolin @_drd0c, Teymur Kheirkhabarov @HeirhabarovT, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml
-- Unmapped:     (none)
-- False Pos:    (none)
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-5805', 'Win-System-5723')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('5805', '5723')
  AND rawEventMsg LIKE '%kali%' OR rawEventMsg LIKE '%mimikatz%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://www.secura.com/blog/zero-logon
- https://bi-zone.medium.com/hunting-for-zerologon-f65c61586382

---

## Vulnerable Netlogon Secure Channel Connection Allowed

| Field | Value |
|---|---|
| **Sigma ID** | `a0cb7110-edf0-47a4-9177-541a4083128a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1548 |
| **Author** | NVISO |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/netlogon/win_system_vul_cve_2020_1472.yml)**

> Detects that a vulnerable Netlogon secure channel connection was allowed, which could be an indicator of CVE-2020-1472.

```sql
-- ============================================================
-- Title:        Vulnerable Netlogon Secure Channel Connection Allowed
-- Sigma ID:     a0cb7110-edf0-47a4-9177-541a4083128a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1548
-- Author:       NVISO
-- Date:         2020-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/netlogon/win_system_vul_cve_2020_1472.yml
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
WHERE eventType IN ('Win-System-5829')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'NetLogon')
    AND winEventId = '5829')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc

---

## NTFS Vulnerability Exploitation

| Field | Value |
|---|---|
| **Sigma ID** | `f14719ce-d3ab-4e25-9ce6-2899092260b0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1499.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/ntfs/win_system_ntfs_vuln_exploit.yml)**

> This the exploitation of a NTFS vulnerability as reported without many details via Twitter

```sql
-- ============================================================
-- Title:        NTFS Vulnerability Exploitation
-- Sigma ID:     f14719ce-d3ab-4e25-9ce6-2899092260b0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1499.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/ntfs/win_system_ntfs_vuln_exploit.yml
-- Unmapped:     Origin, Description
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: Origin
-- UNMAPPED_FIELD: Description

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-55')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Ntfs')
    AND winEventId = '55'
    AND rawEventMsg = 'File System Driver'
    AND rawEventMsg LIKE '%contains a corrupted file record%' AND rawEventMsg LIKE '%The name of the file is "\\"%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/jonasLyk/status/1347900440000811010
- https://twitter.com/wdormann/status/1347958161609809921
- https://www.bleepingcomputer.com/news/security/windows-10-bug-corrupts-your-hard-drive-on-seeing-this-files-icon/

---

## CobaltStrike Service Installations - System

| Field | Value |
|---|---|
| **Sigma ID** | `5a105d34-05fc-401e-8553-272b45c1522d` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1021.002, T1543.003, T1569.002 |
| **Author** | Florian Roth (Nextron Systems), Wojciech Lesicki |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_cobaltstrike_service_installs.yml)**

> Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement

```sql
-- ============================================================
-- Title:        CobaltStrike Service Installations - System
-- Sigma ID:     5a105d34-05fc-401e-8553-272b45c1522d
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence, execution | T1021.002, T1543.003, T1569.002
-- Author:       Florian Roth (Nextron Systems), Wojciech Lesicki
-- Date:         2021-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_cobaltstrike_service_installs.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND rawEventMsg LIKE '%ADMIN$%' AND rawEventMsg LIKE '%.exe%')
  OR rawEventMsg LIKE '%\%COMSPEC\%%' AND rawEventMsg LIKE '%start%' AND rawEventMsg LIKE '%powershell%'
  OR rawEventMsg LIKE '%powershell -nop -w hidden -encodedcommand%'
  OR match(rawEventMsg, 'SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTI3LjAuMC4xOg|ElFWCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzEyNy4wLjAuMTo|BJRVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xMjcuMC4wLj')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.sans.org/webcasts/119395
- https://www.crowdstrike.com/blog/getting-the-bacon-from-cobalt-strike-beacon/
- https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/

---

## Windows Defender Threat Detection Service Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `6c0a7755-6d31-44fa-80e1-133e57752680` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Ján Trenčanský, frack113 |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml)**

> Detects when the "Windows Defender Threat Protection" service is disabled.

```sql
-- ============================================================
-- Title:        Windows Defender Threat Detection Service Disabled
-- Sigma ID:     6c0a7755-6d31-44fa-80e1-133e57752680
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1562.001
-- Author:       Ján Trenčanský, frack113
-- Date:         2020-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml
-- Unmapped:     param1, param2
-- False Pos:    Administrator actions; Auto updates of Windows Defender causes restarts
-- ============================================================
-- UNMAPPED_FIELD: param1
-- UNMAPPED_FIELD: param2

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7036')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '7036'
    AND indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND rawEventMsg IN ('Windows Defender Antivirus Service', 'Service antivirus Microsoft Defender')
    AND rawEventMsg IN ('stopped', 'arrêté'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator actions; Auto updates of Windows Defender causes restarts

**References:**
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

---

## smbexec.py Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `52a85084-6989-40c3-8f32-091e12e13f09` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1021.002, T1569.002 |
| **Author** | Omer Faruk Celik |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_hack_smbexec.yml)**

> Detects the use of smbexec.py tool by detecting a specific service installation

```sql
-- ============================================================
-- Title:        smbexec.py Service Installation
-- Sigma ID:     52a85084-6989-40c3-8f32-091e12e13f09
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1021.002, T1569.002
-- Author:       Omer Faruk Celik
-- Date:         2018-03-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_hack_smbexec.yml
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
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/
- https://github.com/fortra/impacket/blob/33058eb2fde6976ea62e04bc7d6b629d64d44712/examples/smbexec.py#L286-L296
- https://github.com/fortra/impacket/blob/edef71f17bc1240f9f8c957bbda98662951ac3ec/examples/smbexec.py#L60

---

## Invoke-Obfuscation CLIP+ Launcher - System

| Field | Value |
|---|---|
| **Sigma ID** | `f7385ee2-0e0c-11eb-adc1-0242ac120002` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_clip_services.yml)**

> Detects Obfuscated use of Clip.exe to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation CLIP+ Launcher - System
-- Sigma ID:     f7385ee2-0e0c-11eb-adc1-0242ac120002
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_clip_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%&&%' AND rawEventMsg LIKE '%clipboard]::%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Obfuscated IEX Invocation - System

| Field | Value |
|---|---|
| **Sigma ID** | `51aa9387-1c53-4153-91cc-d73c59ae1ca9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1027 |
| **Author** | Daniel Bohannon (@Mandiant/@FireEye), oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_obfuscated_iex_services.yml)**

> Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the code block linked in the references

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Obfuscated IEX Invocation - System
-- Sigma ID:     51aa9387-1c53-4153-91cc-d73c59ae1ca9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1027
-- Author:       Daniel Bohannon (@Mandiant/@FireEye), oscd.community
-- Date:         2019-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_obfuscated_iex_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '7045'
  AND (match(rawEventMsg, '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['))
  OR (match(rawEventMsg, '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\['))
  OR (match(rawEventMsg, '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\['))
  OR (match(rawEventMsg, '\$env:ComSpec\[(\s*\d{1,3}\s*,){2}'))
  OR (match(rawEventMsg, '\\*mdr\*\W\s*\)\.Name'))
  OR (match(rawEventMsg, '\$VerbosePreference\.ToString\('))
  OR (match(rawEventMsg, '\String\]\s*\$VerbosePreference')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/danielbohannon/Invoke-Obfuscation/blob/f20e7f843edd0a3a7716736e9eddfa423395dd26/Out-ObfuscatedStringCommand.ps1#L873-L888

---

## Invoke-Obfuscation STDIN+ Launcher - System

| Field | Value |
|---|---|
| **Sigma ID** | `72862bf2-0eb1-11eb-adc1-0242ac120002` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_stdin_services.yml)**

> Detects Obfuscated use of stdin to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation STDIN+ Launcher - System
-- Sigma ID:     72862bf2-0eb1-11eb-adc1-0242ac120002
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_stdin_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%powershell%'
    AND (rawEventMsg LIKE '%/c%' OR rawEventMsg LIKE '%/r%'))
  AND (rawEventMsg LIKE '%noexit%')
  OR (rawEventMsg LIKE '%input%' AND rawEventMsg LIKE '%$%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR+ Launcher - System

| Field | Value |
|---|---|
| **Sigma ID** | `8ca7004b-e620-4ecb-870e-86129b5b8e75` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Jonathan Cheong, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_var_services.yml)**

> Detects Obfuscated use of Environment Variables to execute PowerShell

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR+ Launcher - System
-- Sigma ID:     8ca7004b-e620-4ecb-870e-86129b5b8e75
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Jonathan Cheong, oscd.community
-- Date:         2020-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_var_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%"set%' AND rawEventMsg LIKE '%-f%'
    AND (rawEventMsg LIKE '%/c%' OR rawEventMsg LIKE '%/r%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation COMPRESS OBFUSCATION - System

| Field | Value |
|---|---|
| **Sigma ID** | `175997c5-803c-4b08-8bb0-70b099f47595` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_compress_services.yml)**

> Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation COMPRESS OBFUSCATION - System
-- Sigma ID:     175997c5-803c-4b08-8bb0-70b099f47595
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_compress_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%new-object%' AND rawEventMsg LIKE '%text.encoding]::ascii%' AND rawEventMsg LIKE '%readtoend%'
    AND (rawEventMsg LIKE '%:system.io.compression.deflatestream%' OR rawEventMsg LIKE '%system.io.streamreader%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation RUNDLL LAUNCHER - System

| Field | Value |
|---|---|
| **Sigma ID** | `11b52f18-aaec-4d60-9143-5dd8cc4706b9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_rundll_services.yml)**

> Detects Obfuscated Powershell via RUNDLL LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation RUNDLL LAUNCHER - System
-- Sigma ID:     11b52f18-aaec-4d60-9143-5dd8cc4706b9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_rundll_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%rundll32.exe%' AND rawEventMsg LIKE '%shell32.dll%' AND rawEventMsg LIKE '%shellexec\_rundll%' AND rawEventMsg LIKE '%powershell%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Stdin - System

| Field | Value |
|---|---|
| **Sigma ID** | `487c7524-f892-4054-b263-8a0ace63fc25` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_stdin_services.yml)**

> Detects Obfuscated Powershell via Stdin in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Stdin - System
-- Sigma ID:     487c7524-f892-4054-b263-8a0ace63fc25
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_stdin_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%set%' AND rawEventMsg LIKE '%&&%'
    AND (rawEventMsg LIKE '%environment%' OR rawEventMsg LIKE '%invoke%' OR rawEventMsg LIKE '%input%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Clip - System

| Field | Value |
|---|---|
| **Sigma ID** | `63e3365d-4824-42d8-8b82-e56810fefa0c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_clip_services.yml)**

> Detects Obfuscated Powershell via use Clip.exe in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Clip - System
-- Sigma ID:     63e3365d-4824-42d8-8b82-e56810fefa0c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_clip_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%(Clipboard|i%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use MSHTA - System

| Field | Value |
|---|---|
| **Sigma ID** | `7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_mshta_services.yml)**

> Detects Obfuscated Powershell via use MSHTA in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use MSHTA - System
-- Sigma ID:     7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_mshta_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%mshta%' AND rawEventMsg LIKE '%vbscript:createobject%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation Via Use Rundll32 - System

| Field | Value |
|---|---|
| **Sigma ID** | `641a4bfb-c017-44f7-800c-2aee0184ce9b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Nikita Nazarov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_rundll32_services.yml)**

> Detects Obfuscated Powershell via use Rundll32 in Scripts

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation Via Use Rundll32 - System
-- Sigma ID:     641a4bfb-c017-44f7-800c-2aee0184ce9b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Nikita Nazarov, oscd.community
-- Date:         2020-10-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_rundll32_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%&&%' AND rawEventMsg LIKE '%rundll32%' AND rawEventMsg LIKE '%shell32.dll%' AND rawEventMsg LIKE '%shellexec\_rundll%'
    AND (rawEventMsg LIKE '%value%' OR rawEventMsg LIKE '%invoke%' OR rawEventMsg LIKE '%comspec%' OR rawEventMsg LIKE '%iex%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System

| Field | Value |
|---|---|
| **Sigma ID** | `14bcba49-a428-42d9-b943-e2ce0f0f7ae6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1027, T1059.001 |
| **Author** | Timur Zinniatullin, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_var_services.yml)**

> Detects Obfuscated Powershell via VAR++ LAUNCHER

```sql
-- ============================================================
-- Title:        Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System
-- Sigma ID:     14bcba49-a428-42d9-b943-e2ce0f0f7ae6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1027, T1059.001
-- Author:       Timur Zinniatullin, oscd.community
-- Date:         2020-10-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_var_services.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%&&set%' AND rawEventMsg LIKE '%cmd%' AND rawEventMsg LIKE '%/c%' AND rawEventMsg LIKE '%-f%'
    AND (rawEventMsg LIKE '%{0}%' OR rawEventMsg LIKE '%{1}%' OR rawEventMsg LIKE '%{2}%' OR rawEventMsg LIKE '%{3}%' OR rawEventMsg LIKE '%{4}%' OR rawEventMsg LIKE '%{5}%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/SigmaHQ/sigma/issues/1009

---

## KrbRelayUp Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `e97d9903-53b2-41fc-8cb9-889ed4093e80` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543 |
| **Author** | Sittikorn S, Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml)**

> Detects service creation from KrbRelayUp tool used for privilege escalation in Windows domain environments where LDAP signing is not enforced (the default settings)

```sql
-- ============================================================
-- Title:        KrbRelayUp Service Installation
-- Sigma ID:     e97d9903-53b2-41fc-8cb9-889ed4093e80
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543
-- Author:       Sittikorn S, Tim Shelton
-- Date:         2022-05-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '7045'
    AND serviceName = 'KrbSCM')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Dec0ne/KrbRelayUp

---

## Credential Dumping Tools Service Execution - System

| Field | Value |
|---|---|
| **Sigma ID** | `4976aa50-8f41-45c6-8b15-ab3fc10e79ed` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1003.001, T1003.002, T1003.004, T1003.005, T1003.006, T1569.002 |
| **Author** | Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_mal_creddumper.yml)**

> Detects well-known credential dumping tools execution via service execution events

```sql
-- ============================================================
-- Title:        Credential Dumping Tools Service Execution - System
-- Sigma ID:     4976aa50-8f41-45c6-8b15-ab3fc10e79ed
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1003.001, T1003.002, T1003.004, T1003.005, T1003.006, T1569.002
-- Author:       Florian Roth (Nextron Systems), Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
-- Date:         2017-03-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_mal_creddumper.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate Administrator using credential dumping tool for password recovery
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND (rawEventMsg LIKE '%cachedump%' OR rawEventMsg LIKE '%dumpsvc%' OR rawEventMsg LIKE '%fgexec%' OR rawEventMsg LIKE '%gsecdump%' OR rawEventMsg LIKE '%mimidrv%' OR rawEventMsg LIKE '%pwdump%' OR rawEventMsg LIKE '%servpw%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate Administrator using credential dumping tool for password recovery

**References:**
- https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment

---

## Meterpreter or Cobalt Strike Getsystem Service Installation - System

| Field | Value |
|---|---|
| **Sigma ID** | `843544a7-56e0-4dcc-a44f-5cc266dd97d6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1134.001, T1134.002 |
| **Author** | Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml)**

> Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation

```sql
-- ============================================================
-- Title:        Meterpreter or Cobalt Strike Getsystem Service Installation - System
-- Sigma ID:     843544a7-56e0-4dcc-a44f-5cc266dd97d6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1134.001, T1134.002
-- Author:       Teymur Kheirkhabarov, Ecco, Florian Roth (Nextron Systems)
-- Date:         2019-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
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
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
- https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

---

## Moriya Rootkit - System

| Field | Value |
|---|---|
| **Sigma ID** | `25b9c01c-350d-4b95-bed1-836d04a4f324` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | Bhabesh Raj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_moriya_rootkit.yml)**

> Detects the use of Moriya rootkit as described in the securelist's Operation TunnelSnake report

```sql
-- ============================================================
-- Title:        Moriya Rootkit - System
-- Sigma ID:     25b9c01c-350d-4b95-bed1-836d04a4f324
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       Bhabesh Raj
-- Date:         2021-05-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_moriya_rootkit.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND serviceName = 'ZzNetSvc')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://securelist.com/operation-tunnelsnake-and-moriya-rootkit/101831

---

## PowerShell Scripts Installed as Services

| Field | Value |
|---|---|
| **Sigma ID** | `a2e5019d-a658-4c6a-92bf-7197b54e2cae` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | oscd.community, Natalia Shornikova |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml)**

> Detects powershell script installed as a Service

```sql
-- ============================================================
-- Title:        PowerShell Scripts Installed as Services
-- Sigma ID:     a2e5019d-a658-4c6a-92bf-7197b54e2cae
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       oscd.community, Natalia Shornikova
-- Date:         2020-10-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND (rawEventMsg LIKE '%powershell%' OR rawEventMsg LIKE '%pwsh%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

---

## Anydesk Remote Access Software Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `530a6faa-ff3d-4022-b315-50828e77eef5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml)**

> Detects the installation of the anydesk software service. Which could be an indication of anydesk abuse if you the software isn't already used.

```sql
-- ============================================================
-- Title:        Anydesk Remote Access Software Service Installation
-- Sigma ID:     530a6faa-ff3d-4022-b315-50828e77eef5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2022-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate usage of the anydesk tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (serviceName LIKE '%AnyDesk%' AND serviceName LIKE '%Service%')
  OR (rawEventMsg LIKE '%AnyDesk%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the anydesk tool

**References:**
- https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
- https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/

---

## CSExec Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `a27e5fa9-c35e-4e3d-b7e0-1ce2af66ad12` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_csexecsvc.yml)**

> Detects CSExec service installation and execution events

```sql
-- ============================================================
-- Title:        CSExec Service Installation
-- Sigma ID:     a27e5fa9-c35e-4e3d-b7e0-1ce2af66ad12
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_csexecsvc.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (serviceName = 'csexecsvc')
  OR (rawEventMsg LIKE '%\\csexecsvc.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/malcomvetter/CSExec

---

## HackTool Service Registration or Execution

| Field | Value |
|---|---|
| **Sigma ID** | `d26ce60c-2151-403c-9a42-49420d87b5e4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_hacktools.yml)**

> Detects installation or execution of services

```sql
-- ============================================================
-- Title:        HackTool Service Registration or Execution
-- Sigma ID:     d26ce60c-2151-403c-9a42-49420d87b5e4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_hacktools.yml
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
WHERE eventType IN ('Win-System-7045', 'Win-System-7036')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId IN ('7045', '7036'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Mesh Agent Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `e0d1ad53-c7eb-48ec-a87a-72393cc6cedc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_mesh_agent.yml)**

> Detects a Mesh Agent service installation. Mesh Agent is used to remotely manage computers

```sql
-- ============================================================
-- Title:        Mesh Agent Service Installation
-- Sigma ID:     e0d1ad53-c7eb-48ec-a87a-72393cc6cedc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_mesh_agent.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate use of the tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (rawEventMsg LIKE '%MeshAgent.exe%')
  OR (serviceName LIKE '%Mesh Agent%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the tool

**References:**
- https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/

---

## NetSupport Manager Service Install

| Field | Value |
|---|---|
| **Sigma ID** | `2d510d8d-912b-45c5-b1df-36faa3d8c3f4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_netsupport_manager.yml)**

> Detects NetSupport Manager service installation on the target system.

```sql
-- ============================================================
-- Title:        NetSupport Manager Service Install
-- Sigma ID:     2d510d8d-912b-45c5-b1df-36faa3d8c3f4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_netsupport_manager.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate use of the tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (rawEventMsg LIKE '%\\NetSupport Manager\\client32.exe%')
  OR (serviceName = 'Client32'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the tool

**References:**
- http://resources.netsupportsoftware.com/resources/manualpdfs/nsm_manual_uk.pdf

---

## PAExec Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `de7ce410-b3fb-4e8a-b38c-3b999e2c3420` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_paexec.yml)**

> Detects PAExec service installation

```sql
-- ============================================================
-- Title:        PAExec Service Installation
-- Sigma ID:     de7ce410-b3fb-4e8a-b38c-3b999e2c3420
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_paexec.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (serviceName LIKE 'PAExec-%')
  OR (rawEventMsg LIKE 'C:\\WINDOWS\\PAExec-%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.poweradmin.com/paexec/

---

## New PDQDeploy Service - Server Side

| Field | Value |
|---|---|
| **Sigma ID** | `ee9ca27c-9bd7-4cee-9b01-6e906be7cae3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_pdqdeploy.yml)**

> Detects a PDQDeploy service installation which indicates that PDQDeploy was installed on the machines.
PDQDeploy can be abused by attackers to remotely install packages or execute commands on target machines


```sql
-- ============================================================
-- Title:        New PDQDeploy Service - Server Side
-- Sigma ID:     ee9ca27c-9bd7-4cee-9b01-6e906be7cae3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_pdqdeploy.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate use of the tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (rawEventMsg LIKE '%PDQDeployService.exe%')
  OR (serviceName IN ('PDQDeploy', 'PDQ Deploy')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the tool

**References:**
- https://documentation.pdq.com/PDQDeploy/13.0.3.0/index.html?windows-services.htm

---

## New PDQDeploy Service - Client Side

| Field | Value |
|---|---|
| **Sigma ID** | `b98a10af-1e1e-44a7-bab2-4cc026917648` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_pdqdeploy_runner.yml)**

> Detects PDQDeploy service installation on the target system.
When a package is deployed via PDQDeploy it installs a remote service on the target machine with the name "PDQDeployRunner-X" where "X" is an integer starting from 1


```sql
-- ============================================================
-- Title:        New PDQDeploy Service - Client Side
-- Sigma ID:     b98a10af-1e1e-44a7-bab2-4cc026917648
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_pdqdeploy_runner.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate use of the tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (rawEventMsg LIKE '%PDQDeployRunner-%')
  OR (serviceName LIKE 'PDQDeployRunner-%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the tool

**References:**
- https://documentation.pdq.com/PDQDeploy/13.0.3.0/index.html?windows-services.htm

---

## ProcessHacker Privilege Elevation

| Field | Value |
|---|---|
| **Sigma ID** | `c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1543.003, T1569.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_pua_proceshacker.yml)**

> Detects a ProcessHacker tool that elevated privileges to a very high level

```sql
-- ============================================================
-- Title:        ProcessHacker Privilege Elevation
-- Sigma ID:     c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1543.003, T1569.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-05-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_pua_proceshacker.yml
-- Unmapped:     AccountName
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: AccountName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND serviceName LIKE 'ProcessHacker%'
    AND rawEventMsg = 'LocalSystem')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/1kwpeter/status/1397816101455765504

---

## RemCom Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `9e36ed87-4986-482e-8e3b-5c23ffff11bf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_remcom.yml)**

> Detects RemCom service installation and execution events

```sql
-- ============================================================
-- Title:        RemCom Service Installation
-- Sigma ID:     9e36ed87-4986-482e-8e3b-5c23ffff11bf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_remcom.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (serviceName = 'RemComSvc')
  OR (rawEventMsg LIKE '%\\RemComSvc.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/kavika13/RemCom/

---

## Remote Access Tool Services Have Been Installed - System

| Field | Value |
|---|---|
| **Sigma ID** | `1a31b18a-f00c-4061-9900-f735b96c99fc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1543.003, T1569.002 |
| **Author** | Connor Martin, Nasreddine Bencherchali |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_remote_access_software.yml)**

> Detects service installation of different remote access tools software. These software are often abused by threat actors to perform

```sql
-- ============================================================
-- Title:        Remote Access Tool Services Have Been Installed - System
-- Sigma ID:     1a31b18a-f00c-4061-9900-f735b96c99fc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution | T1543.003, T1569.002
-- Author:       Connor Martin, Nasreddine Bencherchali
-- Date:         2022-12-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_remote_access_software.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045', 'Win-System-7036')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId IN ('7045', '7036')
    AND (serviceName LIKE '%AmmyyAdmin%' OR serviceName LIKE '%Atera%' OR serviceName LIKE '%BASupportExpressSrvcUpdater%' OR serviceName LIKE '%BASupportExpressStandaloneService%' OR serviceName LIKE '%chromoting%' OR serviceName LIKE '%GoToAssist%' OR serviceName LIKE '%GoToMyPC%' OR serviceName LIKE '%jumpcloud%' OR serviceName LIKE '%LMIGuardianSvc%' OR serviceName LIKE '%LogMeIn%' OR serviceName LIKE '%monblanking%' OR serviceName LIKE '%Parsec%' OR serviceName LIKE '%RManService%' OR serviceName LIKE '%RPCPerformanceService%' OR serviceName LIKE '%RPCService%' OR serviceName LIKE '%SplashtopRemoteService%' OR serviceName LIKE '%SSUService%' OR serviceName LIKE '%TeamViewer%' OR serviceName LIKE '%TightVNC%' OR serviceName LIKE '%vncserver%' OR serviceName LIKE '%Zoho%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/misbehaving-rats/

---

## Remote Utilities Host Service Install

| Field | Value |
|---|---|
| **Sigma ID** | `85cce894-dd8b-4427-a958-5cc47a4dc9b9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_remote_utilities.yml)**

> Detects Remote Utilities Host service installation on the target system.

```sql
-- ============================================================
-- Title:        Remote Utilities Host Service Install
-- Sigma ID:     85cce894-dd8b-4427-a958-5cc47a4dc9b9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_remote_utilities.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate use of the tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (rawEventMsg LIKE '%\\rutserv.exe%' AND rawEventMsg LIKE '%-service%')
  OR (serviceName = 'Remote Utilities - Host'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the tool

**References:**
- https://www.remoteutilities.com/support/kb/host-service-won-t-start/

---

## Sliver C2 Default Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `31c51af6-e7aa-4da7-84d4-8f32cc580af2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1543.003, T1569.002 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_sliver.yml)**

> Detects known malicious service installation that appear in cases in which a Sliver implants execute the PsExec commands

```sql
-- ============================================================
-- Title:        Sliver C2 Default Service Installation
-- Sigma ID:     31c51af6-e7aa-4da7-84d4-8f32cc580af2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1543.003, T1569.002
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_sliver.yml
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
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/BishopFox/sliver/blob/79f2d48fcdfc2bee4713b78d431ea4b27f733f30/client/command/commands.go#L1231
- https://www.microsoft.com/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/

---

## Service Installed By Unusual Client - System

| Field | Value |
|---|---|
| **Sigma ID** | `71c276aa-49cd-43d2-b920-2dcd3e6962d5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543 |
| **Author** | Tim Rauch (Nextron Systems), Elastic (idea) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_sups_unusal_client.yml)**

> Detects a service installed by a client which has PID 0 or whose parent has PID 0

```sql
-- ============================================================
-- Title:        Service Installed By Unusual Client - System
-- Sigma ID:     71c276aa-49cd-43d2-b920-2dcd3e6962d5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543
-- Author:       Tim Rauch (Nextron Systems), Elastic (idea)
-- Date:         2022-09-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_sups_unusal_client.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  procId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND procId = '0')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.elastic.co/guide/en/security/current/windows-service-installed-via-an-unusual-client.html

---

## Suspicious Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `1d61f71d-59d2-479e-9562-4ff5f4ead16b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | pH-T (Nextron Systems), Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_susp.yml)**

> Detects suspicious service installation commands

```sql
-- ============================================================
-- Title:        Suspicious Service Installation
-- Sigma ID:     1d61f71d-59d2-479e-9562-4ff5f4ead16b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       pH-T (Nextron Systems), Florian Roth (Nextron Systems)
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_susp.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND (rawEventMsg LIKE '% -nop %' OR rawEventMsg LIKE '% -sta %' OR rawEventMsg LIKE '% -w hidden %' OR rawEventMsg LIKE '%:\\Temp\\%' OR rawEventMsg LIKE '%.downloadfile(%' OR rawEventMsg LIKE '%.downloadstring(%' OR rawEventMsg LIKE '%\\ADMIN$\\%' OR rawEventMsg LIKE '%\\Perflogs\\%' OR rawEventMsg LIKE '%&&%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## PsExec Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `42c575ea-e41e-41f1-b248-8093c3e82a28` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml)**

> Detects PsExec service installation and execution events

```sql
-- ============================================================
-- Title:        PsExec Service Installation
-- Sigma ID:     42c575ea-e41e-41f1-b248-8093c3e82a28
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Thomas Patzke
-- Date:         2017-06-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (serviceName = 'PSEXESVC')
  OR (rawEventMsg LIKE '%\\PSEXESVC.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.jpcert.or.jp/english/pub/sr/ir_research.html
- https://jpcertcc.github.io/ToolAnalysisResultSheet

---

## TacticalRMM Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `4bb79b62-ef12-4861-981d-2aab43fab642` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_tacticalrmm.yml)**

> Detects a TacticalRMM service installation. Tactical RMM is a remote monitoring & management tool.

```sql
-- ============================================================
-- Title:        TacticalRMM Service Installation
-- Sigma ID:     4bb79b62-ef12-4861-981d-2aab43fab642
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-11-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_tacticalrmm.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate use of the tool
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (rawEventMsg LIKE '%tacticalrmm.exe%')
  OR (serviceName LIKE '%TacticalRMM Agent Service%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the tool

**References:**
- https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/

---

## Tap Driver Installation

| Field | Value |
|---|---|
| **Sigma ID** | `8e4cf0e5-aa5d-4dc3-beff-dc26917744a9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048 |
| **Author** | Daniil Yugoslavskiy, Ian Davis, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_tap_driver.yml)**

> Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques

```sql
-- ============================================================
-- Title:        Tap Driver Installation
-- Sigma ID:     8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1048
-- Author:       Daniil Yugoslavskiy, Ian Davis, oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_tap_driver.yml
-- Unmapped:     ImagePath
-- False Pos:    Legitimate OpenVPN TAP installation
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND rawEventMsg LIKE '%tap0901%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate OpenVPN TAP installation

**References:**
- https://community.openvpn.net/openvpn/wiki/ManagingWindowsTAPDrivers

---

## Uncommon Service Installation Image Path

| Field | Value |
|---|---|
| **Sigma ID** | `26481afe-db26-4228-b264-25a29fe6efc7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_uncommon.yml)**

> Detects uncommon service installation commands by looking at suspicious or uncommon image path values containing references to encoded powershell commands, temporary paths, etc.


```sql
-- ============================================================
-- Title:        Uncommon Service Installation Image Path
-- Sigma ID:     26481afe-db26-4228-b264-25a29fe6efc7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_install_uncommon.yml
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
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Windows Service Terminated With Error

| Field | Value |
|---|---|
| **Sigma ID** | `acfa2210-0d71-4eeb-b477-afab494d596c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_error_generic.yml)**

> Detects Windows services that got terminated for whatever reason

```sql
-- ============================================================
-- Title:        Windows Service Terminated With Error
-- Sigma ID:     acfa2210-0d71-4eeb-b477-afab494d596c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_error_generic.yml
-- Unmapped:     (none)
-- False Pos:    False positives could occur since service termination could happen due to multiple reasons
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
WHERE eventType IN ('Win-System-7023')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7023')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives could occur since service termination could happen due to multiple reasons

**References:**
- https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/

---

## Important Windows Service Terminated With Error

| Field | Value |
|---|---|
| **Sigma ID** | `d6b5520d-3934-48b4-928c-2aa3f92d6963` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_error_important.yml)**

> Detects important or interesting Windows services that got terminated for whatever reason

```sql
-- ============================================================
-- Title:        Important Windows Service Terminated With Error
-- Sigma ID:     d6b5520d-3934-48b4-928c-2aa3f92d6963
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_error_important.yml
-- Unmapped:     param1, Binary
-- False Pos:    Rare false positives could occur since service termination could happen due to multiple reasons
-- ============================================================
-- UNMAPPED_FIELD: param1
-- UNMAPPED_FIELD: Binary

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7023')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7023')
  AND ((rawEventMsg LIKE '% Antivirus%' OR rawEventMsg LIKE '% Firewall%' OR rawEventMsg LIKE '%Application Guard%' OR rawEventMsg LIKE '%BitLocker Drive Encryption Service%' OR rawEventMsg LIKE '%Encrypting File System%' OR rawEventMsg LIKE '%Microsoft Defender%' OR rawEventMsg LIKE '%Threat Protection%' OR rawEventMsg LIKE '%Windows Event Log%'))
  OR ((rawEventMsg LIKE '%770069006e0064006500660065006e006400%' OR rawEventMsg LIKE '%4500760065006e0074004c006f006700%' OR rawEventMsg LIKE '%6d0070007300730076006300%' OR rawEventMsg LIKE '%530065006e0073006500%' OR rawEventMsg LIKE '%450046005300%' OR rawEventMsg LIKE '%420044004500530056004300%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare false positives could occur since service termination could happen due to multiple reasons

**References:**
- https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/

---

## Important Windows Service Terminated Unexpectedly

| Field | Value |
|---|---|
| **Sigma ID** | `56abae0c-6212-4b97-adc0-0b559bb950c3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_unexpectedly.yml)**

> Detects important or interesting Windows services that got terminated unexpectedly.

```sql
-- ============================================================
-- Title:        Important Windows Service Terminated Unexpectedly
-- Sigma ID:     56abae0c-6212-4b97-adc0-0b559bb950c3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_unexpectedly.yml
-- Unmapped:     param1, Binary
-- False Pos:    Rare false positives could occur since service termination could happen due to multiple reasons
-- ============================================================
-- UNMAPPED_FIELD: param1
-- UNMAPPED_FIELD: Binary

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7034')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7034')
  AND (rawEventMsg LIKE '%Message Queuing%')
  OR ((rawEventMsg LIKE '%4d0053004d005100%' OR rawEventMsg LIKE '%6d0073006d007100%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare false positives could occur since service termination could happen due to multiple reasons

**References:**
- https://www.randori.com/blog/vulnerability-analysis-queuejumper-cve-2023-21554/

---

## RTCore Suspicious Service Installation

| Field | Value |
|---|---|
| **Sigma ID** | `91c49341-e2ef-40c0-ac45-49ec5c3fe26c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_rtcore64_service_install.yml)**

> Detects the installation of RTCore service. Which could be an indication of Micro-Star MSI Afterburner vulnerable driver abuse

```sql
-- ============================================================
-- Title:        RTCore Suspicious Service Installation
-- Sigma ID:     91c49341-e2ef-40c0-ac45-49ec5c3fe26c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_rtcore64_service_install.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  serviceName,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND serviceName = 'RTCore64')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/br-sn/CheekyBlinder/blob/e1764a8a0e7cda8a3716aefa35799f560686e01c/CheekyBlinder/CheekyBlinder.cpp

---

## Service Installation in Suspicious Folder

| Field | Value |
|---|---|
| **Sigma ID** | `5e993621-67d4-488a-b9ae-b420d08b96cb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | pH-T (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_folder.yml)**

> Detects service installation in suspicious folder appdata

```sql
-- ============================================================
-- Title:        Service Installation in Suspicious Folder
-- Sigma ID:     5e993621-67d4-488a-b9ae-b420d08b96cb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       pH-T (Nextron Systems)
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_folder.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'
    AND (rawEventMsg LIKE '%\\AppData\\%' OR rawEventMsg LIKE '%\\\\\\\\127.0.0.1%' OR rawEventMsg LIKE '%\\\\\\\\localhost%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Service Installation with Suspicious Folder Pattern

| Field | Value |
|---|---|
| **Sigma ID** | `1b2ae822-6fe1-43ba-aa7c-d1a3b3d1d5f2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | pH-T (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_folder_pattern.yml)**

> Detects service installation with suspicious folder patterns

```sql
-- ============================================================
-- Title:        Service Installation with Suspicious Folder Pattern
-- Sigma ID:     1b2ae822-6fe1-43ba-aa7c-d1a3b3d1d5f2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       pH-T (Nextron Systems)
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_folder_pattern.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045')
  AND (match(rawEventMsg, '^[Cc]:\\[Pp]rogram[Dd]ata\\.{1,9}\.exe'))
  OR (match(rawEventMsg, '^[Cc]:\\.{1,9}\.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---

## Suspicious Service Installation Script

| Field | Value |
|---|---|
| **Sigma ID** | `70f00d10-60b2-4f34-b9a0-dc3df3fe762a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1543.003 |
| **Author** | pH-T (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_script.yml)**

> Detects suspicious service installation scripts

```sql
-- ============================================================
-- Title:        Suspicious Service Installation Script
-- Sigma ID:     70f00d10-60b2-4f34-b9a0-dc3df3fe762a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1543.003
-- Author:       pH-T (Nextron Systems)
-- Date:         2022-03-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_script.yml
-- Unmapped:     ImagePath
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: ImagePath
-- UNSUPPORTED_MODIFIER: contains|windash

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  metrics_string.value[indexOf(metrics_string.name,'provider')] AS provider_Name,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-System-7045')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%cscript%' OR rawEventMsg LIKE '%mshta%' OR rawEventMsg LIKE '%powershell%' OR rawEventMsg LIKE '%pwsh%' OR rawEventMsg LIKE '%regsvr32%' OR rawEventMsg LIKE '%rundll32%' OR rawEventMsg LIKE '%wscript%')
  AND (rawEventMsg LIKE '% -c %' OR rawEventMsg LIKE '% -r %' OR rawEventMsg LIKE '% -k %')
  AND (indexOf(metrics_string.name, 'provider') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'provider')] = 'Service Control Manager')
    AND winEventId = '7045'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research

---
