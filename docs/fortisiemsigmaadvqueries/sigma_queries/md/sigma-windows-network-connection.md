# Sigma → FortiSIEM: Windows Network Connection

> 51 rules · Generated 2026-03-17

## Table of Contents

- [Network Connection Initiated By AddinUtil.EXE](#network-connection-initiated-by-addinutilexe)
- [Uncommon Connection to Active Directory Web Services](#uncommon-connection-to-active-directory-web-services)
- [Uncommon Network Connection Initiated By Certutil.EXE](#uncommon-network-connection-initiated-by-certutilexe)
- [Outbound Network Connection Initiated By Cmstp.EXE](#outbound-network-connection-initiated-by-cmstpexe)
- [Outbound Network Connection Initiated By Microsoft Dialer](#outbound-network-connection-initiated-by-microsoft-dialer)
- [Network Connection Initiated To AzureWebsites.NET By Non-Browser Process](#network-connection-initiated-to-azurewebsitesnet-by-non-browser-process)
- [Network Connection Initiated To BTunnels Domains](#network-connection-initiated-to-btunnels-domains)
- [Network Connection Initiated To Cloudflared Tunnels Domains](#network-connection-initiated-to-cloudflared-tunnels-domains)
- [Network Communication With Crypto Mining Pool](#network-communication-with-crypto-mining-pool)
- [New Connection Initiated To Potential Dead Drop Resolver Domain](#new-connection-initiated-to-potential-dead-drop-resolver-domain)
- [Network Connection Initiated To DevTunnels Domain](#network-connection-initiated-to-devtunnels-domain)
- [Suspicious Dropbox API Usage](#suspicious-dropbox-api-usage)
- [Suspicious Network Connection to IP Lookup Service APIs](#suspicious-network-connection-to-ip-lookup-service-apis)
- [Suspicious Non-Browser Network Communication With Google API](#suspicious-non-browser-network-communication-with-google-api)
- [Communication To LocaltoNet Tunneling Service Initiated](#communication-to-localtonet-tunneling-service-initiated)
- [Network Connection Initiated To Mega.nz](#network-connection-initiated-to-meganz)
- [Process Initiated Network Connection To Ngrok Domain](#process-initiated-network-connection-to-ngrok-domain)
- [Communication To Ngrok Tunneling Service Initiated](#communication-to-ngrok-tunneling-service-initiated)
- [Potentially Suspicious Network Connection To Notion API](#potentially-suspicious-network-connection-to-notion-api)
- [Network Communication Initiated To Portmap.IO Domain](#network-communication-initiated-to-portmapio-domain)
- [Suspicious Non-Browser Network Communication With Telegram API](#suspicious-non-browser-network-communication-with-telegram-api)
- [Network Connection Initiated To Visual Studio Code Tunnels Domain](#network-connection-initiated-to-visual-studio-code-tunnels-domain)
- [Network Connection Initiated By Eqnedt32.EXE](#network-connection-initiated-by-eqnedt32exe)
- [Network Connection Initiated via Finger.EXE](#network-connection-initiated-via-fingerexe)
- [Network Connection Initiated By IMEWDBLD.EXE](#network-connection-initiated-by-imewdbldexe)
- [Network Connection Initiated Via Notepad.EXE](#network-connection-initiated-via-notepadexe)
- [Office Application Initiated Network Connection To Non-Local IP](#office-application-initiated-network-connection-to-non-local-ip)
- [Office Application Initiated Network Connection Over Uncommon Ports](#office-application-initiated-network-connection-over-uncommon-ports)
- [Python Initiated Connection](#python-initiated-connection)
- [Outbound RDP Connections Over Non-Standard Tools](#outbound-rdp-connections-over-non-standard-tools)
- [RDP Over Reverse SSH Tunnel](#rdp-over-reverse-ssh-tunnel)
- [RDP to HTTP or HTTPS Target Ports](#rdp-to-http-or-https-target-ports)
- [RegAsm.EXE Initiating Network Connection To Public IP](#regasmexe-initiating-network-connection-to-public-ip)
- [Network Connection Initiated By Regsvr32.EXE](#network-connection-initiated-by-regsvr32exe)
- [Remote Access Tool - AnyDesk Incoming Connection](#remote-access-tool-anydesk-incoming-connection)
- [Rundll32 Internet Connection](#rundll32-internet-connection)
- [Silenttrinity Stager Msbuild Activity](#silenttrinity-stager-msbuild-activity)
- [Suspicious Network Connection Binary No CommandLine](#suspicious-network-connection-binary-no-commandline)
- [Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder](#network-communication-initiated-to-file-sharing-domains-from-process-located-in-suspicious-folder)
- [Network Connection Initiated From Process Located In Potentially Suspicious Or Uncommon Location](#network-connection-initiated-from-process-located-in-potentially-suspicious-or-uncommon-location)
- [Potentially Suspicious Malware Callback Communication](#potentially-suspicious-malware-callback-communication)
- [Communication To Uncommon Destination Ports](#communication-to-uncommon-destination-ports)
- [Uncommon Outbound Kerberos Connection](#uncommon-outbound-kerberos-connection)
- [Microsoft Sync Center Suspicious Network Connections](#microsoft-sync-center-suspicious-network-connections)
- [Suspicious Outbound SMTP Connections](#suspicious-outbound-smtp-connections)
- [Potential Remote PowerShell Session Initiated](#potential-remote-powershell-session-initiated)
- [Outbound Network Connection To Public IP Via Winlogon](#outbound-network-connection-to-public-ip-via-winlogon)
- [Suspicious Wordpad Outbound Connections](#suspicious-wordpad-outbound-connections)
- [Local Network Connection Initiated By Script Interpreter](#local-network-connection-initiated-by-script-interpreter)
- [Outbound Network Connection Initiated By Script Interpreter](#outbound-network-connection-initiated-by-script-interpreter)
- [Potentially Suspicious Wuauclt Network Connection](#potentially-suspicious-wuauclt-network-connection)

## Network Connection Initiated By AddinUtil.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `5205613d-2a63-4412-a895-3a2458b587b3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218 |
| **Author** | Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_addinutil_initiated.yml)**

> Detects a network connection initiated by the Add-In deployment cache updating utility "AddInutil.exe".
This could indicate a potential command and control communication as this tool doesn't usually initiate network activity.


```sql
-- ============================================================
-- Title:        Network Connection Initiated By AddinUtil.EXE
-- Sigma ID:     5205613d-2a63-4412-a895-3a2458b587b3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218
-- Author:       Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
-- Date:         2023-09-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_addinutil_initiated.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\addinutil.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html

---

## Uncommon Connection to Active Directory Web Services

| Field | Value |
|---|---|
| **Sigma ID** | `b3ad3c0f-c949-47a1-a30e-b0491ccae876` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087 |
| **Author** | @kostastsale |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_adws_unusual_connection.yml)**

> Detects uncommon network connections to the Active Directory Web Services (ADWS) from processes not typically associated with ADWS management.


```sql
-- ============================================================
-- Title:        Uncommon Connection to Active Directory Web Services
-- Sigma ID:     b3ad3c0f-c949-47a1-a30e-b0491ccae876
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1087
-- Author:       @kostastsale
-- Date:         2024-01-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_adws_unusual_connection.yml
-- Unmapped:     (none)
-- False Pos:    ADWS is used by a number of legitimate applications that need to interact with Active Directory. These applications should be added to the allow-listing to avoid false positives.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'True')
    AND destIpPort = '9389')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** ADWS is used by a number of legitimate applications that need to interact with Active Directory. These applications should be added to the allow-listing to avoid false positives.

**References:**
- https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c
- https://github.com/FalconForceTeam/FalconFriday/blob/a9219dfcfd89836f34660223f47d766982bdce46/Discovery/ADWS_Connection_from_Unexpected_Binary-Win.md

---

## Uncommon Network Connection Initiated By Certutil.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `0dba975d-a193-4ed1-a067-424df57570d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml)**

> Detects a network connection initiated by the certutil.exe utility.
Attackers can abuse the utility in order to download malware or additional payloads.


```sql
-- ============================================================
-- Title:        Uncommon Network Connection Initiated By Certutil.EXE
-- Sigma ID:     0dba975d-a193-4ed1-a067-424df57570d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113, Florian Roth (Nextron Systems)
-- Date:         2022-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\certutil.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND destIpPort IN ('80', '135', '443', '445'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil

---

## Outbound Network Connection Initiated By Cmstp.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `efafe0bf-4238-479e-af8f-797bd3490d2d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1218.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_cmstp_initiated_connection.yml)**

> Detects a network connection initiated by Cmstp.EXE
Its uncommon for "cmstp.exe" to initiate an outbound network connection. Investigate the source of such requests to determine if they are malicious.


```sql
-- ============================================================
-- Title:        Outbound Network Connection Initiated By Cmstp.EXE
-- Sigma ID:     efafe0bf-4238-479e-af8f-797bd3490d2d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1218.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_cmstp_initiated_connection.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\cmstp.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/

---

## Outbound Network Connection Initiated By Microsoft Dialer

| Field | Value |
|---|---|
| **Sigma ID** | `37e4024a-6c80-4d8f-b95d-2e7e94f3a8d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1071.001 |
| **Author** | CertainlyP |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_dialer_initiated_connection.yml)**

> Detects outbound network connection initiated by Microsoft Dialer.
The Microsoft Dialer, also known as Phone Dialer, is a built-in utility application included in various versions of the Microsoft Windows operating system. Its primary function is to provide users with a graphical interface for managing phone calls via a modem or a phone line connected to the computer.
This is an outdated process in the current conext of it's usage and is a common target for info stealers for process injection, and is used to make C2 connections, common example is "Rhadamanthys"


```sql
-- ============================================================
-- Title:        Outbound Network Connection Initiated By Microsoft Dialer
-- Sigma ID:     37e4024a-6c80-4d8f-b95d-2e7e94f3a8d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1071.001
-- Author:       CertainlyP
-- Date:         2024-04-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_dialer_initiated_connection.yml
-- Unmapped:     (none)
-- False Pos:    In Modern Windows systems, unable to see legitimate usage of this process, However, if an organization has legitimate purpose for this there can be false positives.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%:\\Windows\\System32\\dialer.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** In Modern Windows systems, unable to see legitimate usage of this process, However, if an organization has legitimate purpose for this there can be false positives.

**References:**
- https://tria.ge/240301-rk34sagf5x/behavioral2
- https://app.any.run/tasks/6720b85b-9c53-4a12-b1dc-73052a78477d
- https://research.checkpoint.com/2023/rhadamanthys-v0-5-0-a-deep-dive-into-the-stealers-components/
- https://strontic.github.io/xcyclopedia/library/dialer.exe-0B69655F912619756C704A0BF716B61F.html

---

## Network Connection Initiated To AzureWebsites.NET By Non-Browser Process

| Field | Value |
|---|---|
| **Sigma ID** | `5c80b618-0dbb-46e6-acbb-03d90bcb6d83` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1102, T1102.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml)**

> Detects an initiated network connection by a non browser process on the system to "azurewebsites.net". The latter was often used by threat actors as a malware hosting and exfiltration site.


```sql
-- ============================================================
-- Title:        Network Connection Initiated To AzureWebsites.NET By Non-Browser Process
-- Sigma ID:     5c80b618-0dbb-46e6-acbb-03d90bcb6d83
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1102, T1102.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%azurewebsites.net'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.sentinelone.com/labs/wip26-espionage-threat-actors-abuse-cloud-infrastructure-in-targeted-telco-attacks/
- https://symantec-enterprise-blogs.security.com/threat-intelligence/harvester-new-apt-attacks-asia
- https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
- https://intezer.com/blog/research/how-we-escaped-docker-in-azure-functions/

---

## Network Connection Initiated To BTunnels Domains

| Field | Value |
|---|---|
| **Sigma ID** | `9e02c8ec-02b9-43e8-81eb-34a475ba7965` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1572 |
| **Author** | Kamran Saifullah |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_btunnels.yml)**

> Detects network connections to BTunnels domains initiated by a process on the system.
Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        Network Connection Initiated To BTunnels Domains
-- Sigma ID:     9e02c8ec-02b9-43e8-81eb-34a475ba7965
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567, T1572
-- Author:       Kamran Saifullah
-- Date:         2024-09-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_btunnels.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of BTunnels will also trigger this.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.btunnel.co.in'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of BTunnels will also trigger this.

**References:**
- https://defr0ggy.github.io/research/Utilizing-BTunnel-For-Data-Exfiltration/

---

## Network Connection Initiated To Cloudflared Tunnels Domains

| Field | Value |
|---|---|
| **Sigma ID** | `7cd1dcdc-6edf-4896-86dc-d1f19ad64903` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1572 |
| **Author** | Kamran Saifullah, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_cloudflared_communication.yml)**

> Detects network connections to Cloudflared tunnels domains initiated by a process on the system.
Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        Network Connection Initiated To Cloudflared Tunnels Domains
-- Sigma ID:     7cd1dcdc-6edf-4896-86dc-d1f19ad64903
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567, T1572
-- Author:       Kamran Saifullah, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-05-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_cloudflared_communication.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of cloudflare tunnels will also trigger this.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.v2.argotunnel.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%protocol-v2.argotunnel.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%trycloudflare.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%update.argotunnel.com')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of cloudflare tunnels will also trigger this.

**References:**
- https://defr0ggy.github.io/research/Abusing-Cloudflared-A-Proxy-Service-To-Host-Share-Applications/
- https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
- Internal Research

---

## Network Communication With Crypto Mining Pool

| Field | Value |
|---|---|
| **Sigma ID** | `fa5b1358-b040-4403-9868-15f7d9ab6329` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1496 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_crypto_mining_pools.yml)**

> Detects initiated network connections to crypto mining pools

```sql
-- ============================================================
-- Title:        Network Communication With Crypto Mining Pool
-- Sigma ID:     fa5b1358-b040-4403-9868-15f7d9ab6329
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        impact | T1496
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_crypto_mining_pools.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] IN ('alimabi.cn', 'ap.luckpool.net', 'bcn.pool.minergate.com', 'bcn.vip.pool.minergate.com', 'bohemianpool.com', 'ca-aipg.miningocean.org', 'ca-dynex.miningocean.org', 'ca-neurai.miningocean.org', 'ca-qrl.miningocean.org', 'ca-upx.miningocean.org', 'ca-zephyr.miningocean.org', 'ca.minexmr.com', 'ca.monero.herominers.com', 'cbd.monerpool.org', 'cbdv2.monerpool.org', 'cryptmonero.com', 'crypto-pool.fr', 'crypto-pool.info', 'cryptonight-hub.miningpoolhub.com', 'd1pool.ddns.net', 'd5pool.us', 'daili01.monerpool.org', 'de-aipg.miningocean.org', 'de-dynex.miningocean.org', 'de-zephyr.miningocean.org', 'de.minexmr.com', 'dl.nbminer.com', 'donate.graef.in', 'donate.ssl.xmrig.com', 'donate.v2.xmrig.com', 'donate.xmrig.com', 'donate2.graef.in', 'drill.moneroworld.com', 'dwarfpool.com', 'emercoin.com', 'emercoin.net', 'emergate.net', 'ethereumpool.co', 'eu.luckpool.net', 'eu.minerpool.pw', 'fcn-xmr.pool.minergate.com', 'fee.xmrig.com', 'fr-aipg.miningocean.org', 'fr-dynex.miningocean.org', 'fr-neurai.miningocean.org', 'fr-qrl.miningocean.org', 'fr-upx.miningocean.org', 'fr-zephyr.miningocean.org', 'fr.minexmr.com', 'hellominer.com', 'herominers.com', 'hk-aipg.miningocean.org', 'hk-dynex.miningocean.org', 'hk-neurai.miningocean.org', 'hk-qrl.miningocean.org', 'hk-upx.miningocean.org', 'hk-zephyr.miningocean.org', 'huadong1-aeon.ppxxmr.com', 'iwanttoearn.money', 'jw-js1.ppxxmr.com', 'koto-pool.work', 'lhr.nbminer.com', 'lhr3.nbminer.com', 'linux.monerpool.org', 'lokiturtle.herominers.com', 'luckpool.net', 'masari.miner.rocks', 'mine.c3pool.com', 'mine.moneropool.com', 'mine.ppxxmr.com', 'mine.zpool.ca', 'mine1.ppxxmr.com', 'minemonero.gq', 'miner.ppxxmr.com', 'miner.rocks', 'minercircle.com', 'minergate.com', 'minerpool.pw', 'minerrocks.com', 'miners.pro', 'minerxmr.ru', 'minexmr.cn', 'minexmr.com', 'mining-help.ru', 'miningpoolhub.com', 'mixpools.org', 'moner.monerpool.org', 'moner1min.monerpool.org', 'monero-master.crypto-pool.fr', 'monero.crypto-pool.fr', 'monero.hashvault.pro', 'monero.herominers.com', 'monero.lindon-pool.win', 'monero.miners.pro', 'monero.riefly.id', 'monero.us.to', 'monerocean.stream', 'monerogb.com', 'monerohash.com', 'moneroocean.stream', 'moneropool.com', 'moneropool.nl', 'monerorx.com', 'monerpool.org', 'moriaxmr.com', 'mro.pool.minergate.com', 'multipool.us', 'myxmr.pw', 'na.luckpool.net', 'nanopool.org', 'nbminer.com', 'node3.luckpool.net', 'noobxmr.com', 'pangolinminer.comgandalph3000.com', 'pool.4i7i.com', 'pool.armornetwork.org', 'pool.cortins.tk', 'pool.gntl.co.uk', 'pool.hashvault.pro', 'pool.minergate.com', 'pool.minexmr.com', 'pool.monero.hashvault.pro', 'pool.ppxxmr.com', 'pool.somec.cc', 'pool.support', 'pool.supportxmr.com', 'pool.usa-138.com', 'pool.xmr.pt', 'pool.xmrfast.com', 'pool2.armornetwork.org', 'poolchange.ppxxmr.com', 'pooldd.com', 'poolmining.org', 'poolto.be', 'ppxvip1.ppxxmr.com', 'ppxxmr.com', 'prohash.net', 'r.twotouchauthentication.online', 'randomx.xmrig.com', 'ratchetmining.com', 'seed.emercoin.com', 'seed.emercoin.net', 'seed.emergate.net', 'seed1.joulecoin.org', 'seed2.joulecoin.org', 'seed3.joulecoin.org', 'seed4.joulecoin.org', 'seed5.joulecoin.org', 'seed6.joulecoin.org', 'seed7.joulecoin.org', 'seed8.joulecoin.org', 'sg-aipg.miningocean.org', 'sg-dynex.miningocean.org', 'sg-neurai.miningocean.org', 'sg-qrl.miningocean.org', 'sg-upx.miningocean.org', 'sg-zephyr.miningocean.org', 'sg.minexmr.com', 'sheepman.mine.bz', 'siamining.com', 'sumokoin.minerrocks.com', 'supportxmr.com', 'suprnova.cc', 'teracycle.net', 'trtl.cnpool.cc', 'trtl.pool.mine2gether.com', 'turtle.miner.rocks', 'us-aipg.miningocean.org', 'us-dynex.miningocean.org', 'us-neurai.miningocean.org', 'us-west.minexmr.com', 'us-zephyr.miningocean.org', 'usxmrpool.com', 'viaxmr.com', 'webservicepag.webhop.net', 'xiazai.monerpool.org', 'xiazai1.monerpool.org', 'xmc.pool.minergate.com', 'xmo.pool.minergate.com', 'xmr-asia1.nanopool.org', 'xmr-au1.nanopool.org', 'xmr-eu1.nanopool.org', 'xmr-eu2.nanopool.org', 'xmr-jp1.nanopool.org', 'xmr-us-east1.nanopool.org', 'xmr-us-west1.nanopool.org', 'xmr-us.suprnova.cc', 'xmr-usa.dwarfpool.com', 'xmr.2miners.com', 'xmr.5b6b7b.ru', 'xmr.alimabi.cn', 'xmr.bohemianpool.com', 'xmr.crypto-pool.fr', 'xmr.crypto-pool.info', 'xmr.f2pool.com', 'xmr.hashcity.org', 'xmr.hex7e4.ru', 'xmr.ip28.net', 'xmr.monerpool.org', 'xmr.mypool.online', 'xmr.nanopool.org', 'xmr.pool.gntl.co.uk', 'xmr.pool.minergate.com', 'xmr.poolto.be', 'xmr.ppxxmr.com', 'xmr.prohash.net', 'xmr.simka.pw', 'xmr.somec.cc', 'xmr.suprnova.cc', 'xmr.usa-138.com', 'xmr.vip.pool.minergate.com', 'xmr1min.monerpool.org', 'xmrf.520fjh.org', 'xmrf.fjhan.club', 'xmrfast.com', 'xmrigcc.graef.in', 'xmrminer.cc', 'xmrpool.de', 'xmrpool.eu', 'xmrpool.me', 'xmrpool.net', 'xmrpool.xyz', 'xx11m.monerpool.org', 'xx11mv2.monerpool.org', 'xxx.hex7e4.ru', 'zarabotaibitok.ru', 'zer0day.ru'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.poolwatch.io/coin/monero
- https://github.com/stamparm/maltrail/blob/3ea70459b9559134449423c0a7d8b965ac5c40ea/trails/static/suspicious/crypto_mining.txt
- https://www.virustotal.com/gui/search/behaviour_network%253A*.miningocean.org/files

---

## New Connection Initiated To Potential Dead Drop Resolver Domain

| Field | Value |
|---|---|
| **Sigma ID** | `297ae038-edc2-4b2e-bb3e-7c5fc94dd5c7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1102, T1102.001 |
| **Author** | Sorina Ionescu, X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml)**

> Detects an executable, which is not an internet browser or known application, initiating network connections to legit popular websites, which were seen to be used as dead drop resolvers in previous attacks.
In this context attackers leverage known websites such as "facebook", "youtube", etc. In order to pass through undetected.


```sql
-- ============================================================
-- Title:        New Connection Initiated To Potential Dead Drop Resolver Domain
-- Sigma ID:     297ae038-edc2-4b2e-bb3e-7c5fc94dd5c7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1102, T1102.001
-- Author:       Sorina Ionescu, X__Junior (Nextron Systems)
-- Date:         2022-08-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml
-- Unmapped:     (none)
-- False Pos:    One might need to exclude other internet browsers found in it's network or other applications like ones mentioned above from Microsoft Defender.; Ninite contacting githubusercontent.com
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.t.me' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%4shared.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%abuse.ch' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%anonfiles.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%cdn.discordapp.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%cloudflare.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ddns.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%discord.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%docs.google.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%drive.google.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%dropbox.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%dropmefiles.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%facebook.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%feeds.rapidfeeds.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%fotolog.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ghostbin.co/' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%githubusercontent.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%gofile.io' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%hastebin.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%imgur.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%livejournal.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mediafire.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mega.co.nz' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mega.nz' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%onedrive.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pages.dev' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%paste.ee' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pastebin.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pastebin.pl' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pastetext.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pixeldrain.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%privatlab.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%privatlab.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%reddit.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%send.exploit.in' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%sendspace.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%steamcommunity.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%storage.googleapis.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%technet.microsoft.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%temp.sh' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%transfer.sh' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%trycloudflare.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%twitter.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ufile.io' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%vimeo.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%w3spaces.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%wetransfer.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%workers.dev' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%youtube.com')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** One might need to exclude other internet browsers found in it's network or other applications like ones mentioned above from Microsoft Defender.; Ninite contacting githubusercontent.com

**References:**
- https://web.archive.org/web/20220830134315/https://content.fireeye.com/apt-41/rpt-apt41/
- https://securelist.com/the-tetrade-brazilian-banking-malware/97779/
- https://blog.bushidotoken.net/2021/04/dead-drop-resolvers-espionage-inspired.html
- https://github.com/kleiton0x00/RedditC2
- https://twitter.com/kleiton0x7e/status/1600567316810551296
- https://www.linkedin.com/posts/kleiton-kurti_github-kleiton0x00redditc2-abusing-reddit-activity-7009939662462984192-5DbI/?originalSubdomain=al

---

## Network Connection Initiated To DevTunnels Domain

| Field | Value |
|---|---|
| **Sigma ID** | `9501f8e6-8e3d-48fc-a8a6-1089dd5d7ef4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.001, T1572 |
| **Author** | Kamran Saifullah |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_devtunnels.yml)**

> Detects network connections to Devtunnels domains initiated by a process on a system. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        Network Connection Initiated To DevTunnels Domain
-- Sigma ID:     9501f8e6-8e3d-48fc-a8a6-1089dd5d7ef4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567.001, T1572
-- Author:       Kamran Saifullah
-- Date:         2023-11-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_devtunnels.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of Devtunnels will also trigger this.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.devtunnels.ms'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Devtunnels will also trigger this.

**References:**
- https://blueteamops.medium.com/detecting-dev-tunnels-16f0994dc3e2
- https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security
- https://cydefops.com/devtunnels-unleashed

---

## Suspicious Dropbox API Usage

| Field | Value |
|---|---|
| **Sigma ID** | `25eabf56-22f0-4915-a1ed-056b8dae0a68` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1105, T1567.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_dropbox_api.yml)**

> Detects an executable that isn't dropbox but communicates with the Dropbox API

```sql
-- ============================================================
-- Title:        Suspicious Dropbox API Usage
-- Sigma ID:     25eabf56-22f0-4915-a1ed-056b8dae0a68
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1105, T1567.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-04-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_dropbox_api.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the API with a tool that the author wasn't aware of
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%api.dropboxapi.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%content.dropboxapi.com')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the API with a tool that the author wasn't aware of

**References:**
- https://app.any.run/tasks/7e906adc-9d11-447f-8641-5f40375ecebb
- https://www.zscaler.com/blogs/security-research/new-espionage-attack-molerats-apt-targeting-users-middle-east

---

## Suspicious Network Connection to IP Lookup Service APIs

| Field | Value |
|---|---|
| **Sigma ID** | `edf3485d-dac4-4d50-90e4-b0e5813f7e60` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1016 |
| **Author** | Janantha Marasinghe, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_external_ip_lookup.yml)**

> Detects external IP address lookups by non-browser processes via services such as "api.ipify.org". This could be indicative of potential post compromise internet test activity.

```sql
-- ============================================================
-- Title:        Suspicious Network Connection to IP Lookup Service APIs
-- Sigma ID:     edf3485d-dac4-4d50-90e4-b0e5813f7e60
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1016
-- Author:       Janantha Marasinghe, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-04-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_external_ip_lookup.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the external websites for troubleshooting or network monitoring
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] IN ('www.ip.cn', 'l2.io')))
  OR ((indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%api.2ip.ua%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%api.bigdatacloud.net%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%api.ipify.org%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%bot.whatismyipaddress.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%canireachthe.net%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%checkip.amazonaws.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%checkip.dyndns.org%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%curlmyip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%db-ip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%edns.ip-api.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%eth0.me%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%freegeoip.app%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%geoipy.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%getip.pro%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%icanhazip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ident.me%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ifconfig.io%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ifconfig.me%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ip-api.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ip.360.cn%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ip.anysrc.net%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ip.taobao.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ip.tyk.nu%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipaddressworld.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipapi.co%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipconfig.io%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipecho.net%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipinfo.io%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipip.net%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipof.in%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipv4.icanhazip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipv4bot.whatismyipaddress.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipv6-test.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ipwho.is%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%jsonip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%myexternalip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%seeip.org%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%wgetip.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%whatismyip.akamai.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%whois.pconline.com.cn%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%wtfismyip.com%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the external websites for troubleshooting or network monitoring

**References:**
- https://github.com/rsp/scripts/blob/c8bb272d68164a9836e4f273d8f924927f39b8c6/externalip-benchmark.md
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a
- https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
- https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html

---

## Suspicious Non-Browser Network Communication With Google API

| Field | Value |
|---|---|
| **Sigma ID** | `7e9cf7b6-e827-11ed-a05b-0242ac120003` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1102 |
| **Author** | Gavin Knapp |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_google_api_non_browser_access.yml)**

> Detects a non-browser process interacting with the Google API which could indicate the use of a covert C2 such as Google Sheet C2 (GC2-sheet)


```sql
-- ============================================================
-- Title:        Suspicious Non-Browser Network Communication With Google API
-- Sigma ID:     7e9cf7b6-e827-11ed-a05b-0242ac120003
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1102
-- Author:       Gavin Knapp
-- Date:         2023-05-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_google_api_non_browser_access.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications communicating with the "googleapis.com" endpoints that are not already in the exclusion list. This is environmental dependent and requires further testing and tuning.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%drive.googleapis.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%oauth2.googleapis.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%sheets.googleapis.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%www.googleapis.com%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications communicating with the "googleapis.com" endpoints that are not already in the exclusion list. This is environmental dependent and requires further testing and tuning.

**References:**
- https://github.com/looCiprian/GC2-sheet
- https://youtu.be/n2dFlSaBBKo
- https://services.google.com/fh/files/blogs/gcat_threathorizons_full_apr2023.pdf
- https://www.tanium.com/blog/apt41-deploys-google-gc2-for-attacks-cyber-threat-intelligence-roundup/
- https://www.bleepingcomputer.com/news/security/hackers-abuse-google-command-and-control-red-team-tool-in-attacks/

---

## Communication To LocaltoNet Tunneling Service Initiated

| Field | Value |
|---|---|
| **Sigma ID** | `3ab65069-d82a-4d44-a759-466661a082d1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1572, T1090, T1102 |
| **Author** | Andreas Braathen (mnemonic.io) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_localtonet_tunnel.yml)**

> Detects an executable initiating a network connection to "LocaltoNet" tunneling sub-domains.
LocaltoNet is a reverse proxy that enables localhost services to be exposed to the Internet.
Attackers have been seen to use this service for command-and-control activities to bypass MFA and perimeter controls.


```sql
-- ============================================================
-- Title:        Communication To LocaltoNet Tunneling Service Initiated
-- Sigma ID:     3ab65069-d82a-4d44-a759-466661a082d1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1572, T1090, T1102
-- Author:       Andreas Braathen (mnemonic.io)
-- Date:         2024-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_localtonet_tunnel.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the LocaltoNet service.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.localto.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.localtonet.com'))
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the LocaltoNet service.

**References:**
- https://localtonet.com/documents/supported-tunnels
- https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications

---

## Network Connection Initiated To Mega.nz

| Field | Value |
|---|---|
| **Sigma ID** | `fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_mega_nz.yml)**

> Detects a network connection initiated by a binary to "api.mega.co.nz".
Attackers were seen abusing file sharing websites similar to "mega.nz" in order to upload/download additional payloads.


```sql
-- ============================================================
-- Title:        Network Connection Initiated To Mega.nz
-- Sigma ID:     fdeebdf0-9f3f-4d08-84a6-4c4d13e39fe4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-12-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_mega_nz.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate MEGA installers and utilities are expected to communicate with this domain. Exclude hosts that are known to be allowed to use this tool.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mega.co.nz' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mega.nz')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate MEGA installers and utilities are expected to communicate with this domain. Exclude hosts that are known to be allowed to use this tool.

**References:**
- https://megatools.megous.com/
- https://www.mandiant.com/resources/russian-targeting-gov-business

---

## Process Initiated Network Connection To Ngrok Domain

| Field | Value |
|---|---|
| **Sigma ID** | `18249279-932f-45e2-b37a-8925f2597670` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1572, T1102 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_ngrok.yml)**

> Detects an executable initiating a network connection to "ngrok" domains.
Attackers were seen using this "ngrok" in order to store their second stage payloads and malware.
While communication with such domains can be legitimate, often times is a sign of either data exfiltration by malicious actors or additional download.


```sql
-- ============================================================
-- Title:        Process Initiated Network Connection To Ngrok Domain
-- Sigma ID:     18249279-932f-45e2-b37a-8925f2597670
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1567, T1572, T1102
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_ngrok.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the ngrok service.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.ngrok-free.app' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.ngrok-free.dev' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.ngrok.app' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.ngrok.dev' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.ngrok.io')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the ngrok service.

**References:**
- https://ngrok.com/
- https://ngrok.com/blog-post/new-ngrok-domains
- https://www.virustotal.com/gui/file/cca0c1182ac114b44dc52dd2058fcd38611c20bb6b5ad84710681d38212f835a/
- https://www.rnbo.gov.ua/files/2023_YEAR/CYBERCENTER/november/APT29%20attacks%20Embassies%20using%20CVE-2023-38831%20-%20report%20en.pdf

---

## Communication To Ngrok Tunneling Service Initiated

| Field | Value |
|---|---|
| **Sigma ID** | `1d08ac94-400d-4469-a82f-daee9a908849` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1568.002, T1572, T1090, T1102 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.yml)**

> Detects an executable initiating a network connection to "ngrok" tunneling domains.
Attackers were seen using this "ngrok" in order to store their second stage payloads and malware.
While communication with such domains can be legitimate, often times is a sign of either data exfiltration by malicious actors or additional download.


```sql
-- ============================================================
-- Title:        Communication To Ngrok Tunneling Service Initiated
-- Sigma ID:     1d08ac94-400d-4469-a82f-daee9a908849
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1567, T1568.002, T1572, T1090, T1102
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-11-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of the ngrok service.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.us.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.eu.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.ap.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.au.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.sa.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.jp.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.in.ngrok.com%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the ngrok service.

**References:**
- https://twitter.com/hakluke/status/1587733971814977537/photo/1
- https://ngrok.com/docs/secure-tunnels/tunnels/ssh-reverse-tunnel-agent

---

## Potentially Suspicious Network Connection To Notion API

| Field | Value |
|---|---|
| **Sigma ID** | `7e9cf7b6-e827-11ed-a05b-15959c120003` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1102 |
| **Author** | Gavin Knapp |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_notion_api_susp_communication.yml)**

> Detects a non-browser process communicating with the Notion API. This could indicate potential use of a covert C2 channel such as "OffensiveNotion C2"

```sql
-- ============================================================
-- Title:        Potentially Suspicious Network Connection To Notion API
-- Sigma ID:     7e9cf7b6-e827-11ed-a05b-15959c120003
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1102
-- Author:       Gavin Knapp
-- Date:         2023-05-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_notion_api_susp_communication.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications communicating with the "api.notion.com" endpoint that are not already in the exclusion list. The desktop and browser applications do not appear to be using the API by default unless integrations are configured.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%api.notion.com%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications communicating with the "api.notion.com" endpoint that are not already in the exclusion list. The desktop and browser applications do not appear to be using the API by default unless integrations are configured.

**References:**
- https://github.com/mttaggart/OffensiveNotion
- https://medium.com/@huskyhacks.mk/we-put-a-c2-in-your-notetaking-app-offensivenotion-3e933bace332

---

## Network Communication Initiated To Portmap.IO Domain

| Field | Value |
|---|---|
| **Sigma ID** | `07837ab9-60e1-481f-a74d-c31fb496a94c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1041, T1090.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_portmap.yml)**

> Detects an executable accessing the portmap.io domain, which could be a sign of forbidden C2 traffic or data exfiltration by malicious actors

```sql
-- ============================================================
-- Title:        Network Communication Initiated To Portmap.IO Domain
-- Sigma ID:     07837ab9-60e1-481f-a74d-c31fb496a94c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1041, T1090.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2024-05-31
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_portmap.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of portmap.io domains
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.portmap.io'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of portmap.io domains

**References:**
- https://portmap.io/
- https://github.com/rapid7/metasploit-framework/issues/11337
- https://pro.twitter.com/JaromirHorejsi/status/1795001037746761892/photo/2

---

## Suspicious Non-Browser Network Communication With Telegram API

| Field | Value |
|---|---|
| **Sigma ID** | `c3dbbc9f-ef1d-470a-a90a-d343448d5875` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1102, T1567, T1105 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access.yml)**

> Detects an a non-browser process interacting with the Telegram API which could indicate use of a covert C2

```sql
-- ============================================================
-- Title:        Suspicious Non-Browser Network Communication With Telegram API
-- Sigma ID:     c3dbbc9f-ef1d-470a-a90a-d343448d5875
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1102, T1567, T1105
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate applications communicating with the Telegram API e.g. web browsers not in the exclusion list, app with an RSS  etc.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%api.telegram.org%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate applications communicating with the Telegram API e.g. web browsers not in the exclusion list, app with an RSS  etc.

**References:**
- https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/small-sieve/NCSC-MAR-Small-Sieve.pdf

---

## Network Connection Initiated To Visual Studio Code Tunnels Domain

| Field | Value |
|---|---|
| **Sigma ID** | `4b657234-038e-4ad5-997c-4be42340bce4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1572 |
| **Author** | Kamran Saifullah |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_vscode_tunnel_connection.yml)**

> Detects network connections to Visual Studio Code tunnel domains initiated by a process on a system. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        Network Connection Initiated To Visual Studio Code Tunnels Domain
-- Sigma ID:     4b657234-038e-4ad5-997c-4be42340bce4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567, T1572
-- Author:       Kamran Saifullah
-- Date:         2023-11-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_domain_vscode_tunnel_connection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of Visual Studio Code tunnel will also trigger this.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.tunnels.api.visualstudio.com'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Visual Studio Code tunnel will also trigger this.

**References:**
- https://ipfyx.fr/post/visual-studio-code-tunnel/
- https://badoption.eu/blog/2023/01/31/code_c2.html
- https://cydefops.com/vscode-data-exfiltration

---

## Network Connection Initiated By Eqnedt32.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `a66bc059-c370-472c-a0d7-f8fd1bf9d583` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1203 |
| **Author** | Max Altgelt (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_eqnedt.yml)**

> Detects network connections from the Equation Editor process "eqnedt32.exe".

```sql
-- ============================================================
-- Title:        Network Connection Initiated By Eqnedt32.EXE
-- Sigma ID:     a66bc059-c370-472c-a0d7-f8fd1bf9d583
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1203
-- Author:       Max Altgelt (Nextron Systems)
-- Date:         2022-04-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_eqnedt.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\eqnedt32.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/forensicitguy/status/1513538712986079238
- https://forensicitguy.github.io/xloader-formbook-velvetsweatshop-spreadsheet/
- https://news.sophos.com/en-us/2019/07/18/a-new-equation-editor-exploit-goes-commercial-as-maldoc-attacks-using-it-spike/

---

## Network Connection Initiated via Finger.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `2fdaf50b-9fd5-449f-ba69-f17248119af6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1071.004, T1059.003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_finger.yml)**

> Detects network connections via finger.exe, which can be abused by threat actors to retrieve remote commands for execution on Windows devices.
In one ClickFix malware campaign, adversaries leveraged the finger protocol to fetch commands from a remote server.
Since the finger utility is not commonly used in modern Windows environments, its presence already raises suspicion.
Investigating such network connections can also help identify potential malicious infrastructure used by threat actors


```sql
-- ============================================================
-- Title:        Network Connection Initiated via Finger.EXE
-- Sigma ID:     2fdaf50b-9fd5-449f-ba69-f17248119af6
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1071.004, T1059.003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_finger.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\finger.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.bleepingcomputer.com/news/security/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/

---

## Network Connection Initiated By IMEWDBLD.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `8d7e392e-9b28-49e1-831d-5949c6281228` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_imewdbld.yml)**

> Detects a network connection initiated by IMEWDBLD.EXE. This might indicate potential abuse of the utility as a LOLBIN in order to download arbitrary files or additional payloads.


```sql
-- ============================================================
-- Title:        Network Connection Initiated By IMEWDBLD.EXE
-- Sigma ID:     8d7e392e-9b28-49e1-831d-5949c6281228
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113
-- Date:         2022-01-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_imewdbld.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\IMEWDBLD.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
- https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/

---

## Network Connection Initiated Via Notepad.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `e81528db-fc02-45e8-8e98-4e84aba1f10b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1055 |
| **Author** | EagleEye Team |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_notepad.yml)**

> Detects a network connection that is initiated by the "notepad.exe" process.
This might be a sign of process injection from a beacon process or something similar.
Notepad rarely initiates a network communication except when printing documents for example.


```sql
-- ============================================================
-- Title:        Network Connection Initiated Via Notepad.EXE
-- Sigma ID:     e81528db-fc02-45e8-8e98-4e84aba1f10b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1055
-- Author:       EagleEye Team
-- Date:         2020-05-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_notepad.yml
-- Unmapped:     (none)
-- False Pos:    Printing documents via notepad might cause communication with the printer via port 9100 or similar.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\notepad.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Printing documents via notepad might cause communication with the printer via port 9100 or similar.

**References:**
- https://web.archive.org/web/20200219102749/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf
- https://www.cobaltstrike.com/blog/why-is-notepad-exe-connecting-to-the-internet

---

## Office Application Initiated Network Connection To Non-Local IP

| Field | Value |
|---|---|
| **Sigma ID** | `75e33ce3-ae32-4dcc-9aa8-a2a3029d6f84` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1203 |
| **Author** | Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_office_outbound_non_local_ip.yml)**

> Detects an office application (Word, Excel, PowerPoint)  that initiate a network connection to a non-private IP addresses.
This rule aims to detect traffic similar to one seen exploited in CVE-2021-42292.
This rule will require an initial baseline and tuning that is specific to your organization.


```sql
-- ============================================================
-- Title:        Office Application Initiated Network Connection To Non-Local IP
-- Sigma ID:     75e33ce3-ae32-4dcc-9aa8-a2a3029d6f84
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1203
-- Author:       Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
-- Date:         2021-11-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_office_outbound_non_local_ip.yml
-- Unmapped:     (none)
-- False Pos:    You may have to tune certain domains out that Excel may call out to, such as microsoft or other business use case domains.; Office documents commonly have templates that refer to external addresses, like "sharepoint.ourcompany.com" may have to be tuned.; It is highly recommended to baseline your activity and tune out common business use cases.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\excel.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe' OR procName LIKE '%\\wordview.exe')
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** You may have to tune certain domains out that Excel may call out to, such as microsoft or other business use case domains.; Office documents commonly have templates that refer to external addresses, like "sharepoint.ourcompany.com" may have to be tuned.; It is highly recommended to baseline your activity and tune out common business use cases.

**References:**
- https://corelight.com/blog/detecting-cve-2021-42292
- https://learn.microsoft.com/de-de/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide

---

## Office Application Initiated Network Connection Over Uncommon Ports

| Field | Value |
|---|---|
| **Sigma ID** | `3b5ba899-9842-4bc2-acc2-12308498bf42` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_office_uncommon_ports.yml)**

> Detects an office suit application (Word, Excel, PowerPoint, Outlook) communicating to target systems over uncommon ports.

```sql
-- ============================================================
-- Title:        Office Application Initiated Network Connection Over Uncommon Ports
-- Sigma ID:     3b5ba899-9842-4bc2-acc2-12308498bf42
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-07-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_office_uncommon_ports.yml
-- Unmapped:     (none)
-- False Pos:    Other ports can be used, apply additional filters accordingly
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (procName LIKE '%\\excel.exe' OR procName LIKE '%\\outlook.exe' OR procName LIKE '%\\powerpnt.exe' OR procName LIKE '%\\winword.exe' OR procName LIKE '%\\wordview.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other ports can be used, apply additional filters accordingly

**References:**
- https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit

---

## Python Initiated Connection

| Field | Value |
|---|---|
| **Sigma ID** | `bef0bc5a-b9ae-425d-85c6-7b2d705980c6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1046 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_python.yml)**

> Detects a Python process initiating a network connection. While this often relates to package installation, it can also indicate a potential malicious script communicating with a C&C server.

```sql
-- ============================================================
-- Title:        Python Initiated Connection
-- Sigma ID:     bef0bc5a-b9ae-425d-85c6-7b2d705980c6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1046
-- Author:       frack113
-- Date:         2021-12-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_python.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate python scripts using the socket library or similar will trigger this. Apply additional filters and perform an initial baseline before deploying.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\python%' AND procName LIKE '%.exe%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate python scripts using the socket library or similar will trigger this. Apply additional filters and perform an initial baseline before deploying.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md#atomic-test-4---port-scan-using-python
- https://pypi.org/project/scapy/

---

## Outbound RDP Connections Over Non-Standard Tools

| Field | Value |
|---|---|
| **Sigma ID** | `ed74fe75-7594-4b4b-ae38-e38e3fd2eb23` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021.001 |
| **Author** | Markus Neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rdp_outbound_over_non_standard_tools.yml)**

> Detects Non-Standard tools initiating a connection over port 3389 indicating possible lateral movement.
An initial baseline is required before using this utility to exclude third party RDP tooling that you might use.


```sql
-- ============================================================
-- Title:        Outbound RDP Connections Over Non-Standard Tools
-- Sigma ID:     ed74fe75-7594-4b4b-ae38-e38e3fd2eb23
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021.001
-- Author:       Markus Neis
-- Date:         2019-05-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rdp_outbound_over_non_standard_tools.yml
-- Unmapped:     (none)
-- False Pos:    Third party RDP tools
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (destIpPort = '3389'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Third party RDP tools

**References:**
- https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708

---

## RDP Over Reverse SSH Tunnel

| Field | Value |
|---|---|
| **Sigma ID** | `5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1572, T1021.001 |
| **Author** | Samir Bousseaden |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml)**

> Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389

```sql
-- ============================================================
-- Title:        RDP Over Reverse SSH Tunnel
-- Sigma ID:     5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1572, T1021.001
-- Author:       Samir Bousseaden
-- Date:         2019-02-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpAddrV4,
  procName,
  srcIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((isIPAddressInRange(toString(destIpAddrV4), '127.0.0.0/8') OR isIPAddressInRange(toString(destIpAddrV4), '::1/128'))
  AND (procName LIKE '%\\svchost.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND srcIpPort = '3389'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/cyb3rops/status/1096842275437625346

---

## RDP to HTTP or HTTPS Target Ports

| Field | Value |
|---|---|
| **Sigma ID** | `b1e5da3b-ca8e-4adf-915c-9921f3d85481` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1572, T1021.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rdp_to_http.yml)**

> Detects svchost hosting RDP termsvcs communicating to target systems on TCP port 80 or 443

```sql
-- ============================================================
-- Title:        RDP to HTTP or HTTPS Target Ports
-- Sigma ID:     b1e5da3b-ca8e-4adf-915c-9921f3d85481
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1572, T1021.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-04-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rdp_to_http.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  srcIpPort,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\svchost.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND srcIpPort = '3389'
    AND destIpPort IN ('80', '443'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/tekdefense/status/1519711183162556416?s=12&t=OTsHCBkQOTNs1k3USz65Zg
- https://www.mandiant.com/resources/bypassing-network-restrictions-through-rdp-tunneling

---

## RegAsm.EXE Initiating Network Connection To Public IP

| Field | Value |
|---|---|
| **Sigma ID** | `0531e43a-d77d-47c2-b89f-5fe50321c805` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218.009 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_regasm_network_activity.yml)**

> Detects "RegAsm.exe" initiating a network connection to public IP adresses

```sql
-- ============================================================
-- Title:        RegAsm.EXE Initiating Network Connection To Public IP
-- Sigma ID:     0531e43a-d77d-47c2-b89f-5fe50321c805
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218.009
-- Author:       frack113
-- Date:         2024-04-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_regasm_network_activity.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\regasm.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://app.any.run/tasks/ec207948-4916-47eb-a0f4-4c6abb2e7668/
- https://research.splunk.com/endpoint/07921114-6db4-4e2e-ae58-3ea8a52ae93f/
- https://lolbas-project.github.io/lolbas/Binaries/Regasm/

---

## Network Connection Initiated By Regsvr32.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `c7e91a02-d771-4a6d-a700-42587e0b1095` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1559.001, T1218.010 |
| **Author** | Dmitriy Lifanov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_regsvr32_network_activity.yml)**

> Detects a network connection initiated by "Regsvr32.exe"

```sql
-- ============================================================
-- Title:        Network Connection Initiated By Regsvr32.EXE
-- Sigma ID:     c7e91a02-d771-4a6d-a700-42587e0b1095
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1559.001, T1218.010
-- Author:       Dmitriy Lifanov, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_regsvr32_network_activity.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\regsvr32.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
- https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/

---

## Remote Access Tool - AnyDesk Incoming Connection

| Field | Value |
|---|---|
| **Sigma ID** | `d58ba5c6-0ed7-4b9d-a433-6878379efda9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1219.002 |
| **Author** | @d4ns4n_ (Wuerth-Phoenix) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_remote_access_tools_anydesk_incoming_connection.yml)**

> Detects incoming connections to AnyDesk. This could indicate a potential remote attacker trying to connect to a listening instance of AnyDesk and use it as potential command and control channel.


```sql
-- ============================================================
-- Title:        Remote Access Tool - AnyDesk Incoming Connection
-- Sigma ID:     d58ba5c6-0ed7-4b9d-a433-6878379efda9
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1219.002
-- Author:       @d4ns4n_ (Wuerth-Phoenix)
-- Date:         2024-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_remote_access_tools_anydesk_incoming_connection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate incoming connections (e.g. sysadmin activity). Most of the time I would expect outgoing connections (initiated locally).
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((procName LIKE '%\\AnyDesk.exe' OR procName LIKE '%\\AnyDeskMSI.exe')
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'false'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate incoming connections (e.g. sysadmin activity). Most of the time I would expect outgoing connections (initiated locally).

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-2---anydesk-files-detected-test-on-windows
- https://asec.ahnlab.com/en/40263/

---

## Rundll32 Internet Connection

| Field | Value |
|---|---|
| **Sigma ID** | `cdc8da7d-c303-42f8-b08c-b4ab47230263` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1218.011 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rundll32_net_connections.yml)**

> Detects a rundll32 that communicates with public IP addresses

```sql
-- ============================================================
-- Title:        Rundll32 Internet Connection
-- Sigma ID:     cdc8da7d-c303-42f8-b08c-b4ab47230263
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1218.011
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-11-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_rundll32_net_connections.yml
-- Unmapped:     (none)
-- False Pos:    Communication to other corporate systems that use IP addresses from public address spaces
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\rundll32.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Communication to other corporate systems that use IP addresses from public address spaces

**References:**
- https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100

---

## Silenttrinity Stager Msbuild Activity

| Field | Value |
|---|---|
| **Sigma ID** | `50e54b8d-ad73-43f8-96a1-5191685b17a4` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1127.001 |
| **Author** | Kiran kumar s, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_silenttrinity_stager_msbuild_activity.yml)**

> Detects a possible remote connections to Silenttrinity c2

```sql
-- ============================================================
-- Title:        Silenttrinity Stager Msbuild Activity
-- Sigma ID:     50e54b8d-ad73-43f8-96a1-5191685b17a4
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1127.001
-- Author:       Kiran kumar s, oscd.community
-- Date:         2020-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_silenttrinity_stager_msbuild_activity.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\msbuild.exe'
  AND (destIpPort IN ('80', '443')
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.blackhillsinfosec.com/my-first-joyride-with-silenttrinity/

---

## Suspicious Network Connection Binary No CommandLine

| Field | Value |
|---|---|
| **Sigma ID** | `20384606-a124-4fec-acbb-8bd373728613` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_binary_no_cmdline.yml)**

> Detects suspicious network connections made by a well-known Windows binary run with no command line parameters

```sql
-- ============================================================
-- Title:        Suspicious Network Connection Binary No CommandLine
-- Sigma ID:     20384606-a124-4fec-acbb-8bd373728613
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-07-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_binary_no_cmdline.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'command')] AS commandLine,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (procName LIKE '%\\regsvr32.exe' OR procName LIKE '%\\rundll32.exe' OR procName LIKE '%\\dllhost.exe')
    AND (indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%\\regsvr32.exe' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%\\rundll32.exe' OR metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '%\\dllhost.exe')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/raspberry-robin/

---

## Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder

| Field | Value |
|---|---|
| **Sigma ID** | `e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_file_sharing_domains_susp_folders.yml)**

> Detects executables located in potentially suspicious directories initiating network connections towards file sharing domains.

```sql
-- ============================================================
-- Title:        Network Communication Initiated To File Sharing Domains From Process Located In Suspicious Folder
-- Sigma ID:     e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2018-08-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_file_sharing_domains_susp_folders.yml
-- Unmapped:     (none)
-- False Pos:    Some installers located in the temp directory might communicate with the Github domains in order to download additional software. Baseline these cases or move the github domain to a lower level hunting rule.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%.githubusercontent.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%anonfiles.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%cdn.discordapp.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ddns.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%dl.dropboxusercontent.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ghostbin.co' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%github.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%glitch.me' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%gofile.io' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%hastebin.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mediafire.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mega.co.nz' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%mega.nz' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%onrender.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pages.dev' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%paste.ee' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pastebin.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pastebin.pl' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pastetext.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%pixeldrain.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%privatlab.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%privatlab.net' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%send.exploit.in' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%sendspace.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%storage.googleapis.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%storjshare.io' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%supabase.co' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%temp.sh' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%transfer.sh' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%trycloudflare.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%ufile.io' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%w3spaces.com' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%workers.dev')))
  AND (procName LIKE '%:\\$Recycle.bin%' OR procName LIKE '%:\\Perflogs\\%' OR procName LIKE '%:\\Temp\\%' OR procName LIKE '%:\\Users\\Default\\%' OR procName LIKE '%:\\Users\\Public\\%' OR procName LIKE '%:\\Windows\\Fonts\\%' OR procName LIKE '%:\\Windows\\IME\\%' OR procName LIKE '%:\\Windows\\System32\\Tasks\\%' OR procName LIKE '%:\\Windows\\Tasks\\%' OR procName LIKE '%:\\Windows\\Temp\\%' OR procName LIKE '%\\AppData\\Temp\\%' OR procName LIKE '%\\config\\systemprofile\\%' OR procName LIKE '%\\Windows\\addins\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some installers located in the temp directory might communicate with the Github domains in order to download additional software. Baseline these cases or move the github domain to a lower level hunting rule.

**References:**
- https://twitter.com/M_haggis/status/900741347035889665
- https://twitter.com/M_haggis/status/1032799638213066752
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
- https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
- https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/exfil/Invoke-ExfilDataToGitHub.ps1

---

## Network Connection Initiated From Process Located In Potentially Suspicious Or Uncommon Location

| Field | Value |
|---|---|
| **Sigma ID** | `7b434893-c57d-4f41-908d-6a17bf1ae98f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_initiated_uncommon_or_suspicious_locations.yml)**

> Detects a network connection initiated by programs or processes running from suspicious or uncommon files system locations.


```sql
-- ============================================================
-- Title:        Network Connection Initiated From Process Located In Potentially Suspicious Or Uncommon Location
-- Sigma ID:     7b434893-c57d-4f41-908d-6a17bf1ae98f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2017-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_initiated_uncommon_or_suspicious_locations.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (procName LIKE '%:\\$Recycle.bin%' OR procName LIKE '%:\\Perflogs\\%' OR procName LIKE '%:\\Temp\\%' OR procName LIKE '%:\\Users\\Default\\%' OR procName LIKE '%:\\Users\\Public\\%' OR procName LIKE '%:\\Windows\\Fonts\\%' OR procName LIKE '%:\\Windows\\IME\\%' OR procName LIKE '%:\\Windows\\System32\\Tasks\\%' OR procName LIKE '%:\\Windows\\Tasks\\%' OR procName LIKE '%\\config\\systemprofile\\%' OR procName LIKE '%\\Contacts\\%' OR procName LIKE '%\\Favorites\\%' OR procName LIKE '%\\Favourites\\%' OR procName LIKE '%\\Music\\%' OR procName LIKE '%\\Pictures\\%' OR procName LIKE '%\\Videos\\%' OR procName LIKE '%\\Windows\\addins\\%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo

---

## Potentially Suspicious Malware Callback Communication

| Field | Value |
|---|---|
| **Sigma ID** | `4b89abaa-99fe-4232-afdd-8f9aa4d20382` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1571 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_malware_callback_port.yml)**

> Detects programs that connect to known malware callback ports based on statistical analysis from two different sandbox system databases


```sql
-- ============================================================
-- Title:        Potentially Suspicious Malware Callback Communication
-- Sigma ID:     4b89abaa-99fe-4232-afdd-8f9aa4d20382
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1571
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_malware_callback_port.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND destIpPort IN ('100', '198', '200', '243', '473', '666', '700', '743', '777', '1443', '1515', '1777', '1817', '1904', '1960', '2443', '2448', '3360', '3675', '3939', '4040', '4433', '4438', '4443', '4444', '4455', '5445', '5552', '5649', '6625', '7210', '7777', '8143', '8843', '9631', '9943', '10101', '12102', '12103', '12322', '13145', '13394', '13504', '13505', '13506', '13507', '14102', '14103', '14154', '49180', '65520', '65535'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo

---

## Communication To Uncommon Destination Ports

| Field | Value |
|---|---|
| **Sigma ID** | `6d8c3d20-a5e1-494f-8412-4571d716cf5c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1571 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_malware_callback_ports_uncommon.yml)**

> Detects programs that connect to uncommon destination ports

```sql
-- ============================================================
-- Title:        Communication To Uncommon Destination Ports
-- Sigma ID:     6d8c3d20-a5e1-494f-8412-4571d716cf5c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1571
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_malware_callback_ports_uncommon.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND destIpPort IN ('8080', '8888'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo

---

## Uncommon Outbound Kerberos Connection

| Field | Value |
|---|---|
| **Sigma ID** | `e54979bd-c5f9-4d6c-967b-a04b19ac4c74` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1558, T1550.003 |
| **Author** | Ilyas Ochkov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_outbound_kerberos_connection.yml)**

> Detects uncommon outbound network activity via Kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.


```sql
-- ============================================================
-- Title:        Uncommon Outbound Kerberos Connection
-- Sigma ID:     e54979bd-c5f9-4d6c-967b-a04b19ac4c74
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1558, T1550.003
-- Author:       Ilyas Ochkov, oscd.community
-- Date:         2019-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_outbound_kerberos_connection.yml
-- Unmapped:     (none)
-- False Pos:    Web Browsers and third party application might generate similar activity. An initial baseline is required.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (destIpPort = '88'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Web Browsers and third party application might generate similar activity. An initial baseline is required.

**References:**
- https://github.com/GhostPack/Rubeus

---

## Microsoft Sync Center Suspicious Network Connections

| Field | Value |
|---|---|
| **Sigma ID** | `9f2cc74d-78af-4eb2-bb64-9cd1d292b87b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1055, T1218 |
| **Author** | elhoim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_outbound_mobsync_connection.yml)**

> Detects suspicious connections from Microsoft Sync Center to non-private IPs.

```sql
-- ============================================================
-- Title:        Microsoft Sync Center Suspicious Network Connections
-- Sigma ID:     9f2cc74d-78af-4eb2-bb64-9cd1d292b87b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1055, T1218
-- Author:       elhoim
-- Date:         2022-04-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_outbound_mobsync_connection.yml
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
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\mobsync.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://redcanary.com/blog/intelligence-insights-november-2021/

---

## Suspicious Outbound SMTP Connections

| Field | Value |
|---|---|
| **Sigma ID** | `9976fa64-2804-423c-8a5b-646ade840773` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_outbound_smtp_connections.yml)**

> Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
The data may also be sent to an alternate network location from the main command and control server.


```sql
-- ============================================================
-- Title:        Suspicious Outbound SMTP Connections
-- Sigma ID:     9976fa64-2804-423c-8a5b-646ade840773
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1048.003
-- Author:       frack113
-- Date:         2022-01-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_outbound_smtp_connections.yml
-- Unmapped:     (none)
-- False Pos:    Other SMTP tools
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (destIpPort IN ('25', '587', '465', '2525')
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other SMTP tools

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1048.003/T1048.003.md#atomic-test-5---exfiltration-over-alternative-protocol---smtp
- https://www.ietf.org/rfc/rfc2821.txt

---

## Potential Remote PowerShell Session Initiated

| Field | Value |
|---|---|
| **Sigma ID** | `c539afac-c12a-46ed-b1bd-5a5567c9f045` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1021.006 |
| **Author** | Roberto Rodriguez @Cyb3rWard0g |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_remote_powershell_session.yml)**

> Detects a process that initiated a network connection over ports 5985 or 5986 from a non-network service account.
This could potentially indicates a remote PowerShell connection.


```sql
-- ============================================================
-- Title:        Potential Remote PowerShell Session Initiated
-- Sigma ID:     c539afac-c12a-46ed-b1bd-5a5567c9f045
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001, T1021.006
-- Author:       Roberto Rodriguez @Cyb3rWard0g
-- Date:         2019-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_remote_powershell_session.yml
-- Unmapped:     SourceIsIpv6
-- False Pos:    Legitimate usage of remote PowerShell, e.g. remote administration and monitoring.; Network Service user name of a not-covered localization
-- ============================================================
-- UNMAPPED_FIELD: SourceIsIpv6

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  destIpPort,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (destIpPort IN ('5985', '5986')
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND rawEventMsg = 'false')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of remote PowerShell, e.g. remote administration and monitoring.; Network Service user name of a not-covered localization

**References:**
- https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html

---

## Outbound Network Connection To Public IP Via Winlogon

| Field | Value |
|---|---|
| **Sigma ID** | `7610a4ea-c06d-495f-a2ac-0a696abcfd3b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1218.011 |
| **Author** | Christopher Peacock @securepeacock, SCYTHE @scythe_io |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_winlogon_net_connections.yml)**

> Detects a "winlogon.exe" process that initiate network communications with public IP addresses

```sql
-- ============================================================
-- Title:        Outbound Network Connection To Public IP Via Winlogon
-- Sigma ID:     7610a4ea-c06d-495f-a2ac-0a696abcfd3b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1218.011
-- Author:       Christopher Peacock @securepeacock, SCYTHE @scythe_io
-- Date:         2023-04-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_winlogon_net_connections.yml
-- Unmapped:     (none)
-- False Pos:    Communication to other corporate systems that use IP addresses from public address spaces
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\winlogon.exe'
    AND indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Communication to other corporate systems that use IP addresses from public address spaces

**References:**
- https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/

---

## Suspicious Wordpad Outbound Connections

| Field | Value |
|---|---|
| **Sigma ID** | `786cdae8-fefb-4eb2-9227-04e34060db01` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wordpad_uncommon_ports.yml)**

> Detects a network connection initiated by "wordpad.exe" over uncommon destination ports.
This might indicate potential process injection activity from a beacon or similar mechanisms.


```sql
-- ============================================================
-- Title:        Suspicious Wordpad Outbound Connections
-- Sigma ID:     786cdae8-fefb-4eb2-9227-04e34060db01
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       X__Junior (Nextron Systems)
-- Date:         2023-07-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wordpad_uncommon_ports.yml
-- Unmapped:     (none)
-- False Pos:    Other ports can be used, apply additional filters accordingly
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND procName LIKE '%\\wordpad.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Other ports can be used, apply additional filters accordingly

**References:**
- https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit

---

## Local Network Connection Initiated By Script Interpreter

| Field | Value |
|---|---|
| **Sigma ID** | `08249dc0-a28d-4555-8ba5-9255a198e08c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wscript_cscript_local_connection.yml)**

> Detects a script interpreter (Wscript/Cscript) initiating a local network connection to download or execute a script hosted on a shared folder.


```sql
-- ============================================================
-- Title:        Local Network Connection Initiated By Script Interpreter
-- Sigma ID:     08249dc0-a28d-4555-8ba5-9255a198e08c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113
-- Date:         2022-08-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wscript_cscript_local_connection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  destIpAddrV4,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (procName LIKE '%\\wscript.exe' OR procName LIKE '%\\cscript.exe')
    AND (isIPAddressInRange(toString(destIpAddrV4), '127.0.0.0/8') OR isIPAddressInRange(toString(destIpAddrV4), '10.0.0.0/8') OR isIPAddressInRange(toString(destIpAddrV4), '172.16.0.0/12') OR isIPAddressInRange(toString(destIpAddrV4), '192.168.0.0/16') OR isIPAddressInRange(toString(destIpAddrV4), '169.254.0.0/16') OR isIPAddressInRange(toString(destIpAddrV4), '::1/128') OR isIPAddressInRange(toString(destIpAddrV4), 'fe80::/10') OR isIPAddressInRange(toString(destIpAddrV4), 'fc00::/7')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/28d190330fe44de6ff4767fc400cc10fa7cd6540/atomics/T1105/T1105.md

---

## Outbound Network Connection Initiated By Script Interpreter

| Field | Value |
|---|---|
| **Sigma ID** | `992a6cae-db6a-43c8-9cec-76d7195c96fc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wscript_cscript_outbound_connection.yml)**

> Detects a script interpreter wscript/cscript opening a network connection to a non-local network. Adversaries may use script to download malicious payloads.

```sql
-- ============================================================
-- Title:        Outbound Network Connection Initiated By Script Interpreter
-- Sigma ID:     992a6cae-db6a-43c8-9cec-76d7195c96fc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113, Florian Roth (Nextron Systems)
-- Date:         2022-08-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wscript_cscript_outbound_connection.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate scripts
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  metrics_string.value[indexOf(metrics_string.name,'initiated')] AS initiated,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND (procName LIKE '%\\wscript.exe' OR procName LIKE '%\\cscript.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate scripts

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/28d190330fe44de6ff4767fc400cc10fa7cd6540/atomics/T1105/T1105.md

---

## Potentially Suspicious Wuauclt Network Connection

| Field | Value |
|---|---|
| **Sigma ID** | `c649a6c7-cd8c-4a78-9c04-000fc76df954` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wuauclt_network_connection.yml)**

> Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making network connections.
One could easily make the DLL spawn a new process and inject to it to proxy the network connection and bypass this rule.


```sql
-- ============================================================
-- Title:        Potentially Suspicious Wuauclt Network Connection
-- Sigma ID:     c649a6c7-cd8c-4a78-9c04-000fc76df954
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wuauclt_network_connection.yml
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
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-3-Network-Connect-IPv4')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%wuauclt%'
    AND indexOf(metrics_string.name, 'command') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'command')] LIKE '% /RunHandlerComServer%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://dtm.uk/wuauclt/

---
