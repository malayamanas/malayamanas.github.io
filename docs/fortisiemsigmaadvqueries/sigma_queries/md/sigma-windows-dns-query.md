# Sigma → FortiSIEM: Windows Dns Query

> 22 rules · Generated 2026-03-17

## Table of Contents

- [DNS Query for Anonfiles.com Domain - Sysmon](#dns-query-for-anonfilescom-domain-sysmon)
- [AppX Package Installation Attempts Via AppInstaller.EXE](#appx-package-installation-attempts-via-appinstallerexe)
- [Cloudflared Tunnels Related DNS Requests](#cloudflared-tunnels-related-dns-requests)
- [DNS Query To Common Malware Hosting and Shortener Services](#dns-query-to-common-malware-hosting-and-shortener-services)
- [DNS Query To Devtunnels Domain](#dns-query-to-devtunnels-domain)
- [DNS Server Discovery Via LDAP Query](#dns-server-discovery-via-ldap-query)
- [DNS Query To AzureWebsites.NET By Non-Browser Process](#dns-query-to-azurewebsitesnet-by-non-browser-process)
- [DNS Query by Finger Utility](#dns-query-by-finger-utility)
- [Notepad++ Updater DNS Query to Uncommon Domains](#notepad-updater-dns-query-to-uncommon-domains)
- [DNS HybridConnectionManager Service Bus](#dns-hybridconnectionmanager-service-bus)
- [Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing](#suspicious-dns-query-indicating-kerberos-coercion-via-dns-object-spn-spoofing)
- [Suspicious Cobalt Strike DNS Beaconing - Sysmon](#suspicious-cobalt-strike-dns-beaconing-sysmon)
- [DNS Query To MEGA Hosting Website](#dns-query-to-mega-hosting-website)
- [DNS Query Request To OneLaunch Update Service](#dns-query-request-to-onelaunch-update-service)
- [DNS Query Request By QuickAssist.EXE](#dns-query-request-by-quickassistexe)
- [DNS Query Request By Regsvr32.EXE](#dns-query-request-by-regsvr32exe)
- [DNS Query To Remote Access Software Domain From Non-Browser App](#dns-query-to-remote-access-software-domain-from-non-browser-app)
- [Suspicious DNS Query for IP Lookup Service APIs](#suspicious-dns-query-for-ip-lookup-service-apis)
- [TeamViewer Domain Query By Non-TeamViewer Application](#teamviewer-domain-query-by-non-teamviewer-application)
- [DNS Query Tor .Onion Address - Sysmon](#dns-query-tor-onion-address-sysmon)
- [DNS Query To Ufile.io](#dns-query-to-ufileio)
- [DNS Query To Visual Studio Code Tunnels Domain](#dns-query-to-visual-studio-code-tunnels-domain)

## DNS Query for Anonfiles.com Domain - Sysmon

| Field | Value |
|---|---|
| **Sigma ID** | `065cceea-77ec-4030-9052-fc0affea7110` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | pH-T (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_anonymfiles_com.yml)**

> Detects DNS queries for "anonfiles.com", which is an anonymous file upload platform often used for malicious purposes

```sql
-- ============================================================
-- Title:        DNS Query for Anonfiles.com Domain - Sysmon
-- Sigma ID:     065cceea-77ec-4030-9052-fc0affea7110
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       pH-T (Nextron Systems)
-- Date:         2022-07-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_anonymfiles_com.yml
-- Unmapped:     QueryName
-- False Pos:    Rare legitimate access to anonfiles.com
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%.anonfiles.com%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate access to anonfiles.com

**References:**
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte

---

## AppX Package Installation Attempts Via AppInstaller.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `7cff77e1-9663-46a3-8260-17f2e1aa9d0a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_appinstaller.yml)**

> Detects DNS queries made by "AppInstaller.EXE". The AppInstaller is the default handler for the "ms-appinstaller" URI. It attempts to load/install a package from the referenced URL


```sql
-- ============================================================
-- Title:        AppX Package Installation Attempts Via AppInstaller.EXE
-- Sigma ID:     7cff77e1-9663-46a3-8260-17f2e1aa9d0a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       frack113
-- Date:         2021-11-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_appinstaller.yml
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
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE 'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller\_%'
    AND procName LIKE '%\\AppInstaller.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/notwhickey/status/1333900137232523264
- https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/

---

## Cloudflared Tunnels Related DNS Requests

| Field | Value |
|---|---|
| **Sigma ID** | `a1d9eec5-33b2-4177-8d24-27fe754d0812` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001, T1572 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_cloudflared_communication.yml)**

> Detects DNS requests to Cloudflared tunnels domains.
Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        Cloudflared Tunnels Related DNS Requests
-- Sigma ID:     a1d9eec5-33b2-4177-8d24-27fe754d0812
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001, T1572
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-12-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_cloudflared_communication.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate use of cloudflare tunnels will also trigger this.
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.v2.argotunnel.com' OR rawEventMsg LIKE '%protocol-v2.argotunnel.com' OR rawEventMsg LIKE '%trycloudflare.com' OR rawEventMsg LIKE '%update.argotunnel.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of cloudflare tunnels will also trigger this.

**References:**
- https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
- Internal Research

---

## DNS Query To Common Malware Hosting and Shortener Services

| Field | Value |
|---|---|
| **Sigma ID** | `f8c1e80b-c73a-476a-ae24-6c72528b1521` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.004 |
| **Author** | Ahmed Nosir (@egycondor) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_common_malware_hosting_services.yml)**

> Detects DNS queries to domains commonly used by threat actors to host malware payloads or redirect through URL shorteners.
These include platforms like Cloudflare Workers, TryCloudflare, InfinityFree, and URL shorteners such as tinyurl and lihi.cc.
Such DNS activity can indicate potential delivery or command-and-control communication attempts.


```sql
-- ============================================================
-- Title:        DNS Query To Common Malware Hosting and Shortener Services
-- Sigma ID:     f8c1e80b-c73a-476a-ae24-6c72528b1521
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1071.004
-- Author:       Ahmed Nosir (@egycondor)
-- Date:         2025-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_common_malware_hosting_services.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate use of these services is possible but rare in enterprise environments
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%msapp.workers.dev%' OR rawEventMsg LIKE '%trycloudflare.com%' OR rawEventMsg LIKE '%infinityfreeapp.com%' OR rawEventMsg LIKE '%my5353.com%' OR rawEventMsg LIKE '%reurl.cc%' OR rawEventMsg LIKE '%lihi.cc%' OR rawEventMsg LIKE '%tinyurl.com%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of these services is possible but rare in enterprise environments

**References:**
- https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics

---

## DNS Query To Devtunnels Domain

| Field | Value |
|---|---|
| **Sigma ID** | `1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001, T1572 |
| **Author** | citron_ninja |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_devtunnels_communication.yml)**

> Detects DNS query requests to Devtunnels domains. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        DNS Query To Devtunnels Domain
-- Sigma ID:     1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001, T1572
-- Author:       citron_ninja
-- Date:         2023-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_devtunnels_communication.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate use of Devtunnels will also trigger this.
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%.devtunnels.ms'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Devtunnels will also trigger this.

**References:**
- https://blueteamops.medium.com/detecting-dev-tunnels-16f0994dc3e2
- https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security
- https://cydefops.com/devtunnels-unleashed

---

## DNS Server Discovery Via LDAP Query

| Field | Value |
|---|---|
| **Sigma ID** | `a21bcd7e-38ec-49ad-b69a-9ea17e69509e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1482 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_dns_server_discovery_via_ldap_query.yml)**

> Detects DNS server discovery via LDAP query requests from uncommon applications

```sql
-- ============================================================
-- Title:        DNS Server Discovery Via LDAP Query
-- Sigma ID:     a21bcd7e-38ec-49ad-b69a-9ea17e69509e
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1482
-- Author:       frack113
-- Date:         2022-08-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_dns_server_discovery_via_ldap_query.yml
-- Unmapped:     QueryName
-- False Pos:    Likely
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '\_ldap.%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/980f3f83fd81f37c1ca9c02dccfd1c3d9f9d0841/atomics/T1016/T1016.md#atomic-test-9---dns-server-discovery-using-nslookup
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04

---

## DNS Query To AzureWebsites.NET By Non-Browser Process

| Field | Value |
|---|---|
| **Sigma ID** | `e043f529-8514-4205-8ab0-7f7d2927b400` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml)**

> Detects a DNS query by a non browser process on the system to "azurewebsites.net". The latter was often used by threat actors as a malware hosting and exfiltration site.


```sql
-- ============================================================
-- Title:        DNS Query To AzureWebsites.NET By Non-Browser Process
-- Sigma ID:     e043f529-8514-4205-8ab0-7f7d2927b400
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2024-06-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml
-- Unmapped:     QueryName
-- False Pos:    Likely with other browser software. Apply additional filters for any other browsers you might use.
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%azurewebsites.net'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely with other browser software. Apply additional filters for any other browsers you might use.

**References:**
- https://www.sentinelone.com/labs/wip26-espionage-threat-actors-abuse-cloud-infrastructure-in-targeted-telco-attacks/
- https://symantec-enterprise-blogs.security.com/threat-intelligence/harvester-new-apt-attacks-asia
- https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
- https://intezer.com/blog/research/how-we-escaped-docker-in-azure-functions/

---

## DNS Query by Finger Utility

| Field | Value |
|---|---|
| **Sigma ID** | `c082c2b0-525b-4dbc-9a26-a57dc4692074` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1071.004, T1059.003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_finger.yml)**

> Detects DNS queries made by the finger utility, which can be abused by threat actors to retrieve remote commands for execution on Windows devices.
In one ClickFix malware campaign, adversaries leveraged the finger protocol to fetch commands from a remote server.
Since the finger utility is not commonly used in modern Windows environments, its presence already raises suspicion.
Investigating such DNS queries can also help identify potential malicious infrastructure used by threat actors for command and control (C2) communication.


```sql
-- ============================================================
-- Title:        DNS Query by Finger Utility
-- Sigma ID:     c082c2b0-525b-4dbc-9a26-a57dc4692074
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        execution | T1071.004, T1059.003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_finger.yml
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
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\finger.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.bleepingcomputer.com/news/security/decades-old-finger-protocol-abused-in-clickfix-malware-attacks/

---

## Notepad++ Updater DNS Query to Uncommon Domains

| Field | Value |
|---|---|
| **Sigma ID** | `2074e137-1b73-4e2d-88ba-5a3407dbdce0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1195.002, T1557 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_gup_query_to_uncommon_domains.yml)**

> Detects when the Notepad++ updater (gup.exe) makes DNS queries to domains that are not part of the known legitimate update infrastructure.
This could indicate potential exploitation of the updater mechanism or suspicious network activity that warrants further investigation.


```sql
-- ============================================================
-- Title:        Notepad++ Updater DNS Query to Uncommon Domains
-- Sigma ID:     2074e137-1b73-4e2d-88ba-5a3407dbdce0
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        collection | T1195.002, T1557
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2026-02-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_gup_query_to_uncommon_domains.yml
-- Unmapped:     (none)
-- False Pos:    Some legitimate network misconfigurations or proxy issues causing unexpected DNS queries.; Other legitimate query to official domains not listed in the filter, needing tuning.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\gup.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some legitimate network misconfigurations or proxy issues causing unexpected DNS queries.; Other legitimate query to official domains not listed in the filter, needing tuning.

**References:**
- https://notepad-plus-plus.org/news/v889-released/
- https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
- https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
- https://www.validin.com/blog/exploring_notepad_plus_plus_network_indicators/
- https://securelist.com/notepad-supply-chain-attack/118708/

---

## DNS HybridConnectionManager Service Bus

| Field | Value |
|---|---|
| **Sigma ID** | `7bd3902d-8b8b-4dd4-838a-c6862d40150d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1554 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_hybridconnectionmgr_servicebus.yml)**

> Detects Azure Hybrid Connection Manager services querying the Azure service bus service

```sql
-- ============================================================
-- Title:        DNS HybridConnectionManager Service Bus
-- Sigma ID:     7bd3902d-8b8b-4dd4-838a-c6862d40150d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1554
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2021-04-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_hybridconnectionmgr_servicebus.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%servicebus.windows.net%'
    AND procName LIKE '%HybridConnectionManager%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service

**References:**
- https://twitter.com/Cyb3rWard0g/status/1381642789369286662

---

## Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing

| Field | Value |
|---|---|
| **Sigma ID** | `e7a21b5f-d8c4-4ae5-b8d9-93c5d3f28e1c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection, persistence |
| **MITRE Techniques** | T1557.001, T1187 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_kerberos_coercion_via_dns_object_spoofing.yml)**

> Detects DNS queries containing patterns associated with Kerberos coercion attacks via DNS object spoofing.
The pattern "1UWhRCAAAAA..BAAAA" is a base64-encoded signature that corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure.
Attackers can use this technique to coerce authentication from victim systems to attacker-controlled hosts.
It is one of the strong indicators of a Kerberos coercion attack, where adversaries manipulate DNS records
to spoof Service Principal Names (SPNs) and redirect authentication requests like CVE-2025-33073.


```sql
-- ============================================================
-- Title:        Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing
-- Sigma ID:     e7a21b5f-d8c4-4ae5-b8d9-93c5d3f28e1c
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        collection, persistence | T1557.001, T1187
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_kerberos_coercion_via_dns_object_spoofing.yml
-- Unmapped:     QueryName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%UWhRCA%' AND rawEventMsg LIKE '%BAAAA%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
- https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html

---

## Suspicious Cobalt Strike DNS Beaconing - Sysmon

| Field | Value |
|---|---|
| **Sigma ID** | `f356a9c4-effd-4608-bbf8-408afd5cd006` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1071.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_mal_cobaltstrike.yml)**

> Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons

```sql
-- ============================================================
-- Title:        Suspicious Cobalt Strike DNS Beaconing - Sysmon
-- Sigma ID:     f356a9c4-effd-4608-bbf8-408afd5cd006
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1071.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-11-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_mal_cobaltstrike.yml
-- Unmapped:     QueryName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'aaa.stage.%' OR rawEventMsg LIKE 'post.1%')
  OR rawEventMsg LIKE '%.stage.123456.%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
- https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/

---

## DNS Query To MEGA Hosting Website

| Field | Value |
|---|---|
| **Sigma ID** | `613c03ba-0779-4a53-8a1f-47f914a4ded3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Aaron Greetham (@beardofbinary) - NCC Group |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_mega_nz.yml)**

> Detects DNS queries for subdomains related to MEGA sharing website

```sql
-- ============================================================
-- Title:        DNS Query To MEGA Hosting Website
-- Sigma ID:     613c03ba-0779-4a53-8a1f-47f914a4ded3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Aaron Greetham (@beardofbinary) - NCC Group
-- Date:         2021-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_mega_nz.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate DNS queries and usage of Mega
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%userstorage.mega.co.nz%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate DNS queries and usage of Mega

**References:**
- https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/

---

## DNS Query Request To OneLaunch Update Service

| Field | Value |
|---|---|
| **Sigma ID** | `df68f791-ad95-447f-a271-640a0dab9cf8` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1056 |
| **Author** | Josh Nickels |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_onelaunch_update_service.yml)**

> Detects DNS query requests to "update.onelaunch.com". This domain is associated with the OneLaunch adware application.
When the OneLaunch application is installed it will attempt to get updates from this domain.


```sql
-- ============================================================
-- Title:        DNS Query Request To OneLaunch Update Service
-- Sigma ID:     df68f791-ad95-447f-a271-640a0dab9cf8
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1056
-- Author:       Josh Nickels
-- Date:         2024-02-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_onelaunch_update_service.yml
-- Unmapped:     QueryName
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'update.onelaunch.com'
    AND procName LIKE '%\\OneLaunch.exe')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.malwarebytes.com/blog/detections/pup-optional-onelaunch-silentcf
- https://www.myantispyware.com/2020/12/14/how-to-uninstall-onelaunch-browser-removal-guide/
- https://malware.guide/browser-hijacker/remove-onelaunch-virus/

---

## DNS Query Request By QuickAssist.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `882e858a-3233-4ba8-855e-2f3d3575803d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1071.001, T1210 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_quickassist.yml)**

> Detects DNS queries initiated by "QuickAssist.exe" to Microsoft Quick Assist primary endpoint that is used to establish a session.


```sql
-- ============================================================
-- Title:        DNS Query Request By QuickAssist.EXE
-- Sigma ID:     882e858a-3233-4ba8-855e-2f3d3575803d
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        T1071.001, T1210
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-12-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_quickassist.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate use of Quick Assist in the environment.
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%\\QuickAssist.exe'
    AND rawEventMsg LIKE '%remoteassistance.support.services.microsoft.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Quick Assist in the environment.

**References:**
- https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
- https://www.linkedin.com/posts/kevin-beaumont-security_ive-been-assisting-a-few-orgs-hit-with-successful-activity-7268055739116445701-xxjZ/
- https://x.com/cyb3rops/status/1862406110365245506
- https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist

---

## DNS Query Request By Regsvr32.EXE

| Field | Value |
|---|---|
| **Sigma ID** | `36e037c4-c228-4866-b6a3-48eb292b9955` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1559.001, T1218.010 |
| **Author** | Dmitriy Lifanov, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_regsvr32_dns_query.yml)**

> Detects DNS queries initiated by "Regsvr32.exe"

```sql
-- ============================================================
-- Title:        DNS Query Request By Regsvr32.EXE
-- Sigma ID:     36e037c4-c228-4866-b6a3-48eb292b9955
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1559.001, T1218.010
-- Author:       Dmitriy Lifanov, oscd.community
-- Date:         2019-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_regsvr32_dns_query.yml
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
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND procName LIKE '%\\regsvr32.exe'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
- https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/

---

## DNS Query To Remote Access Software Domain From Non-Browser App

| Field | Value |
|---|---|
| **Sigma ID** | `4d07b1f4-cb00-4470-b9f8-b0191d48ff52` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | frack113, Connor Martin |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_remote_access_software_domains_non_browsers.yml)**

> An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


```sql
-- ============================================================
-- Title:        DNS Query To Remote Access Software Domain From Non-Browser App
-- Sigma ID:     4d07b1f4-cb00-4470-b9f8-b0191d48ff52
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       frack113, Connor Martin
-- Date:         2022-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_remote_access_software_domains_non_browsers.yml
-- Unmapped:     (none)
-- False Pos:    Likely with other browser software. Apply additional filters for any other browsers you might use.
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Likely with other browser software. Apply additional filters for any other browsers you might use.

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-3---logmein-files-detected-test-on-windows
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-6---ammyy-admin-software-execution
- https://redcanary.com/blog/misbehaving-rats/
- https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/hunting-for-omi-vulnerability-exploitation-with-azure-sentinel/ba-p/2764093
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
- https://blog.sekoia.io/scattered-spider-laying-new-eggs/
- https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist#disable-quick-assist-within-your-organization

---

## Suspicious DNS Query for IP Lookup Service APIs

| Field | Value |
|---|---|
| **Sigma ID** | `ec82e2a5-81ea-4211-a1f8-37a0286df2c2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1590 |
| **Author** | Brandon George (blog post), Thomas Patzke |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_susp_external_ip_lookup.yml)**

> Detects DNS queries for IP lookup services such as "api.ipify.org" originating from a non browser process.

```sql
-- ============================================================
-- Title:        Suspicious DNS Query for IP Lookup Service APIs
-- Sigma ID:     ec82e2a5-81ea-4211-a1f8-37a0286df2c2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance | T1590
-- Author:       Brandon George (blog post), Thomas Patzke
-- Date:         2021-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_susp_external_ip_lookup.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate usage of IP lookup services such as ipify API
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('www.ip.cn', 'l2.io'))
  OR ((rawEventMsg LIKE '%api.2ip.ua%' OR rawEventMsg LIKE '%api.bigdatacloud.net%' OR rawEventMsg LIKE '%api.ipify.org%' OR rawEventMsg LIKE '%bot.whatismyipaddress.com%' OR rawEventMsg LIKE '%canireachthe.net%' OR rawEventMsg LIKE '%checkip.amazonaws.com%' OR rawEventMsg LIKE '%checkip.dyndns.org%' OR rawEventMsg LIKE '%curlmyip.com%' OR rawEventMsg LIKE '%db-ip.com%' OR rawEventMsg LIKE '%edns.ip-api.com%' OR rawEventMsg LIKE '%eth0.me%' OR rawEventMsg LIKE '%freegeoip.app%' OR rawEventMsg LIKE '%geoipy.com%' OR rawEventMsg LIKE '%getip.pro%' OR rawEventMsg LIKE '%icanhazip.com%' OR rawEventMsg LIKE '%ident.me%' OR rawEventMsg LIKE '%ifconfig.io%' OR rawEventMsg LIKE '%ifconfig.me%' OR rawEventMsg LIKE '%ip-api.com%' OR rawEventMsg LIKE '%ip.360.cn%' OR rawEventMsg LIKE '%ip.anysrc.net%' OR rawEventMsg LIKE '%ip.taobao.com%' OR rawEventMsg LIKE '%ip.tyk.nu%' OR rawEventMsg LIKE '%ipaddressworld.com%' OR rawEventMsg LIKE '%ipapi.co%' OR rawEventMsg LIKE '%ipconfig.io%' OR rawEventMsg LIKE '%ipecho.net%' OR rawEventMsg LIKE '%ipinfo.io%' OR rawEventMsg LIKE '%ipip.net%' OR rawEventMsg LIKE '%ipof.in%' OR rawEventMsg LIKE '%ipv4.icanhazip.com%' OR rawEventMsg LIKE '%ipv4bot.whatismyipaddress.com%' OR rawEventMsg LIKE '%ipv6-test.com%' OR rawEventMsg LIKE '%ipwho.is%' OR rawEventMsg LIKE '%jsonip.com%' OR rawEventMsg LIKE '%myexternalip.com%' OR rawEventMsg LIKE '%seeip.org%' OR rawEventMsg LIKE '%wgetip.com%' OR rawEventMsg LIKE '%whatismyip.akamai.com%' OR rawEventMsg LIKE '%whois.pconline.com.cn%' OR rawEventMsg LIKE '%wtfismyip.com%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of IP lookup services such as ipify API

**References:**
- https://www.binarydefense.com/analysis-of-hancitor-when-boring-begets-beacon
- https://twitter.com/neonprimetime/status/1436376497980428318
- https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html

---

## TeamViewer Domain Query By Non-TeamViewer Application

| Field | Value |
|---|---|
| **Sigma ID** | `778ba9a8-45e4-4b80-8e3e-34a419f0b85e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_teamviewer_domain_query_by_uncommon_app.yml)**

> Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)

```sql
-- ============================================================
-- Title:        TeamViewer Domain Query By Non-TeamViewer Application
-- Sigma ID:     778ba9a8-45e4-4b80-8e3e-34a419f0b85e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-01-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_teamviewer_domain_query_by_uncommon_app.yml
-- Unmapped:     QueryName
-- False Pos:    Unknown binary names of TeamViewer; Depending on the environment the rule might require some initial tuning before usage to avoid FP with third party applications
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('taf.teamviewer.com', 'udp.ping.teamviewer.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown binary names of TeamViewer; Depending on the environment the rule might require some initial tuning before usage to avoid FP with third party applications

**References:**
- https://www.teamviewer.com/en-us/

---

## DNS Query Tor .Onion Address - Sysmon

| Field | Value |
|---|---|
| **Sigma ID** | `b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090.003 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_tor_onion_domain_query.yml)**

> Detects DNS queries to an ".onion" address related to Tor routing networks

```sql
-- ============================================================
-- Title:        DNS Query Tor .Onion Address - Sysmon
-- Sigma ID:     b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090.003
-- Author:       frack113
-- Date:         2022-02-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_tor_onion_domain_query.yml
-- Unmapped:     QueryName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.hiddenservice.net' OR rawEventMsg LIKE '%.onion.ca' OR rawEventMsg LIKE '%.onion.cab' OR rawEventMsg LIKE '%.onion.casa' OR rawEventMsg LIKE '%.onion.city' OR rawEventMsg LIKE '%.onion.direct' OR rawEventMsg LIKE '%.onion.dog' OR rawEventMsg LIKE '%.onion.glass' OR rawEventMsg LIKE '%.onion.gq' OR rawEventMsg LIKE '%.onion.ink' OR rawEventMsg LIKE '%.onion.it' OR rawEventMsg LIKE '%.onion.link' OR rawEventMsg LIKE '%.onion.lt' OR rawEventMsg LIKE '%.onion.lu' OR rawEventMsg LIKE '%.onion.nu' OR rawEventMsg LIKE '%.onion.pet' OR rawEventMsg LIKE '%.onion.plus' OR rawEventMsg LIKE '%.onion.rip' OR rawEventMsg LIKE '%.onion.sh' OR rawEventMsg LIKE '%.onion.to' OR rawEventMsg LIKE '%.onion.top' OR rawEventMsg LIKE '%.onion' OR rawEventMsg LIKE '%.s1.tor-gateways.de' OR rawEventMsg LIKE '%.s2.tor-gateways.de' OR rawEventMsg LIKE '%.s3.tor-gateways.de' OR rawEventMsg LIKE '%.s4.tor-gateways.de' OR rawEventMsg LIKE '%.s5.tor-gateways.de' OR rawEventMsg LIKE '%.t2w.pw' OR rawEventMsg LIKE '%.tor2web.ae.org' OR rawEventMsg LIKE '%.tor2web.blutmagie.de' OR rawEventMsg LIKE '%.tor2web.com' OR rawEventMsg LIKE '%.tor2web.fi' OR rawEventMsg LIKE '%.tor2web.io' OR rawEventMsg LIKE '%.tor2web.org' OR rawEventMsg LIKE '%.tor2web.xyz' OR rawEventMsg LIKE '%.torlink.co')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
- https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/ASimDNS/imDNS_TorProxies.yaml

---

## DNS Query To Ufile.io

| Field | Value |
|---|---|
| **Sigma ID** | `1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | yatinwad, TheDFIRReport |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_ufile_io_query.yml)**

> Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration

```sql
-- ============================================================
-- Title:        DNS Query To Ufile.io
-- Sigma ID:     1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       yatinwad, TheDFIRReport
-- Date:         2022-06-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_ufile_io_query.yml
-- Unmapped:     QueryName
-- False Pos:    DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ufile.io%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take

**References:**
- https://thedfirreport.com/2021/12/13/diavol-ransomware/

---

## DNS Query To Visual Studio Code Tunnels Domain

| Field | Value |
|---|---|
| **Sigma ID** | `b3e6418f-7c7a-4fad-993a-93b65027a9f1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | citron_ninja |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_vscode_tunnel_communication.yml)**

> Detects DNS query requests to Visual Studio Code tunnel domains. Attackers can abuse that feature to establish a reverse shell or persistence on a machine.


```sql
-- ============================================================
-- Title:        DNS Query To Visual Studio Code Tunnels Domain
-- Sigma ID:     b3e6418f-7c7a-4fad-993a-93b65027a9f1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       citron_ninja
-- Date:         2023-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_vscode_tunnel_communication.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate use of Visual Studio Code tunnel will also trigger this.
-- ============================================================
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-22-DNS-Query')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%.tunnels.api.visualstudio.com'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Visual Studio Code tunnel will also trigger this.

**References:**
- https://ipfyx.fr/post/visual-studio-code-tunnel/
- https://badoption.eu/blog/2023/01/31/code_c2.html
- https://cydefops.com/vscode-data-exfiltration

---
