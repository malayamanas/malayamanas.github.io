# Sigma → FortiSIEM:  Proxy

> 29 rules · Generated 2026-03-17

## Table of Contents

- [Download from Suspicious Dyndns Hosts](#download-from-suspicious-dyndns-hosts)
- [Download From Suspicious TLD - Blacklist](#download-from-suspicious-tld-blacklist)
- [Download From Suspicious TLD - Whitelist](#download-from-suspicious-tld-whitelist)
- [Windows WebDAV User Agent](#windows-webdav-user-agent)
- [F5 BIG-IP iControl Rest API Command Execution - Proxy](#f5-big-ip-icontrol-rest-api-command-execution-proxy)
- [Potential Hello-World Scraper Botnet Activity](#potential-hello-world-scraper-botnet-activity)
- [HackTool - BabyShark Agent Default URL Pattern](#hacktool-babyshark-agent-default-url-pattern)
- [HackTool - CobaltStrike Malleable Profile Patterns - Proxy](#hacktool-cobaltstrike-malleable-profile-patterns-proxy)
- [HackTool - Empire UserAgent URI Combo](#hacktool-empire-useragent-uri-combo)
- [PUA - Advanced IP/Port Scanner Update Check](#pua-advanced-ipport-scanner-update-check)
- [PwnDrp Access](#pwndrp-access)
- [Raw Paste Service Access](#raw-paste-service-access)
- [Flash Player Update from Suspicious Location](#flash-player-update-from-suspicious-location)
- [Suspicious Network Communication With IPFS](#suspicious-network-communication-with-ipfs)
- [Telegram API Access](#telegram-api-access)
- [APT User Agent](#apt-user-agent)
- [Suspicious Base64 Encoded User-Agent](#suspicious-base64-encoded-user-agent)
- [Bitsadmin to Uncommon IP Server Address](#bitsadmin-to-uncommon-ip-server-address)
- [Bitsadmin to Uncommon TLD](#bitsadmin-to-uncommon-tld)
- [Crypto Miner User Agent](#crypto-miner-user-agent)
- [HTTP Request With Empty User Agent](#http-request-with-empty-user-agent)
- [Exploit Framework User Agent](#exploit-framework-user-agent)
- [Hack Tool User Agent](#hack-tool-user-agent)
- [Malware User Agent](#malware-user-agent)
- [Windows PowerShell User Agent](#windows-powershell-user-agent)
- [Rclone Activity via Proxy](#rclone-activity-via-proxy)
- [Suspicious User Agent](#suspicious-user-agent)
- [Potential Base64 Encoded User-Agent](#potential-base64-encoded-user-agent)
- [Suspicious External WebDAV Execution](#suspicious-external-webdav-execution)

## Download from Suspicious Dyndns Hosts

| Field | Value |
|---|---|
| **Sigma ID** | `195c1119-ef07-4909-bb12-e66f5e07bf3c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105, T1568 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_download_susp_dyndns.yml)**

> Detects download of certain file types from hosts with dynamic DNS names (selected list)

```sql
-- ============================================================
-- Title:        Download from Suspicious Dyndns Hosts
-- Sigma ID:     195c1119-ef07-4909-bb12-e66f5e07bf3c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105, T1568
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_download_susp_dyndns.yml
-- Unmapped:     c-uri-extension, cs-host
-- False Pos:    Software downloads
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri-extension
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('exe', 'vbs', 'bat', 'rar', 'ps1', 'doc', 'docm', 'xls', 'xlsm', 'pptm', 'rtf', 'hta', 'dll', 'ws', 'wsf', 'sct', 'zip')
    AND (rawEventMsg LIKE '%.hopto.org' OR rawEventMsg LIKE '%.no-ip.org' OR rawEventMsg LIKE '%.no-ip.info' OR rawEventMsg LIKE '%.no-ip.biz' OR rawEventMsg LIKE '%.no-ip.com' OR rawEventMsg LIKE '%.noip.com' OR rawEventMsg LIKE '%.ddns.name' OR rawEventMsg LIKE '%.myftp.org' OR rawEventMsg LIKE '%.myftp.biz' OR rawEventMsg LIKE '%.serveblog.net' OR rawEventMsg LIKE '%.servebeer.com' OR rawEventMsg LIKE '%.servemp3.com' OR rawEventMsg LIKE '%.serveftp.com' OR rawEventMsg LIKE '%.servequake.com' OR rawEventMsg LIKE '%.servehalflife.com' OR rawEventMsg LIKE '%.servehttp.com' OR rawEventMsg LIKE '%.servegame.com' OR rawEventMsg LIKE '%.servepics.com' OR rawEventMsg LIKE '%.myvnc.com' OR rawEventMsg LIKE '%.ignorelist.com' OR rawEventMsg LIKE '%.jkub.com' OR rawEventMsg LIKE '%.dlinkddns.com' OR rawEventMsg LIKE '%.jumpingcrab.com' OR rawEventMsg LIKE '%.ddns.info' OR rawEventMsg LIKE '%.mooo.com' OR rawEventMsg LIKE '%.dns-dns.com' OR rawEventMsg LIKE '%.strangled.net' OR rawEventMsg LIKE '%.adultdns.net' OR rawEventMsg LIKE '%.craftx.biz' OR rawEventMsg LIKE '%.ddns01.com' OR rawEventMsg LIKE '%.dns53.biz' OR rawEventMsg LIKE '%.dnsapi.info' OR rawEventMsg LIKE '%.dnsd.info' OR rawEventMsg LIKE '%.dnsdynamic.com' OR rawEventMsg LIKE '%.dnsdynamic.net' OR rawEventMsg LIKE '%.dnsget.org' OR rawEventMsg LIKE '%.fe100.net' OR rawEventMsg LIKE '%.flashserv.net' OR rawEventMsg LIKE '%.ftp21.net' OR rawEventMsg LIKE '%.http01.com' OR rawEventMsg LIKE '%.http80.info' OR rawEventMsg LIKE '%.https443.com' OR rawEventMsg LIKE '%.imap01.com' OR rawEventMsg LIKE '%.kadm5.com' OR rawEventMsg LIKE '%.mysq1.net' OR rawEventMsg LIKE '%.ns360.info' OR rawEventMsg LIKE '%.ntdll.net' OR rawEventMsg LIKE '%.ole32.com' OR rawEventMsg LIKE '%.proxy8080.com' OR rawEventMsg LIKE '%.sql01.com' OR rawEventMsg LIKE '%.ssh01.com' OR rawEventMsg LIKE '%.ssh22.net' OR rawEventMsg LIKE '%.tempors.com' OR rawEventMsg LIKE '%.tftpd.net' OR rawEventMsg LIKE '%.ttl60.com' OR rawEventMsg LIKE '%.ttl60.org' OR rawEventMsg LIKE '%.user32.com' OR rawEventMsg LIKE '%.voip01.com' OR rawEventMsg LIKE '%.wow64.net' OR rawEventMsg LIKE '%.x64.me' OR rawEventMsg LIKE '%.xns01.com' OR rawEventMsg LIKE '%.dyndns.org' OR rawEventMsg LIKE '%.dyndns.info' OR rawEventMsg LIKE '%.dyndns.tv' OR rawEventMsg LIKE '%.dyndns-at-home.com' OR rawEventMsg LIKE '%.dnsomatic.com' OR rawEventMsg LIKE '%.zapto.org' OR rawEventMsg LIKE '%.webhop.net' OR rawEventMsg LIKE '%.25u.com' OR rawEventMsg LIKE '%.slyip.net'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Software downloads

**References:**
- https://www.alienvault.com/blogs/security-essentials/dynamic-dns-security-and-potential-threats

---

## Download From Suspicious TLD - Blacklist

| Field | Value |
|---|---|
| **Sigma ID** | `00d0b5ab-1f55-4120-8e83-487c0a7baf19` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1566, T1203, T1204.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_download_susp_tlds_blacklist.yml)**

> Detects download of certain file types from hosts in suspicious TLDs

```sql
-- ============================================================
-- Title:        Download From Suspicious TLD - Blacklist
-- Sigma ID:     00d0b5ab-1f55-4120-8e83-487c0a7baf19
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1566, T1203, T1204.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-11-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_download_susp_tlds_blacklist.yml
-- Unmapped:     c-uri-extension, cs-host
-- False Pos:    All kinds of software downloads
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri-extension
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('exe', 'vbs', 'bat', 'rar', 'ps1', 'doc', 'docm', 'xls', 'xlsm', 'pptm', 'rtf', 'hta', 'dll', 'ws', 'wsf', 'sct', 'zip')
    AND (rawEventMsg LIKE '%.country' OR rawEventMsg LIKE '%.stream' OR rawEventMsg LIKE '%.gdn' OR rawEventMsg LIKE '%.mom' OR rawEventMsg LIKE '%.xin' OR rawEventMsg LIKE '%.kim' OR rawEventMsg LIKE '%.men' OR rawEventMsg LIKE '%.loan' OR rawEventMsg LIKE '%.download' OR rawEventMsg LIKE '%.racing' OR rawEventMsg LIKE '%.online' OR rawEventMsg LIKE '%.science' OR rawEventMsg LIKE '%.ren' OR rawEventMsg LIKE '%.gb' OR rawEventMsg LIKE '%.win' OR rawEventMsg LIKE '%.top' OR rawEventMsg LIKE '%.review' OR rawEventMsg LIKE '%.vip' OR rawEventMsg LIKE '%.party' OR rawEventMsg LIKE '%.tech' OR rawEventMsg LIKE '%.xyz' OR rawEventMsg LIKE '%.date' OR rawEventMsg LIKE '%.faith' OR rawEventMsg LIKE '%.zip' OR rawEventMsg LIKE '%.cricket' OR rawEventMsg LIKE '%.space' OR rawEventMsg LIKE '%.info' OR rawEventMsg LIKE '%.vn' OR rawEventMsg LIKE '%.cm' OR rawEventMsg LIKE '%.am' OR rawEventMsg LIKE '%.cc' OR rawEventMsg LIKE '%.asia' OR rawEventMsg LIKE '%.ws' OR rawEventMsg LIKE '%.tk' OR rawEventMsg LIKE '%.biz' OR rawEventMsg LIKE '%.su' OR rawEventMsg LIKE '%.st' OR rawEventMsg LIKE '%.ro' OR rawEventMsg LIKE '%.ge' OR rawEventMsg LIKE '%.ms' OR rawEventMsg LIKE '%.pk' OR rawEventMsg LIKE '%.nu' OR rawEventMsg LIKE '%.me' OR rawEventMsg LIKE '%.ph' OR rawEventMsg LIKE '%.to' OR rawEventMsg LIKE '%.tt' OR rawEventMsg LIKE '%.name' OR rawEventMsg LIKE '%.tv' OR rawEventMsg LIKE '%.kz' OR rawEventMsg LIKE '%.tc' OR rawEventMsg LIKE '%.mobi' OR rawEventMsg LIKE '%.study' OR rawEventMsg LIKE '%.click' OR rawEventMsg LIKE '%.link' OR rawEventMsg LIKE '%.trade' OR rawEventMsg LIKE '%.accountant' OR rawEventMsg LIKE '%.cf' OR rawEventMsg LIKE '%.gq' OR rawEventMsg LIKE '%.ml' OR rawEventMsg LIKE '%.ga' OR rawEventMsg LIKE '%.pw'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** All kinds of software downloads

**References:**
- https://www.symantec.com/connect/blogs/shady-tld-research-gdn-and-our-2016-wrap
- https://promos.mcafee.com/en-US/PDF/MTMW_Report.pdf
- https://www.spamhaus.org/statistics/tlds/
- https://krebsonsecurity.com/2018/06/bad-men-at-work-please-dont-click/

---

## Download From Suspicious TLD - Whitelist

| Field | Value |
|---|---|
| **Sigma ID** | `b5de2919-b74a-4805-91a7-5049accbaefe` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1566, T1203, T1204.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_download_susp_tlds_whitelist.yml)**

> Detects executable downloads from suspicious remote systems

```sql
-- ============================================================
-- Title:        Download From Suspicious TLD - Whitelist
-- Sigma ID:     b5de2919-b74a-4805-91a7-5049accbaefe
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution | T1566, T1203, T1204.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_download_susp_tlds_whitelist.yml
-- Unmapped:     c-uri-extension, cs-host
-- False Pos:    All kind of software downloads
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri-extension
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('exe', 'vbs', 'bat', 'rar', 'ps1', 'doc', 'docm', 'xls', 'xlsm', 'pptm', 'rtf', 'hta', 'dll', 'ws', 'wsf', 'sct', 'zip')
  AND NOT ((rawEventMsg LIKE '%.com' OR rawEventMsg LIKE '%.org' OR rawEventMsg LIKE '%.net' OR rawEventMsg LIKE '%.edu' OR rawEventMsg LIKE '%.gov' OR rawEventMsg LIKE '%.uk' OR rawEventMsg LIKE '%.ca' OR rawEventMsg LIKE '%.de' OR rawEventMsg LIKE '%.jp' OR rawEventMsg LIKE '%.fr' OR rawEventMsg LIKE '%.au' OR rawEventMsg LIKE '%.us' OR rawEventMsg LIKE '%.ch' OR rawEventMsg LIKE '%.it' OR rawEventMsg LIKE '%.nl' OR rawEventMsg LIKE '%.se' OR rawEventMsg LIKE '%.no' OR rawEventMsg LIKE '%.es')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** All kind of software downloads

**References:**
- Internal Research

---

## Windows WebDAV User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `e09aed7a-09e0-4c9a-90dd-f0d52507347e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_downloadcradle_webdav.yml)**

> Detects WebDav DownloadCradle

```sql
-- ============================================================
-- Title:        Windows WebDAV User Agent
-- Sigma ID:     e09aed7a-09e0-4c9a-90dd-f0d52507347e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-04-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_downloadcradle_webdav.yml
-- Unmapped:     c-useragent, cs-method
-- False Pos:    Administrative scripts that download files from the Internet; Administrative scripts that retrieve certain website contents; Legitimate WebDAV administration
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: cs-method

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'Microsoft-WebDAV-MiniRedir/%'
    AND rawEventMsg = 'GET')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts that download files from the Internet; Administrative scripts that retrieve certain website contents; Legitimate WebDAV administration

**References:**
- https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html

---

## F5 BIG-IP iControl Rest API Command Execution - Proxy

| Field | Value |
|---|---|
| **Sigma ID** | `b59c98c6-95e8-4d65-93ee-f594dfb96b17` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Nasreddine Bencherchali (Nextron Systems), Thurein Oo |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_f5_tm_utility_bash_api_request.yml)**

> Detects POST requests to the F5 BIG-IP iControl Rest API "bash" endpoint, which allows the execution of commands on the BIG-IP

```sql
-- ============================================================
-- Title:        F5 BIG-IP iControl Rest API Command Execution - Proxy
-- Sigma ID:     b59c98c6-95e8-4d65-93ee-f594dfb96b17
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       Nasreddine Bencherchali (Nextron Systems), Thurein Oo
-- Date:         2023-11-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_f5_tm_utility_bash_api_request.yml
-- Unmapped:     cs-method, c-uri
-- False Pos:    Legitimate usage of the BIG IP REST API to execute command for administration purposes
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: cs-method
-- UNMAPPED_FIELD: c-uri

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'POST'
    AND rawEventMsg LIKE '%/mgmt/tm/util/bash')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of the BIG IP REST API to execute command for administration purposes

**References:**
- https://f5-sdk.readthedocs.io/en/latest/apidoc/f5.bigip.tm.util.html#module-f5.bigip.tm.util.bash
- https://community.f5.com/t5/technical-forum/icontrolrest-11-5-execute-bash-command/td-p/203029
- https://community.f5.com/t5/technical-forum/running-bash-commands-via-rest-api/td-p/272516

---

## Potential Hello-World Scraper Botnet Activity

| Field | Value |
|---|---|
| **Sigma ID** | `1712bafe-be05-4a0e-89d4-17a3ed151bf5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1595 |
| **Author** | Joseph A. M. |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hello_world_user_agent.yml)**

> Detects network traffic potentially associated with a scraper botnet variant that uses the "Hello-World/1.0" user-agent string.


```sql
-- ============================================================
-- Title:        Potential Hello-World Scraper Botnet Activity
-- Sigma ID:     1712bafe-be05-4a0e-89d4-17a3ed151bf5
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        reconnaissance | T1595
-- Author:       Joseph A. M.
-- Date:         2025-08-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hello_world_user_agent.yml
-- Unmapped:     c-useragent, cs-method
-- False Pos:    Legitimate network monitoring or vulnerability scanning tools that may use this generic user agent.; Internal development or testing scripts. Consider filtering by source IP if this is expected from certain systems.
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: cs-method

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Hello-World/1.0'
    AND rawEventMsg = 'GET')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate network monitoring or vulnerability scanning tools that may use this generic user agent.; Internal development or testing scripts. Consider filtering by source IP if this is expected from certain systems.

**References:**
- https://www.greynoise.io/blog/new-scraper-botnet-concentrated-in-taiwan
- https://viz.greynoise.io/tags/hello-world-scraper-botnet?days=30

---

## HackTool - BabyShark Agent Default URL Pattern

| Field | Value |
|---|---|
| **Sigma ID** | `304810ed-8853-437f-9e36-c4975c3dfd7e` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hktl_baby_shark_default_agent_url.yml)**

> Detects Baby Shark C2 Framework default communication patterns

```sql
-- ============================================================
-- Title:        HackTool - BabyShark Agent Default URL Pattern
-- Sigma ID:     304810ed-8853-437f-9e36-c4975c3dfd7e
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-06-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hktl_baby_shark_default_agent_url.yml
-- Unmapped:     c-uri
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%momyshark\\?key=%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://nasbench.medium.com/understanding-detecting-c2-frameworks-babyshark-641be4595845

---

## HackTool - CobaltStrike Malleable Profile Patterns - Proxy

| Field | Value |
|---|---|
| **Sigma ID** | `f3f21ce1-cdef-4bfc-8328-ed2e826f5fac` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Markus Neis, Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hktl_cobalt_strike_malleable_c2_requests.yml)**

> Detects cobalt strike malleable profiles patterns (URI, User-Agents, Methods).

```sql
-- ============================================================
-- Title:        HackTool - CobaltStrike Malleable Profile Patterns - Proxy
-- Sigma ID:     f3f21ce1-cdef-4bfc-8328-ed2e826f5fac
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Markus Neis, Florian Roth (Nextron Systems)
-- Date:         2024-02-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hktl_cobalt_strike_malleable_c2_requests.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/rsmudge/Malleable-C2-Profiles/blob/26323784672913923d20c5a638c6ca79459e8529/normal/amazon.profile
- https://www.hybrid-analysis.com/sample/ee5eca8648e45e2fea9dac0d920ef1a1792d8690c41ee7f20343de1927cc88b9?environmentId=100
- https://github.com/rsmudge/Malleable-C2-Profiles/blob/26323784672913923d20c5a638c6ca79459e8529/normal/ocsp.profile
- https://github.com/yeyintminthuhtut/Malleable-C2-Profiles-Collection/
- https://github.com/rsmudge/Malleable-C2-Profiles/blob/26323784672913923d20c5a638c6ca79459e8529/normal/onedrive_getonly.profile

---

## HackTool - Empire UserAgent URI Combo

| Field | Value |
|---|---|
| **Sigma ID** | `b923f7d6-ac89-4a50-a71a-89fb846b4aa8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hktl_empire_ua_uri_patterns.yml)**

> Detects user agent and URI paths used by empire agents

```sql
-- ============================================================
-- Title:        HackTool - Empire UserAgent URI Combo
-- Sigma ID:     b923f7d6-ac89-4a50-a71a-89fb846b4aa8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2020-07-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_hktl_empire_ua_uri_patterns.yml
-- Unmapped:     c-useragent, cs-uri, cs-method
-- False Pos:    Valid requests with this exact user agent to server scripts of the defined names
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: cs-uri
-- UNMAPPED_FIELD: cs-method

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
    AND rawEventMsg IN ('/admin/get.php', '/news.php', '/login/process.php')
    AND rawEventMsg = 'POST')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid requests with this exact user agent to server scripts of the defined names

**References:**
- https://github.com/BC-SECURITY/Empire

---

## PUA - Advanced IP/Port Scanner Update Check

| Field | Value |
|---|---|
| **Sigma ID** | `1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery, reconnaissance |
| **MITRE Techniques** | T1590 |
| **Author** | Axel Olsson |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_pua_advanced_ip_scanner_update_check.yml)**

> Detect the update check performed by Advanced IP/Port Scanner utilities.

```sql
-- ============================================================
-- Title:        PUA - Advanced IP/Port Scanner Update Check
-- Sigma ID:     1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery, reconnaissance | T1590
-- Author:       Axel Olsson
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_pua_advanced_ip_scanner_update_check.yml
-- Unmapped:     c-uri, c-uri-query
-- False Pos:    Expected if you legitimately use the Advanced IP or Port Scanner utilities in your environement.
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri
-- UNMAPPED_FIELD: c-uri-query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%/checkupdate.php%'
    AND rawEventMsg LIKE '%lng=%' AND rawEventMsg LIKE '%ver=%' AND rawEventMsg LIKE '%beta=%' AND rawEventMsg LIKE '%type=%' AND rawEventMsg LIKE '%rmode=%' AND rawEventMsg LIKE '%product=%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Expected if you legitimately use the Advanced IP or Port Scanner utilities in your environement.

**References:**
- https://www.advanced-ip-scanner.com/
- https://www.advanced-port-scanner.com/

---

## PwnDrp Access

| Field | Value |
|---|---|
| **Sigma ID** | `2b1ee7e4-89b6-4739-b7bb-b811b6607e5e` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1071.001, T1102.001, T1102.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_pwndrop.yml)**

> Detects downloads from PwnDrp web servers developed for red team testing and most likely also used for criminal activity

```sql
-- ============================================================
-- Title:        PwnDrp Access
-- Sigma ID:     2b1ee7e4-89b6-4739-b7bb-b811b6607e5e
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1071.001, T1102.001, T1102.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2020-04-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_pwndrop.yml
-- Unmapped:     c-uri
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%/pwndrop/%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://breakdev.org/pwndrop/

---

## Raw Paste Service Access

| Field | Value |
|---|---|
| **Sigma ID** | `5468045b-4fcc-4d1a-973c-c9c9578edacb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001, T1102.001, T1102.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_raw_paste_service_access.yml)**

> Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form

```sql
-- ============================================================
-- Title:        Raw Paste Service Access
-- Sigma ID:     5468045b-4fcc-4d1a-973c-c9c9578edacb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001, T1102.001, T1102.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-12-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_raw_paste_service_access.yml
-- Unmapped:     c-uri
-- False Pos:    User activity (e.g. developer that shared and copied code snippets and used the raw link instead of just copy & paste)
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.paste.ee/r/%' OR rawEventMsg LIKE '%.pastebin.com/raw/%' OR rawEventMsg LIKE '%.hastebin.com/raw/%' OR rawEventMsg LIKE '%.ghostbin.co/paste/*/raw/%' OR rawEventMsg LIKE '%pastetext.net/%' OR rawEventMsg LIKE '%pastebin.pl/%' OR rawEventMsg LIKE '%paste.ee/%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User activity (e.g. developer that shared and copied code snippets and used the raw link instead of just copy & paste)

**References:**
- https://www.virustotal.com/gui/domain/paste.ee/relations

---

## Flash Player Update from Suspicious Location

| Field | Value |
|---|---|
| **Sigma ID** | `4922a5dd-6743-4fc2-8e81-144374280997` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1189, T1204.002, T1036.005 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml)**

> Detects a flashplayer update from an unofficial location

```sql
-- ============================================================
-- Title:        Flash Player Update from Suspicious Location
-- Sigma ID:     4922a5dd-6743-4fc2-8e81-144374280997
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1189, T1204.002, T1036.005
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml
-- Unmapped:     c-uri, cs-host
-- False Pos:    Unknown flash download locations
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-uri
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%/flash\_install.php%')
  OR (rawEventMsg LIKE '%/install\_flash\_player.exe')
  AND NOT (rawEventMsg LIKE '%.adobe.com'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown flash download locations

**References:**
- https://gist.github.com/roycewilliams/a723aaf8a6ac3ba4f817847610935cfb

---

## Suspicious Network Communication With IPFS

| Field | Value |
|---|---|
| **Sigma ID** | `eb6c2004-1cef-427f-8885-9042974e5eb6` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1056 |
| **Author** | Gavin Knapp |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_susp_ipfs_cred_harvest.yml)**

> Detects connections to interplanetary file system (IPFS) containing a user's email address which mirrors behaviours observed in recent phishing campaigns leveraging IPFS to host credential harvesting webpages.

```sql
-- ============================================================
-- Title:        Suspicious Network Communication With IPFS
-- Sigma ID:     eb6c2004-1cef-427f-8885-9042974e5eb6
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection | T1056
-- Author:       Gavin Knapp
-- Date:         2023-03-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_susp_ipfs_cred_harvest.yml
-- Unmapped:     cs-uri
-- False Pos:    Legitimate use of IPFS being used in the organisation. However the cs-uri regex looking for a user email will likely negate this.
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: cs-uri

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, '(?i)(ipfs\.io/|ipfs\.io\s).+\..+@.+\.[a-z]+')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of IPFS being used in the organisation. However the cs-uri regex looking for a user email will likely negate this.

**References:**
- https://blog.talosintelligence.com/ipfs-abuse/
- https://github.com/Cisco-Talos/IOCs/tree/80caca039988252fbb3f27a2e89c2f2917f582e0/2022/11
- https://isc.sans.edu/diary/IPFS%20phishing%20and%20the%20need%20for%20correctly%20set%20HTTP%20security%20headers/29638

---

## Telegram API Access

| Field | Value |
|---|---|
| **Sigma ID** | `b494b165-6634-483d-8c47-2026a6c52372` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001, T1102.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_telegram_api.yml)**

> Detects suspicious requests to Telegram API without the usual Telegram User-Agent

```sql
-- ============================================================
-- Title:        Telegram API Access
-- Sigma ID:     b494b165-6634-483d-8c47-2026a6c52372
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001, T1102.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-06-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_telegram_api.yml
-- Unmapped:     cs-host, c-useragent
-- False Pos:    Legitimate use of Telegram bots in the company
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: cs-host
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'api.telegram.org'
  AND NOT ((rawEventMsg LIKE '%Telegram%' OR rawEventMsg LIKE '%Bot%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Telegram bots in the company

**References:**
- https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
- https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
- https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/

---

## APT User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `6ec820f2-e963-4801-9127-d8b2dce4d31b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems), Markus Neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_apt.yml)**

> Detects suspicious user agent strings used in APT malware in proxy logs

```sql
-- ============================================================
-- Title:        APT User Agent
-- Sigma ID:     6ec820f2-e963-4801-9127-d8b2dce4d31b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems), Markus Neis
-- Date:         2019-11-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_apt.yml
-- Unmapped:     c-useragent
-- False Pos:    Old browsers
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('SJZJ (compatible; MSIE 6.0; Win32)', 'Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0', 'User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC', 'Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)', 'webclient', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200', 'Mozilla/4.0 (compatible; MSI 6.0;', 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0', 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/', 'Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2', 'Mozilla/4.0', 'Netscape', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Firefox/3.6.13 GTB7.1', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)', 'Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)', 'Mozilla/4.0 (compatible; MSIE 8.0; Win32)', 'Mozilla v5.1 (Windows NT 6.1; rv:6.0.1) Gecko/20100101 Firefox/6.0.1', 'Mozilla/6.1 (compatible; MSIE 9.0; Windows NT 5.3; Trident/5.0)', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; InfoPath.1)', 'Mozilla/5.0 (Windows NT 6.1; WOW64) WinHttp/1.6.3.8 (WinHTTP/5.1) like Gecko', 'Mozilla v5.1 *', 'MSIE 8.0', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.2)', 'Mozilla/4.0 (compatible; RMS)', 'Mozilla/4.0 (compatible; MSIE 6.0; DynGate)', 'O/9.27 (W; U; Z)', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0*', 'Mozilla/5.0 (Windows NT 9; *', 'hots scot', 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT)', 'Mozilla/5.0 (Windows NT 6.1; WOW64) Chrome/28.0.1500.95 Safari/537.36', 'Mozilla/5.0 (Windows NT 6.2; Win32; rv:47.0)', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1;', 'Mozilla/5.0 (X11; Linux i686; rv:22.0) Firefox/22.0', 'Mozilla/5.0 Chrome/72.0.3626.109 Safari/537.36', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:FTS_06) Gecko/22.36.35.06 Firefox/2.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36 Edg/100.0.1185.39', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; InfoPath.3; .NET4.0C; .NET4.0E)', 'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; Tablet PC 2.0)', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246001')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Old browsers

**References:**
- Internal Research

---

## Suspicious Base64 Encoded User-Agent

| Field | Value |
|---|---|
| **Sigma ID** | `d443095b-a221-4957-a2c4-cd1756c9b747` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_base64_encoded.yml)**

> Detects suspicious encoded User-Agent strings, as seen used by some malware.

```sql
-- ============================================================
-- Title:        Suspicious Base64 Encoded User-Agent
-- Sigma ID:     d443095b-a221-4957-a2c4-cd1756c9b747
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-05-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_base64_encoded.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'Q2hyb21l%' OR rawEventMsg LIKE 'QXBwbGVXZWJLaX%' OR rawEventMsg LIKE 'RGFsdmlr%' OR rawEventMsg LIKE 'TW96aWxsY%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://deviceatlas.com/blog/list-of-user-agent-strings#desktop

---

## Bitsadmin to Uncommon IP Server Address

| Field | Value |
|---|---|
| **Sigma ID** | `8ccd35a2-1c7c-468b-b568-ac6cdf80eec3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1071.001, T1197 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_ip.yml)**

> Detects Bitsadmin connections to IP addresses instead of FQDN names

```sql
-- ============================================================
-- Title:        Bitsadmin to Uncommon IP Server Address
-- Sigma ID:     8ccd35a2-1c7c-468b-b568-ac6cdf80eec3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1071.001, T1197
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-06-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_ip.yml
-- Unmapped:     c-useragent, cs-host
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'Microsoft BITS/%'
    AND (rawEventMsg LIKE '%1' OR rawEventMsg LIKE '%2' OR rawEventMsg LIKE '%3' OR rawEventMsg LIKE '%4' OR rawEventMsg LIKE '%5' OR rawEventMsg LIKE '%6' OR rawEventMsg LIKE '%7' OR rawEventMsg LIKE '%8' OR rawEventMsg LIKE '%9'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://isc.sans.edu/diary/Microsoft+BITS+Used+to+Download+Payloads/21027

---

## Bitsadmin to Uncommon TLD

| Field | Value |
|---|---|
| **Sigma ID** | `9eb68894-7476-4cd6-8752-23b51f5883a7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1071.001, T1197 |
| **Author** | Florian Roth (Nextron Systems), Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_tld.yml)**

> Detects Bitsadmin connections to domains with uncommon TLDs

```sql
-- ============================================================
-- Title:        Bitsadmin to Uncommon TLD
-- Sigma ID:     9eb68894-7476-4cd6-8752-23b51f5883a7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1071.001, T1197
-- Author:       Florian Roth (Nextron Systems), Tim Shelton
-- Date:         2019-03-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_tld.yml
-- Unmapped:     c-useragent, cs-host
-- False Pos:    Rare programs that use Bitsadmin and update from regional TLDs e.g. .uk or .ca
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'Microsoft BITS/%'
  AND NOT ((rawEventMsg LIKE '%.com' OR rawEventMsg LIKE '%.net' OR rawEventMsg LIKE '%.org' OR rawEventMsg LIKE '%.scdn.co' OR rawEventMsg LIKE '%.sfx.ms')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare programs that use Bitsadmin and update from regional TLDs e.g. .uk or .ca

**References:**
- https://twitter.com/jhencinski/status/1102695118455349248
- https://isc.sans.edu/forums/diary/Investigating+Microsoft+BITS+Activity/23281/

---

## Crypto Miner User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `fa935401-513b-467b-81f4-f9e77aa0dd78` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_cryptominer.yml)**

> Detects suspicious user agent strings used by crypto miners in proxy logs

```sql
-- ============================================================
-- Title:        Crypto Miner User Agent
-- Sigma ID:     fa935401-513b-467b-81f4-f9e77aa0dd78
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2019-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_cryptominer.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'XMRig %' OR rawEventMsg LIKE 'ccminer%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/xmrig/xmrig/blob/da22b3e6c45825f3ac1f208255126cb8585cd4fc/src/base/kernel/Platform_win.cpp#L65
- https://github.com/xmrig/xmrig/blob/427b6516e0550200c17ca28675118f0fffcc323f/src/version.h

---

## HTTP Request With Empty User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `21e44d78-95e7-421b-a464-ffd8395659c4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_empty.yml)**

> Detects a potentially suspicious empty user agent strings in proxy log.
Could potentially indicate an uncommon request method.


```sql
-- ============================================================
-- Title:        HTTP Request With Empty User Agent
-- Sigma ID:     21e44d78-95e7-421b-a464-ffd8395659c4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_empty.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = ''
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/Carlos_Perez/status/883455096645931008

---

## Exploit Framework User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `fdd1bfb5-f60b-4a35-910e-f36ed3d0b32f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_frameworks.yml)**

> Detects suspicious user agent strings used by exploit / pentest frameworks like Metasploit in proxy logs

```sql
-- ============================================================
-- Title:        Exploit Framework User Agent
-- Sigma ID:     fdd1bfb5-f60b-4a35-910e-f36ed3d0b32f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_frameworks.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Internet Explorer *', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; InfoPath.2)', 'Mozilla/4.0 (compatible; Metasploit RSPEC)', 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SIMBAR={7DB0F6DE-8DE7-4841-9084-28FA914B0F2E}; SLCC1; .N', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MAAU)', 'Mozilla/5.0', 'Mozilla/4.0 (compatible; SPIPE/1.0', 'Mozilla/5.0 (Windows NT 6.3; rv:39.0) Gecko/20100101 Firefox/35.0', 'Sametime Community Agent', 'X-FORWARDED-FOR', 'DotDotPwn v2.1', 'SIPDROID', 'Mozilla/5.0 (Windows NT 10.0; Win32; x32; rv:60.0)', 'Mozilla/6.0 (X11; Linux x86_64; rv:24.0) Gecko/20140205     Firefox/27.0 Iceweasel/25.3.0', '*wordpress hash grabber*', '*exploit*', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blog.didierstevens.com/2015/03/16/quickpost-metasploit-user-agent-strings/

---

## Hack Tool User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `c42a3073-30fb-48ae-8c99-c23ada84b103` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190, T1110 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_hacktool.yml)**

> Detects suspicious user agent strings user by hack tools in proxy logs

```sql
-- ============================================================
-- Title:        Hack Tool User Agent
-- Sigma ID:     c42a3073-30fb-48ae-8c99-c23ada84b103
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190, T1110
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_hacktool.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%(hydra)%' OR rawEventMsg LIKE '% arachni/%' OR rawEventMsg LIKE '% BFAC %' OR rawEventMsg LIKE '% brutus %' OR rawEventMsg LIKE '% cgichk %' OR rawEventMsg LIKE '%core-project/1.0%' OR rawEventMsg LIKE '% crimscanner/%' OR rawEventMsg LIKE '%datacha0s%' OR rawEventMsg LIKE '%dirbuster%' OR rawEventMsg LIKE '%domino hunter%' OR rawEventMsg LIKE '%dotdotpwn%' OR rawEventMsg LIKE '%FHScan Core%' OR rawEventMsg LIKE '%floodgate%' OR rawEventMsg LIKE '%get-minimal%' OR rawEventMsg LIKE '%gootkit auto-rooter scanner%' OR rawEventMsg LIKE '%grendel-scan%' OR rawEventMsg LIKE '% inspath %' OR rawEventMsg LIKE '%internet ninja%' OR rawEventMsg LIKE '%jaascois%' OR rawEventMsg LIKE '% zmeu %' OR rawEventMsg LIKE '%masscan%' OR rawEventMsg LIKE '% metis %' OR rawEventMsg LIKE '%morfeus fucking scanner%' OR rawEventMsg LIKE '%n-stealth%' OR rawEventMsg LIKE '%nsauditor%' OR rawEventMsg LIKE '%pmafind%' OR rawEventMsg LIKE '%security scan%' OR rawEventMsg LIKE '%springenwerk%' OR rawEventMsg LIKE '%teh forest lobster%' OR rawEventMsg LIKE '%toata dragostea%' OR rawEventMsg LIKE '% vega/%' OR rawEventMsg LIKE '%voideye%' OR rawEventMsg LIKE '%webshag%' OR rawEventMsg LIKE '%webvulnscan%' OR rawEventMsg LIKE '% whcc/%' OR rawEventMsg LIKE '% Havij%' OR rawEventMsg LIKE '%absinthe%' OR rawEventMsg LIKE '%bsqlbf%' OR rawEventMsg LIKE '%mysqloit%' OR rawEventMsg LIKE '%pangolin%' OR rawEventMsg LIKE '%sql power injector%' OR rawEventMsg LIKE '%sqlmap%' OR rawEventMsg LIKE '%sqlninja%' OR rawEventMsg LIKE '%uil2pn%' OR rawEventMsg LIKE '%ruler%' OR rawEventMsg LIKE '%Mozilla/5.0 (Windows; U; Windows NT 5.1; pt-PT; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/fastly/waf_testbed/blob/8bfc406551f3045e418cbaad7596cff8da331dfc/templates/default/scanners-user-agents.data.erb
- http://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-user_agents.rules

---

## Malware User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `5c84856b-55a5-45f1-826f-13f37250cf4e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems), X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_malware.yml)**

> Detects suspicious user agent strings used by malware in proxy logs

```sql
-- ============================================================
-- Title:        Malware User Agent
-- Sigma ID:     5c84856b-55a5-45f1-826f-13f37250cf4e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems), X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date:         2017-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_malware.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Chrome /53.0', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0)', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR  1.1.4322)', 'HttpBrowser/1.0', '*<|>*', 'nsis_inetc (mozilla)', 'Wget/1.9+cvs-stable (Red Hat modified)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)', '*zeroup*', 'Mozilla/5.0 (Windows NT 5.1 ; v.*', '* adlib/*', '* tiny', '* BGroom *', '* changhuatong', '* CholTBAgent', 'Mozilla/5.0 WinInet', 'RookIE/1.0', 'M', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)', 'Mozilla/4.0 (compatible;MSIE 7.0;Windows NT 6.0)', 'backdoorbot', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30731)', 'Opera/8.81 (Windows NT 6.0; U; en)', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30729)', 'Opera', 'Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)', 'Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)', 'MSIE', '*(Charon; Inferno)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)', 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)', 'Mozilla/4.0(compatible; MSIE 6.0; Windows NT 5.1)', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 10.0; Win64; x64)', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64)', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; InfoPath.3)', 'Mozilla/5.0 (Windows NT 6.1)', 'AppleWebkit/587.38 (KHTML, like Gecko)', 'Chrome/91.0.4472.77', 'Safari/537.36', 'Edge/91.0.864.37', 'Firefox/89.0', 'Gecko/20100101', '* pxyscand*', '* asd', '* mdms', 'sample', 'nocase', 'Moxilla', 'Win32 *', '*Microsoft Internet Explorer*', 'agent *', 'AutoIt', 'IczelionDownLoad', 'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 10.0; .NET4.0C; .NET4.0E; Tablet PC 2.0)', 'record', 'mozzzzzzzzzzz', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0', 'Havana/0.1', 'antSword/v2.1', 'rqwrwqrqwrqw', 'qwrqrwrqwrqwr', 'rc2.0/client', 'TakeMyPainBack', 'xxx', '20112211', '23591', '901785252112', '1235125521512', '125122112551', 'B1D3N_RIM_MY_ASS', 'AYAYAYAY1337', 'iMightJustPayMySelfForAFeature', 'ForAFeature', 'Ares_ldr_v_*', 'Microsoft Internet Explorer', 'CLCTR', 'uploader', 'agent', 'License', 'vb wininet', 'Client', 'Lilith-Bot/3.0', 'svc/1.0', 'WSHRAT', 'ZeroStresser Botnet/1.5', 'OK', 'Project1sqlite', 'Project1', 'DuckTales', 'Zadanie', 'GunnaWunnaBlueTips', 'Xlmst', 'GeekingToTheMoon', 'SunShineMoonLight', 'BunnyRequester', 'BunnyTasks', 'BunnyStealer', 'BunnyLoader_Dropper', 'BunnyLoader', 'BunnyShell', 'SPARK-COMMIT', '4B4DB4B3', 'SouthSide', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-user_agents.rules
- http://www.botopedia.org/search?searchword=scan&searchphrase=all
- https://networkraptor.blogspot.com/2015/01/user-agent-strings.html
- https://perishablepress.com/blacklist/ua-2013.txt
- https://www.bluecoat.com/en-gb/security-blog/2015-05-05/know-your-agents
- https://twitter.com/kladblokje_88/status/1614673320124743681?s=12&t=joEpeVa5d58aHYNGA_To7Q
- https://pbs.twimg.com/media/FtYbfsDXoAQ1Y8M?format=jpg&name=large
- https://twitter.com/crep1x/status/1635034100213112833

---

## Windows PowerShell User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `c8557060-9221-4448-8794-96320e6f3e74` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_powershell.yml)**

> Detects Windows PowerShell Web Access

```sql
-- ============================================================
-- Title:        Windows PowerShell User Agent
-- Sigma ID:     c8557060-9221-4448-8794-96320e6f3e74
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_powershell.yml
-- Unmapped:     c-useragent
-- False Pos:    Administrative scripts that download files from the Internet; Administrative scripts that retrieve certain website contents
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '% WindowsPowerShell/%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative scripts that download files from the Internet; Administrative scripts that retrieve certain website contents

**References:**
- https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest

---

## Rclone Activity via Proxy

| Field | Value |
|---|---|
| **Sigma ID** | `2c03648b-e081-41a5-b9fb-7d854a915091` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Janantha Marasinghe |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_rclone.yml)**

> Detects the use of rclone, a command-line program to manage files on cloud storage, via its default user-agent string

```sql
-- ============================================================
-- Title:        Rclone Activity via Proxy
-- Sigma ID:     2c03648b-e081-41a5-b9fb-7d854a915091
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Janantha Marasinghe
-- Date:         2022-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_rclone.yml
-- Unmapped:     c-useragent
-- False Pos:    Valid requests with this exact user agent to that is used by legitimate scripts or sysadmin operations
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE 'rclone/v%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid requests with this exact user agent to that is used by legitimate scripts or sysadmin operations

**References:**
- https://rclone.org/
- https://www.kroll.com/en/insights/publications/cyber/new-m365-business-email-compromise-attacks-with-rclone

---

## Suspicious User Agent

| Field | Value |
|---|---|
| **Sigma ID** | `7195a772-4b3f-43a4-a210-6a003d65caa1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_susp.yml)**

> Detects suspicious malformed user agent strings in proxy logs

```sql
-- ============================================================
-- Title:        Suspicious User Agent
-- Sigma ID:     7195a772-4b3f-43a4-a210-6a003d65caa1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_susp.yml
-- Unmapped:     c-useragent, cs-host
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: cs-host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND NOT ((rawEventMsg = 'Mozilla/3.0 * Acrobat *')
  OR ((rawEventMsg LIKE '%.acrobat.com' OR rawEventMsg LIKE '%.adobe.com' OR rawEventMsg LIKE '%.adobe.io')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/fastly/waf_testbed/blob/8bfc406551f3045e418cbaad7596cff8da331dfc/templates/default/scanners-user-agents.data.erb

---

## Potential Base64 Encoded User-Agent

| Field | Value |
|---|---|
| **Sigma ID** | `894a8613-cf12-48b3-8e57-9085f54aa0c3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Florian Roth (Nextron Systems), Brian Ingram (update) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_susp_base64.yml)**

> Detects User Agent strings that end with an equal sign, which can be a sign of base64 encoding.

```sql
-- ============================================================
-- Title:        Potential Base64 Encoded User-Agent
-- Sigma ID:     894a8613-cf12-48b3-8e57-9085f54aa0c3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Florian Roth (Nextron Systems), Brian Ingram (update)
-- Date:         2022-07-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_ua_susp_base64.yml
-- Unmapped:     c-useragent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy
-- UNMAPPED_FIELD: c-useragent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%='
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://blogs.jpcert.or.jp/en/2022/07/yamabot.html
- https://deviceatlas.com/blog/list-of-user-agent-strings#desktop

---

## Suspicious External WebDAV Execution

| Field | Value |
|---|---|
| **Sigma ID** | `1ae64f96-72b6-48b3-ad3d-e71dff6c6398` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1584, T1566 |
| **Author** | Ahmed Farouk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_webdav_external_execution.yml)**

> Detects executables launched from external WebDAV shares using the WebDAV Explorer integration, commonly seen in initial access campaigns.


```sql
-- ============================================================
-- Title:        Suspicious External WebDAV Execution
-- Sigma ID:     1ae64f96-72b6-48b3-ad3d-e71dff6c6398
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1584, T1566
-- Author:       Ahmed Farouk
-- Date:         2024-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/web/proxy_generic/proxy_webdav_external_execution.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: proxy

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://dear-territory-023.notion.site/WebDav-Share-Testing-e4950fa0c00149c3aa430d779b9b1d0f?pvs=4
- https://micahbabinski.medium.com/search-ms-webdav-and-chill-99c5b23ac462
- https://www.trendmicro.com/en_no/research/24/b/cve202421412-water-hydra-targets-traders-with-windows-defender-s.html
- https://www.trellix.com/en-us/about/newsroom/stories/research/beyond-file-search-a-novel-method.html

---
