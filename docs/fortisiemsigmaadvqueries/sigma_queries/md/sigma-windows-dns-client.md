# Sigma → FortiSIEM: Windows Dns-Client

> 6 rules · Generated 2026-03-17

## Table of Contents

- [DNS Query for Anonfiles.com Domain - DNS Client](#dns-query-for-anonfilescom-domain-dns-client)
- [Suspicious Cobalt Strike DNS Beaconing - DNS Client](#suspicious-cobalt-strike-dns-beaconing-dns-client)
- [DNS Query To MEGA Hosting Website - DNS Client](#dns-query-to-mega-hosting-website-dns-client)
- [DNS Query To Put.io - DNS Client](#dns-query-to-putio-dns-client)
- [Query Tor Onion Address - DNS Client](#query-tor-onion-address-dns-client)
- [DNS Query To Ufile.io - DNS Client](#dns-query-to-ufileio-dns-client)

## DNS Query for Anonfiles.com Domain - DNS Client

| Field | Value |
|---|---|
| **Sigma ID** | `29f171d7-aa47-42c7-9c7b-3c87938164d9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_anonymfiles_com.yml)**

> Detects DNS queries for anonfiles.com, which is an anonymous file upload platform often used for malicious purposes

```sql
-- ============================================================
-- Title:        DNS Query for Anonfiles.com Domain - DNS Client
-- Sigma ID:     29f171d7-aa47-42c7-9c7b-3c87938164d9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_anonymfiles_com.yml
-- Unmapped:     QueryName
-- False Pos:    Rare legitimate access to anonfiles.com
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-client
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '3008'
    AND rawEventMsg LIKE '%.anonfiles.com%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate access to anonfiles.com

**References:**
- https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte

---

## Suspicious Cobalt Strike DNS Beaconing - DNS Client

| Field | Value |
|---|---|
| **Sigma ID** | `0d18728b-f5bf-4381-9dcf-915539fff6c2` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1071.004 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_mal_cobaltstrike.yml)**

> Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons

```sql
-- ============================================================
-- Title:        Suspicious Cobalt Strike DNS Beaconing - DNS Client
-- Sigma ID:     0d18728b-f5bf-4381-9dcf-915539fff6c2
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1071.004
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_mal_cobaltstrike.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-client

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '3008'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
- https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/

---

## DNS Query To MEGA Hosting Website - DNS Client

| Field | Value |
|---|---|
| **Sigma ID** | `66474410-b883-415f-9f8d-75345a0a66a6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_mega_nz.yml)**

> Detects DNS queries for subdomains related to MEGA sharing website

```sql
-- ============================================================
-- Title:        DNS Query To MEGA Hosting Website - DNS Client
-- Sigma ID:     66474410-b883-415f-9f8d-75345a0a66a6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_mega_nz.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate DNS queries and usage of Mega
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-client
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '3008'
    AND rawEventMsg LIKE '%userstorage.mega.co.nz%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate DNS queries and usage of Mega

**References:**
- https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/

---

## DNS Query To Put.io - DNS Client

| Field | Value |
|---|---|
| **Sigma ID** | `8b69fd42-9dad-4674-abef-7fdef43ef92a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Omar Khaled (@beacon_exe) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_put_io.yml)**

> Detects DNS queries for subdomains related to "Put.io" sharing website.

```sql
-- ============================================================
-- Title:        DNS Query To Put.io - DNS Client
-- Sigma ID:     8b69fd42-9dad-4674-abef-7fdef43ef92a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Omar Khaled (@beacon_exe)
-- Date:         2024-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_put_io.yml
-- Unmapped:     QueryName
-- False Pos:    Legitimate DNS queries and usage of Put.io
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-client
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '3008'
    AND (rawEventMsg LIKE '%api.put.io%' OR rawEventMsg LIKE '%upload.put.io%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate DNS queries and usage of Put.io

**References:**
- https://darkatlas.io/blog/medusa-ransomware-group-opsec-failure

---

## Query Tor Onion Address - DNS Client

| Field | Value |
|---|---|
| **Sigma ID** | `8384bd26-bde6-4da9-8e5d-4174a7a47ca2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090.003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_tor_onion.yml)**

> Detects DNS resolution of an .onion address related to Tor routing networks

```sql
-- ============================================================
-- Title:        Query Tor Onion Address - DNS Client
-- Sigma ID:     8384bd26-bde6-4da9-8e5d-4174a7a47ca2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090.003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-02-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_tor_onion.yml
-- Unmapped:     QueryName
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-client
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '3008'
    AND (rawEventMsg LIKE '%.hiddenservice.net' OR rawEventMsg LIKE '%.onion.ca' OR rawEventMsg LIKE '%.onion.cab' OR rawEventMsg LIKE '%.onion.casa' OR rawEventMsg LIKE '%.onion.city' OR rawEventMsg LIKE '%.onion.direct' OR rawEventMsg LIKE '%.onion.dog' OR rawEventMsg LIKE '%.onion.glass' OR rawEventMsg LIKE '%.onion.gq' OR rawEventMsg LIKE '%.onion.guide' OR rawEventMsg LIKE '%.onion.in.net' OR rawEventMsg LIKE '%.onion.ink' OR rawEventMsg LIKE '%.onion.it' OR rawEventMsg LIKE '%.onion.link' OR rawEventMsg LIKE '%.onion.lt' OR rawEventMsg LIKE '%.onion.lu' OR rawEventMsg LIKE '%.onion.ly' OR rawEventMsg LIKE '%.onion.mn' OR rawEventMsg LIKE '%.onion.network' OR rawEventMsg LIKE '%.onion.nu' OR rawEventMsg LIKE '%.onion.pet' OR rawEventMsg LIKE '%.onion.plus' OR rawEventMsg LIKE '%.onion.pt' OR rawEventMsg LIKE '%.onion.pw' OR rawEventMsg LIKE '%.onion.rip' OR rawEventMsg LIKE '%.onion.sh' OR rawEventMsg LIKE '%.onion.si' OR rawEventMsg LIKE '%.onion.to' OR rawEventMsg LIKE '%.onion.top' OR rawEventMsg LIKE '%.onion.ws' OR rawEventMsg LIKE '%.onion' OR rawEventMsg LIKE '%.s1.tor-gateways.de' OR rawEventMsg LIKE '%.s2.tor-gateways.de' OR rawEventMsg LIKE '%.s3.tor-gateways.de' OR rawEventMsg LIKE '%.s4.tor-gateways.de' OR rawEventMsg LIKE '%.s5.tor-gateways.de' OR rawEventMsg LIKE '%.t2w.pw' OR rawEventMsg LIKE '%.tor2web.ae.org' OR rawEventMsg LIKE '%.tor2web.blutmagie.de' OR rawEventMsg LIKE '%.tor2web.com' OR rawEventMsg LIKE '%.tor2web.fi' OR rawEventMsg LIKE '%.tor2web.io' OR rawEventMsg LIKE '%.tor2web.org' OR rawEventMsg LIKE '%.tor2web.xyz' OR rawEventMsg LIKE '%.torlink.co'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
- https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/ASimDNS/imDNS_TorProxies.yaml

---

## DNS Query To Ufile.io - DNS Client

| Field | Value |
|---|---|
| **Sigma ID** | `090ffaad-c01a-4879-850c-6d57da98452d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567.002 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_ufile_io.yml)**

> Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration

```sql
-- ============================================================
-- Title:        DNS Query To Ufile.io - DNS Client
-- Sigma ID:     090ffaad-c01a-4879-850c-6d57da98452d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1567.002
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_ufile_io.yml
-- Unmapped:     QueryName
-- False Pos:    DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-client
-- UNMAPPED_FIELD: QueryName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '3008'
    AND rawEventMsg LIKE '%ufile.io%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take

**References:**
- https://thedfirreport.com/2021/12/13/diavol-ransomware/

---
