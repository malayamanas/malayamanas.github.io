# Sigma → FortiSIEM:  Dns

> 7 rules · Generated 2026-03-17

## Table of Contents

- [DNS Query to External Service Interaction Domains](#dns-query-to-external-service-interaction-domains)
- [Cobalt Strike DNS Beaconing](#cobalt-strike-dns-beaconing)
- [Monero Crypto Coin Mining Pool Lookup](#monero-crypto-coin-mining-pool-lookup)
- [Suspicious DNS Query with B64 Encoded String](#suspicious-dns-query-with-b64-encoded-string)
- [Telegram Bot API Request](#telegram-bot-api-request)
- [DNS TXT Answer with Possible Execution Strings](#dns-txt-answer-with-possible-execution-strings)
- [Wannacry Killswitch Domain](#wannacry-killswitch-domain)

## DNS Query to External Service Interaction Domains

| Field | Value |
|---|---|
| **Sigma ID** | `aff715fa-4dd5-497a-8db3-910bea555566` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1190, T1595.002 |
| **Author** | Florian Roth (Nextron Systems), Matt Kelly (list of domains) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_external_service_interaction_domains.yml)**

> Detects suspicious DNS queries to external service interaction domains often used for out-of-band interactions after successful RCE


```sql
-- ============================================================
-- Title:        DNS Query to External Service Interaction Domains
-- Sigma ID:     aff715fa-4dd5-497a-8db3-910bea555566
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        reconnaissance | T1190, T1595.002
-- Author:       Florian Roth (Nextron Systems), Matt Kelly (list of domains)
-- Date:         2022-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_external_service_interaction_domains.yml
-- Unmapped:     query
-- False Pos:    Legitimate security scanning.
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.burpcollaborator.net' OR rawEventMsg LIKE '%.canarytokens.com' OR rawEventMsg LIKE '%.ceye.io' OR rawEventMsg LIKE '%.ddns.1443.eu.org' OR rawEventMsg LIKE '%.ddns.bypass.eu.org' OR rawEventMsg LIKE '%.ddns.xn--gg8h.eu.org' OR rawEventMsg LIKE '%.digimg.store' OR rawEventMsg LIKE '%.dns.su18.org' OR rawEventMsg LIKE '%.dnshook.site' OR rawEventMsg LIKE '%.dnslog.cn' OR rawEventMsg LIKE '%.dnslog.ink' OR rawEventMsg LIKE '%.instances.httpworkbench.com' OR rawEventMsg LIKE '%.interact.sh' OR rawEventMsg LIKE '%.log.dnslog.pp.ua' OR rawEventMsg LIKE '%.log.dnslog.qzz.io' OR rawEventMsg LIKE '%.log.dnslogs.dpdns.org' OR rawEventMsg LIKE '%.log.javaweb.org' OR rawEventMsg LIKE '%.log.nat.cloudns.ph' OR rawEventMsg LIKE '%.oast.fun' OR rawEventMsg LIKE '%.oast.live' OR rawEventMsg LIKE '%.oast.me' OR rawEventMsg LIKE '%.oast.online' OR rawEventMsg LIKE '%.oast.pro' OR rawEventMsg LIKE '%.oast.site' OR rawEventMsg LIKE '%.oastify.com' OR rawEventMsg LIKE '%.p8.lol' OR rawEventMsg LIKE '%.requestbin.net')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate security scanning.

**References:**
- https://twitter.com/breakersall/status/1533493587828260866
- https://www.bitdefender.com/en-us/blog/businessinsights/bitdefender-advisory-critical-unauthenticated-rce-windows-server-update-services-cve-2025-59287
- https://github.com/SigmaHQ/sigma/pull/5724#issuecomment-3466382234

---

## Cobalt Strike DNS Beaconing

| Field | Value |
|---|---|
| **Sigma ID** | `2975af79-28c4-4d2f-a951-9095f229df29` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1071.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_mal_cobaltstrike.yml)**

> Detects suspicious DNS queries known from Cobalt Strike beacons

```sql
-- ============================================================
-- Title:        Cobalt Strike DNS Beaconing
-- Sigma ID:     2975af79-28c4-4d2f-a951-9095f229df29
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1071.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_mal_cobaltstrike.yml
-- Unmapped:     query
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
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

## Monero Crypto Coin Mining Pool Lookup

| Field | Value |
|---|---|
| **Sigma ID** | `b593fd50-7335-4682-a36c-4edcb68e4641` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact, exfiltration |
| **MITRE Techniques** | T1496, T1567 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml)**

> Detects suspicious DNS queries to Monero mining pools

```sql
-- ============================================================
-- Title:        Monero Crypto Coin Mining Pool Lookup
-- Sigma ID:     b593fd50-7335-4682-a36c-4edcb68e4641
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        impact, exfiltration | T1496, T1567
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-10-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml
-- Unmapped:     query
-- False Pos:    Legitimate crypto coin mining
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%pool.minexmr.com%' OR rawEventMsg LIKE '%fr.minexmr.com%' OR rawEventMsg LIKE '%de.minexmr.com%' OR rawEventMsg LIKE '%sg.minexmr.com%' OR rawEventMsg LIKE '%ca.minexmr.com%' OR rawEventMsg LIKE '%us-west.minexmr.com%' OR rawEventMsg LIKE '%pool.supportxmr.com%' OR rawEventMsg LIKE '%mine.c3pool.com%' OR rawEventMsg LIKE '%xmr-eu1.nanopool.org%' OR rawEventMsg LIKE '%xmr-eu2.nanopool.org%' OR rawEventMsg LIKE '%xmr-us-east1.nanopool.org%' OR rawEventMsg LIKE '%xmr-us-west1.nanopool.org%' OR rawEventMsg LIKE '%xmr-asia1.nanopool.org%' OR rawEventMsg LIKE '%xmr-jp1.nanopool.org%' OR rawEventMsg LIKE '%xmr-au1.nanopool.org%' OR rawEventMsg LIKE '%xmr.2miners.com%' OR rawEventMsg LIKE '%xmr.hashcity.org%' OR rawEventMsg LIKE '%xmr.f2pool.com%' OR rawEventMsg LIKE '%xmrpool.eu%' OR rawEventMsg LIKE '%pool.hashvault.pro%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate crypto coin mining

**References:**
- https://www.nextron-systems.com/2021/10/24/monero-mining-pool-fqdns/

---

## Suspicious DNS Query with B64 Encoded String

| Field | Value |
|---|---|
| **Sigma ID** | `4153a907-2451-4e4f-a578-c52bb6881432` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048.003, T1071.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_susp_b64_queries.yml)**

> Detects suspicious DNS queries using base64 encoding

```sql
-- ============================================================
-- Title:        Suspicious DNS Query with B64 Encoded String
-- Sigma ID:     4153a907-2451-4e4f-a578-c52bb6881432
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1048.003, T1071.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_susp_b64_queries.yml
-- Unmapped:     query
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%==.%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/krmaxwell/dns-exfiltration

---

## Telegram Bot API Request

| Field | Value |
|---|---|
| **Sigma ID** | `c64c5175-5189-431b-a55e-6d9882158251` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1102.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_susp_telegram_api.yml)**

> Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind

```sql
-- ============================================================
-- Title:        Telegram Bot API Request
-- Sigma ID:     c64c5175-5189-431b-a55e-6d9882158251
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1102.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-06-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_susp_telegram_api.yml
-- Unmapped:     query
-- False Pos:    Legitimate use of Telegram bots in the company
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'api.telegram.org'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Telegram bots in the company

**References:**
- https://core.telegram.org/bots/faq
- https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
- https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
- https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/

---

## DNS TXT Answer with Possible Execution Strings

| Field | Value |
|---|---|
| **Sigma ID** | `8ae51330-899c-4641-8125-e39f2e07da72` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.004 |
| **Author** | Markus Neis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_susp_txt_exec_strings.yml)**

> Detects strings used in command execution in DNS TXT Answer

```sql
-- ============================================================
-- Title:        DNS TXT Answer with Possible Execution Strings
-- Sigma ID:     8ae51330-899c-4641-8125-e39f2e07da72
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.004
-- Author:       Markus Neis
-- Date:         2018-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_susp_txt_exec_strings.yml
-- Unmapped:     record_type, answer
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: record_type
-- UNMAPPED_FIELD: answer

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'TXT'
    AND (rawEventMsg LIKE '%IEX%' OR rawEventMsg LIKE '%Invoke-Expression%' OR rawEventMsg LIKE '%cmd.exe%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/stvemillertime/status/1024707932447854592
- https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Backdoors/DNS_TXT_Pwnage.ps1

---

## Wannacry Killswitch Domain

| Field | Value |
|---|---|
| **Sigma ID** | `3eaf6218-3bed-4d8a-8707-274096f12a18` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1071.001 |
| **Author** | Mike Wade |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_wannacry_killswitch_domain.yml)**

> Detects wannacry killswitch domain dns queries

```sql
-- ============================================================
-- Title:        Wannacry Killswitch Domain
-- Sigma ID:     3eaf6218-3bed-4d8a-8707-274096f12a18
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1071.001
-- Author:       Mike Wade
-- Date:         2020-09-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/dns/net_dns_wannacry_killswitch_domain.yml
-- Unmapped:     query
-- False Pos:    Analyst testing
-- ============================================================
-- UNMAPPED_LOGSOURCE: dns
-- UNMAPPED_FIELD: query

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.testing', 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.test', 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com', 'ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com', 'iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Analyst testing

**References:**
- https://www.mandiant.com/resources/blog/wannacry-ransomware-campaign

---
