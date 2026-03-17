# Sigma → FortiSIEM: Zeek Dns

> 5 rules · Generated 2026-03-17

## Table of Contents

- [Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing - Network](#suspicious-dns-query-indicating-kerberos-coercion-via-dns-object-spn-spoofing-network)
- [DNS Events Related To Mining Pools](#dns-events-related-to-mining-pools)
- [New Kind of Network (NKN) Detection](#new-kind-of-network-nkn-detection)
- [Suspicious DNS Z Flag Bit Set](#suspicious-dns-z-flag-bit-set)
- [DNS TOR Proxies](#dns-tor-proxies)

## Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing - Network

| Field | Value |
|---|---|
| **Sigma ID** | `5588576c-5898-4fac-bcdd-7475a60e8f43` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection, persistence |
| **MITRE Techniques** | T1557.001, T1187 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_kerberos_coercion_via_dns_object_spn_spoofing.yml)**

> Detects DNS queries containing patterns associated with Kerberos coercion attacks via DNS object spoofing.
The pattern "1UWhRCAAAAA..BAAAA" is a base64-encoded signature that corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure.
Attackers can use this technique to coerce authentication from victim systems to attacker-controlled hosts.
It is one of the strong indicators of a Kerberos coercion attack, where adversaries manipulate DNS records
to spoof Service Principal Names (SPNs) and redirect authentication requests like CVE-2025-33073.


```sql
-- ============================================================
-- Title:        Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing - Network
-- Sigma ID:     5588576c-5898-4fac-bcdd-7475a60e8f43
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        collection, persistence | T1557.001, T1187
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-06-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_kerberos_coercion_via_dns_object_spn_spoofing.yml
-- Unmapped:     query
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dns
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
  AND rawEventMsg LIKE '%UWhRCA%' AND rawEventMsg LIKE '%BAAAA%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
- https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html

---

## DNS Events Related To Mining Pools

| Field | Value |
|---|---|
| **Sigma ID** | `bf74135c-18e8-4a72-a926-0e4f47888c19` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | execution, impact |
| **MITRE Techniques** | T1569.002, T1496 |
| **Author** | Saw Winn Naung, Azure-Sentinel, @neu5ron |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_mining_pools.yml)**

> Identifies clients that may be performing DNS lookups associated with common currency mining pools.

```sql
-- ============================================================
-- Title:        DNS Events Related To Mining Pools
-- Sigma ID:     bf74135c-18e8-4a72-a926-0e4f47888c19
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        execution, impact | T1569.002, T1496
-- Author:       Saw Winn Naung, Azure-Sentinel, @neu5ron
-- Date:         2021-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_mining_pools.yml
-- Unmapped:     query
-- False Pos:    A DNS lookup does not necessarily  mean a successful attempt, verify a) if there was a response using the zeek answers field, if there was then verify the connections (conn.log) to those IPs. b) verify if HTTP, SSL, or TLS activity to the domain that was queried. http.log field is 'host' and ssl/tls is 'server_name'.
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dns
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
  AND (rawEventMsg LIKE '%monerohash.com' OR rawEventMsg LIKE '%do-dear.com' OR rawEventMsg LIKE '%xmrminerpro.com' OR rawEventMsg LIKE '%secumine.net' OR rawEventMsg LIKE '%xmrpool.com' OR rawEventMsg LIKE '%minexmr.org' OR rawEventMsg LIKE '%hashanywhere.com' OR rawEventMsg LIKE '%xmrget.com' OR rawEventMsg LIKE '%mininglottery.eu' OR rawEventMsg LIKE '%minergate.com' OR rawEventMsg LIKE '%moriaxmr.com' OR rawEventMsg LIKE '%multipooler.com' OR rawEventMsg LIKE '%moneropools.com' OR rawEventMsg LIKE '%xmrpool.eu' OR rawEventMsg LIKE '%coolmining.club' OR rawEventMsg LIKE '%supportxmr.com' OR rawEventMsg LIKE '%minexmr.com' OR rawEventMsg LIKE '%hashvault.pro' OR rawEventMsg LIKE '%xmrpool.net' OR rawEventMsg LIKE '%crypto-pool.fr' OR rawEventMsg LIKE '%xmr.pt' OR rawEventMsg LIKE '%miner.rocks' OR rawEventMsg LIKE '%walpool.com' OR rawEventMsg LIKE '%herominers.com' OR rawEventMsg LIKE '%gntl.co.uk' OR rawEventMsg LIKE '%semipool.com' OR rawEventMsg LIKE '%coinfoundry.org' OR rawEventMsg LIKE '%cryptoknight.cc' OR rawEventMsg LIKE '%fairhash.org' OR rawEventMsg LIKE '%baikalmine.com' OR rawEventMsg LIKE '%tubepool.xyz' OR rawEventMsg LIKE '%fairpool.xyz' OR rawEventMsg LIKE '%asiapool.io' OR rawEventMsg LIKE '%coinpoolit.webhop.me' OR rawEventMsg LIKE '%nanopool.org' OR rawEventMsg LIKE '%moneropool.com' OR rawEventMsg LIKE '%miner.center' OR rawEventMsg LIKE '%prohash.net' OR rawEventMsg LIKE '%poolto.be' OR rawEventMsg LIKE '%cryptoescrow.eu' OR rawEventMsg LIKE '%monerominers.net' OR rawEventMsg LIKE '%cryptonotepool.org' OR rawEventMsg LIKE '%extrmepool.org' OR rawEventMsg LIKE '%webcoin.me' OR rawEventMsg LIKE '%kippo.eu' OR rawEventMsg LIKE '%hashinvest.ws' OR rawEventMsg LIKE '%monero.farm' OR rawEventMsg LIKE '%linux-repository-updates.com' OR rawEventMsg LIKE '%1gh.com' OR rawEventMsg LIKE '%dwarfpool.com' OR rawEventMsg LIKE '%hash-to-coins.com' OR rawEventMsg LIKE '%pool-proxy.com' OR rawEventMsg LIKE '%hashfor.cash' OR rawEventMsg LIKE '%fairpool.cloud' OR rawEventMsg LIKE '%litecoinpool.org' OR rawEventMsg LIKE '%mineshaft.ml' OR rawEventMsg LIKE '%abcxyz.stream' OR rawEventMsg LIKE '%moneropool.ru' OR rawEventMsg LIKE '%cryptonotepool.org.uk' OR rawEventMsg LIKE '%extremepool.org' OR rawEventMsg LIKE '%extremehash.com' OR rawEventMsg LIKE '%hashinvest.net' OR rawEventMsg LIKE '%unipool.pro' OR rawEventMsg LIKE '%crypto-pools.org' OR rawEventMsg LIKE '%monero.net' OR rawEventMsg LIKE '%backup-pool.com' OR rawEventMsg LIKE '%mooo.com' OR rawEventMsg LIKE '%freeyy.me' OR rawEventMsg LIKE '%cryptonight.net' OR rawEventMsg LIKE '%shscrypto.net')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A DNS lookup does not necessarily  mean a successful attempt, verify a) if there was a response using the zeek answers field, if there was then verify the connections (conn.log) to those IPs. b) verify if HTTP, SSL, or TLS activity to the domain that was queried. http.log field is 'host' and ssl/tls is 'server_name'.

**References:**
- https://github.com/Azure/Azure-Sentinel/blob/fa0411f9424b6c47b4d5a20165e4f1b168c1f103/Detections/ASimDNS/imDNS_Miners.yaml

---

## New Kind of Network (NKN) Detection

| Field | Value |
|---|---|
| **Sigma ID** | `fa7703d6-0ee8-4949-889c-48c84bc15b6f` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | Michael Portera (@mportatoes) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_nkn.yml)**

> NKN is a networking service using blockchain technology to support a decentralized network of peers. While there are legitimate uses for it, it can also be used as a C2 channel. This rule looks for a DNS request to the ma>

```sql
-- ============================================================
-- Title:        New Kind of Network (NKN) Detection
-- Sigma ID:     fa7703d6-0ee8-4949-889c-48c84bc15b6f
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        (none)
-- Author:       Michael Portera (@mportatoes)
-- Date:         2022-04-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_nkn.yml
-- Unmapped:     query
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dns
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
  AND rawEventMsg LIKE '%seed%' AND rawEventMsg LIKE '%.nkn.org%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/nknorg/nkn-sdk-go
- https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/
- https://github.com/Maka8ka/NGLite

---

## Suspicious DNS Z Flag Bit Set

| Field | Value |
|---|---|
| **Sigma ID** | `ede05abc-2c9e-4624-9944-9ff17fdc0bf5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1095, T1571 |
| **Author** | @neu5ron, SOC Prime Team, Corelight |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_susp_zbit_flag.yml)**

> The DNS Z flag is bit within the DNS protocol header that is, per the IETF design, meant to be used reserved (unused).
Although recently it has been used in DNSSec, the value being set to anything other than 0 should be rare.
Otherwise if it is set to non 0 and DNSSec is being used, then excluding the legitimate domains is low effort and high reward.
Determine if multiple of these files were accessed in a short period of time to further enhance the possibility of seeing if this was a one off or the possibility of larger sensitive file gathering.
This Sigma query is designed to accompany the Corelight Threat Hunting Guide, which can be found here: https://www3.corelight.com/corelights-introductory-guide-to-threat-hunting-with-zeek-bro-logs'


```sql
-- ============================================================
-- Title:        Suspicious DNS Z Flag Bit Set
-- Sigma ID:     ede05abc-2c9e-4624-9944-9ff17fdc0bf5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1095, T1571
-- Author:       @neu5ron, SOC Prime Team, Corelight
-- Date:         2021-05-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_susp_zbit_flag.yml
-- Unmapped:     Z, query, qtype_name, answers, id.resp_p
-- False Pos:    Internal or legitimate external domains using DNSSec. Verify if these are legitimate DNSSec domains and then exclude them.; If you work in a Public Sector then it may be good to exclude things like endswith ".edu", ".gov" and or ".mil"
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dns
-- UNMAPPED_FIELD: Z
-- UNMAPPED_FIELD: query
-- UNMAPPED_FIELD: qtype_name
-- UNMAPPED_FIELD: answers
-- UNMAPPED_FIELD: id.resp_p

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (NOT (rawEventMsg = '0')
  AND rawEventMsg LIKE '%.%'
  AND NOT ((rawEventMsg LIKE '%.arpa' OR rawEventMsg LIKE '%.local' OR rawEventMsg LIKE '%.ultradns.net' OR rawEventMsg LIKE '%.twtrdns.net' OR rawEventMsg LIKE '%.azuredns-prd.info' OR rawEventMsg LIKE '%.azure-dns.com' OR rawEventMsg LIKE '%.azuredns-ff.info' OR rawEventMsg LIKE '%.azuredns-ff.org' OR rawEventMsg LIKE '%.azuregov-dns.org')))
  OR rawEventMsg IN ('ns', 'mx')
  OR rawEventMsg LIKE '%\\\\x00'
  OR rawEventMsg IN ('137', '138', '139')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Internal or legitimate external domains using DNSSec. Verify if these are legitimate DNSSec domains and then exclude them.; If you work in a Public Sector then it may be good to exclude things like endswith ".edu", ".gov" and or ".mil"

**References:**
- https://twitter.com/neu5ron/status/1346245602502443009
- https://tdm.socprime.com/tdm/info/eLbyj4JjI15v#sigma
- https://tools.ietf.org/html/rfc2929#section-2.1
- https://www.netresec.com/?page=Blog&month=2021-01&post=Finding-Targeted-SUNBURST-Victims-with-pDNS

---

## DNS TOR Proxies

| Field | Value |
|---|---|
| **Sigma ID** | `a8322756-015c-42e7-afb1-436e85ed3ff5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048 |
| **Author** | Saw Winn Naung , Azure-Sentinel |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_torproxy.yml)**

> Identifies IPs performing DNS lookups associated with common Tor proxies.

```sql
-- ============================================================
-- Title:        DNS TOR Proxies
-- Sigma ID:     a8322756-015c-42e7-afb1-436e85ed3ff5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1048
-- Author:       Saw Winn Naung , Azure-Sentinel
-- Date:         2021-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dns_torproxy.yml
-- Unmapped:     query
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dns
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
  AND (rawEventMsg LIKE '%.hiddenservice.net' OR rawEventMsg LIKE '%.onion.ca' OR rawEventMsg LIKE '%.onion.cab' OR rawEventMsg LIKE '%.onion.casa' OR rawEventMsg LIKE '%.onion.city' OR rawEventMsg LIKE '%.onion.direct' OR rawEventMsg LIKE '%.onion.dog' OR rawEventMsg LIKE '%.onion.glass' OR rawEventMsg LIKE '%.onion.gq' OR rawEventMsg LIKE '%.onion.guide' OR rawEventMsg LIKE '%.onion.in.net' OR rawEventMsg LIKE '%.onion.ink' OR rawEventMsg LIKE '%.onion.it' OR rawEventMsg LIKE '%.onion.link' OR rawEventMsg LIKE '%.onion.lt' OR rawEventMsg LIKE '%.onion.lu' OR rawEventMsg LIKE '%.onion.ly' OR rawEventMsg LIKE '%.onion.mn' OR rawEventMsg LIKE '%.onion.network' OR rawEventMsg LIKE '%.onion.nu' OR rawEventMsg LIKE '%.onion.pet' OR rawEventMsg LIKE '%.onion.plus' OR rawEventMsg LIKE '%.onion.pt' OR rawEventMsg LIKE '%.onion.pw' OR rawEventMsg LIKE '%.onion.rip' OR rawEventMsg LIKE '%.onion.sh' OR rawEventMsg LIKE '%.onion.si' OR rawEventMsg LIKE '%.onion.to' OR rawEventMsg LIKE '%.onion.top' OR rawEventMsg LIKE '%.onion.ws' OR rawEventMsg LIKE '%.onion' OR rawEventMsg LIKE '%.s1.tor-gateways.de' OR rawEventMsg LIKE '%.s2.tor-gateways.de' OR rawEventMsg LIKE '%.s3.tor-gateways.de' OR rawEventMsg LIKE '%.s4.tor-gateways.de' OR rawEventMsg LIKE '%.s5.tor-gateways.de' OR rawEventMsg LIKE '%.t2w.pw' OR rawEventMsg LIKE '%.tor2web.ae.org' OR rawEventMsg LIKE '%.tor2web.blutmagie.de' OR rawEventMsg LIKE '%.tor2web.com' OR rawEventMsg LIKE '%.tor2web.fi' OR rawEventMsg LIKE '%.tor2web.io' OR rawEventMsg LIKE '%.tor2web.org' OR rawEventMsg LIKE '%.tor2web.xyz' OR rawEventMsg LIKE '%.torlink.co')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/ASimDNS/imDNS_TorProxies.yaml

---
