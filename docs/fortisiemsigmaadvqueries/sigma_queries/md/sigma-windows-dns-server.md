# Sigma → FortiSIEM: Windows Dns-Server

> 2 rules · Generated 2026-03-17

## Table of Contents

- [Failed DNS Zone Transfer](#failed-dns-zone-transfer)
- [DNS Server Error Failed Loading the ServerLevelPluginDLL](#dns-server-error-failed-loading-the-serverlevelplugindll)

## Failed DNS Zone Transfer

| Field | Value |
|---|---|
| **Sigma ID** | `6d444368-6da1-43fe-b2fc-44202430480e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1590.002 |
| **Author** | Zach Mathis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_server/win_dns_server_failed_dns_zone_transfer.yml)**

> Detects when a DNS zone transfer failed.

```sql
-- ============================================================
-- Title:        Failed DNS Zone Transfer
-- Sigma ID:     6d444368-6da1-43fe-b2fc-44202430480e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance | T1590.002
-- Author:       Zach Mathis
-- Date:         2023-05-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_server/win_dns_server_failed_dns_zone_transfer.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-server

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
  AND winEventId = '6004'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://kb.eventtracker.com/evtpass/evtpages/EventId_6004_Microsoft-Windows-DNS-Server-Service_65410.asp

---

## DNS Server Error Failed Loading the ServerLevelPluginDLL

| Field | Value |
|---|---|
| **Sigma ID** | `cbe51394-cd93-4473-b555-edf0144952d9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1574.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_server/win_dns_server_susp_server_level_plugin_dll.yml)**

> Detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded

```sql
-- ============================================================
-- Title:        DNS Server Error Failed Loading the ServerLevelPluginDLL
-- Sigma ID:     cbe51394-cd93-4473-b555-edf0144952d9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1574.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-05-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_server/win_dns_server_susp_server_level_plugin_dll.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/dns-server

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
  AND winEventId IN ('150', '770', '771')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
- https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx
- https://twitter.com/gentilkiwi/status/861641945944391680

---
