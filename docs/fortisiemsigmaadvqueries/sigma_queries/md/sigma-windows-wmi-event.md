# Sigma → FortiSIEM: Windows Wmi Event

> 3 rules · Generated 2026-03-17

## Table of Contents

- [WMI Event Subscription](#wmi-event-subscription)
- [Suspicious Encoded Scripts in a WMI Consumer](#suspicious-encoded-scripts-in-a-wmi-consumer)
- [Suspicious Scripting in a WMI Consumer](#suspicious-scripting-in-a-wmi-consumer)

## WMI Event Subscription

| Field | Value |
|---|---|
| **Sigma ID** | `0f06a3a5-6a09-413f-8743-e6cf35561297` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1546.003 |
| **Author** | Tom Ueltschi (@c_APT_ure) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/wmi_event/sysmon_wmi_event_subscription.yml)**

> Detects creation of WMI event subscription persistence method

```sql
-- ============================================================
-- Title:        WMI Event Subscription
-- Sigma ID:     0f06a3a5-6a09-413f-8743-e6cf35561297
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1546.003
-- Author:       Tom Ueltschi (@c_APT_ure)
-- Date:         2019-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/wmi_event/sysmon_wmi_event_subscription.yml
-- Unmapped:     (none)
-- False Pos:    Exclude legitimate (vetted) use of WMI event subscription in your network
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-19-WMI-Event-Filter')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('19', '20', '21')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Exclude legitimate (vetted) use of WMI event subscription in your network

**References:**
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-19-wmievent-wmieventfilter-activity-detected
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-20-wmievent-wmieventconsumer-activity-detected
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-21-wmievent-wmieventconsumertofilter-activity-detected

---

## Suspicious Encoded Scripts in a WMI Consumer

| Field | Value |
|---|---|
| **Sigma ID** | `83844185-1c5b-45bc-bcf3-b5bf3084ca5b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1047, T1546.003 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/wmi_event/sysmon_wmi_susp_encoded_scripts.yml)**

> Detects suspicious encoded payloads in WMI Event Consumers

```sql
-- ============================================================
-- Title:        Suspicious Encoded Scripts in a WMI Consumer
-- Sigma ID:     83844185-1c5b-45bc-bcf3-b5bf3084ca5b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1047, T1546.003
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-09-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/wmi_event/sysmon_wmi_susp_encoded_scripts.yml
-- Unmapped:     Destination
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: Destination

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-19-WMI-Event-Filter')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, 'V3JpdGVQcm9jZXNzTWVtb3J5|FdyaXRlUHJvY2Vzc01lbW9yeQ|BXcml0ZVByb2Nlc3NNZW1vcn|VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU|FRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2R|BUaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZQ|VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVyIFdpbjMy|FRoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlciBXaW4zMg|BUaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZXIgV2luMz')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/RiccardoAncarani/LiquidSnake

---

## Suspicious Scripting in a WMI Consumer

| Field | Value |
|---|---|
| **Sigma ID** | `fe21810c-2a8c-478f-8dd3-5a287fb2a0e0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.005 |
| **Author** | Florian Roth (Nextron Systems), Jonhnathan Ribeiro |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/wmi_event/sysmon_wmi_susp_scripting.yml)**

> Detects suspicious commands that are related to scripting/powershell in WMI Event Consumers

```sql
-- ============================================================
-- Title:        Suspicious Scripting in a WMI Consumer
-- Sigma ID:     fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.005
-- Author:       Florian Roth (Nextron Systems), Jonhnathan Ribeiro
-- Date:         2019-04-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/wmi_event/sysmon_wmi_susp_scripting.yml
-- Unmapped:     Destination
-- False Pos:    Legitimate administrative scripts
-- ============================================================
-- UNMAPPED_FIELD: Destination

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-19-WMI-Event-Filter')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%new-object%' AND rawEventMsg LIKE '%net.webclient%' AND rawEventMsg LIKE '%.downloadstring%')
  OR (rawEventMsg LIKE '%new-object%' AND rawEventMsg LIKE '%net.webclient%' AND rawEventMsg LIKE '%.downloadfile%')
  OR ((rawEventMsg LIKE '% iex(%' OR rawEventMsg LIKE '% -nop %' OR rawEventMsg LIKE '% -noprofile %' OR rawEventMsg LIKE '% -decode %' OR rawEventMsg LIKE '% -enc %' OR rawEventMsg LIKE '%WScript.Shell%' OR rawEventMsg LIKE '%System.Security.Cryptography.FromBase64Transform%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative scripts

**References:**
- https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
- https://github.com/Neo23x0/signature-base/blob/615bf1f6bac3c1bdc417025c40c073e6c2771a76/yara/gen_susp_lnk_files.yar#L19
- https://github.com/RiccardoAncarani/LiquidSnake

---
