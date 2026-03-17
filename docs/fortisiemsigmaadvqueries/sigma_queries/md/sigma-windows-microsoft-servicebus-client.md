# Sigma → FortiSIEM: Windows Microsoft-Servicebus-Client

> 1 rule · Generated 2026-03-17

## Table of Contents

- [HybridConnectionManager Service Running](#hybridconnectionmanager-service-running)

## HybridConnectionManager Service Running

| Field | Value |
|---|---|
| **Sigma ID** | `b55d23e5-6821-44ff-8a6e-67218891e49f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1554 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/servicebus/win_hybridconnectionmgr_svc_running.yml)**

> Rule to detect the Hybrid Connection Manager service running on an endpoint.

```sql
-- ============================================================
-- Title:        HybridConnectionManager Service Running
-- Sigma ID:     b55d23e5-6821-44ff-8a6e-67218891e49f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1554
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2021-04-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/servicebus/win_hybridconnectionmgr_svc_running.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate use of Hybrid Connection Manager via Azure function apps.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/microsoft-servicebus-client

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
  AND (winEventId IN ('40300', '40301', '40302')
  AND rawEventMsg LIKE '%HybridConnection%' OR rawEventMsg LIKE '%sb://%' OR rawEventMsg LIKE '%servicebus.windows.net%' OR rawEventMsg LIKE '%HybridConnectionManage%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of Hybrid Connection Manager via Azure function apps.

**References:**
- https://twitter.com/Cyb3rWard0g/status/1381642789369286662

---
