# Sigma → FortiSIEM: Windows Terminalservices-Localsessionmanager

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Ngrok Usage with Remote Desktop Service](#ngrok-usage-with-remote-desktop-service)

## Ngrok Usage with Remote Desktop Service

| Field | Value |
|---|---|
| **Sigma ID** | `64d51a51-32a6-49f0-9f3d-17e34d640272` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/terminalservices/win_terminalservices_rdp_ngrok.yml)**

> Detects cases in which ngrok, a reverse proxy tool, forwards events to the local RDP port, which could be a sign of malicious behaviour

```sql
-- ============================================================
-- Title:        Ngrok Usage with Remote Desktop Service
-- Sigma ID:     64d51a51-32a6-49f0-9f3d-17e34d640272
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2022-04-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/terminalservices/win_terminalservices_rdp_ngrok.yml
-- Unmapped:     Address
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/terminalservices-localsessionmanager
-- UNMAPPED_FIELD: Address

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
  AND (winEventId = '21'
    AND rawEventMsg LIKE '%16777216%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/tekdefense/status/1519711183162556416?s=12&t=OTsHCBkQOTNs1k3USz65Zg
- https://ngrok.com/

---
