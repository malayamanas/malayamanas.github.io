# Sigma → FortiSIEM: Windows Driver-Framework

> 1 rule · Generated 2026-03-17

## Table of Contents

- [USB Device Plugged](#usb-device-plugged)

## USB Device Plugged

| Field | Value |
|---|---|
| **Sigma ID** | `1a4bd6e3-4c6e-405d-a9a3-53a116e341d4` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1200 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/driverframeworks/win_usb_device_plugged.yml)**

> Detects plugged/unplugged USB devices

```sql
-- ============================================================
-- Title:        USB Device Plugged
-- Sigma ID:     1a4bd6e3-4c6e-405d-a9a3-53a116e341d4
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1200
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-11-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/driverframeworks/win_usb_device_plugged.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrative activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/driver-framework

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
  AND winEventId IN ('2003', '2100', '2102')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activity

**References:**
- https://df-stream.com/2014/01/the-windows-7-event-log-and-usb-device/
- https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/

---
