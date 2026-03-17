# Sigma → FortiSIEM: Windows Shell-Core

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious Application Installed](#suspicious-application-installed)

## Suspicious Application Installed

| Field | Value |
|---|---|
| **Sigma ID** | `83c161b6-ca67-4f33-8ad0-644a0737cf07` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml)**

> Detects suspicious application installed by looking at the added shortcut to the app resolver cache

```sql
-- ============================================================
-- Title:        Suspicious Application Installed
-- Sigma ID:     83c161b6-ca67-4f33-8ad0-644a0737cf07
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml
-- Unmapped:     Name, AppID
-- False Pos:    Packages or applications being legitimately used by users or administrators
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/shell-core
-- UNMAPPED_FIELD: Name
-- UNMAPPED_FIELD: AppID

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
  AND (winEventId = '28115'
    AND (rawEventMsg LIKE '%Zenmap%' OR rawEventMsg LIKE '%AnyDesk%' OR rawEventMsg LIKE '%wireshark%' OR rawEventMsg LIKE '%openvpn%'))
  OR (winEventId = '28115'
    AND (rawEventMsg LIKE '%zenmap.exe%' OR rawEventMsg LIKE '%prokzult ad%' OR rawEventMsg LIKE '%wireshark%' OR rawEventMsg LIKE '%openvpn%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Packages or applications being legitimately used by users or administrators

**References:**
- https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3

---
