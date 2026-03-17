# Sigma → FortiSIEM: Windows 

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Mimikatz Use](#mimikatz-use)

## Mimikatz Use

| Field | Value |
|---|---|
| **Sigma ID** | `06d71506-7beb-4f22-8888-e2e5e2ca7fd8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1003.002, T1003.004, T1003.001, T1003.006 |
| **Author** | Florian Roth (Nextron Systems), David ANDRE (additional keywords) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/win_alert_mimikatz_keywords.yml)**

> This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)

```sql
-- ============================================================
-- Title:        Mimikatz Use
-- Sigma ID:     06d71506-7beb-4f22-8888-e2e5e2ca7fd8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1003.002, T1003.004, T1003.001, T1003.006
-- Author:       Florian Roth (Nextron Systems), David ANDRE (additional keywords)
-- Date:         2017-01-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/win_alert_mimikatz_keywords.yml
-- Unmapped:     (none)
-- False Pos:    Naughty administrators; AV Signature updates; Files with Mimikatz in their filename
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows

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
  AND (rawEventMsg LIKE '%dpapi::masterkey%' OR rawEventMsg LIKE '%eo.oe.kiwi%' OR rawEventMsg LIKE '%event::clear%' OR rawEventMsg LIKE '%event::drop%' OR rawEventMsg LIKE '%gentilkiwi.com%' OR rawEventMsg LIKE '%kerberos::golden%' OR rawEventMsg LIKE '%kerberos::ptc%' OR rawEventMsg LIKE '%kerberos::ptt%' OR rawEventMsg LIKE '%kerberos::tgt%' OR rawEventMsg LIKE '%Kiwi Legit Printer%' OR rawEventMsg LIKE '%lsadump::%' OR rawEventMsg LIKE '%mimidrv.sys%' OR rawEventMsg LIKE '%\\mimilib.dll%' OR rawEventMsg LIKE '%misc::printnightmare%' OR rawEventMsg LIKE '%misc::shadowcopies%' OR rawEventMsg LIKE '%misc::skeleton%' OR rawEventMsg LIKE '%privilege::backup%' OR rawEventMsg LIKE '%privilege::debug%' OR rawEventMsg LIKE '%privilege::driver%' OR rawEventMsg LIKE '%sekurlsa::%'
  AND NOT (winEventId = '15'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Naughty administrators; AV Signature updates; Files with Mimikatz in their filename

**References:**
- https://tools.thehacker.recipes/mimikatz/modules

---
