# Sigma → FortiSIEM: Linux Clamav

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Relevant ClamAV Message](#relevant-clamav-message)

## Relevant ClamAV Message

| Field | Value |
|---|---|
| **Sigma ID** | `36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1588.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/clamav/lnx_clamav_relevant_message.yml)**

> Detects relevant ClamAV messages

```sql
-- ============================================================
-- Title:        Relevant ClamAV Message
-- Sigma ID:     36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1588.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-03-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/clamav/lnx_clamav_relevant_message.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux/clamav

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Trojan*FOUND%' OR rawEventMsg LIKE '%VirTool*FOUND%' OR rawEventMsg LIKE '%Webshell*FOUND%' OR rawEventMsg LIKE '%Rootkit*FOUND%' OR rawEventMsg LIKE '%Htran*FOUND%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/clam_av_rules.xml

---
