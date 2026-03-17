# Sigma → FortiSIEM: Linux Syslog

> 2 rules · Generated 2026-03-17

## Table of Contents

- [Disabling Security Tools - Builtin](#disabling-security-tools-builtin)
- [Suspicious Named Error](#suspicious-named-error)

## Disabling Security Tools - Builtin

| Field | Value |
|---|---|
| **Sigma ID** | `49f5dfc1-f92e-4d34-96fa-feba3f6acf36` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.004 |
| **Author** | Ömer Günal, Alejandro Ortuno, oscd.community |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml)**

> Detects disabling security tools

```sql
-- ============================================================
-- Title:        Disabling Security Tools - Builtin
-- Sigma ID:     49f5dfc1-f92e-4d34-96fa-feba3f6acf36
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.004
-- Author:       Ömer Günal, Alejandro Ortuno, oscd.community
-- Date:         2020-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administration activities
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Generic_Syslog')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%stopping iptables%' OR rawEventMsg LIKE '%stopping ip6tables%' OR rawEventMsg LIKE '%stopping firewalld%' OR rawEventMsg LIKE '%stopping cbdaemon%' OR rawEventMsg LIKE '%stopping falcon-sensor%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administration activities

**References:**
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md

---

## Suspicious Named Error

| Field | Value |
|---|---|
| **Sigma ID** | `c8e35e96-19ce-4f16-aeb6-fd5588dc5365` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/syslog/lnx_syslog_susp_named.yml)**

> Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

```sql
-- ============================================================
-- Title:        Suspicious Named Error
-- Sigma ID:     c8e35e96-19ce-4f16-aeb6-fd5588dc5365
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-02-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/syslog/lnx_syslog_susp_named.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Generic_Syslog')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '% dropping source port zero packet from %' OR rawEventMsg LIKE '% denied AXFR from %' OR rawEventMsg LIKE '% exiting (due to fatal error)%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/named_rules.xml

---
