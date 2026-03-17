# Sigma → FortiSIEM: Velocity Application

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potential Server Side Template Injection In Velocity](#potential-server-side-template-injection-in-velocity)

## Potential Server Side Template Injection In Velocity

| Field | Value |
|---|---|
| **Sigma ID** | `16c86189-b556-4ee8-b4c7-7e350a195a4f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/velocity/velocity_ssti_injection.yml)**

> Detects exceptions in velocity template renderer, this most likely happens due to dynamic rendering of user input and may lead to RCE.

```sql
-- ============================================================
-- Title:        Potential Server Side Template Injection In Velocity
-- Sigma ID:     16c86189-b556-4ee8-b4c7-7e350a195a4f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/velocity/velocity_ssti_injection.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs; Missing .vm files
-- ============================================================
-- UNMAPPED_LOGSOURCE: velocity/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ParseErrorException%' OR rawEventMsg LIKE '%VelocityException%' OR rawEventMsg LIKE '%TemplateInitException%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs; Missing .vm files

**References:**
- https://antgarsil.github.io/posts/velocity/
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---
