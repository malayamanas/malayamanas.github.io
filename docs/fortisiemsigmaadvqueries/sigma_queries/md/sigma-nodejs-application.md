# Sigma → FortiSIEM: Nodejs Application

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potential RCE Exploitation Attempt In NodeJS](#potential-rce-exploitation-attempt-in-nodejs)

## Potential RCE Exploitation Attempt In NodeJS

| Field | Value |
|---|---|
| **Sigma ID** | `97661d9d-2beb-4630-b423-68985291a8af` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/nodejs/nodejs_rce_exploitation_attempt.yml)**

> Detects process execution related errors in NodeJS. If the exceptions are caused due to user input then they may suggest an RCE vulnerability.

```sql
-- ============================================================
-- Title:        Potential RCE Exploitation Attempt In NodeJS
-- Sigma ID:     97661d9d-2beb-4630-b423-68985291a8af
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/nodejs/nodejs_rce_exploitation_attempt.yml
-- Unmapped:     (none)
-- False Pos:    Puppeteer invocation exceptions often contain child_process related errors, that doesn't necessarily mean that the app is vulnerable.
-- ============================================================
-- UNMAPPED_LOGSOURCE: nodejs/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%node:child\_process%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Puppeteer invocation exceptions often contain child_process related errors, that doesn't necessarily mean that the app is vulnerable.

**References:**
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---
