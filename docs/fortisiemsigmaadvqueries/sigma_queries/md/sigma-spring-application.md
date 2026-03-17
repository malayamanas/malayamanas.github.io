# Sigma → FortiSIEM: Spring Application

> 2 rules · Generated 2026-03-17

## Table of Contents

- [Spring Framework Exceptions](#spring-framework-exceptions)
- [Potential SpEL Injection In Spring Framework](#potential-spel-injection-in-spring-framework)

## Spring Framework Exceptions

| Field | Value |
|---|---|
| **Sigma ID** | `ae48ab93-45f7-4051-9dfe-5d30a3f78e33` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/spring/spring_application_exceptions.yml)**

> Detects suspicious Spring framework exceptions that could indicate exploitation attempts

```sql
-- ============================================================
-- Title:        Spring Framework Exceptions
-- Sigma ID:     ae48ab93-45f7-4051-9dfe-5d30a3f78e33
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1190
-- Author:       Thomas Patzke
-- Date:         2017-08-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/spring/spring_application_exceptions.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: spring/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%AccessDeniedException%' OR rawEventMsg LIKE '%CsrfException%' OR rawEventMsg LIKE '%InvalidCsrfTokenException%' OR rawEventMsg LIKE '%MissingCsrfTokenException%' OR rawEventMsg LIKE '%CookieTheftException%' OR rawEventMsg LIKE '%InvalidCookieException%' OR rawEventMsg LIKE '%RequestRejectedException%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://docs.spring.io/spring-security/site/docs/current/api/overview-tree.html

---

## Potential SpEL Injection In Spring Framework

| Field | Value |
|---|---|
| **Sigma ID** | `e9edd087-89d8-48c9-b0b4-5b9bb10896b8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/spring/spring_spel_injection.yml)**

> Detects potential SpEL Injection exploitation, which may lead to RCE.

```sql
-- ============================================================
-- Title:        Potential SpEL Injection In Spring Framework
-- Sigma ID:     e9edd087-89d8-48c9-b0b4-5b9bb10896b8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/spring/spring_spel_injection.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: spring/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%org.springframework.expression.ExpressionException%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---
