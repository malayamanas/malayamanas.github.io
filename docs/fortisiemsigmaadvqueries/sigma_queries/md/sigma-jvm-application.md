# Sigma → FortiSIEM: Jvm Application

> 5 rules · Generated 2026-03-17

## Table of Contents

- [Potential JNDI Injection Exploitation In JVM Based Application](#potential-jndi-injection-exploitation-in-jvm-based-application)
- [Potential Local File Read Vulnerability In JVM Based Application](#potential-local-file-read-vulnerability-in-jvm-based-application)
- [Potential OGNL Injection Exploitation In JVM Based Application](#potential-ognl-injection-exploitation-in-jvm-based-application)
- [Process Execution Error In JVM Based Application](#process-execution-error-in-jvm-based-application)
- [Potential XXE Exploitation Attempt In JVM Based Application](#potential-xxe-exploitation-attempt-in-jvm-based-application)

## Potential JNDI Injection Exploitation In JVM Based Application

| Field | Value |
|---|---|
| **Sigma ID** | `bb0e9cec-d4da-46f5-997f-22efc59f3dca` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_jndi_injection_exploitation_attempt.yml)**

> Detects potential JNDI Injection exploitation. Often coupled with Log4Shell exploitation.

```sql
-- ============================================================
-- Title:        Potential JNDI Injection Exploitation In JVM Based Application
-- Sigma ID:     bb0e9cec-d4da-46f5-997f-22efc59f3dca
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_jndi_injection_exploitation_attempt.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: jvm/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%com.sun.jndi.ldap.%' OR rawEventMsg LIKE '%org.apache.logging.log4j.core.net.JndiManager%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs
- https://secariolabs.com/research/analysing-and-reproducing-poc-for-log4j-2-15-0

---

## Potential Local File Read Vulnerability In JVM Based Application

| Field | Value |
|---|---|
| **Sigma ID** | `e032f5bc-4563-4096-ae3b-064bab588685` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_local_file_read.yml)**

> Detects potential local file read vulnerability in JVM based apps.
If the exceptions are caused due to user input and contain path traversal payloads then it's a red flag.


```sql
-- ============================================================
-- Title:        Potential Local File Read Vulnerability In JVM Based Application
-- Sigma ID:     e032f5bc-4563-4096-ae3b-064bab588685
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_local_file_read.yml
-- Unmapped:     
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: jvm/application
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%FileNotFoundException%' OR rawEventMsg LIKE '%/../../..%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---

## Potential OGNL Injection Exploitation In JVM Based Application

| Field | Value |
|---|---|
| **Sigma ID** | `4d0af518-828e-4a04-a751-a7d03f3046ad` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_ognl_injection_exploitation_attempt.yml)**

> Detects potential OGNL Injection exploitation, which may lead to RCE.
OGNL is an expression language that is supported in many JVM based systems.
OGNL Injection is the reason for some high profile RCE's such as Apache Struts (CVE-2017-5638) and Confluence (CVE-2022-26134)


```sql
-- ============================================================
-- Title:        Potential OGNL Injection Exploitation In JVM Based Application
-- Sigma ID:     4d0af518-828e-4a04-a751-a7d03f3046ad
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_ognl_injection_exploitation_attempt.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: jvm/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%org.apache.commons.ognl.OgnlException%' OR rawEventMsg LIKE '%ExpressionSyntaxException%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---

## Process Execution Error In JVM Based Application

| Field | Value |
|---|---|
| **Sigma ID** | `d65f37da-a26a-48f8-8159-3dde96680ad2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_rce_exploitation_attempt.yml)**

> Detects process execution related exceptions in JVM based apps, often relates to RCE

```sql
-- ============================================================
-- Title:        Process Execution Error In JVM Based Application
-- Sigma ID:     d65f37da-a26a-48f8-8159-3dde96680ad2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_rce_exploitation_attempt.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: jvm/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Cannot run program%' OR rawEventMsg LIKE '%java.lang.ProcessImpl%' OR rawEventMsg LIKE '%java.lang.ProcessBuilder%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---

## Potential XXE Exploitation Attempt In JVM Based Application

| Field | Value |
|---|---|
| **Sigma ID** | `c4e06896-e27c-4583-95ac-91ce2279345d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Moti Harmats |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_xxe_exploitation_attempt.yml)**

> Detects XML parsing issues, if the application expects to work with XML make sure that the parser is initialized safely.

```sql
-- ============================================================
-- Title:        Potential XXE Exploitation Attempt In JVM Based Application
-- Sigma ID:     c4e06896-e27c-4583-95ac-91ce2279345d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Moti Harmats
-- Date:         2023-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/jvm/java_xxe_exploitation_attempt.yml
-- Unmapped:     (none)
-- False Pos:    If the application expects to work with XML there may be parsing issues that don't necessarily mean XXE.
-- ============================================================
-- UNMAPPED_LOGSOURCE: jvm/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%SAXParseException%' OR rawEventMsg LIKE '%DOMException%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If the application expects to work with XML there may be parsing issues that don't necessarily mean XXE.

**References:**
- https://rules.sonarsource.com/java/RSPEC-2755
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- https://www.wix.engineering/post/threat-and-vulnerability-hunting-with-application-server-error-logs

---
