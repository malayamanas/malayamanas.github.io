# Sigma → FortiSIEM: Django Application

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Django Framework Exceptions](#django-framework-exceptions)

## Django Framework Exceptions

| Field | Value |
|---|---|
| **Sigma ID** | `fd435618-981e-4a7c-81f8-f78ce480d616` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Thomas Patzke |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/django/appframework_django_exceptions.yml)**

> Detects suspicious Django web application framework exceptions that could indicate exploitation attempts

```sql
-- ============================================================
-- Title:        Django Framework Exceptions
-- Sigma ID:     fd435618-981e-4a7c-81f8-f78ce480d616
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        T1190
-- Author:       Thomas Patzke
-- Date:         2017-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/django/appframework_django_exceptions.yml
-- Unmapped:     (none)
-- False Pos:    Application bugs
-- ============================================================
-- UNMAPPED_LOGSOURCE: django/application

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%SuspiciousOperation%' OR rawEventMsg LIKE '%DisallowedHost%' OR rawEventMsg LIKE '%DisallowedModelAdminLookup%' OR rawEventMsg LIKE '%DisallowedModelAdminToField%' OR rawEventMsg LIKE '%DisallowedRedirect%' OR rawEventMsg LIKE '%InvalidSessionKey%' OR rawEventMsg LIKE '%RequestDataTooBig%' OR rawEventMsg LIKE '%SuspiciousFileOperation%' OR rawEventMsg LIKE '%SuspiciousMultipartForm%' OR rawEventMsg LIKE '%SuspiciousSession%' OR rawEventMsg LIKE '%TooManyFieldsSent%' OR rawEventMsg LIKE '%PermissionDenied%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application bugs

**References:**
- https://docs.djangoproject.com/en/1.11/ref/exceptions/
- https://docs.djangoproject.com/en/1.11/topics/logging/#django-security

---
