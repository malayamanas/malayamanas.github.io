# Sigma → FortiSIEM: Bitbucket Audit

> 14 rules · Generated 2026-03-17

## Table of Contents

- [Bitbucket Full Data Export Triggered](#bitbucket-full-data-export-triggered)
- [Bitbucket Global Permission Changed](#bitbucket-global-permission-changed)
- [Bitbucket Global Secret Scanning Rule Deleted](#bitbucket-global-secret-scanning-rule-deleted)
- [Bitbucket Global SSH Settings Changed](#bitbucket-global-ssh-settings-changed)
- [Bitbucket Audit Log Configuration Updated](#bitbucket-audit-log-configuration-updated)
- [Bitbucket Project Secret Scanning Allowlist Added](#bitbucket-project-secret-scanning-allowlist-added)
- [Bitbucket Secret Scanning Exempt Repository Added](#bitbucket-secret-scanning-exempt-repository-added)
- [Bitbucket Secret Scanning Rule Deleted](#bitbucket-secret-scanning-rule-deleted)
- [Bitbucket Unauthorized Access To A Resource](#bitbucket-unauthorized-access-to-a-resource)
- [Bitbucket Unauthorized Full Data Export Triggered](#bitbucket-unauthorized-full-data-export-triggered)
- [Bitbucket User Details Export Attempt Detected](#bitbucket-user-details-export-attempt-detected)
- [Bitbucket User Login Failure](#bitbucket-user-login-failure)
- [Bitbucket User Login Failure Via SSH](#bitbucket-user-login-failure-via-ssh)
- [Bitbucket User Permissions Export Attempt](#bitbucket-user-permissions-export-attempt)

## Bitbucket Full Data Export Triggered

| Field | Value |
|---|---|
| **Sigma ID** | `195e1b9d-bfc2-4ffa-ab4e-35aef69815f8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1213.003 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_full_data_export_triggered.yml)**

> Detects when full data export is attempted.

```sql
-- ============================================================
-- Title:        Bitbucket Full Data Export Triggered
-- Sigma ID:     195e1b9d-bfc2-4ffa-ab4e-35aef69815f8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1213.003
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_full_data_export_triggered.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Data pipeline'
    AND rawEventMsg = 'Full data export triggered')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/adminjiraserver0811/importing-and-exporting-data-1019391889.html

---

## Bitbucket Global Permission Changed

| Field | Value |
|---|---|
| **Sigma ID** | `aac6c4f4-87c7-4961-96ac-c3fd3a42c310` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_permissions_change_detected.yml)**

> Detects global permissions change activity.

```sql
-- ============================================================
-- Title:        Bitbucket Global Permission Changed
-- Sigma ID:     aac6c4f4-87c7-4961-96ac-c3fd3a42c310
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_permissions_change_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Permissions'
    AND rawEventMsg IN ('Global permission remove request', 'Global permission removed', 'Global permission granted', 'Global permission requested'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/global-permissions-776640369.html

---

## Bitbucket Global Secret Scanning Rule Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `e16cf0f0-ee88-4901-bd0b-4c8d13d9ee05` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_secret_scanning_rule_deleted.yml)**

> Detects Bitbucket global secret scanning rule deletion activity.

```sql
-- ============================================================
-- Title:        Bitbucket Global Secret Scanning Rule Deleted
-- Sigma ID:     e16cf0f0-ee88-4901-bd0b-4c8d13d9ee05
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_secret_scanning_rule_deleted.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Global administration'
    AND rawEventMsg = 'Global secret scanning rule deleted')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html

---

## Bitbucket Global SSH Settings Changed

| Field | Value |
|---|---|
| **Sigma ID** | `16ab6143-510a-44e2-a615-bdb80b8317fc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001, T1021.004 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_ssh_settings_change_detected.yml)**

> Detects Bitbucket global SSH access configuration changes.

```sql
-- ============================================================
-- Title:        Bitbucket Global SSH Settings Changed
-- Sigma ID:     16ab6143-510a-44e2-a615-bdb80b8317fc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001, T1021.004
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_global_ssh_settings_change_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Global administration'
    AND rawEventMsg = 'SSH settings changed')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/enable-ssh-access-to-git-repositories-776640358.html

---

## Bitbucket Audit Log Configuration Updated

| Field | Value |
|---|---|
| **Sigma ID** | `6aa12161-235a-4dfb-9c74-fe08df8d8da1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_log_configuration_update_detected.yml)**

> Detects changes to the bitbucket audit log configuration.

```sql
-- ============================================================
-- Title:        Bitbucket Audit Log Configuration Updated
-- Sigma ID:     6aa12161-235a-4dfb-9c74-fe08df8d8da1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_log_configuration_update_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Auditing'
    AND rawEventMsg = 'Audit log configuration updated')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html

---

## Bitbucket Project Secret Scanning Allowlist Added

| Field | Value |
|---|---|
| **Sigma ID** | `42ccce6d-7bd3-4930-95cd-e4d83fa94a30` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_project_secret_scanning_allowlist_added.yml)**

> Detects when a secret scanning allowlist rule is added for projects.

```sql
-- ============================================================
-- Title:        Bitbucket Project Secret Scanning Allowlist Added
-- Sigma ID:     42ccce6d-7bd3-4930-95cd-e4d83fa94a30
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_project_secret_scanning_allowlist_added.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Projects'
    AND rawEventMsg = 'Project secret scanning allowlist rule added')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html

---

## Bitbucket Secret Scanning Exempt Repository Added

| Field | Value |
|---|---|
| **Sigma ID** | `b91e8d5e-0033-44fe-973f-b730316f23a1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_exempt_repository_detected.yml)**

> Detects when a repository is exempted from secret scanning feature.

```sql
-- ============================================================
-- Title:        Bitbucket Secret Scanning Exempt Repository Added
-- Sigma ID:     b91e8d5e-0033-44fe-973f-b730316f23a1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_exempt_repository_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Repositories'
    AND rawEventMsg = 'Secret scanning exempt repository added')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html

---

## Bitbucket Secret Scanning Rule Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `ff91e3f0-ad15-459f-9a85-1556390c138d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_rule_deleted.yml)**

> Detects when secret scanning rule is deleted for the project or repository.

```sql
-- ============================================================
-- Title:        Bitbucket Secret Scanning Rule Deleted
-- Sigma ID:     ff91e3f0-ad15-459f-9a85-1556390c138d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_secret_scanning_rule_deleted.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('Projects', 'Repositories')
    AND rawEventMsg IN ('Project secret scanning rule deleted', 'Repository secret scanning rule deleted'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html

---

## Bitbucket Unauthorized Access To A Resource

| Field | Value |
|---|---|
| **Sigma ID** | `7215374a-de4f-4b33-8ba5-70804c9251d3` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1586 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml)**

> Detects unauthorized access attempts to a resource.

```sql
-- ============================================================
-- Title:        Bitbucket Unauthorized Access To A Resource
-- Sigma ID:     7215374a-de4f-4b33-8ba5-70804c9251d3
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1586
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Access attempts to non-existent repositories or due to outdated plugins. Usually "Anonymous" user is reported in the "author.name" field in most cases.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Security'
    AND rawEventMsg = 'Unauthorized access to a resource')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Access attempts to non-existent repositories or due to outdated plugins. Usually "Anonymous" user is reported in the "author.name" field in most cases.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html

---

## Bitbucket Unauthorized Full Data Export Triggered

| Field | Value |
|---|---|
| **Sigma ID** | `34d81081-03c9-4a7f-91c9-5e46af625cde` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1213.003, T1586 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_unauthorized_full_data_export_triggered.yml)**

> Detects when full data export is attempted an unauthorized user.

```sql
-- ============================================================
-- Title:        Bitbucket Unauthorized Full Data Export Triggered
-- Sigma ID:     34d81081-03c9-4a7f-91c9-5e46af625cde
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        collection | T1213.003, T1586
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_unauthorized_full_data_export_triggered.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Data pipeline'
    AND rawEventMsg = 'Unauthorized full data export triggered')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/secret-scanning-1157471613.html

---

## Bitbucket User Details Export Attempt Detected

| Field | Value |
|---|---|
| **Sigma ID** | `5259cbf2-0a75-48bf-b57a-c54d6fabaef3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection, reconnaissance, discovery |
| **MITRE Techniques** | T1213, T1082, T1591.004 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_details_export_attempt_detected.yml)**

> Detects user data export activity.

```sql
-- ============================================================
-- Title:        Bitbucket User Details Export Attempt Detected
-- Sigma ID:     5259cbf2-0a75-48bf-b57a-c54d6fabaef3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection, reconnaissance, discovery | T1213, T1082, T1591.004
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_details_export_attempt_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Users and groups'
    AND rawEventMsg IN ('User permissions export failed', 'User permissions export started', 'User permissions exported'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://support.atlassian.com/security-and-access-policies/docs/export-user-accounts

---

## Bitbucket User Login Failure

| Field | Value |
|---|---|
| **Sigma ID** | `70ed1d26-0050-4b38-a599-92c53d57d45a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_detected.yml)**

> Detects user authentication failure events.
Please note that this rule can be noisy and it is recommended to use with correlation based on "author.name" field.


```sql
-- ============================================================
-- Title:        Bitbucket User Login Failure
-- Sigma ID:     70ed1d26-0050-4b38-a599-92c53d57d45a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user wrong password attempts.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Authentication'
    AND rawEventMsg = 'User login failed')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user wrong password attempts.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html

---

## Bitbucket User Login Failure Via SSH

| Field | Value |
|---|---|
| **Sigma ID** | `d3f90469-fb05-42ce-b67d-0fded91bbef3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.004, T1110 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_via_ssh_detected.yml)**

> Detects SSH user login access failures.
Please note that this rule can be noisy and is recommended to use with correlation based on "author.name" field.


```sql
-- ============================================================
-- Title:        Bitbucket User Login Failure Via SSH
-- Sigma ID:     d3f90469-fb05-42ce-b67d-0fded91bbef3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.004, T1110
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_via_ssh_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user wrong password attempts.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Authentication'
    AND rawEventMsg = 'User login failed(SSH)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user wrong password attempts.

**References:**
- https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html
- https://confluence.atlassian.com/bitbucketserver/enable-ssh-access-to-git-repositories-776640358.html

---

## Bitbucket User Permissions Export Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `87cc6698-3e07-4ba2-9b43-a85a73e151e2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | reconnaissance, collection, discovery |
| **MITRE Techniques** | T1213, T1082, T1591.004 |
| **Author** | Muhammad Faisal (@faisalusuf) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_permissions_export_attempt_detected.yml)**

> Detects user permission data export attempt.

```sql
-- ============================================================
-- Title:        Bitbucket User Permissions Export Attempt
-- Sigma ID:     87cc6698-3e07-4ba2-9b43-a85a73e151e2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        reconnaissance, collection, discovery | T1213, T1082, T1591.004
-- Author:       Muhammad Faisal (@faisalusuf)
-- Date:         2024-02-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/bitbucket/audit/bitbucket_audit_user_permissions_export_attempt_detected.yml
-- Unmapped:     auditType.category, auditType.action
-- False Pos:    Legitimate user activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: bitbucket/audit
-- UNMAPPED_FIELD: auditType.category
-- UNMAPPED_FIELD: auditType.action

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Users and groups'
    AND rawEventMsg IN ('User details export failed', 'User details export started', 'User details exported'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user activity.

**References:**
- https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html
- https://confluence.atlassian.com/bitbucketserver/users-and-groups-776640439.html

---
