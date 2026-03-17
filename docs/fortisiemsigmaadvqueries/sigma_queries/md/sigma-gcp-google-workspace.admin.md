# Sigma → FortiSIEM: Gcp Google Workspace.Admin

> 7 rules · Generated 2026-03-17

## Table of Contents

- [Google Workspace Application Access Level Modified](#google-workspace-application-access-level-modified)
- [Google Workspace Application Removed](#google-workspace-application-removed)
- [Google Workspace Granted Domain API Access](#google-workspace-granted-domain-api-access)
- [Google Workspace MFA Disabled](#google-workspace-mfa-disabled)
- [Google Workspace Role Modified or Deleted](#google-workspace-role-modified-or-deleted)
- [Google Workspace Role Privilege Deleted](#google-workspace-role-privilege-deleted)
- [Google Workspace User Granted Admin Privileges](#google-workspace-user-granted-admin-privileges)

## Google Workspace Application Access Level Modified

| Field | Value |
|---|---|
| **Sigma ID** | `22f2fb54-5312-435d-852f-7c74f81684ca` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.003 |
| **Author** | Bryan Lim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_application_access_levels_modified.yml)**

> Detects when an access level is changed for a Google workspace application.
An access level is part of BeyondCorp Enterprise which is Google Workspace's way of enforcing Zero Trust model.
An adversary would be able to remove access levels to gain easier access to Google workspace resources.


```sql
-- ============================================================
-- Title:        Google Workspace Application Access Level Modified
-- Sigma ID:     22f2fb54-5312-435d-852f-7c74f81684ca
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098.003
-- Author:       Bryan Lim
-- Date:         2024-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_application_access_levels_modified.yml
-- Unmapped:     eventService, eventName, setting_name
-- False Pos:    Legitimate administrative activities changing the access levels for an application
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: setting_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg = 'CHANGE_APPLICATION_SETTING'
    AND rawEventMsg LIKE 'ContextAwareAccess%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities changing the access levels for an application

**References:**
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-application-settings
- https://support.google.com/a/answer/9261439

---

## Google Workspace Application Removed

| Field | Value |
|---|---|
| **Sigma ID** | `ee2803f0-71c8-4831-b48b-a1fc57601ee4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_application_removed.yml)**

> Detects when an an application is removed from Google Workspace.

```sql
-- ============================================================
-- Title:        Google Workspace Application Removed
-- Sigma ID:     ee2803f0-71c8-4831-b48b-a1fc57601ee4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_application_removed.yml
-- Unmapped:     eventService, eventName
-- False Pos:    Application being removed may be performed by a System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg IN ('REMOVE_APPLICATION', 'REMOVE_APPLICATION_FROM_WHITELIST'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application being removed may be performed by a System Administrator.

**References:**
- https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings?hl=en#REMOVE_APPLICATION
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings?hl=en#REMOVE_APPLICATION_FROM_WHITELIST

---

## Google Workspace Granted Domain API Access

| Field | Value |
|---|---|
| **Sigma ID** | `04e2a23a-9b29-4a5c-be3a-3542e3f982ba` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_granted_domain_api_access.yml)**

> Detects when an API access service account is granted domain authority.

```sql
-- ============================================================
-- Title:        Google Workspace Granted Domain API Access
-- Sigma ID:     04e2a23a-9b29-4a5c-be3a-3542e3f982ba
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Austin Songer
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_granted_domain_api_access.yml
-- Unmapped:     eventService, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg = 'AUTHORIZE_API_CLIENT_ACCESS')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings#AUTHORIZE_API_CLIENT_ACCESS

---

## Google Workspace MFA Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `780601d1-6376-4f2a-884e-b8d45599f78c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_mfa_disabled.yml)**

> Detects when multi-factor authentication (MFA) is disabled.

```sql
-- ============================================================
-- Title:        Google Workspace MFA Disabled
-- Sigma ID:     780601d1-6376-4f2a-884e-b8d45599f78c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_mfa_disabled.yml
-- Unmapped:     eventService, eventName, new_value
-- False Pos:    MFA may be disabled and performed by a system administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: new_value

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg IN ('ENFORCE_STRONG_AUTHENTICATION', 'ALLOW_STRONG_AUTHENTICATION'))
  AND rawEventMsg = 'false')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** MFA may be disabled and performed by a system administrator.

**References:**
- https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings#ENFORCE_STRONG_AUTHENTICATION
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-security-settings?hl=en#ALLOW_STRONG_AUTHENTICATION

---

## Google Workspace Role Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `6aef64e3-60c6-4782-8db3-8448759c714e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_role_modified_or_deleted.yml)**

> Detects when an a role is modified or deleted in Google Workspace.

```sql
-- ============================================================
-- Title:        Google Workspace Role Modified or Deleted
-- Sigma ID:     6aef64e3-60c6-4782-8db3-8448759c714e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_role_modified_or_deleted.yml
-- Unmapped:     eventService, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg IN ('DELETE_ROLE', 'RENAME_ROLE', 'UPDATE_ROLE'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings

---

## Google Workspace Role Privilege Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `bf638ef7-4d2d-44bb-a1dc-a238252e6267` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_role_privilege_deleted.yml)**

> Detects when an a role privilege is deleted in Google Workspace.

```sql
-- ============================================================
-- Title:        Google Workspace Role Privilege Deleted
-- Sigma ID:     bf638ef7-4d2d-44bb-a1dc-a238252e6267
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_role_privilege_deleted.yml
-- Unmapped:     eventService, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg = 'REMOVE_PRIVILEGE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings

---

## Google Workspace User Granted Admin Privileges

| Field | Value |
|---|---|
| **Sigma ID** | `2d1b83e4-17c6-4896-a37b-29140b40a788` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_user_granted_admin_privileges.yml)**

> Detects when an Google Workspace user is granted admin privileges.

```sql
-- ============================================================
-- Title:        Google Workspace User Granted Admin Privileges
-- Sigma ID:     2d1b83e4-17c6-4896-a37b-29140b40a788
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Austin Songer
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/gcp_gworkspace_user_granted_admin_privileges.yml
-- Unmapped:     eventService, eventName
-- False Pos:    Google Workspace admin role privileges, may be modified by system administrators.
-- ============================================================
-- UNMAPPED_LOGSOURCE: gcp/google_workspace.admin
-- UNMAPPED_FIELD: eventService
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admin.googleapis.com'
    AND rawEventMsg IN ('GRANT_DELEGATED_ADMIN_PRIVILEGES', 'GRANT_ADMIN_PRIVILEGE'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Google Workspace admin role privileges, may be modified by system administrators.

**References:**
- https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
- https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-user-settings#GRANT_ADMIN_PRIVILEGE

---
