# Sigma → FortiSIEM: Okta Okta

> 21 rules · Generated 2026-03-17

## Table of Contents

- [Okta Admin Functions Access Through Proxy](#okta-admin-functions-access-through-proxy)
- [Okta Admin Role Assigned to an User or Group](#okta-admin-role-assigned-to-an-user-or-group)
- [Okta Admin Role Assignment Created](#okta-admin-role-assignment-created)
- [Okta API Token Created](#okta-api-token-created)
- [Okta API Token Revoked](#okta-api-token-revoked)
- [Okta Application Modified or Deleted](#okta-application-modified-or-deleted)
- [Okta Application Sign-On Policy Modified or Deleted](#okta-application-sign-on-policy-modified-or-deleted)
- [Okta FastPass Phishing Detection](#okta-fastpass-phishing-detection)
- [Okta Identity Provider Created](#okta-identity-provider-created)
- [Okta MFA Reset or Deactivated](#okta-mfa-reset-or-deactivated)
- [Okta Network Zone Deactivated or Deleted](#okta-network-zone-deactivated-or-deleted)
- [Okta New Admin Console Behaviours](#okta-new-admin-console-behaviours)
- [Potential Okta Password in AlternateID Field](#potential-okta-password-in-alternateid-field)
- [Okta Policy Modified or Deleted](#okta-policy-modified-or-deleted)
- [Okta Policy Rule Modified or Deleted](#okta-policy-rule-modified-or-deleted)
- [Okta Security Threat Detected](#okta-security-threat-detected)
- [Okta Suspicious Activity Reported by End-user](#okta-suspicious-activity-reported-by-end-user)
- [Okta Unauthorized Access to App](#okta-unauthorized-access-to-app)
- [Okta User Account Locked Out](#okta-user-account-locked-out)
- [New Okta User Created](#new-okta-user-created)
- [Okta User Session Start Via An Anonymising Proxy Service](#okta-user-session-start-via-an-anonymising-proxy-service)

## Okta Admin Functions Access Through Proxy

| Field | Value |
|---|---|
| **Sigma ID** | `9058ca8b-f397-4fd1-a9fa-2b7aad4d6309` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Muhammad Faisal @faisalusuf |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_activity_from_proxy_query.yml)**

> Detects access to Okta admin functions through proxy.

```sql
-- ============================================================
-- Title:        Okta Admin Functions Access Through Proxy
-- Sigma ID:     9058ca8b-f397-4fd1-a9fa-2b7aad4d6309
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Muhammad Faisal @faisalusuf
-- Date:         2023-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_activity_from_proxy_query.yml
-- Unmapped:     debugContext.debugData.requestUri, securityContext.isProxy
-- False Pos:    False positives are expected if administrators access these function through proxy legitimatly. Apply additional filters if necessary
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: debugContext.debugData.requestUri
-- UNMAPPED_FIELD: securityContext.isProxy

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%admin%'
    AND rawEventMsg = 'true')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** False positives are expected if administrators access these function through proxy legitimatly. Apply additional filters if necessary

**References:**
- https://www.beyondtrust.com/blog/entry/okta-support-unit-breach
- https://dataconomy.com/2023/10/23/okta-data-breach/
- https://blog.cloudflare.com/how-cloudflare-mitigated-yet-another-okta-compromise/

---

## Okta Admin Role Assigned to an User or Group

| Field | Value |
|---|---|
| **Sigma ID** | `413d4a81-6c98-4479-9863-014785fd579c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.003 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_role_assigned_to_user_or_group.yml)**

> Detects when an the Administrator role is assigned to an user or group.

```sql
-- ============================================================
-- Title:        Okta Admin Role Assigned to an User or Group
-- Sigma ID:     413d4a81-6c98-4479-9863-014785fd579c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098.003
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_role_assigned_to_user_or_group.yml
-- Unmapped:     eventtype
-- False Pos:    Administrator roles could be assigned to users or group by other admin users.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('group.privilege.grant', 'user.account.privilege.grant')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator roles could be assigned to users or group by other admin users.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Admin Role Assignment Created

| Field | Value |
|---|---|
| **Sigma ID** | `139bdd4b-9cd7-49ba-a2f4-744d0a8f5d8c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Nikita Khalimonenkov |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_role_assignment_created.yml)**

> Detects when a new admin role assignment is created. Which could be a sign of privilege escalation or persistence

```sql
-- ============================================================
-- Title:        Okta Admin Role Assignment Created
-- Sigma ID:     139bdd4b-9cd7-49ba-a2f4-744d0a8f5d8c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Nikita Khalimonenkov
-- Date:         2023-01-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_role_assignment_created.yml
-- Unmapped:     eventtype
-- False Pos:    Legitimate creation of a new admin role assignment
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'iam.resourceset.bindings.add'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate creation of a new admin role assignment

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta API Token Created

| Field | Value |
|---|---|
| **Sigma ID** | `19951c21-229d-4ccb-8774-b993c3ff3c5c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_api_token_created.yml)**

> Detects when a API token is created

```sql
-- ============================================================
-- Title:        Okta API Token Created
-- Sigma ID:     19951c21-229d-4ccb-8774-b993c3ff3c5c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_api_token_created.yml
-- Unmapped:     eventtype
-- False Pos:    Legitimate creation of an API token by authorized users
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'system.api_token.create'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate creation of an API token by authorized users

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta API Token Revoked

| Field | Value |
|---|---|
| **Sigma ID** | `cf1dbc6b-6205-41b4-9b88-a83980d2255b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_api_token_revoked.yml)**

> Detects when a API Token is revoked.

```sql
-- ============================================================
-- Title:        Okta API Token Revoked
-- Sigma ID:     cf1dbc6b-6205-41b4-9b88-a83980d2255b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_api_token_revoked.yml
-- Unmapped:     eventtype
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'system.api_token.revoke'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Application Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `7899144b-e416-4c28-b0b5-ab8f9e0a541d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_application_modified_or_deleted.yml)**

> Detects when an application is modified or deleted.

```sql
-- ============================================================
-- Title:        Okta Application Modified or Deleted
-- Sigma ID:     7899144b-e416-4c28-b0b5-ab8f9e0a541d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_application_modified_or_deleted.yml
-- Unmapped:     eventtype
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('application.lifecycle.update', 'application.lifecycle.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Application Sign-On Policy Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `8f668cc4-c18e-45fe-ad00-624a981cf88a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_application_sign_on_policy_modified_or_deleted.yml)**

> Detects when an application Sign-on Policy is modified or deleted.

```sql
-- ============================================================
-- Title:        Okta Application Sign-On Policy Modified or Deleted
-- Sigma ID:     8f668cc4-c18e-45fe-ad00-624a981cf88a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_application_sign_on_policy_modified_or_deleted.yml
-- Unmapped:     eventtype
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('application.policy.sign_on.update', 'application.policy.sign_on.rule.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta FastPass Phishing Detection

| Field | Value |
|---|---|
| **Sigma ID** | `ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1566 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_fastpass_phishing_detection.yml)**

> Detects when Okta FastPass prevents a known phishing site.

```sql
-- ============================================================
-- Title:        Okta FastPass Phishing Detection
-- Sigma ID:     ee39a9f7-5a79-4b0a-9815-d36b3cf28d3e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1566
-- Author:       Austin Songer @austinsonger
-- Date:         2023-05-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_fastpass_phishing_detection.yml
-- Unmapped:     outcome.reason, outcome.result, eventtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: outcome.reason
-- UNMAPPED_FIELD: outcome.result
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'FastPass declined phishing attempt'
    AND rawEventMsg = 'FAILURE'
    AND rawEventMsg = 'user.authentication.auth_via_mfa')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://sec.okta.com/fastpassphishingdetection
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Identity Provider Created

| Field | Value |
|---|---|
| **Sigma ID** | `969c7590-8c19-4797-8c1b-23155de6e7ac` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.001 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_identity_provider_created.yml)**

> Detects when a new identity provider is created for Okta.

```sql
-- ============================================================
-- Title:        Okta Identity Provider Created
-- Sigma ID:     969c7590-8c19-4797-8c1b-23155de6e7ac
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098.001
-- Author:       kelnage
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_identity_provider_created.yml
-- Unmapped:     eventtype
-- False Pos:    When an admin creates a new, authorised identity provider.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'system.idp.lifecycle.create'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When an admin creates a new, authorised identity provider.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection

---

## Okta MFA Reset or Deactivated

| Field | Value |
|---|---|
| **Sigma ID** | `50e068d7-1e6b-4054-87e5-0a592c40c7e0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556.006 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_mfa_reset_or_deactivated.yml)**

> Detects when an attempt at deactivating  or resetting MFA.

```sql
-- ============================================================
-- Title:        Okta MFA Reset or Deactivated
-- Sigma ID:     50e068d7-1e6b-4054-87e5-0a592c40c7e0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1556.006
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_mfa_reset_or_deactivated.yml
-- Unmapped:     eventtype
-- False Pos:    If a MFA reset or deactivated was performed by a system administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('user.mfa.factor.deactivate', 'user.mfa.factor.reset_all')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If a MFA reset or deactivated was performed by a system administrator.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Network Zone Deactivated or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `9f308120-69ed-4506-abde-ac6da81f4310` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_network_zone_deactivated_or_deleted.yml)**

> Detects when an Network Zone is Deactivated or Deleted.

```sql
-- ============================================================
-- Title:        Okta Network Zone Deactivated or Deleted
-- Sigma ID:     9f308120-69ed-4506-abde-ac6da81f4310
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_network_zone_deactivated_or_deleted.yml
-- Unmapped:     eventtype
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('zone.deactivate', 'zone.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta New Admin Console Behaviours

| Field | Value |
|---|---|
| **Sigma ID** | `a0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_new_behaviours_admin_console.yml)**

> Detects when Okta identifies new activity in the Admin Console.

```sql
-- ============================================================
-- Title:        Okta New Admin Console Behaviours
-- Sigma ID:     a0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       kelnage
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_new_behaviours_admin_console.yml
-- Unmapped:     eventtype, target.displayname, debugcontext.debugdata.behaviors, debugcontext.debugdata.logonlysecuritydata
-- False Pos:    When an admin begins using the Admin Console and one of Okta's heuristics incorrectly identifies the behavior as being unusual.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype
-- UNMAPPED_FIELD: target.displayname
-- UNMAPPED_FIELD: debugcontext.debugdata.behaviors
-- UNMAPPED_FIELD: debugcontext.debugdata.logonlysecuritydata

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'policy.evaluate_sign_on'
    AND rawEventMsg = 'Okta Admin Console')
  AND (rawEventMsg LIKE '%POSITIVE%')
  OR (rawEventMsg LIKE '%POSITIVE%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When an admin begins using the Admin Console and one of Okta's heuristics incorrectly identifies the behavior as being unusual.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection

---

## Potential Okta Password in AlternateID Field

| Field | Value |
|---|---|
| **Sigma ID** | `91b76b84-8589-47aa-9605-c837583b82a9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1552 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_password_in_alternateid_field.yml)**

> Detects when a user has potentially entered their password into the
username field, which will cause the password to be retained in log files.


```sql
-- ============================================================
-- Title:        Potential Okta Password in AlternateID Field
-- Sigma ID:     91b76b84-8589-47aa-9605-c837583b82a9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1552
-- Author:       kelnage
-- Date:         2023-04-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_password_in_alternateid_field.yml
-- Unmapped:     legacyeventtype, actor.alternateid
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: legacyeventtype
-- UNMAPPED_FIELD: actor.alternateid

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'core.user_auth.login_failed'
  AND NOT (match(rawEventMsg, '(^0oa.*|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10})')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://www.mitiga.io/blog/how-okta-passwords-can-be-compromised-uncovering-a-risk-to-user-data
- https://help.okta.com/en-us/Content/Topics/users-groups-profiles/usgp-create-character-restriction.htm

---

## Okta Policy Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `1667a172-ed4c-463c-9969-efd92195319a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_policy_modified_or_deleted.yml)**

> Detects when an Okta policy is modified or deleted.

```sql
-- ============================================================
-- Title:        Okta Policy Modified or Deleted
-- Sigma ID:     1667a172-ed4c-463c-9969-efd92195319a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_policy_modified_or_deleted.yml
-- Unmapped:     eventtype
-- False Pos:    Okta Policies being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('policy.lifecycle.update', 'policy.lifecycle.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Okta Policies being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Policy Rule Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `0c97c1d3-4057-45c9-b148-1de94b631931` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_policy_rule_modified_or_deleted.yml)**

> Detects when an Policy Rule is Modified or Deleted.

```sql
-- ============================================================
-- Title:        Okta Policy Rule Modified or Deleted
-- Sigma ID:     0c97c1d3-4057-45c9-b148-1de94b631931
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_policy_rule_modified_or_deleted.yml
-- Unmapped:     eventtype
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('policy.rule.update', 'policy.rule.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Security Threat Detected

| Field | Value |
|---|---|
| **Sigma ID** | `5c82f0b9-3c6d-477f-a318-0e14a1df73e0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_security_threat_detected.yml)**

> Detects when an security threat is detected in Okta.

```sql
-- ============================================================
-- Title:        Okta Security Threat Detected
-- Sigma ID:     5c82f0b9-3c6d-477f-a318-0e14a1df73e0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_security_threat_detected.yml
-- Unmapped:     eventtype
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'security.threat.detected'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://okta.github.io/okta-help/en/prod/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.htm
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta Suspicious Activity Reported by End-user

| Field | Value |
|---|---|
| **Sigma ID** | `07e97cc6-aed1-43ae-9081-b3470d2367f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1586.003 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_suspicious_activity_enduser_report.yml)**

> Detects when an Okta end-user reports activity by their account as being potentially suspicious.

```sql
-- ============================================================
-- Title:        Okta Suspicious Activity Reported by End-user
-- Sigma ID:     07e97cc6-aed1-43ae-9081-b3470d2367f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1586.003
-- Author:       kelnage
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_suspicious_activity_enduser_report.yml
-- Unmapped:     eventtype
-- False Pos:    If an end-user incorrectly identifies normal activity as suspicious.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'user.account.report_suspicious_activity_by_enduser'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If an end-user incorrectly identifies normal activity as suspicious.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://github.com/okta/workflows-templates/blob/1164f0eb71ce47c9ddc7d850e9ab87b5a2b42333/workflows/suspicious_activity_reported/readme.md

---

## Okta Unauthorized Access to App

| Field | Value |
|---|---|
| **Sigma ID** | `6cc2b61b-d97e-42ef-a9dd-8aa8dc951657` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_unauthorized_access_to_app.yml)**

> Detects when unauthorized access to app occurs.

```sql
-- ============================================================
-- Title:        Okta Unauthorized Access to App
-- Sigma ID:     6cc2b61b-d97e-42ef-a9dd-8aa8dc951657
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_unauthorized_access_to_app.yml
-- Unmapped:     displaymessage
-- False Pos:    User might of believe that they had access.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: displaymessage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'User attempted unauthorized access to app'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User might of believe that they had access.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta User Account Locked Out

| Field | Value |
|---|---|
| **Sigma ID** | `14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_account_locked_out.yml)**

> Detects when an user account is locked out.

```sql
-- ============================================================
-- Title:        Okta User Account Locked Out
-- Sigma ID:     14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_account_locked_out.yml
-- Unmapped:     displaymessage
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: displaymessage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Max sign in attempts exceeded'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://developer.okta.com/docs/reference/api/event-types/

---

## New Okta User Created

| Field | Value |
|---|---|
| **Sigma ID** | `b6c718dd-8f53-4b9f-98d8-93fdca966969` |
| **Level** | informational |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_created.yml)**

> Detects new user account creation

```sql
-- ============================================================
-- Title:        New Okta User Created
-- Sigma ID:     b6c718dd-8f53-4b9f-98d8-93fdca966969
-- Level:        informational  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_created.yml
-- Unmapped:     eventtype
-- False Pos:    Legitimate and authorized user creation
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'user.lifecycle.create'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate and authorized user creation

**References:**
- https://developer.okta.com/docs/reference/api/event-types/

---

## Okta User Session Start Via An Anonymising Proxy Service

| Field | Value |
|---|---|
| **Sigma ID** | `bde30855-5c53-4c18-ae90-1ff79ebc9578` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.006 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_session_start_via_anonymised_proxy.yml)**

> Detects when an Okta user session starts where the user is behind an anonymising proxy service.

```sql
-- ============================================================
-- Title:        Okta User Session Start Via An Anonymising Proxy Service
-- Sigma ID:     bde30855-5c53-4c18-ae90-1ff79ebc9578
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.006
-- Author:       kelnage
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_user_session_start_via_anonymised_proxy.yml
-- Unmapped:     eventtype, securitycontext.isproxy
-- False Pos:    If a user requires an anonymising proxy due to valid justifications.
-- ============================================================
-- UNMAPPED_LOGSOURCE: okta/okta
-- UNMAPPED_FIELD: eventtype
-- UNMAPPED_FIELD: securitycontext.isproxy

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'user.session.start'
    AND rawEventMsg = 'true')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If a user requires an anonymising proxy due to valid justifications.

**References:**
- https://developer.okta.com/docs/reference/api/system-log/
- https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection

---
