# Sigma → FortiSIEM: Onelogin Onelogin.Events

> 2 rules · Generated 2026-03-17

## Table of Contents

- [OneLogin User Assumed Another User](#onelogin-user-assumed-another-user)
- [OneLogin User Account Locked](#onelogin-user-account-locked)

## OneLogin User Assumed Another User

| Field | Value |
|---|---|
| **Sigma ID** | `62fff148-278d-497e-8ecd-ad6083231a35` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/onelogin/onelogin_assumed_another_user.yml)**

> Detects when an user assumed another user account.

```sql
-- ============================================================
-- Title:        OneLogin User Assumed Another User
-- Sigma ID:     62fff148-278d-497e-8ecd-ad6083231a35
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/onelogin/onelogin_assumed_another_user.yml
-- Unmapped:     event_type_id
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: onelogin/onelogin.events
-- UNMAPPED_FIELD: event_type_id

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '3'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://developers.onelogin.com/api-docs/1/events/event-resource

---

## OneLogin User Account Locked

| Field | Value |
|---|---|
| **Sigma ID** | `a717c561-d117-437e-b2d9-0118a7035d01` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/identity/onelogin/onelogin_user_account_locked.yml)**

> Detects when an user account is locked or suspended.

```sql
-- ============================================================
-- Title:        OneLogin User Account Locked
-- Sigma ID:     a717c561-d117-437e-b2d9-0118a7035d01
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/identity/onelogin/onelogin_user_account_locked.yml
-- Unmapped:     event_type_id
-- False Pos:    System may lock or suspend user accounts.
-- ============================================================
-- UNMAPPED_LOGSOURCE: onelogin/onelogin.events
-- UNMAPPED_FIELD: event_type_id

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '532'
  OR rawEventMsg = '553'
  OR rawEventMsg = '551'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System may lock or suspend user accounts.

**References:**
- https://developers.onelogin.com/api-docs/1/events/event-resource/

---
