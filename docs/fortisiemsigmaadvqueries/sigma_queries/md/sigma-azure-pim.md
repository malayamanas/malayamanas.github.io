# Sigma → FortiSIEM: Azure Pim

> 7 rules · Generated 2026-03-17

## Table of Contents

- [Stale Accounts In A Privileged Role](#stale-accounts-in-a-privileged-role)
- [Invalid PIM License](#invalid-pim-license)
- [Roles Assigned Outside PIM](#roles-assigned-outside-pim)
- [Roles Activated Too Frequently](#roles-activated-too-frequently)
- [Roles Activation Doesn't Require MFA](#roles-activation-doesnt-require-mfa)
- [Roles Are Not Being Used](#roles-are-not-being-used)
- [Too Many Global Admins](#too-many-global-admins)

## Stale Accounts In A Privileged Role

| Field | Value |
|---|---|
| **Sigma ID** | `e402c26a-267a-45bd-9615-bd9ceda6da85` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_account_stale.yml)**

> Identifies when an account hasn't signed in during the past n number of days.

```sql
-- ============================================================
-- Title:        Stale Accounts In A Privileged Role
-- Sigma ID:     e402c26a-267a-45bd-9615-bd9ceda6da85
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_account_stale.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate if potential generic account that cannot be removed.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'staleSignInAlertIncident'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate if potential generic account that cannot be removed.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#potential-stale-accounts-in-a-privileged-role

---

## Invalid PIM License

| Field | Value |
|---|---|
| **Sigma ID** | `58af08eb-f9e1-43c8-9805-3ad9b0482bd8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_invalid_license.yml)**

> Identifies when an organization doesn't have the proper license for PIM and is out of compliance.

```sql
-- ============================================================
-- Title:        Invalid PIM License
-- Sigma ID:     58af08eb-f9e1-43c8-9805-3ad9b0482bd8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_invalid_license.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate if licenses have expired.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'invalidLicenseAlertIncident'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate if licenses have expired.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#the-organization-doesnt-have-microsoft-entra-premium-p2-or-microsoft-entra-id-governance

---

## Roles Assigned Outside PIM

| Field | Value |
|---|---|
| **Sigma ID** | `b1bc08d1-8224-4758-a0e6-fbcfc98c73bb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_assigned_outside_of_pim.yml)**

> Identifies when a privilege role assignment has taken place outside of PIM and may indicate an attack.

```sql
-- ============================================================
-- Title:        Roles Assigned Outside PIM
-- Sigma ID:     b1bc08d1-8224-4758-a0e6-fbcfc98c73bb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_assigned_outside_of_pim.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate where users are being assigned privileged roles outside of Privileged Identity Management and prohibit future assignments from there.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate where users are being assigned privileged roles outside of Privileged Identity Management and prohibit future assignments from there.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-are-being-assigned-outside-of-privileged-identity-management

---

## Roles Activated Too Frequently

| Field | Value |
|---|---|
| **Sigma ID** | `645fd80d-6c07-435b-9e06-7bc1b5656cba` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_frequent_activation.yml)**

> Identifies when the same privilege role has multiple activations by the same user.

```sql
-- ============================================================
-- Title:        Roles Activated Too Frequently
-- Sigma ID:     645fd80d-6c07-435b-9e06-7bc1b5656cba
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_frequent_activation.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate where if active time period for a role is set too short.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'sequentialActivationRenewalsAlertIncident'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate where if active time period for a role is set too short.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-are-being-activated-too-frequently

---

## Roles Activation Doesn't Require MFA

| Field | Value |
|---|---|
| **Sigma ID** | `94a66f46-5b64-46ce-80b2-75dcbe627cc0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_no_mfa_required.yml)**

> Identifies when a privilege role can be activated without performing mfa.

```sql
-- ============================================================
-- Title:        Roles Activation Doesn't Require MFA
-- Sigma ID:     94a66f46-5b64-46ce-80b2-75dcbe627cc0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_no_mfa_required.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate if user is performing MFA at sign-in.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'noMfaOnRoleActivationAlertIncident'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate if user is performing MFA at sign-in.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-dont-require-multi-factor-authentication-for-activation

---

## Roles Are Not Being Used

| Field | Value |
|---|---|
| **Sigma ID** | `8c6ec464-4ae4-43ac-936a-291da66ed13d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_not_used.yml)**

> Identifies when a user has been assigned a privilege role and are not using that role.

```sql
-- ============================================================
-- Title:        Roles Are Not Being Used
-- Sigma ID:     8c6ec464-4ae4-43ac-936a-291da66ed13d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_not_used.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate if potential generic account that cannot be removed.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'redundantAssignmentAlertIncident'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate if potential generic account that cannot be removed.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#administrators-arent-using-their-privileged-roles

---

## Too Many Global Admins

| Field | Value |
|---|---|
| **Sigma ID** | `7bbc309f-e2b1-4eb1-8369-131a367d67d3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_too_many_global_admins.yml)**

> Identifies an event where there are there are too many accounts assigned the Global Administrator role.

```sql
-- ============================================================
-- Title:        Too Many Global Admins
-- Sigma ID:     7bbc309f-e2b1-4eb1-8369-131a367d67d3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_too_many_global_admins.yml
-- Unmapped:     riskEventType
-- False Pos:    Investigate if threshold setting in PIM is too low.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/pim
-- UNMAPPED_FIELD: riskEventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'tooManyGlobalAdminsAssignedToTenantAlertIncident'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Investigate if threshold setting in PIM is too low.

**References:**
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#there-are-too-many-global-administrators

---
