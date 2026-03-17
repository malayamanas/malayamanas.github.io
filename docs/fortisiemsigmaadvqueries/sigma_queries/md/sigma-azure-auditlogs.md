# Sigma → FortiSIEM: Azure Auditlogs

> 38 rules · Generated 2026-03-17

## Table of Contents

- [CA Policy Removed by Non Approved Actor](#ca-policy-removed-by-non-approved-actor)
- [CA Policy Updated by Non Approved Actor](#ca-policy-updated-by-non-approved-actor)
- [New CA Policy by Non-approved Actor](#new-ca-policy-by-non-approved-actor)
- [Account Created And Deleted Within A Close Time Frame](#account-created-and-deleted-within-a-close-time-frame)
- [Bitlocker Key Retrieval](#bitlocker-key-retrieval)
- [Certificate-Based Authentication Enabled](#certificate-based-authentication-enabled)
- [Changes to Device Registration Policy](#changes-to-device-registration-policy)
- [Guest Users Invited To Tenant By Non Approved Inviters](#guest-users-invited-to-tenant-by-non-approved-inviters)
- [New Root Certificate Authority Added](#new-root-certificate-authority-added)
- [Users Added to Global or Device Admin Roles](#users-added-to-global-or-device-admin-roles)
- [Application AppID Uri Configuration Changes](#application-appid-uri-configuration-changes)
- [Added Credentials to Existing Application](#added-credentials-to-existing-application)
- [Delegated Permissions Granted For All Users](#delegated-permissions-granted-for-all-users)
- [End User Consent](#end-user-consent)
- [End User Consent Blocked](#end-user-consent-blocked)
- [Added Owner To Application](#added-owner-to-application)
- [App Granted Microsoft Permissions](#app-granted-microsoft-permissions)
- [App Granted Privileged Delegated Or App Permissions](#app-granted-privileged-delegated-or-app-permissions)
- [App Assigned To Azure RBAC/Microsoft Entra Role](#app-assigned-to-azure-rbacmicrosoft-entra-role)
- [Application URI Configuration Changes](#application-uri-configuration-changes)
- [Windows LAPS Credential Dump From Entra ID](#windows-laps-credential-dump-from-entra-id)
- [Change to Authentication Method](#change-to-authentication-method)
- [Azure Domain Federation Settings Modified](#azure-domain-federation-settings-modified)
- [User Added To Group With CA Policy Modification Access](#user-added-to-group-with-ca-policy-modification-access)
- [User Removed From Group With CA Policy Modification Access](#user-removed-from-group-with-ca-policy-modification-access)
- [Guest User Invited By Non Approved Inviters](#guest-user-invited-by-non-approved-inviters)
- [User State Changed From Guest To Member](#user-state-changed-from-guest-to-member)
- [PIM Approvals And Deny Elevation](#pim-approvals-and-deny-elevation)
- [PIM Alert Setting Changes To Disabled](#pim-alert-setting-changes-to-disabled)
- [Changes To PIM Settings](#changes-to-pim-settings)
- [User Added To Privilege Role](#user-added-to-privilege-role)
- [Bulk Deletion Changes To Privileged Account Permissions](#bulk-deletion-changes-to-privileged-account-permissions)
- [Privileged Account Creation](#privileged-account-creation)
- [Azure Subscription Permission Elevation Via AuditLogs](#azure-subscription-permission-elevation-via-auditlogs)
- [Temporary Access Pass Added To An Account](#temporary-access-pass-added-to-an-account)
- [User Risk and MFA Registration Policy Updated](#user-risk-and-mfa-registration-policy-updated)
- [Multi Factor Authentication Disabled For User Account](#multi-factor-authentication-disabled-for-user-account)
- [Password Reset By User Account](#password-reset-by-user-account)

## CA Policy Removed by Non Approved Actor

| Field | Value |
|---|---|
| **Sigma ID** | `26e7c5e2-6545-481e-b7e6-050143459635` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548, T1556 |
| **Author** | Corissa Koopmans, '@corissalea' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_ca_policy_removedby_bad_actor.yml)**

> Monitor and alert on conditional access changes where non approved actor removed CA Policy.

```sql
-- ============================================================
-- Title:        CA Policy Removed by Non Approved Actor
-- Sigma ID:     26e7c5e2-6545-481e-b7e6-050143459635
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1548, T1556
-- Author:       Corissa Koopmans, '@corissalea'
-- Date:         2022-07-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_ca_policy_removedby_bad_actor.yml
-- Unmapped:     properties.message
-- False Pos:    Misconfigured role permissions; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Delete conditional access policy'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Misconfigured role permissions; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access

---

## CA Policy Updated by Non Approved Actor

| Field | Value |
|---|---|
| **Sigma ID** | `50a3c7aa-ec29-44a4-92c1-fce229eef6fc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548, T1556 |
| **Author** | Corissa Koopmans, '@corissalea' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_ca_policy_updatedby_bad_actor.yml)**

> Monitor and alert on conditional access changes. Is Initiated by (actor) approved to make changes? Review Modified Properties and compare "old" vs "new" value.

```sql
-- ============================================================
-- Title:        CA Policy Updated by Non Approved Actor
-- Sigma ID:     50a3c7aa-ec29-44a4-92c1-fce229eef6fc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1548, T1556
-- Author:       Corissa Koopmans, '@corissalea'
-- Date:         2022-07-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_ca_policy_updatedby_bad_actor.yml
-- Unmapped:     properties.message
-- False Pos:    Misconfigured role permissions; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Update conditional access policy'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Misconfigured role permissions; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access

---

## New CA Policy by Non-approved Actor

| Field | Value |
|---|---|
| **Sigma ID** | `0922467f-db53-4348-b7bf-dee8d0d348c6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548 |
| **Author** | Corissa Koopmans, '@corissalea' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_new_ca_policy_addedby_bad_actor.yml)**

> Monitor and alert on conditional access changes.

```sql
-- ============================================================
-- Title:        New CA Policy by Non-approved Actor
-- Sigma ID:     0922467f-db53-4348-b7bf-dee8d0d348c6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1548
-- Author:       Corissa Koopmans, '@corissalea'
-- Date:         2022-07-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_new_ca_policy_addedby_bad_actor.yml
-- Unmapped:     properties.message
-- False Pos:    Misconfigured role permissions; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Add conditional access policy'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Misconfigured role permissions; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure

---

## Account Created And Deleted Within A Close Time Frame

| Field | Value |
|---|---|
| **Sigma ID** | `6f583da0-3a90-4566-a4ed-83c09fe18bbf` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1', Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_account_created_deleted.yml)**

> Detects when an account was created and deleted in a short period of time.

```sql
-- ============================================================
-- Title:        Account Created And Deleted Within A Close Time Frame
-- Sigma ID:     6f583da0-3a90-4566-a4ed-83c09fe18bbf
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1', Tim Shelton
-- Date:         2022-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_account_created_deleted.yml
-- Unmapped:     properties.message, Status
-- False Pos:    Legit administrative action
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message
-- UNMAPPED_FIELD: Status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('Add user', 'Delete user')
    AND rawEventMsg = 'Success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legit administrative action

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#short-lived-accounts

---

## Bitlocker Key Retrieval

| Field | Value |
|---|---|
| **Sigma ID** | `a0413867-daf3-43dd-9245-734b3a787942` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Michael Epping, '@mepples21' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_bitlocker_key_retrieval.yml)**

> Monitor and alert for Bitlocker key retrieval.

```sql
-- ============================================================
-- Title:        Bitlocker Key Retrieval
-- Sigma ID:     a0413867-daf3-43dd-9245-734b3a787942
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Michael Epping, '@mepples21'
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_bitlocker_key_retrieval.yml
-- Unmapped:     Category, OperationName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'KeyManagement'
    AND rawEventMsg = 'Read BitLocker key')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#bitlocker-key-retrieval

---

## Certificate-Based Authentication Enabled

| Field | Value |
|---|---|
| **Sigma ID** | `c2496b41-16a9-4016-a776-b23f8910dc58` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | Harjot Shah Singh, '@cyb3rjy0t' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_certificate_based_authencation_enabled.yml)**

> Detects when certificate based authentication has been enabled in an Azure Active Directory tenant.

```sql
-- ============================================================
-- Title:        Certificate-Based Authentication Enabled
-- Sigma ID:     c2496b41-16a9-4016-a776-b23f8910dc58
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       Harjot Shah Singh, '@cyb3rjy0t'
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_certificate_based_authencation_enabled.yml
-- Unmapped:     OperationName, TargetResources.modifiedProperties
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: OperationName
-- UNMAPPED_FIELD: TargetResources.modifiedProperties

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Authentication Methods Policy Update'
    AND rawEventMsg LIKE '%AuthenticationMethodsPolicy%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f
- https://goodworkaround.com/2022/02/15/digging-into-azure-ad-certificate-based-authentication/

---

## Changes to Device Registration Policy

| Field | Value |
|---|---|
| **Sigma ID** | `9494bff8-959f-4440-bbce-fb87a208d517` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1484 |
| **Author** | Michael Epping, '@mepples21' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_device_registration_policy_changes.yml)**

> Monitor and alert for changes to the device registration policy.

```sql
-- ============================================================
-- Title:        Changes to Device Registration Policy
-- Sigma ID:     9494bff8-959f-4440-bbce-fb87a208d517
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1484
-- Author:       Michael Epping, '@mepples21'
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_device_registration_policy_changes.yml
-- Unmapped:     Category, ActivityDisplayName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: ActivityDisplayName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Policy'
    AND rawEventMsg = 'Set device registration policies')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#device-registrations-and-joins-outside-policy

---

## Guest Users Invited To Tenant By Non Approved Inviters

| Field | Value |
|---|---|
| **Sigma ID** | `4ad97bf5-a514-41a4-abd3-4f3455ad4865` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_guest_users_invited_to_tenant_by_non_approved_inviters.yml)**

> Detects guest users being invited to tenant by non-approved inviters

```sql
-- ============================================================
-- Title:        Guest Users Invited To Tenant By Non Approved Inviters
-- Sigma ID:     4ad97bf5-a514-41a4-abd3-4f3455ad4865
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_guest_users_invited_to_tenant_by_non_approved_inviters.yml
-- Unmapped:     Category, OperationName, InitiatedBy
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName
-- UNMAPPED_FIELD: InitiatedBy

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'UserManagement'
    AND rawEventMsg = 'Invite external user')
  AND NOT ((rawEventMsg LIKE '%<approved guest inviter use OR for multiple>%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts#monitoring-external-user-sign-ins

---

## New Root Certificate Authority Added

| Field | Value |
|---|---|
| **Sigma ID** | `4bb80281-3756-4ec8-a88e-523c5a6fda9e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | Harjot Shah Singh, '@cyb3rjy0t' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_new_root_ca_added.yml)**

> Detects newly added root certificate authority to an AzureAD tenant to support certificate based authentication.

```sql
-- ============================================================
-- Title:        New Root Certificate Authority Added
-- Sigma ID:     4bb80281-3756-4ec8-a88e-523c5a6fda9e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       Harjot Shah Singh, '@cyb3rjy0t'
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_new_root_ca_added.yml
-- Unmapped:     OperationName, TargetResources.modifiedProperties.newValue
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: OperationName
-- UNMAPPED_FIELD: TargetResources.modifiedProperties.newValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Set Company Information'
    AND rawEventMsg LIKE '%TrustedCAsForPasswordlessAuth%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f
- https://goodworkaround.com/2022/02/15/digging-into-azure-ad-certificate-based-authentication/

---

## Users Added to Global or Device Admin Roles

| Field | Value |
|---|---|
| **Sigma ID** | `11c767ae-500b-423b-bae3-b234450736ed` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Michael Epping, '@mepples21' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_users_added_to_device_admin_roles.yml)**

> Monitor and alert for users added to device admin roles.

```sql
-- ============================================================
-- Title:        Users Added to Global or Device Admin Roles
-- Sigma ID:     11c767ae-500b-423b-bae3-b234450736ed
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Michael Epping, '@mepples21'
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_users_added_to_device_admin_roles.yml
-- Unmapped:     Category, OperationName, TargetResources
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName
-- UNMAPPED_FIELD: TargetResources

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'RoleManagement'
    AND rawEventMsg LIKE '%Add%' AND rawEventMsg LIKE '%member to role%'
    AND (rawEventMsg LIKE '%7698a772-787b-4ac8-901f-60d6b08affd2%' OR rawEventMsg LIKE '%62e90394-69f5-4237-9190-012177145e10%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#device-administrator-roles

---

## Application AppID Uri Configuration Changes

| Field | Value |
|---|---|
| **Sigma ID** | `1b45b0d1-773f-4f23-aedc-814b759563b1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1552, T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_appid_uri_changes.yml)**

> Detects when a configuration change is made to an applications AppID URI.

```sql
-- ============================================================
-- Title:        Application AppID Uri Configuration Changes
-- Sigma ID:     1b45b0d1-773f-4f23-aedc-814b759563b1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1552, T1078.004
-- Author:       Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
-- Date:         2022-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_appid_uri_changes.yml
-- Unmapped:     properties.message
-- False Pos:    When and administrator is making legitimate AppID URI configuration changes to an application. This should be a planned event.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Update Application', 'Update Service principal')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When and administrator is making legitimate AppID URI configuration changes to an application. This should be a planned event.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#appid-uri-added-modified-or-removed

---

## Added Credentials to Existing Application

| Field | Value |
|---|---|
| **Sigma ID** | `cbb67ecc-fb70-4467-9350-c910bdf7c628` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.001 |
| **Author** | Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_credential_added.yml)**

> Detects when a new credential is added to an existing application. Any additional credentials added outside of expected processes could be a malicious actor using those credentials.

```sql
-- ============================================================
-- Title:        Added Credentials to Existing Application
-- Sigma ID:     cbb67ecc-fb70-4467-9350-c910bdf7c628
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098.001
-- Author:       Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
-- Date:         2022-05-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_credential_added.yml
-- Unmapped:     properties.message
-- False Pos:    When credentials are added/removed as part of the normal working hours/workflows
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Update application – Certificates and secrets management', 'Update Service principal/Update Application')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When credentials are added/removed as part of the normal working hours/workflows

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-credentials

---

## Delegated Permissions Granted For All Users

| Field | Value |
|---|---|
| **Sigma ID** | `a6355fbe-f36f-45d8-8efc-ab42465cbc52` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1528 |
| **Author** | Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_delegated_permissions_all_users.yml)**

> Detects when highly privileged delegated permissions are granted on behalf of all users

```sql
-- ============================================================
-- Title:        Delegated Permissions Granted For All Users
-- Sigma ID:     a6355fbe-f36f-45d8-8efc-ab42465cbc52
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1528
-- Author:       Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_delegated_permissions_all_users.yml
-- Unmapped:     properties.message
-- False Pos:    When the permission is legitimately needed for the app
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Add delegated permission grant'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When the permission is legitimately needed for the app

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-granted-highly-privileged-permissions

---

## End User Consent

| Field | Value |
|---|---|
| **Sigma ID** | `9b2cc4c4-2ad4-416d-8e8e-ee6aa6f5035a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1528 |
| **Author** | Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_end_user_consent.yml)**

> Detects when an end user consents to an application

```sql
-- ============================================================
-- Title:        End User Consent
-- Sigma ID:     9b2cc4c4-2ad4-416d-8e8e-ee6aa6f5035a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1528
-- Author:       Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_end_user_consent.yml
-- Unmapped:     ConsentContext.IsAdminConsent
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: ConsentContext.IsAdminConsent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'false'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#end-user-consent

---

## End User Consent Blocked

| Field | Value |
|---|---|
| **Sigma ID** | `7091372f-623c-4293-bc37-20c32b3492be` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1528 |
| **Author** | Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_end_user_consent_blocked.yml)**

> Detects when end user consent is blocked due to risk-based consent.

```sql
-- ============================================================
-- Title:        End User Consent Blocked
-- Sigma ID:     7091372f-623c-4293-bc37-20c32b3492be
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1528
-- Author:       Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
-- Date:         2022-07-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_end_user_consent_blocked.yml
-- Unmapped:     failure_status_reason
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: failure_status_reason

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Microsoft.online.Security.userConsentBlockedForRiskyAppsExceptions'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#end-user-stopped-due-to-risk-based-consent

---

## Added Owner To Application

| Field | Value |
|---|---|
| **Sigma ID** | `74298991-9fc4-460e-a92e-511aa60baec1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552 |
| **Author** | Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_owner_added.yml)**

> Detects when a new owner is added to an application. This gives that account privileges to make modifications and configuration changes to the application.

```sql
-- ============================================================
-- Title:        Added Owner To Application
-- Sigma ID:     74298991-9fc4-460e-a92e-511aa60baec1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552
-- Author:       Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
-- Date:         2022-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_owner_added.yml
-- Unmapped:     properties.message
-- False Pos:    When a new application owner is added by an administrator
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Add owner to application'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When a new application owner is added by an administrator

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#new-owner

---

## App Granted Microsoft Permissions

| Field | Value |
|---|---|
| **Sigma ID** | `c1d147ae-a951-48e5-8b41-dcd0170c7213` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1528 |
| **Author** | Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_permissions_msft.yml)**

> Detects when an application is granted delegated or app role permissions for Microsoft Graph, Exchange, Sharepoint, or Azure AD

```sql
-- ============================================================
-- Title:        App Granted Microsoft Permissions
-- Sigma ID:     c1d147ae-a951-48e5-8b41-dcd0170c7213
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1528
-- Author:       Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
-- Date:         2022-07-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_permissions_msft.yml
-- Unmapped:     properties.message
-- False Pos:    When the permission is legitimately needed for the app
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Add delegated permission grant', 'Add app role assignment to service principal')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When the permission is legitimately needed for the app

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-granted-highly-privileged-permissions

---

## App Granted Privileged Delegated Or App Permissions

| Field | Value |
|---|---|
| **Sigma ID** | `5aecf3d5-f8a0-48e7-99be-3a759df7358f` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.003 |
| **Author** | Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_privileged_permissions.yml)**

> Detects when administrator grants either application permissions (app roles) or highly privileged delegated permissions

```sql
-- ============================================================
-- Title:        App Granted Privileged Delegated Or App Permissions
-- Sigma ID:     5aecf3d5-f8a0-48e7-99be-3a759df7358f
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098.003
-- Author:       Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_privileged_permissions.yml
-- Unmapped:     properties.message
-- False Pos:    When the permission is legitimately needed for the app
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Add app role assignment to service principal'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When the permission is legitimately needed for the app

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-granted-highly-privileged-permissions

---

## App Assigned To Azure RBAC/Microsoft Entra Role

| Field | Value |
|---|---|
| **Sigma ID** | `b04934b2-0a68-4845-8a19-bdfed3a68a7a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.003 |
| **Author** | Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_role_added.yml)**

> Detects when an app is assigned Azure AD roles, such as global administrator, or Azure RBAC roles, such as subscription owner.

```sql
-- ============================================================
-- Title:        App Assigned To Azure RBAC/Microsoft Entra Role
-- Sigma ID:     b04934b2-0a68-4845-8a19-bdfed3a68a7a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098.003
-- Author:       Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
-- Date:         2022-07-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_role_added.yml
-- Unmapped:     targetResources.type, properties.message
-- False Pos:    When the permission is legitimately needed for the app
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: targetResources.type
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Service Principal'
    AND rawEventMsg IN ('Add member to role', 'Add eligible member to role', 'Add scoped member to role'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When the permission is legitimately needed for the app

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#service-principal-assigned-to-a-role

---

## Application URI Configuration Changes

| Field | Value |
|---|---|
| **Sigma ID** | `0055ad1f-be85-4798-83cf-a6da17c993b3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1528, T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_uri_modifications.yml)**

> Detects when a configuration change is made to an applications URI.
URIs for domain names that no longer exist (dangling URIs), not using HTTPS, wildcards at the end of the domain, URIs that are no unique to that app, or URIs that point to domains you do not control should be investigated.


```sql
-- ============================================================
-- Title:        Application URI Configuration Changes
-- Sigma ID:     0055ad1f-be85-4798-83cf-a6da17c993b3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1528, T1078.004
-- Author:       Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
-- Date:         2022-06-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_app_uri_modifications.yml
-- Unmapped:     properties.message
-- False Pos:    When and administrator is making legitimate URI configuration changes to an application. This should be a planned event.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Update Application Sucess- Property Name AppAddress'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When and administrator is making legitimate URI configuration changes to an application. This should be a planned event.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-configuration-changes

---

## Windows LAPS Credential Dump From Entra ID

| Field | Value |
|---|---|
| **Sigma ID** | `a4b25073-8947-489c-a8dd-93b41c23f26d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.005 |
| **Author** | andrewdanis |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_auditlogs_laps_credential_dumping.yml)**

> Detects when an account dumps the LAPS password from Entra ID.

```sql
-- ============================================================
-- Title:        Windows LAPS Credential Dump From Entra ID
-- Sigma ID:     a4b25073-8947-489c-a8dd-93b41c23f26d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098.005
-- Author:       andrewdanis
-- Date:         2024-06-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_auditlogs_laps_credential_dumping.yml
-- Unmapped:     category, activityType, additionalDetails.additionalInfo
-- False Pos:    Approved activity performed by an Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: category
-- UNMAPPED_FIELD: activityType
-- UNMAPPED_FIELD: additionalDetails.additionalInfo

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Device'
    AND rawEventMsg LIKE '%Recover device local administrator password%'
    AND rawEventMsg LIKE '%Successfully recovered local credential by device id%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Approved activity performed by an Administrator.

**References:**
- https://twitter.com/NathanMcNulty/status/1785051227568632263
- https://www.cloudcoffee.ch/microsoft-365/configure-windows-laps-in-microsoft-intune/
- https://techcommunity.microsoft.com/t5/microsoft-entra-blog/introducing-windows-local-administrator-password-solution-with/ba-p/1942487

---

## Change to Authentication Method

| Field | Value |
|---|---|
| **Sigma ID** | `4d78a000-ab52-4564-88a5-7ab5242b20c7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556, T1098 |
| **Author** | AlertIQ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_change_to_authentication_method.yml)**

> Change to authentication method could be an indicator of an attacker adding an auth method to the account so they can have continued access.

```sql
-- ============================================================
-- Title:        Change to Authentication Method
-- Sigma ID:     4d78a000-ab52-4564-88a5-7ab5242b20c7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1556, T1098
-- Author:       AlertIQ
-- Date:         2021-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_change_to_authentication_method.yml
-- Unmapped:     LoggedByService, Category, OperationName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: LoggedByService
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Authentication Methods'
    AND rawEventMsg = 'UserManagement'
    AND rawEventMsg = 'User registered security info')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---

## Azure Domain Federation Settings Modified

| Field | Value |
|---|---|
| **Sigma ID** | `352a54e1-74ba-4929-9d47-8193d67aba1e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_federation_modified.yml)**

> Identifies when an user or application modified the federation settings on the domain.

```sql
-- ============================================================
-- Title:        Azure Domain Federation Settings Modified
-- Sigma ID:     352a54e1-74ba-4929-9d47-8193d67aba1e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Austin Songer
-- Date:         2021-09-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_federation_modified.yml
-- Unmapped:     ActivityDisplayName
-- False Pos:    Federation Settings being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Federation Settings modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: ActivityDisplayName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Set federation settings on domain'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Federation Settings being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Federation Settings modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-monitor-federation-changes

---

## User Added To Group With CA Policy Modification Access

| Field | Value |
|---|---|
| **Sigma ID** | `91c95675-1f27-46d0-bead-d1ae96b97cd3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548, T1556 |
| **Author** | Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml)**

> Monitor and alert on group membership additions of groups that have CA policy modification access

```sql
-- ============================================================
-- Title:        User Added To Group With CA Policy Modification Access
-- Sigma ID:     91c95675-1f27-46d0-bead-d1ae96b97cd3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1548, T1556
-- Author:       Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner'
-- Date:         2022-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml
-- Unmapped:     properties.message
-- False Pos:    User removed from the group is approved
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Add member from group'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User removed from the group is approved

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access

---

## User Removed From Group With CA Policy Modification Access

| Field | Value |
|---|---|
| **Sigma ID** | `665e2d43-70dc-4ccc-9d27-026c9dd7ed9c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1548, T1556 |
| **Author** | Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_group_user_removal_ca_modification.yml)**

> Monitor and alert on group membership removal of groups that have CA policy modification access

```sql
-- ============================================================
-- Title:        User Removed From Group With CA Policy Modification Access
-- Sigma ID:     665e2d43-70dc-4ccc-9d27-026c9dd7ed9c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1548, T1556
-- Author:       Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner'
-- Date:         2022-08-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_group_user_removal_ca_modification.yml
-- Unmapped:     properties.message
-- False Pos:    User removed from the group is approved
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Remove member from group'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User removed from the group is approved

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access

---

## Guest User Invited By Non Approved Inviters

| Field | Value |
|---|---|
| **Sigma ID** | `0b4b72e3-4c53-4d5b-b198-2c58cfef39a9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_guest_invite_failure.yml)**

> Detects when a user that doesn't have permissions to invite a guest user attempts to invite one.

```sql
-- ============================================================
-- Title:        Guest User Invited By Non Approved Inviters
-- Sigma ID:     0b4b72e3-4c53-4d5b-b198-2c58cfef39a9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_guest_invite_failure.yml
-- Unmapped:     properties.message, Status
-- False Pos:    A non malicious user is unaware of the proper process
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message
-- UNMAPPED_FIELD: Status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Invite external user'
    AND rawEventMsg = 'failure')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A non malicious user is unaware of the proper process

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#things-to-monitor

---

## User State Changed From Guest To Member

| Field | Value |
|---|---|
| **Sigma ID** | `8dee7a0d-43fd-4b3c-8cd1-605e189d195e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_guest_to_member.yml)**

> Detects the change of user type from "Guest" to "Member" for potential elevation of privilege.

```sql
-- ============================================================
-- Title:        User State Changed From Guest To Member
-- Sigma ID:     8dee7a0d-43fd-4b3c-8cd1-605e189d195e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-06-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_guest_to_member.yml
-- Unmapped:     Category, OperationName, properties.message
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'UserManagement'
    AND rawEventMsg = 'Update user'
    AND rawEventMsg = '"displayName":"UserType","oldValue":"[\"Guest\"]","newValue":"[\"Member\"]"')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts#monitoring-external-user-sign-ins

---

## PIM Approvals And Deny Elevation

| Field | Value |
|---|---|
| **Sigma ID** | `039a7469-0296-4450-84c0-f6966b16dc6d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_activation_approve_deny.yml)**

> Detects when a PIM elevation is approved or denied. Outside of normal operations should be investigated.

```sql
-- ============================================================
-- Title:        PIM Approvals And Deny Elevation
-- Sigma ID:     039a7469-0296-4450-84c0-f6966b16dc6d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_activation_approve_deny.yml
-- Unmapped:     properties.message
-- False Pos:    Actual admin using PIM.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Request Approved/Denied'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Actual admin using PIM.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment

---

## PIM Alert Setting Changes To Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `aeaef14c-e5bf-4690-a9c8-835caad458bd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_alerts_disabled.yml)**

> Detects when PIM alerts are set to disabled.

```sql
-- ============================================================
-- Title:        PIM Alert Setting Changes To Disabled
-- Sigma ID:     aeaef14c-e5bf-4690-a9c8-835caad458bd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_alerts_disabled.yml
-- Unmapped:     properties.message
-- False Pos:    Administrator disabling PIM alerts as an active choice.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Disable PIM Alert'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator disabling PIM alerts as an active choice.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment

---

## Changes To PIM Settings

| Field | Value |
|---|---|
| **Sigma ID** | `db6c06c4-bf3b-421c-aa88-15672b88c743` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_change_settings.yml)**

> Detects when changes are made to PIM roles

```sql
-- ============================================================
-- Title:        Changes To PIM Settings
-- Sigma ID:     db6c06c4-bf3b-421c-aa88-15672b88c743
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_change_settings.yml
-- Unmapped:     properties.message
-- False Pos:    Legit administrative PIM setting configuration changes
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Update role setting in PIM'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legit administrative PIM setting configuration changes

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment

---

## User Added To Privilege Role

| Field | Value |
|---|---|
| **Sigma ID** | `49a268a4-72f4-4e38-8a7b-885be690c5b5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_priviledged_role_assignment_add.yml)**

> Detects when a user is added to a privileged role.

```sql
-- ============================================================
-- Title:        User Added To Privilege Role
-- Sigma ID:     49a268a4-72f4-4e38-8a7b-885be690c5b5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_priviledged_role_assignment_add.yml
-- Unmapped:     properties.message
-- False Pos:    Legtimate administrator actions of adding members from a role
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Add eligible member (permanent)', 'Add eligible member (eligible)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legtimate administrator actions of adding members from a role

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment

---

## Bulk Deletion Changes To Privileged Account Permissions

| Field | Value |
|---|---|
| **Sigma ID** | `102e11e3-2db5-4c9e-bc26-357d42585d21` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_priviledged_role_assignment_bulk_change.yml)**

> Detects when a user is removed from a privileged role. Bulk changes should be investigated.

```sql
-- ============================================================
-- Title:        Bulk Deletion Changes To Privileged Account Permissions
-- Sigma ID:     102e11e3-2db5-4c9e-bc26-357d42585d21
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_priviledged_role_assignment_bulk_change.yml
-- Unmapped:     properties.message
-- False Pos:    Legtimate administrator actions of removing members from a role
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Remove eligible member (permanent)', 'Remove eligible member (eligible)')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legtimate administrator actions of removing members from a role

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment

---

## Privileged Account Creation

| Field | Value |
|---|---|
| **Sigma ID** | `f7b5b004-dece-46e4-a4a5-f6fd0e1c6947` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H', Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml)**

> Detects when a new admin is created.

```sql
-- ============================================================
-- Title:        Privileged Account Creation
-- Sigma ID:     f7b5b004-dece-46e4-a4a5-f6fd0e1c6947
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H', Tim Shelton
-- Date:         2022-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml
-- Unmapped:     properties.message, Status
-- False Pos:    A legitimate new admin account being created
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message
-- UNMAPPED_FIELD: Status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Add user%' AND rawEventMsg LIKE '%Add member to role%'
    AND rawEventMsg = 'Success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A legitimate new admin account being created

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#changes-to-privileged-accounts

---

## Azure Subscription Permission Elevation Via AuditLogs

| Field | Value |
|---|---|
| **Sigma ID** | `ca9bf243-465e-494a-9e54-bf9fc239057d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_subscription_permissions_elevation_via_auditlogs.yml)**

> Detects when a user has been elevated to manage all Azure Subscriptions.
This change should be investigated immediately if it isn't planned.
This setting could allow an attacker access to Azure subscriptions in your environment.


```sql
-- ============================================================
-- Title:        Azure Subscription Permission Elevation Via AuditLogs
-- Sigma ID:     ca9bf243-465e-494a-9e54-bf9fc239057d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_subscription_permissions_elevation_via_auditlogs.yml
-- Unmapped:     Category, OperationName
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Administrative'
    AND rawEventMsg = 'Assigns the caller to user access admin')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#assignment-and-elevation

---

## Temporary Access Pass Added To An Account

| Field | Value |
|---|---|
| **Sigma ID** | `fa84aaf5-8142-43cd-9ec2-78cfebf878ce` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_tap_added.yml)**

> Detects when a temporary access pass (TAP) is added to an account. TAPs added to priv accounts should be investigated

```sql
-- ============================================================
-- Title:        Temporary Access Pass Added To An Account
-- Sigma ID:     fa84aaf5-8142-43cd-9ec2-78cfebf878ce
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
-- Date:         2022-08-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_tap_added.yml
-- Unmapped:     properties.message, Status
-- False Pos:    Administrator adding a legitimate temporary access pass
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: properties.message
-- UNMAPPED_FIELD: Status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Admin registered security info'
    AND rawEventMsg = 'Admin registered temporary access pass method for user')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator adding a legitimate temporary access pass

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#changes-to-privileged-accounts

---

## User Risk and MFA Registration Policy Updated

| Field | Value |
|---|---|
| **Sigma ID** | `d4c7758e-9417-4f2e-9109-6125d66dabef` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **Author** | Harjot Singh (@cyb3rjy0t) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_update_risk_and_mfa_registration_policy.yml)**

> Detects changes and updates to the user risk and MFA registration policy.
Attackers can modified the policies to Bypass MFA, weaken security thresholds, facilitate further attacks, maintain persistence.


```sql
-- ============================================================
-- Title:        User Risk and MFA Registration Policy Updated
-- Sigma ID:     d4c7758e-9417-4f2e-9109-6125d66dabef
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence
-- Author:       Harjot Singh (@cyb3rjy0t)
-- Date:         2024-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_update_risk_and_mfa_registration_policy.yml
-- Unmapped:     LoggedByService, Category, OperationName
-- False Pos:    Known updates by administrators.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: LoggedByService
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'AAD Management UX'
    AND rawEventMsg = 'Policy'
    AND rawEventMsg = 'Update User Risk and MFA Registration Policy')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Known updates by administrators.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-mfa-policy
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities

---

## Multi Factor Authentication Disabled For User Account

| Field | Value |
|---|---|
| **Sigma ID** | `b18454c8-0be3-41f7-86bc-9c614611b839` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Harjot Singh (@cyb3rjy0t) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_user_account_mfa_disable.yml)**

> Detects changes to the "StrongAuthenticationRequirement" value, where the state is set to "0" or "Disabled".
Threat actors were seen disabling multi factor authentication for users in order to maintain or achieve access to the account. Also see in SIM Swap attacks.


```sql
-- ============================================================
-- Title:        Multi Factor Authentication Disabled For User Account
-- Sigma ID:     b18454c8-0be3-41f7-86bc-9c614611b839
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence
-- Author:       Harjot Singh (@cyb3rjy0t)
-- Date:         2024-08-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_user_account_mfa_disable.yml
-- Unmapped:     LoggedByService, Category, OperationName, TargetResources.ModifiedProperties.DisplayName, TargetResources.ModifiedProperties.NewValue
-- False Pos:    Legitimate authorized activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: LoggedByService
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: OperationName
-- UNMAPPED_FIELD: TargetResources.ModifiedProperties.DisplayName
-- UNMAPPED_FIELD: TargetResources.ModifiedProperties.NewValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Core Directory'
    AND rawEventMsg = 'UserManagement'
    AND rawEventMsg = 'Update user'
    AND rawEventMsg = 'StrongAuthenticationRequirement'
    AND rawEventMsg LIKE '%State":0%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate authorized activity.

**References:**
- https://www.sans.org/blog/defending-against-scattered-spider-and-the-com-with-cybercrime-intelligence/

---

## Password Reset By User Account

| Field | Value |
|---|---|
| **Sigma ID** | `340ee172-4b67-4fb4-832f-f961bdc1f3aa` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | YochanaHenderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_user_password_change.yml)**

> Detect when a user has reset their password in Azure AD

```sql
-- ============================================================
-- Title:        Password Reset By User Account
-- Sigma ID:     340ee172-4b67-4fb4-832f-f961bdc1f3aa
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       YochanaHenderson, '@Yochana-H'
-- Date:         2022-08-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_user_password_change.yml
-- Unmapped:     Category, Status, Initiatedby, Target, ActivityType
-- False Pos:    If this was approved by System Administrator or confirmed user action.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/auditlogs
-- UNMAPPED_FIELD: Category
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: Initiatedby
-- UNMAPPED_FIELD: Target
-- UNMAPPED_FIELD: ActivityType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'UserManagement'
    AND rawEventMsg = 'Success'
    AND rawEventMsg = 'UPN')
  AND (rawEventMsg LIKE '%UPN%'
    AND rawEventMsg LIKE '%Password reset%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator or confirmed user action.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---
