# Sigma → FortiSIEM: Azure Signinlogs

> 24 rules · Generated 2026-03-17

## Table of Contents

- [Account Lockout](#account-lockout)
- [Increased Failed Authentications Of Any Type](#increased-failed-authentications-of-any-type)
- [Measurable Increase Of Successful Authentications](#measurable-increase-of-successful-authentications)
- [Authentications To Important Apps Using Single Factor Authentication](#authentications-to-important-apps-using-single-factor-authentication)
- [Successful Authentications From Countries You Do Not Operate Out Of](#successful-authentications-from-countries-you-do-not-operate-out-of)
- [Discovery Using AzureHound](#discovery-using-azurehound)
- [Device Registration or Join Without MFA](#device-registration-or-join-without-mfa)
- [Failed Authentications From Countries You Do Not Operate Out Of](#failed-authentications-from-countries-you-do-not-operate-out-of)
- [Azure AD Only Single Factor Authentication Required](#azure-ad-only-single-factor-authentication-required)
- [Suspicious SignIns From A Non Registered Device](#suspicious-signins-from-a-non-registered-device)
- [Sign-ins from Non-Compliant Devices](#sign-ins-from-non-compliant-devices)
- [Sign-ins by Unknown Devices](#sign-ins-by-unknown-devices)
- [Potential MFA Bypass Using Legacy Client Authentication](#potential-mfa-bypass-using-legacy-client-authentication)
- [Application Using Device Code Authentication Flow](#application-using-device-code-authentication-flow)
- [Applications That Are Using ROPC Authentication Flow](#applications-that-are-using-ropc-authentication-flow)
- [Account Disabled or Blocked for Sign in Attempts](#account-disabled-or-blocked-for-sign-in-attempts)
- [Sign-in Failure Due to Conditional Access Requirements Not Met](#sign-in-failure-due-to-conditional-access-requirements-not-met)
- [Use of Legacy Authentication Protocols](#use-of-legacy-authentication-protocols)
- [Login to Disabled Account](#login-to-disabled-account)
- [Multifactor Authentication Denied](#multifactor-authentication-denied)
- [Multifactor Authentication Interrupted](#multifactor-authentication-interrupted)
- [Azure Unusual Authentication Interruption](#azure-unusual-authentication-interruption)
- [User Access Blocked by Azure Conditional Access](#user-access-blocked-by-azure-conditional-access)
- [Users Authenticating To Other Azure AD Tenants](#users-authenticating-to-other-azure-ad-tenants)

## Account Lockout

| Field | Value |
|---|---|
| **Sigma ID** | `2b7d6fc0-71ac-4cf7-8ed1-b5788ee5257a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1110 |
| **Author** | AlertIQ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_account_lockout.yml)**

> Identifies user account which has been locked because the user tried to sign in too many times with an incorrect user ID or password.

```sql
-- ============================================================
-- Title:        Account Lockout
-- Sigma ID:     2b7d6fc0-71ac-4cf7-8ed1-b5788ee5257a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1110
-- Author:       AlertIQ
-- Date:         2021-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_account_lockout.yml
-- Unmapped:     ResultType
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '50053'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---

## Increased Failed Authentications Of Any Type

| Field | Value |
|---|---|
| **Sigma ID** | `e1d02b53-c03c-4948-b11d-4d00cca49d03` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_auth_failure_increase.yml)**

> Detects when sign-ins increased by 10% or greater.

```sql
-- ============================================================
-- Title:        Increased Failed Authentications Of Any Type
-- Sigma ID:     e1d02b53-c03c-4948-b11d-4d00cca49d03
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1'
-- Date:         2022-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_auth_failure_increase.yml
-- Unmapped:     Status, Count
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: Count

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'failure'
    AND rawEventMsg = '<10%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins

---

## Measurable Increase Of Successful Authentications

| Field | Value |
|---|---|
| **Sigma ID** | `67d5f8fc-8325-44e4-8f5f-7c0ac07cb5ae` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1', Tim Shelton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_auth_sucess_increase.yml)**

> Detects when successful sign-ins increased by 10% or greater.

```sql
-- ============================================================
-- Title:        Measurable Increase Of Successful Authentications
-- Sigma ID:     67d5f8fc-8325-44e4-8f5f-7c0ac07cb5ae
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1', Tim Shelton
-- Date:         2022-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_auth_sucess_increase.yml
-- Unmapped:     Status, Count
-- False Pos:    Increase of users in the environment
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: Count

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Success'
    AND rawEventMsg = '<10%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Increase of users in the environment

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#monitoring-for-successful-unusual-sign-ins

---

## Authentications To Important Apps Using Single Factor Authentication

| Field | Value |
|---|---|
| **Sigma ID** | `f272fb46-25f2-422c-b667-45837994980f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_auth_to_important_apps_using_single_factor_auth.yml)**

> Detect when authentications to important application(s) only required single-factor authentication

```sql
-- ============================================================
-- Title:        Authentications To Important Apps Using Single Factor Authentication
-- Sigma ID:     f272fb46-25f2-422c-b667-45837994980f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_auth_to_important_apps_using_single_factor_auth.yml
-- Unmapped:     Status, AppId, AuthenticationRequirement
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: AppId
-- UNMAPPED_FIELD: AuthenticationRequirement

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Success'
    AND (rawEventMsg = 'Insert Application ID use OR for multiple')
    AND rawEventMsg = 'singleFactorAuthentication')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts

---

## Successful Authentications From Countries You Do Not Operate Out Of

| Field | Value |
|---|---|
| **Sigma ID** | `8c944ecb-6970-4541-8496-be554b8e2846` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_authentications_from_countries_you_do_not_operate_out_of.yml)**

> Detect successful authentications from countries you do not operate out of.

```sql
-- ============================================================
-- Title:        Successful Authentications From Countries You Do Not Operate Out Of
-- Sigma ID:     8c944ecb-6970-4541-8496-be554b8e2846
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_authentications_from_countries_you_do_not_operate_out_of.yml
-- Unmapped:     Status, Location
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: Location

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Success'
  AND NOT ((rawEventMsg LIKE '%<Countries you DO operate out of e,g GB, use OR for multiple>%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts

---

## Discovery Using AzureHound

| Field | Value |
|---|---|
| **Sigma ID** | `35b781cc-1a08-4a5a-80af-42fd7c315c6b` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.004, T1526 |
| **Author** | Janantha Marasinghe |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_azurehound_discovery.yml)**

> Detects AzureHound (A BloodHound data collector for Microsoft Azure) activity via the default User-Agent that is used during its operation after successful authentication.

```sql
-- ============================================================
-- Title:        Discovery Using AzureHound
-- Sigma ID:     35b781cc-1a08-4a5a-80af-42fd7c315c6b
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1087.004, T1526
-- Author:       Janantha Marasinghe
-- Date:         2022-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_azurehound_discovery.yml
-- Unmapped:     userAgent, ResultType
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: userAgent
-- UNMAPPED_FIELD: ResultType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%azurehound%'
    AND rawEventMsg = '0')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/BloodHoundAD/AzureHound

---

## Device Registration or Join Without MFA

| Field | Value |
|---|---|
| **Sigma ID** | `5afa454e-030c-4ab4-9253-a90aa7fcc581` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Michael Epping, '@mepples21' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_device_registration_or_join_without_mfa.yml)**

> Monitor and alert for device registration or join events where MFA was not performed.

```sql
-- ============================================================
-- Title:        Device Registration or Join Without MFA
-- Sigma ID:     5afa454e-030c-4ab4-9253-a90aa7fcc581
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Michael Epping, '@mepples21'
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_device_registration_or_join_without_mfa.yml
-- Unmapped:     ResourceDisplayName, conditionalAccessStatus, AuthenticationRequirement
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResourceDisplayName
-- UNMAPPED_FIELD: conditionalAccessStatus
-- UNMAPPED_FIELD: AuthenticationRequirement

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'Device Registration Service'
    AND rawEventMsg = 'success')
  AND NOT (rawEventMsg = 'multiFactorAuthentication'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#device-registrations-and-joins-outside-policy

---

## Failed Authentications From Countries You Do Not Operate Out Of

| Field | Value |
|---|---|
| **Sigma ID** | `28870ae4-6a13-4616-bd1a-235a7fad7458` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_failed_auth_from_countries_you_do_not_operate_out_of.yml)**

> Detect failed authentications from countries you do not operate out of.

```sql
-- ============================================================
-- Title:        Failed Authentications From Countries You Do Not Operate Out Of
-- Sigma ID:     28870ae4-6a13-4616-bd1a-235a7fad7458
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-07-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_failed_auth_from_countries_you_do_not_operate_out_of.yml
-- Unmapped:     Status, Location
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: Location

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (NOT (rawEventMsg = 'Success')
  AND NOT ((rawEventMsg LIKE '%<Countries you DO operate out of e,g GB, use OR for multiple>%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts

---

## Azure AD Only Single Factor Authentication Required

| Field | Value |
|---|---|
| **Sigma ID** | `28eea407-28d7-4e42-b0be-575d5ba60b2c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1556.006 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_only_single_factor_auth_required.yml)**

> Detect when users are authenticating without MFA being required.

```sql
-- ============================================================
-- Title:        Azure AD Only Single Factor Authentication Required
-- Sigma ID:     28eea407-28d7-4e42-b0be-575d5ba60b2c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078.004, T1556.006
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-07-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_only_single_factor_auth_required.yml
-- Unmapped:     Status, AuthenticationRequirement
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: AuthenticationRequirement

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Success'
    AND rawEventMsg = 'singleFactorAuthentication')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts

---

## Suspicious SignIns From A Non Registered Device

| Field | Value |
|---|---|
| **Sigma ID** | `572b12d4-9062-11ed-a1eb-0242ac120002` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Harjot Singh, '@cyb3rjy0t' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_risky_sign_ins_with_singlefactorauth_from_unknown_devices.yml)**

> Detects risky authentication from a non AD registered device without MFA being required.

```sql
-- ============================================================
-- Title:        Suspicious SignIns From A Non Registered Device
-- Sigma ID:     572b12d4-9062-11ed-a1eb-0242ac120002
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Harjot Singh, '@cyb3rjy0t'
-- Date:         2023-01-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_risky_sign_ins_with_singlefactorauth_from_unknown_devices.yml
-- Unmapped:     Status, AuthenticationRequirement, RiskState
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: AuthenticationRequirement
-- UNMAPPED_FIELD: RiskState

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Success'
    AND rawEventMsg = 'singleFactorAuthentication'
    AND rawEventMsg = 'atRisk')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#non-compliant-device-sign-in

---

## Sign-ins from Non-Compliant Devices

| Field | Value |
|---|---|
| **Sigma ID** | `4f77e1d7-3982-4ee0-8489-abf2d6b75284` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Michael Epping, '@mepples21' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_sign_ins_from_noncompliant_devices.yml)**

> Monitor and alert for sign-ins where the device was non-compliant.

```sql
-- ============================================================
-- Title:        Sign-ins from Non-Compliant Devices
-- Sigma ID:     4f77e1d7-3982-4ee0-8489-abf2d6b75284
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Michael Epping, '@mepples21'
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_sign_ins_from_noncompliant_devices.yml
-- Unmapped:     DeviceDetail.isCompliant
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: DeviceDetail.isCompliant

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
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#non-compliant-device-sign-in

---

## Sign-ins by Unknown Devices

| Field | Value |
|---|---|
| **Sigma ID** | `4d136857-6a1a-432a-82fc-5dd497ee5e7c` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Michael Epping, '@mepples21' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_sign_ins_from_unknown_devices.yml)**

> Monitor and alert for Sign-ins by unknown devices from non-Trusted locations.

```sql
-- ============================================================
-- Title:        Sign-ins by Unknown Devices
-- Sigma ID:     4d136857-6a1a-432a-82fc-5dd497ee5e7c
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Michael Epping, '@mepples21'
-- Date:         2022-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_sign_ins_from_unknown_devices.yml
-- Unmapped:     AuthenticationRequirement, ResultType, NetworkLocationDetails, DeviceDetail.deviceId
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: AuthenticationRequirement
-- UNMAPPED_FIELD: ResultType
-- UNMAPPED_FIELD: NetworkLocationDetails
-- UNMAPPED_FIELD: DeviceDetail.deviceId

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'singleFactorAuthentication'
    AND rawEventMsg = '0'
    AND rawEventMsg = '[]'
    AND rawEventMsg = '')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#non-compliant-device-sign-in

---

## Potential MFA Bypass Using Legacy Client Authentication

| Field | Value |
|---|---|
| **Sigma ID** | `53bb4f7f-48a8-4475-ac30-5a82ddfdf6fc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110 |
| **Author** | Harjot Singh, '@cyb3rjy0t' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_suspicious_signin_bypassing_mfa.yml)**

> Detects successful authentication from potential clients using legacy authentication via user agent strings. This could be a sign of MFA bypass using a password spray attack.

```sql
-- ============================================================
-- Title:        Potential MFA Bypass Using Legacy Client Authentication
-- Sigma ID:     53bb4f7f-48a8-4475-ac30-5a82ddfdf6fc
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110
-- Author:       Harjot Singh, '@cyb3rjy0t'
-- Date:         2023-03-20
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_ad_suspicious_signin_bypassing_mfa.yml
-- Unmapped:     Status, userAgent
-- False Pos:    Known Legacy Accounts
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: userAgent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Success'
    AND (rawEventMsg LIKE '%BAV2ROPC%' OR rawEventMsg LIKE '%CBAinPROD%' OR rawEventMsg LIKE '%CBAinTAR%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Known Legacy Accounts

**References:**
- https://web.archive.org/web/20230217071802/https://blooteem.com/march-2022
- https://www.microsoft.com/en-us/security/blog/2021/10/26/protect-your-business-from-password-sprays-with-microsoft-dart-recommendations/

---

## Application Using Device Code Authentication Flow

| Field | Value |
|---|---|
| **Sigma ID** | `248649b7-d64f-46f0-9fb2-a52774166fb5` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_app_device_code_authentication.yml)**

> Device code flow is an OAuth 2.0 protocol flow specifically for input constrained devices and is not used in all environments.
If this type of flow is seen in the environment and not being used in an input constrained device scenario, further investigation is warranted.
This can be a misconfigured application or potentially something malicious.


```sql
-- ============================================================
-- Title:        Application Using Device Code Authentication Flow
-- Sigma ID:     248649b7-d64f-46f0-9fb2-a52774166fb5
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
-- Date:         2022-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_app_device_code_authentication.yml
-- Unmapped:     properties.message
-- False Pos:    Applications that are input constrained will need to use device code flow and are valid authentications.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
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
  AND rawEventMsg = 'Device Code'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Applications that are input constrained will need to use device code flow and are valid authentications.

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-authentication-flows

---

## Applications That Are Using ROPC Authentication Flow

| Field | Value |
|---|---|
| **Sigma ID** | `55695bc0-c8cf-461f-a379-2535f563c854` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_app_ropc_authentication.yml)**

> Resource owner password credentials (ROPC) should be avoided if at all possible as this requires the user to expose their current password credentials to the application directly.
The application then uses those credentials to authenticate the user against the identity provider.


```sql
-- ============================================================
-- Title:        Applications That Are Using ROPC Authentication Flow
-- Sigma ID:     55695bc0-c8cf-461f-a379-2535f563c854
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
-- Date:         2022-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_app_ropc_authentication.yml
-- Unmapped:     properties.message
-- False Pos:    Applications that are being used as part of automated testing or a legacy application that cannot use any other modern authentication flow
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
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
  AND rawEventMsg = 'ROPC'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Applications that are being used as part of automated testing or a legacy application that cannot use any other modern authentication flow

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#application-authentication-flows

---

## Account Disabled or Blocked for Sign in Attempts

| Field | Value |
|---|---|
| **Sigma ID** | `4afac85c-224a-4dd7-b1af-8da40e1c60bd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_blocked_account_attempt.yml)**

> Detects when an account is disabled or blocked for sign in but tried to log in

```sql
-- ============================================================
-- Title:        Account Disabled or Blocked for Sign in Attempts
-- Sigma ID:     4afac85c-224a-4dd7-b1af-8da40e1c60bd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Yochana Henderson, '@Yochana-H'
-- Date:         2022-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_blocked_account_attempt.yml
-- Unmapped:     ResultType, ResultDescription
-- False Pos:    Account disabled or blocked in error; Automation account has been blocked or disabled
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType
-- UNMAPPED_FIELD: ResultDescription

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = '50057'
    AND rawEventMsg = 'Failure')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Account disabled or blocked in error; Automation account has been blocked or disabled

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-privileged-accounts

---

## Sign-in Failure Due to Conditional Access Requirements Not Met

| Field | Value |
|---|---|
| **Sigma ID** | `b4a6d707-9430-4f5f-af68-0337f52d5c42` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1110, T1078.004 |
| **Author** | Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_conditional_access_failure.yml)**

> Define a baseline threshold for failed sign-ins due to Conditional Access failures

```sql
-- ============================================================
-- Title:        Sign-in Failure Due to Conditional Access Requirements Not Met
-- Sigma ID:     b4a6d707-9430-4f5f-af68-0337f52d5c42
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1110, T1078.004
-- Author:       Yochana Henderson, '@Yochana-H'
-- Date:         2022-06-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_conditional_access_failure.yml
-- Unmapped:     ResultType, Resultdescription
-- False Pos:    Service Account misconfigured; Misconfigured Systems; Vulnerability Scanners
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType
-- UNMAPPED_FIELD: Resultdescription

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = '53003'
    AND rawEventMsg = 'Blocked by Conditional Access')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service Account misconfigured; Misconfigured Systems; Vulnerability Scanners

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-privileged-accounts

---

## Use of Legacy Authentication Protocols

| Field | Value |
|---|---|
| **Sigma ID** | `60f6535a-760f-42a9-be3f-c9a0a025906e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110 |
| **Author** | Yochana Henderson, '@Yochana-H' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_legacy_authentication_protocols.yml)**

> Alert on when legacy authentication has been used on an account

```sql
-- ============================================================
-- Title:        Use of Legacy Authentication Protocols
-- Sigma ID:     60f6535a-760f-42a9-be3f-c9a0a025906e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110
-- Author:       Yochana Henderson, '@Yochana-H'
-- Date:         2022-06-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_legacy_authentication_protocols.yml
-- Unmapped:     ActivityDetails, ClientApp, Username
-- False Pos:    User has been put in acception group so they can use legacy authentication
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ActivityDetails
-- UNMAPPED_FIELD: ClientApp
-- UNMAPPED_FIELD: Username

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Sign-ins'
    AND rawEventMsg IN ('Other client', 'IMAP', 'POP3', 'MAPI', 'SMTP', 'Exchange ActiveSync', 'Exchange Web Services')
    AND rawEventMsg = 'UPN')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User has been put in acception group so they can use legacy authentication

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-privileged-accounts

---

## Login to Disabled Account

| Field | Value |
|---|---|
| **Sigma ID** | `908655e0-25cf-4ae1-b775-1c8ce9cf43d8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | AlertIQ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml)**

> Detect failed attempts to sign in to disabled accounts.

```sql
-- ============================================================
-- Title:        Login to Disabled Account
-- Sigma ID:     908655e0-25cf-4ae1-b775-1c8ce9cf43d8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       AlertIQ
-- Date:         2021-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml
-- Unmapped:     ResultType, ResultDescription
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType
-- UNMAPPED_FIELD: ResultDescription

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = '50057'
    AND rawEventMsg = 'User account is disabled. The account has been disabled by an administrator.')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---

## Multifactor Authentication Denied

| Field | Value |
|---|---|
| **Sigma ID** | `e40f4962-b02b-4192-9bfe-245f7ece1f99` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110, T1621 |
| **Author** | AlertIQ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_mfa_denies.yml)**

> User has indicated they haven't instigated the MFA prompt and could indicate an attacker has the password for the account.

```sql
-- ============================================================
-- Title:        Multifactor Authentication Denied
-- Sigma ID:     e40f4962-b02b-4192-9bfe-245f7ece1f99
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110, T1621
-- Author:       AlertIQ
-- Date:         2022-03-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_mfa_denies.yml
-- Unmapped:     AuthenticationRequirement, Status
-- False Pos:    Users actually login but miss-click into the Deny button when MFA prompt.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: AuthenticationRequirement
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
  AND (rawEventMsg = 'multiFactorAuthentication'
    AND rawEventMsg LIKE '%MFA Denied%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Users actually login but miss-click into the Deny button when MFA prompt.

**References:**
- https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/

---

## Multifactor Authentication Interrupted

| Field | Value |
|---|---|
| **Sigma ID** | `5496ff55-42ec-4369-81cb-00f417029e25` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004, T1110, T1621 |
| **Author** | AlertIQ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_mfa_interrupted.yml)**

> Identifies user login with multifactor authentication failures, which might be an indication an attacker has the password for the account but can't pass the MFA challenge.

```sql
-- ============================================================
-- Title:        Multifactor Authentication Interrupted
-- Sigma ID:     5496ff55-42ec-4369-81cb-00f417029e25
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004, T1110, T1621
-- Author:       AlertIQ
-- Date:         2021-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_mfa_interrupted.yml
-- Unmapped:     ResultType, ResultDescription
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType
-- UNMAPPED_FIELD: ResultDescription

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = '500121'
    AND rawEventMsg LIKE '%Authentication failed during strong authentication request%')
  OR (rawEventMsg = '50074'
    AND rawEventMsg LIKE '%Strong Auth required%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---

## Azure Unusual Authentication Interruption

| Field | Value |
|---|---|
| **Sigma ID** | `8366030e-7216-476b-9927-271d79f13cf3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_unusual_authentication_interruption.yml)**

> Detects when there is a interruption in the authentication process.

```sql
-- ============================================================
-- Title:        Azure Unusual Authentication Interruption
-- Sigma ID:     8366030e-7216-476b-9927-271d79f13cf3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_unusual_authentication_interruption.yml
-- Unmapped:     ResultType, ResultDescription
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType
-- UNMAPPED_FIELD: ResultDescription

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = '50097'
    AND rawEventMsg = 'Device authentication is required')
  OR (rawEventMsg = '50155'
    AND rawEventMsg = 'DeviceAuthenticationFailed')
  OR (rawEventMsg = '50158'
    AND rawEventMsg = 'ExternalSecurityChallenge - External security challenge was not satisfied')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---

## User Access Blocked by Azure Conditional Access

| Field | Value |
|---|---|
| **Sigma ID** | `9a60e676-26ac-44c3-814b-0c2a8b977adf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1110, T1078.004 |
| **Author** | AlertIQ |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_user_login_blocked_by_conditional_access.yml)**

> Detect access has been blocked by Conditional Access policies.
The access policy does not allow token issuance which might be sights≈ of unauthorizeed login to valid accounts.


```sql
-- ============================================================
-- Title:        User Access Blocked by Azure Conditional Access
-- Sigma ID:     9a60e676-26ac-44c3-814b-0c2a8b977adf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1110, T1078.004
-- Author:       AlertIQ
-- Date:         2021-10-10
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_user_login_blocked_by_conditional_access.yml
-- Unmapped:     ResultType
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: ResultType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '53003'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts

---

## Users Authenticating To Other Azure AD Tenants

| Field | Value |
|---|---|
| **Sigma ID** | `5f521e4b-0105-4b72-845b-2198a54487b9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | MikeDuddington, '@dudders1' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_users_authenticating_to_other_azure_ad_tenants.yml)**

> Detect when users in your Azure AD tenant are authenticating to other Azure AD Tenants.

```sql
-- ============================================================
-- Title:        Users Authenticating To Other Azure AD Tenants
-- Sigma ID:     5f521e4b-0105-4b72-845b-2198a54487b9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       MikeDuddington, '@dudders1'
-- Date:         2022-06-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/signin_logs/azure_users_authenticating_to_other_azure_ad_tenants.yml
-- Unmapped:     Status, HomeTenantId, ResourceTenantId
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/signinlogs
-- UNMAPPED_FIELD: Status
-- UNMAPPED_FIELD: HomeTenantId
-- UNMAPPED_FIELD: ResourceTenantId

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'Success'
    AND rawEventMsg = 'HomeTenantID')
  AND NOT (rawEventMsg LIKE '%HomeTenantID%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts#monitoring-external-user-sign-ins

---
