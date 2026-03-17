# Sigma → FortiSIEM: Azure Riskdetection

> 19 rules · Generated 2026-03-17

## Table of Contents

- [Anomalous Token](#anomalous-token)
- [Anomalous User Activity](#anomalous-user-activity)
- [Activity From Anonymous IP Address](#activity-from-anonymous-ip-address)
- [Anonymous IP Address](#anonymous-ip-address)
- [Atypical Travel](#atypical-travel)
- [Impossible Travel](#impossible-travel)
- [Suspicious Inbox Forwarding Identity Protection](#suspicious-inbox-forwarding-identity-protection)
- [Suspicious Inbox Manipulation Rules](#suspicious-inbox-manipulation-rules)
- [Azure AD Account Credential Leaked](#azure-ad-account-credential-leaked)
- [Malicious IP Address Sign-In Failure Rate](#malicious-ip-address-sign-in-failure-rate)
- [Malicious IP Address Sign-In Suspicious](#malicious-ip-address-sign-in-suspicious)
- [Sign-In From Malware Infected IP](#sign-in-from-malware-infected-ip)
- [New Country](#new-country)
- [Password Spray Activity](#password-spray-activity)
- [Primary Refresh Token Access Attempt](#primary-refresh-token-access-attempt)
- [Suspicious Browser Activity](#suspicious-browser-activity)
- [Azure AD Threat Intelligence](#azure-ad-threat-intelligence)
- [SAML Token Issuer Anomaly](#saml-token-issuer-anomaly)
- [Unfamiliar Sign-In Properties](#unfamiliar-sign-in-properties)

## Anomalous Token

| Field | Value |
|---|---|
| **Sigma ID** | `6555754e-5e7f-4a67-ad1c-4041c413a007` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1528 |
| **Author** | Mark Morowczynski '@markmorow' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_token.yml)**

> Indicates that there are abnormal characteristics in the token such as an unusual token lifetime or a token that is played from an unfamiliar location.

```sql
-- ============================================================
-- Title:        Anomalous Token
-- Sigma ID:     6555754e-5e7f-4a67-ad1c-4041c413a007
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1528
-- Author:       Mark Morowczynski '@markmorow'
-- Date:         2023-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_token.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'anomalousToken'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#anomalous-token
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Anomalous User Activity

| Field | Value |
|---|---|
| **Sigma ID** | `258b6593-215d-4a26-a141-c8e31c1299a6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_user.yml)**

> Indicates that there are anomalous patterns of behavior like suspicious changes to the directory.

```sql
-- ============================================================
-- Title:        Anomalous User Activity
-- Sigma ID:     258b6593-215d-4a26-a141-c8e31c1299a6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_user.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'anomalousUserActivity'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#anomalous-user-activity
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Activity From Anonymous IP Address

| Field | Value |
|---|---|
| **Sigma ID** | `be4d9c86-d702-4030-b52e-c7859110e5e8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_activity.yml)**

> Identifies that users were active from an IP address that has been identified as an anonymous proxy IP address.

```sql
-- ============================================================
-- Title:        Activity From Anonymous IP Address
-- Sigma ID:     be4d9c86-d702-4030-b52e-c7859110e5e8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_activity.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'riskyIPAddress'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#activity-from-anonymous-ip-address
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Anonymous IP Address

| Field | Value |
|---|---|
| **Sigma ID** | `53acd925-2003-440d-a1f3-71a5253fe237` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1528 |
| **Author** | Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_address.yml)**

> Indicates sign-ins from an anonymous IP address, for example, using an anonymous browser or VPN.

```sql
-- ============================================================
-- Title:        Anonymous IP Address
-- Sigma ID:     53acd925-2003-440d-a1f3-71a5253fe237
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1528
-- Author:       Gloria Lee, '@gleeiamglo'
-- Date:         2023-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_address.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'anonymizedIPAddress'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins

**References:**
- https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#anonymous-ip-address

---

## Atypical Travel

| Field | Value |
|---|---|
| **Sigma ID** | `1a41023f-1e70-4026-921a-4d9341a9038e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_atypical_travel.yml)**

> Identifies two sign-ins originating from geographically distant locations, where at least one of the locations may also be atypical for the user, given past behavior.

```sql
-- ============================================================
-- Title:        Atypical Travel
-- Sigma ID:     1a41023f-1e70-4026-921a-4d9341a9038e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_atypical_travel.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'unlikelyTravel'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#atypical-travel
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Impossible Travel

| Field | Value |
|---|---|
| **Sigma ID** | `b2572bf9-e20a-4594-b528-40bde666525a` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_impossible_travel.yml)**

> Identifies user activities originating from geographically distant locations within a time period shorter than the time it takes to travel from the first location to the second.

```sql
-- ============================================================
-- Title:        Impossible Travel
-- Sigma ID:     b2572bf9-e20a-4594-b528-40bde666525a
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_impossible_travel.yml
-- Unmapped:     riskEventType
-- False Pos:    Connecting to a VPN, performing activity and then dropping and performing additional activity.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'impossibleTravel'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Connecting to a VPN, performing activity and then dropping and performing additional activity.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#impossible-travel
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Suspicious Inbox Forwarding Identity Protection

| Field | Value |
|---|---|
| **Sigma ID** | `27e4f1d6-ae72-4ea0-8a67-77a73a289c3d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1114.003 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_inbox_forwarding_rule.yml)**

> Indicates suspicious rules such as an inbox rule that forwards a copy of all emails to an external address

```sql
-- ============================================================
-- Title:        Suspicious Inbox Forwarding Identity Protection
-- Sigma ID:     27e4f1d6-ae72-4ea0-8a67-77a73a289c3d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1114.003
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_inbox_forwarding_rule.yml
-- Unmapped:     riskEventType
-- False Pos:    A legitimate forwarding rule.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'suspiciousInboxForwarding'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A legitimate forwarding rule.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#suspicious-inbox-forwarding
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Suspicious Inbox Manipulation Rules

| Field | Value |
|---|---|
| **Sigma ID** | `ceb55fd0-726e-4656-bf4e-b585b7f7d572` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1140 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_inbox_manipulation.yml)**

> Detects suspicious rules that delete or move messages or folders are set on a user's inbox.

```sql
-- ============================================================
-- Title:        Suspicious Inbox Manipulation Rules
-- Sigma ID:     ceb55fd0-726e-4656-bf4e-b585b7f7d572
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1140
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_inbox_manipulation.yml
-- Unmapped:     riskEventType
-- False Pos:    Actual mailbox rules that are moving items based on their workflow.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'mcasSuspiciousInboxManipulationRules'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Actual mailbox rules that are moving items based on their workflow.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#suspicious-inbox-manipulation-rules
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Azure AD Account Credential Leaked

| Field | Value |
|---|---|
| **Sigma ID** | `19128e5e-4743-48dc-bd97-52e5775af817` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | reconnaissance |
| **MITRE Techniques** | T1589 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_leaked_credentials.yml)**

> Indicates that the user's valid credentials have been leaked.

```sql
-- ============================================================
-- Title:        Azure AD Account Credential Leaked
-- Sigma ID:     19128e5e-4743-48dc-bd97-52e5775af817
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        reconnaissance | T1589
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_leaked_credentials.yml
-- Unmapped:     riskEventType
-- False Pos:    A rare hash collision.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'leakedCredentials'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A rare hash collision.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#leaked-credentials
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Malicious IP Address Sign-In Failure Rate

| Field | Value |
|---|---|
| **Sigma ID** | `a3f55ebd-0c01-4ed6-adc0-8fb76d8cd3cd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_malicious_ip_address.yml)**

> Indicates sign-in from a malicious IP address based on high failure rates.

```sql
-- ============================================================
-- Title:        Malicious IP Address Sign-In Failure Rate
-- Sigma ID:     a3f55ebd-0c01-4ed6-adc0-8fb76d8cd3cd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_malicious_ip_address.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'maliciousIPAddress'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#malicious-ip-address
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Malicious IP Address Sign-In Suspicious

| Field | Value |
|---|---|
| **Sigma ID** | `36440e1c-5c22-467a-889b-593e66498472` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_malicious_ip_address_suspicious.yml)**

> Indicates sign-in from a malicious IP address known to be malicious at time of sign-in.

```sql
-- ============================================================
-- Title:        Malicious IP Address Sign-In Suspicious
-- Sigma ID:     36440e1c-5c22-467a-889b-593e66498472
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_malicious_ip_address_suspicious.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'suspiciousIPAddress'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#malicious-ip-address
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Sign-In From Malware Infected IP

| Field | Value |
|---|---|
| **Sigma ID** | `821b4dc3-1295-41e7-b157-39ab212dd6bd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_malware_linked_ip.yml)**

> Indicates sign-ins from IP addresses infected with malware that is known to actively communicate with a bot server.

```sql
-- ============================================================
-- Title:        Sign-In From Malware Infected IP
-- Sigma ID:     821b4dc3-1295-41e7-b157-39ab212dd6bd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_malware_linked_ip.yml
-- Unmapped:     riskEventType
-- False Pos:    Using an IP address that is shared by many users
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'malwareInfectedIPAddress'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Using an IP address that is shared by many users

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#malware-linked-ip-address-deprecated
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## New Country

| Field | Value |
|---|---|
| **Sigma ID** | `adf9f4d2-559e-4f5c-95be-c28dff0b1476` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_new_coutry_region.yml)**

> Detects sign-ins from new countries. The detection considers past activity locations to determine new and infrequent locations.

```sql
-- ============================================================
-- Title:        New Country
-- Sigma ID:     adf9f4d2-559e-4f5c-95be-c28dff0b1476
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_new_coutry_region.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'newCountry'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#new-country
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Password Spray Activity

| Field | Value |
|---|---|
| **Sigma ID** | `28ecba0a-c743-4690-ad29-9a8f6f25a6f9` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1110 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_password_spray.yml)**

> Indicates that a password spray attack has been successfully performed.

```sql
-- ============================================================
-- Title:        Password Spray Activity
-- Sigma ID:     28ecba0a-c743-4690-ad29-9a8f6f25a6f9
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1110
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_password_spray.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'passwordSpray'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#password-spray
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Primary Refresh Token Access Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `a84fc3b1-c9ce-4125-8e74-bdcdb24021f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1528 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_prt_access.yml)**

> Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft

```sql
-- ============================================================
-- Title:        Primary Refresh Token Access Attempt
-- Sigma ID:     a84fc3b1-c9ce-4125-8e74-bdcdb24021f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1528
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_prt_access.yml
-- Unmapped:     riskEventType
-- False Pos:    This detection is low-volume and is seen infrequently in most organizations. When this detection appears it's high risk, and users should be remediated.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'attemptedPrtAccess'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** This detection is low-volume and is seen infrequently in most organizations. When this detection appears it's high risk, and users should be remediated.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#possible-attempt-to-access-primary-refresh-token-prt
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Suspicious Browser Activity

| Field | Value |
|---|---|
| **Sigma ID** | `944f6adb-7a99-4c69-80c1-b712579e93e6` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_suspicious_browser.yml)**

> Indicates anomalous behavior based on suspicious sign-in activity across multiple tenants from different countries in the same browser

```sql
-- ============================================================
-- Title:        Suspicious Browser Activity
-- Sigma ID:     944f6adb-7a99-4c69-80c1-b712579e93e6
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_suspicious_browser.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'suspiciousBrowser'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#suspicious-browser
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Azure AD Threat Intelligence

| Field | Value |
|---|---|
| **Sigma ID** | `a2cb56ff-4f46-437a-a0fa-ffa4d1303cba` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_threat_intel.yml)**

> Indicates user activity that is unusual for the user or consistent with known attack patterns.

```sql
-- ============================================================
-- Title:        Azure AD Threat Intelligence
-- Sigma ID:     a2cb56ff-4f46-437a-a0fa-ffa4d1303cba
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_threat_intel.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'investigationsThreatIntelligence'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#azure-ad-threat-intelligence-sign-in
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#azure-ad-threat-intelligence-user
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## SAML Token Issuer Anomaly

| Field | Value |
|---|---|
| **Sigma ID** | `e3393cba-31f0-4207-831e-aef90ab17a8c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1606 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_token_issuer_anomaly.yml)**

> Indicates the SAML token issuer for the associated SAML token is potentially compromised. The claims included in the token are unusual or match known attacker patterns

```sql
-- ============================================================
-- Title:        SAML Token Issuer Anomaly
-- Sigma ID:     e3393cba-31f0-4207-831e-aef90ab17a8c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1606
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_token_issuer_anomaly.yml
-- Unmapped:     riskEventType
-- False Pos:    We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'tokenIssuerAnomaly'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#token-issuer-anomaly
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---

## Unfamiliar Sign-In Properties

| Field | Value |
|---|---|
| **Sigma ID** | `128faeef-79dd-44ca-b43c-a9e236a60f49` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_unfamilar_sign_in.yml)**

> Detects sign-in with properties that are unfamiliar to the user. The detection considers past sign-in history to look for anomalous sign-ins.

```sql
-- ============================================================
-- Title:        Unfamiliar Sign-In Properties
-- Sigma ID:     128faeef-79dd-44ca-b43c-a9e236a60f49
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
-- Date:         2023-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/identity_protection/azure_identity_protection_unfamilar_sign_in.yml
-- Unmapped:     riskEventType
-- False Pos:    User changing to a new device, location, browser, etc.
-- ============================================================
-- UNMAPPED_LOGSOURCE: azure/riskdetection
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
  AND rawEventMsg = 'unfamiliarFeatures'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User changing to a new device, location, browser, etc.

**References:**
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#unfamiliar-sign-in-properties
- https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins

---
