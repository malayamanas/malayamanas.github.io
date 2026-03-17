# Sigma → FortiSIEM: M365 Audit

> 3 rules · Generated 2026-03-17

## Table of Contents

- [Azure Login Bypassing Conditional Access Policies](#azure-login-bypassing-conditional-access-policies)
- [Disabling Multi Factor Authentication](#disabling-multi-factor-authentication)
- [New Federated Domain Added](#new-federated-domain-added)

## Azure Login Bypassing Conditional Access Policies

| Field | Value |
|---|---|
| **Sigma ID** | `13f2d3f5-6497-44a7-bf5f-dc13ffafe5dc` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Josh Nickels, Marius Rothenbücher |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/audit/microsoft365_bypass_conditional_access.yml)**

> Detects a successful login to the Microsoft Intune Company Portal which could allow bypassing Conditional Access Policies and InTune device trust using a tool like TokenSmith.


```sql
-- ============================================================
-- Title:        Azure Login Bypassing Conditional Access Policies
-- Sigma ID:     13f2d3f5-6497-44a7-bf5f-dc13ffafe5dc
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        persistence | T1078
-- Author:       Josh Nickels, Marius Rothenbücher
-- Date:         2025-01-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/audit/microsoft365_bypass_conditional_access.yml
-- Unmapped:     Operation, ApplicationId, ResultStatus, RequestType
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/audit
-- UNMAPPED_FIELD: Operation
-- UNMAPPED_FIELD: ApplicationId
-- UNMAPPED_FIELD: ResultStatus
-- UNMAPPED_FIELD: RequestType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'UserLoggedIn'
    AND rawEventMsg = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
    AND rawEventMsg = 'Success'
    AND rawEventMsg = 'Cmsi:Cmsi')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/
- https://github.com/JumpsecLabs/TokenSmith

---

## Disabling Multi Factor Authentication

| Field | Value |
|---|---|
| **Sigma ID** | `60de9b57-dc4d-48b9-a6a0-b39e0469f876` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556.006 |
| **Author** | Splunk Threat Research Team (original rule), Harjot Singh @cyb3rjy0t (sigma rule) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/audit/microsoft365_disabling_mfa.yml)**

> Detects disabling of Multi Factor Authentication.

```sql
-- ============================================================
-- Title:        Disabling Multi Factor Authentication
-- Sigma ID:     60de9b57-dc4d-48b9-a6a0-b39e0469f876
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1556.006
-- Author:       Splunk Threat Research Team (original rule), Harjot Singh @cyb3rjy0t (sigma rule)
-- Date:         2023-09-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/audit/microsoft365_disabling_mfa.yml
-- Unmapped:     Operation
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/audit
-- UNMAPPED_FIELD: Operation

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Disable Strong Authentication.%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://research.splunk.com/cloud/c783dd98-c703-4252-9e8a-f19d9f5c949e/

---

## New Federated Domain Added

| Field | Value |
|---|---|
| **Sigma ID** | `58f88172-a73d-442b-94c9-95eaed3cbb36` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1484.002 |
| **Author** | Splunk Threat Research Team (original rule), Harjot Singh @cyb3rjy0t (sigma rule) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/audit/microsoft365_new_federated_domain_added_audit.yml)**

> Detects the addition of a new Federated Domain.

```sql
-- ============================================================
-- Title:        New Federated Domain Added
-- Sigma ID:     58f88172-a73d-442b-94c9-95eaed3cbb36
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1484.002
-- Author:       Splunk Threat Research Team (original rule), Harjot Singh @cyb3rjy0t (sigma rule)
-- Date:         2023-09-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/audit/microsoft365_new_federated_domain_added_audit.yml
-- Unmapped:     Operation
-- False Pos:    The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/audit
-- UNMAPPED_FIELD: Operation

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%domain%'
  AND (rawEventMsg LIKE '%add%' OR rawEventMsg LIKE '%new%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.

**References:**
- https://research.splunk.com/cloud/e155876a-6048-11eb-ae93-0242ac130002/
- https://o365blog.com/post/aadbackdoor/

---
