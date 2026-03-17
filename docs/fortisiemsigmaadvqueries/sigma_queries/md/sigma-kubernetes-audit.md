# Sigma → FortiSIEM: Kubernetes Audit

> 5 rules · Generated 2026-03-17

## Table of Contents

- [Kubernetes Admission Controller Modification](#kubernetes-admission-controller-modification)
- [Kubernetes CronJob/Job Modification](#kubernetes-cronjobjob-modification)
- [Kubernetes Rolebinding Modification](#kubernetes-rolebinding-modification)
- [Kubernetes Secrets Modified or Deleted](#kubernetes-secrets-modified-or-deleted)
- [Kubernetes Unauthorized or Unauthenticated Access](#kubernetes-unauthorized-or-unauthenticated-access)

## Kubernetes Admission Controller Modification

| Field | Value |
|---|---|
| **Sigma ID** | `eed82177-38f5-4299-8a76-098d50d225ab` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1552, T1552.007 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml)**

> Detects when a modification (create, update or replace) action is taken that affects mutating or validating webhook configurations, as they can be used by an adversary to achieve persistence or exfiltrate access credentials.


```sql
-- ============================================================
-- Title:        Kubernetes Admission Controller Modification
-- Sigma ID:     eed82177-38f5-4299-8a76-098d50d225ab
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078, T1552, T1552.007
-- Author:       kelnage
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml
-- Unmapped:     objectRef.apiGroup, objectRef.resource, verb
-- False Pos:    Modifying the Kubernetes Admission Controller may need to be done by a system administrator.; Automated processes may need to take these actions and may need to be filtered.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/audit
-- UNMAPPED_FIELD: objectRef.apiGroup
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: verb

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'admissionregistration.k8s.io'
    AND rawEventMsg IN ('mutatingwebhookconfigurations', 'validatingwebhookconfigurations')
    AND rawEventMsg IN ('create', 'delete', 'patch', 'replace', 'update'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Modifying the Kubernetes Admission Controller may need to be done by a system administrator.; Automated processes may need to take these actions and may need to be filtered.

**References:**
- https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- https://security.padok.fr/en/blog/kubernetes-webhook-attackers

---

## Kubernetes CronJob/Job Modification

| Field | Value |
|---|---|
| **Sigma ID** | `0c9b3bda-41a6-4442-9345-356ae86343dc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_cronjob_modification.yml)**

> Detects when a Kubernetes CronJob or Job is created or modified.
A Kubernetes Job creates one or more pods to accomplish a specific task, and a CronJob creates Jobs on a recurring schedule.
An adversary can take advantage of this Kubernetes object to schedule Jobs to run containers that execute malicious code within a cluster, allowing them to achieve persistence.


```sql
-- ============================================================
-- Title:        Kubernetes CronJob/Job Modification
-- Sigma ID:     0c9b3bda-41a6-4442-9345-356ae86343dc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution
-- Author:       kelnage
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_cronjob_modification.yml
-- Unmapped:     objectRef.apiGroup, objectRef.resource, verb
-- False Pos:    Modifying a Kubernetes Job or CronJob may need to be done by a system administrator.; Automated processes may need to take these actions and may need to be filtered.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/audit
-- UNMAPPED_FIELD: objectRef.apiGroup
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: verb

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'batch'
    AND rawEventMsg IN ('cronjobs', 'jobs')
    AND rawEventMsg IN ('create', 'delete', 'patch', 'replace', 'update'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Modifying a Kubernetes Job or CronJob may need to be done by a system administrator.; Automated processes may need to take these actions and may need to be filtered.

**References:**
- https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- https://www.redhat.com/en/blog/protecting-kubernetes-against-mitre-attck-persistence#technique-33-kubernetes-cronjob

---

## Kubernetes Rolebinding Modification

| Field | Value |
|---|---|
| **Sigma ID** | `10b97915-ec8d-455f-a815-9a78926585f6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml)**

> Detects when a Kubernetes Rolebinding is created or modified.


```sql
-- ============================================================
-- Title:        Kubernetes Rolebinding Modification
-- Sigma ID:     10b97915-ec8d-455f-a815-9a78926585f6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       kelnage
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml
-- Unmapped:     objectRef.apiGroup, objectRef.resource, verb
-- False Pos:    Modifying a Kubernetes Rolebinding may need to be done by a system administrator.; Automated processes may need to take these actions and may need to be filtered.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/audit
-- UNMAPPED_FIELD: objectRef.apiGroup
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: verb

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'rbac.authorization.k8s.io'
    AND rawEventMsg IN ('clusterrolebindings', 'rolebindings')
    AND rawEventMsg IN ('create', 'delete', 'patch', 'replace', 'update'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Modifying a Kubernetes Rolebinding may need to be done by a system administrator.; Automated processes may need to take these actions and may need to be filtered.

**References:**
- https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- https://medium.com/@seifeddinerajhi/kubernetes-rbac-privilege-escalation-exploits-and-mitigations-26c07629eeab

---

## Kubernetes Secrets Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `58d31a75-a4f8-4c40-985b-373d58162ca2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_secrets_modified_or_deleted.yml)**

> Detects when Kubernetes Secrets are Modified or Deleted.


```sql
-- ============================================================
-- Title:        Kubernetes Secrets Modified or Deleted
-- Sigma ID:     58d31a75-a4f8-4c40-985b-373d58162ca2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       kelnage
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_secrets_modified_or_deleted.yml
-- Unmapped:     objectRef.resource, verb
-- False Pos:    Secrets being modified or deleted may be performed by a system administrator.; Automated processes may need to take these actions and may need to be filtered.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/audit
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: verb

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'secrets'
    AND rawEventMsg IN ('create', 'delete', 'patch', 'replace', 'update'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Secrets being modified or deleted may be performed by a system administrator.; Automated processes may need to take these actions and may need to be filtered.

**References:**
- https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- https://commandk.dev/blog/guide-to-audit-k8s-secrets-for-compliance/

---

## Kubernetes Unauthorized or Unauthenticated Access

| Field | Value |
|---|---|
| **Sigma ID** | `0d933542-1f1f-420d-97d4-21b2c3c492d9` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | kelnage |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_unauthorized_unauthenticated_actions.yml)**

> Detects when a request to the Kubernetes API is rejected due to lack of authorization or due to an expired authentication token being used.
This may indicate an attacker attempting to leverage credentials they have obtained.


```sql
-- ============================================================
-- Title:        Kubernetes Unauthorized or Unauthenticated Access
-- Sigma ID:     0d933542-1f1f-420d-97d4-21b2c3c492d9
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        (none)
-- Author:       kelnage
-- Date:         2024-04-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_unauthorized_unauthenticated_actions.yml
-- Unmapped:     responseStatus.code
-- False Pos:    A misconfigured RBAC policy, a mistake by a valid user, or a wider issue with authentication tokens can also generate these errors.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/audit
-- UNMAPPED_FIELD: responseStatus.code

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('401', '403')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A misconfigured RBAC policy, a mistake by a valid user, or a wider issue with authentication tokens can also generate these errors.

**References:**
- https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/#monitor-api-authentication-issues

---
