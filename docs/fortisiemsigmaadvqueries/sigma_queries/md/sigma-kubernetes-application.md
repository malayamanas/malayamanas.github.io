# Sigma → FortiSIEM: Kubernetes Application

> 10 rules · Generated 2026-03-17

## Table of Contents

- [Deployment Deleted From Kubernetes Cluster](#deployment-deleted-from-kubernetes-cluster)
- [Kubernetes Events Deleted](#kubernetes-events-deleted)
- [Potential Remote Command Execution In Pod Container](#potential-remote-command-execution-in-pod-container)
- [Container With A hostPath Mount Created](#container-with-a-hostpath-mount-created)
- [Creation Of Pod In System Namespace](#creation-of-pod-in-system-namespace)
- [Privileged Container Deployed](#privileged-container-deployed)
- [RBAC Permission Enumeration Attempt](#rbac-permission-enumeration-attempt)
- [Kubernetes Secrets Enumeration](#kubernetes-secrets-enumeration)
- [New Kubernetes Service Account Created](#new-kubernetes-service-account-created)
- [Potential Sidecar Injection Into Running Deployment](#potential-sidecar-injection-into-running-deployment)

## Deployment Deleted From Kubernetes Cluster

| Field | Value |
|---|---|
| **Sigma ID** | `40967487-139b-4811-81d9-c9767a92aa5a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1498 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_deployment_deleted.yml)**

> Detects the removal of a deployment from a Kubernetes cluster.
This could indicate disruptive activity aiming to impact business operations.


```sql
-- ============================================================
-- Title:        Deployment Deleted From Kubernetes Cluster
-- Sigma ID:     40967487-139b-4811-81d9-c9767a92aa5a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1498
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_deployment_deleted.yml
-- Unmapped:     verb, objectRef.resource
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'delete'
    AND rawEventMsg = 'deployments')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Data%20destruction/

---

## Kubernetes Events Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `3132570d-cab2-4561-9ea6-1743644b2290` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml)**

> Detects when events are deleted in Kubernetes.
An adversary may delete Kubernetes events in an attempt to evade detection.


```sql
-- ============================================================
-- Title:        Kubernetes Events Deleted
-- Sigma ID:     3132570d-cab2-4561-9ea6-1743644b2290
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml
-- Unmapped:     verb, objectRef.resource
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'delete'
    AND rawEventMsg = 'events')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Delete%20K8S%20events/

---

## Potential Remote Command Execution In Pod Container

| Field | Value |
|---|---|
| **Sigma ID** | `a1b0ca4e-7835-413e-8471-3ff2b8a66be6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1609 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml)**

> Detects attempts to execute remote commands, within a Pod's container using e.g. the "kubectl exec" command.


```sql
-- ============================================================
-- Title:        Potential Remote Command Execution In Pod Container
-- Sigma ID:     a1b0ca4e-7835-413e-8471-3ff2b8a66be6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1609
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml
-- Unmapped:     verb, objectRef.resource, objectRef.subresource
-- False Pos:    Legitimate debugging activity. Investigate the identity performing the requests and their authorization.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: objectRef.subresource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'create'
    AND rawEventMsg = 'pods'
    AND rawEventMsg = 'exec')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate debugging activity. Investigate the identity performing the requests and their authorization.

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exec%20into%20container/

---

## Container With A hostPath Mount Created

| Field | Value |
|---|---|
| **Sigma ID** | `402b955c-8fe0-4a8c-b635-622b4ac5f902` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1611 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_hostpath_mount.yml)**

> Detects creation of a container with a hostPath mount.
A hostPath volume mounts a directory or a file from the node to the container.
Attackers who have permissions to create a new pod in the cluster may create one with a writable hostPath volume and chroot to escape to the underlying node.


```sql
-- ============================================================
-- Title:        Container With A hostPath Mount Created
-- Sigma ID:     402b955c-8fe0-4a8c-b635-622b4ac5f902
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1611
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_hostpath_mount.yml
-- Unmapped:     verb, objectRef.resource, hostPath
-- False Pos:    The DaemonSet controller creates pods with hostPath volumes within the kube-system namespace.
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: hostPath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'create'
    AND rawEventMsg = 'pods'
    AND rawEventMsg = '*')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The DaemonSet controller creates pods with hostPath volumes within the kube-system namespace.

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Writable%20hostPath%20mount/
- https://blog.appsecco.com/kubernetes-namespace-breakout-using-insecure-host-path-volume-part-1-b382f2a6e216

---

## Creation Of Pod In System Namespace

| Field | Value |
|---|---|
| **Sigma ID** | `a80d927d-ac6e-443f-a867-e8d6e3897318` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1036.005 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_pod_in_system_namespace.yml)**

> Detects deployments of pods within the kube-system namespace, which could be intended to imitate system pods.
System pods, created by controllers such as Deployments or DaemonSets have random suffixes in their names.
Attackers can use this fact and name their backdoor pods as if they were created by these controllers to avoid detection.
Deployment of such a backdoor container e.g. named kube-proxy-bv61v, could be attempted in the kube-system namespace alongside the other administrative containers.


```sql
-- ============================================================
-- Title:        Creation Of Pod In System Namespace
-- Sigma ID:     a80d927d-ac6e-443f-a867-e8d6e3897318
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1036.005
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_pod_in_system_namespace.yml
-- Unmapped:     verb, objectRef.resource, objectRef.namespace
-- False Pos:    System components such as daemon-set-controller and kube-scheduler also create pods in the kube-system namespace
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: objectRef.namespace

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'create'
    AND rawEventMsg = 'pods'
    AND rawEventMsg = 'kube-system')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System components such as daemon-set-controller and kube-scheduler also create pods in the kube-system namespace

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Pod%20or%20container%20name%20similarily/

---

## Privileged Container Deployed

| Field | Value |
|---|---|
| **Sigma ID** | `c5cd1b20-36bb-488d-8c05-486be3d0cb97` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1611 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml)**

> Detects the creation of a "privileged" container, an action which could be indicative of a threat actor mounting a container breakout attacks.
A privileged container is a container that can access the host with all of the root capabilities of the host machine. This allows it to view, interact and modify processes, network operations, IPC calls, the file system, mount points, SELinux configurations etc. as the root user on the host.
Various versions of "privileged" containers can be specified, e.g. by setting the securityContext.privileged flag in the resource specification, setting non-standard Linux capabilities, or configuring the hostNetwork/hostPID fields


```sql
-- ============================================================
-- Title:        Privileged Container Deployed
-- Sigma ID:     c5cd1b20-36bb-488d-8c05-486be3d0cb97
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1611
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_privileged_pod_creation.yml
-- Unmapped:     verb, objectRef.resource, capabilities
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource
-- UNMAPPED_FIELD: capabilities

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'create'
    AND rawEventMsg = 'pods'
    AND rawEventMsg = '*')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html#privilegeescalation-kubernetes-privilegedcontainer
- https://www.elastic.co/guide/en/security/current/kubernetes-pod-created-with-hostnetwork.html
- https://www.elastic.co/guide/en/security/current/kubernetes-container-created-with-excessive-linux-capabilities.html

---

## RBAC Permission Enumeration Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `84b777bd-c946-4d17-aa2e-c39f5a454325` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1069.003, T1087.004 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_rbac_permisions_listing.yml)**

> Detects identities attempting to enumerate their Kubernetes RBAC permissions.
In the early stages of a breach, attackers will aim to list the permissions they have within the compromised environment.
In a Kubernetes cluster, this can be achieved by interacting with the API server, and querying the SelfSubjectAccessReview API via e.g. a "kubectl auth can-i --list" command.
This will enumerate the Role-Based Access Controls (RBAC) rules defining the compromised user's authorization.


```sql
-- ============================================================
-- Title:        RBAC Permission Enumeration Attempt
-- Sigma ID:     84b777bd-c946-4d17-aa2e-c39f5a454325
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1069.003, T1087.004
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_rbac_permisions_listing.yml
-- Unmapped:     verb, apiGroup, objectRef.resource
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: apiGroup
-- UNMAPPED_FIELD: objectRef.resource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'create'
    AND rawEventMsg = 'authorization.k8s.io'
    AND rawEventMsg = 'selfsubjectrulesreviews')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.elastic.co/guide/en/security/current/kubernetes-suspicious-self-subject-review.html

---

## Kubernetes Secrets Enumeration

| Field | Value |
|---|---|
| **Sigma ID** | `eeb3e9e1-b685-44e4-9232-6bb701f925b5` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1552.007 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml)**

> Detects enumeration of Kubernetes secrets.

```sql
-- ============================================================
-- Title:        Kubernetes Secrets Enumeration
-- Sigma ID:     eeb3e9e1-b685-44e4-9232-6bb701f925b5
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1552.007
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_secrets_enumeration.yml
-- Unmapped:     verb, objectRef.resource
-- False Pos:    The Kubernetes dashboard occasionally accesses the kubernetes-dashboard-key-holder secret
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'list'
    AND rawEventMsg = 'secrets')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** The Kubernetes dashboard occasionally accesses the kubernetes-dashboard-key-holder secret

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/List%20K8S%20secrets/

---

## New Kubernetes Service Account Created

| Field | Value |
|---|---|
| **Sigma ID** | `e31bae15-83ed-473e-bf31-faf4f8a17d36` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_serviceaccount_creation.yml)**

> Detects creation of new Kubernetes service account, which could indicate an attacker's attempt to persist within a cluster.


```sql
-- ============================================================
-- Title:        New Kubernetes Service Account Created
-- Sigma ID:     e31bae15-83ed-473e-bf31-faf4f8a17d36
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1136
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_serviceaccount_creation.yml
-- Unmapped:     verb, objectRef.resource
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: objectRef.resource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'create'
    AND rawEventMsg = 'serviceaccounts')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/container%20service%20account/

---

## Potential Sidecar Injection Into Running Deployment

| Field | Value |
|---|---|
| **Sigma ID** | `ad9012a6-e518-4432-9890-f3b82b8fc71f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1609 |
| **Author** | Leo Tsaousis (@laripping) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_sidecar_injection.yml)**

> Detects attempts to inject a sidecar container into a running deployment.
A sidecar container is an additional container within a pod, that resides alongside the main container.
One way to add containers to running resources like Deployments/DeamonSets/StatefulSets, is via a "kubectl patch" operation.
By injecting a new container within a legitimate pod, an attacker can run their code and hide their activity, instead of running their own separated pod in the cluster.


```sql
-- ============================================================
-- Title:        Potential Sidecar Injection Into Running Deployment
-- Sigma ID:     ad9012a6-e518-4432-9890-f3b82b8fc71f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1609
-- Author:       Leo Tsaousis (@laripping)
-- Date:         2024-03-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_sidecar_injection.yml
-- Unmapped:     verb, apiGroup, objectRef.resource
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: kubernetes/application
-- UNMAPPED_FIELD: verb
-- UNMAPPED_FIELD: apiGroup
-- UNMAPPED_FIELD: objectRef.resource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'patch'
    AND rawEventMsg = 'apps'
    AND rawEventMsg = 'deployments')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch
- https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Sidecar%20Injection/

---
