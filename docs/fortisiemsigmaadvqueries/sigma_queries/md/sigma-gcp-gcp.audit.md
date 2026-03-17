# Sigma → FortiSIEM: Gcp Gcp.Audit

> 16 rules · Generated 2026-03-17

## Table of Contents

- [GCP Access Policy Deleted](#gcp-access-policy-deleted)
- [GCP Break-glass Container Workload Deployed](#gcp-break-glass-container-workload-deployed)
- [Google Cloud Storage Buckets Enumeration](#google-cloud-storage-buckets-enumeration)
- [Google Cloud Storage Buckets Modified or Deleted](#google-cloud-storage-buckets-modified-or-deleted)
- [Google Cloud Re-identifies Sensitive Information](#google-cloud-re-identifies-sensitive-information)
- [Google Cloud DNS Zone Modified or Deleted](#google-cloud-dns-zone-modified-or-deleted)
- [Google Cloud Firewall Modified or Deleted](#google-cloud-firewall-modified-or-deleted)
- [Google Full Network Traffic Packet Capture](#google-full-network-traffic-packet-capture)
- [Google Cloud Kubernetes Admission Controller](#google-cloud-kubernetes-admission-controller)
- [Google Cloud Kubernetes CronJob](#google-cloud-kubernetes-cronjob)
- [Google Cloud Kubernetes RoleBinding](#google-cloud-kubernetes-rolebinding)
- [Google Cloud Kubernetes Secrets Modified or Deleted](#google-cloud-kubernetes-secrets-modified-or-deleted)
- [Google Cloud Service Account Disabled or Deleted](#google-cloud-service-account-disabled-or-deleted)
- [Google Cloud Service Account Modified](#google-cloud-service-account-modified)
- [Google Cloud SQL Database Modified or Deleted](#google-cloud-sql-database-modified-or-deleted)
- [Google Cloud VPN Tunnel Modified or Deleted](#google-cloud-vpn-tunnel-modified-or-deleted)

## GCP Access Policy Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `32438676-1dba-4ac7-bf69-b86cba995e05` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Bryan Lim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_access_policy_deleted.yml)**

> Detects when an access policy that is applied to a GCP cloud resource is deleted.
An adversary would be able to remove access policies to gain access to a GCP cloud resource.


```sql
-- ============================================================
-- Title:        GCP Access Policy Deleted
-- Sigma ID:     32438676-1dba-4ac7-bf69-b86cba995e05
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Bryan Lim
-- Date:         2024-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_access_policy_deleted.yml
-- Unmapped:     data.protoPayload.authorizationInfo.permission, data.protoPayload.authorizationInfo.granted, data.protoPayload.serviceName
-- False Pos:    Legitimate administrative activities
-- ============================================================
-- UNMAPPED_FIELD: data.protoPayload.authorizationInfo.permission
-- UNMAPPED_FIELD: data.protoPayload.authorizationInfo.granted
-- UNMAPPED_FIELD: data.protoPayload.serviceName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('accesscontextmanager.accessPolicies.delete', 'accesscontextmanager.accessPolicies.accessLevels.delete', 'accesscontextmanager.accessPolicies.accessZones.delete', 'accesscontextmanager.accessPolicies.authorizedOrgsDescs.delete')
    AND rawEventMsg = 'true'
    AND rawEventMsg = 'accesscontextmanager.googleapis.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative activities

**References:**
- https://cloud.google.com/access-context-manager/docs/audit-logging
- https://cloud.google.com/logging/docs/audit/understanding-audit-logs
- https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog

---

## GCP Break-glass Container Workload Deployed

| Field | Value |
|---|---|
| **Sigma ID** | `76737c19-66ee-4c07-b65a-a03301d1573d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1548 |
| **Author** | Bryan Lim |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_breakglass_container_workload_deployed.yml)**

> Detects the deployment of workloads that are deployed by using the break-glass flag to override Binary Authorization controls.


```sql
-- ============================================================
-- Title:        GCP Break-glass Container Workload Deployed
-- Sigma ID:     76737c19-66ee-4c07-b65a-a03301d1573d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1548
-- Author:       Bryan Lim
-- Date:         2024-01-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_breakglass_container_workload_deployed.yml
-- Unmapped:     data.protoPayload.resource.type, data.protoPayload.logName, data.protoPayload.methodName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: data.protoPayload.resource.type
-- UNMAPPED_FIELD: data.protoPayload.logName
-- UNMAPPED_FIELD: data.protoPayload.methodName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'k8s_cluster'
    AND rawEventMsg IN ('cloudaudit.googleapis.com/activity', 'cloudaudit.googleapis.com%2Factivity')
    AND rawEventMsg = 'io.k8s.core.v1.pods.create')
  AND rawEventMsg LIKE '%image-policy.k8s.io/break-glass%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cloud.google.com/binary-authorization

---

## Google Cloud Storage Buckets Enumeration

| Field | Value |
|---|---|
| **Sigma ID** | `e2feb918-4e77-4608-9697-990a1aaf74c3` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_bucket_enumeration.yml)**

> Detects when storage bucket is enumerated in Google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud Storage Buckets Enumeration
-- Sigma ID:     e2feb918-4e77-4608-9697-990a1aaf74c3
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_bucket_enumeration.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Storage Buckets being enumerated may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Storage Buckets enumerated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('storage.buckets.list', 'storage.buckets.listChannels')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Storage Buckets being enumerated may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Storage Buckets enumerated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/storage/docs/json_api/v1/buckets

---

## Google Cloud Storage Buckets Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `4d9f2ee2-c903-48ab-b9c1-8c0f474913d0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_bucket_modified_or_deleted.yml)**

> Detects when storage bucket is modified or deleted in Google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud Storage Buckets Modified or Deleted
-- Sigma ID:     4d9f2ee2-c903-48ab-b9c1-8c0f474913d0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_bucket_modified_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Storage Buckets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Storage Buckets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('storage.buckets.delete', 'storage.buckets.insert', 'storage.buckets.update', 'storage.buckets.patch')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Storage Buckets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Storage Buckets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/storage/docs/json_api/v1/buckets

---

## Google Cloud Re-identifies Sensitive Information

| Field | Value |
|---|---|
| **Sigma ID** | `234f9f48-904b-4736-a34c-55d23919e4b7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1565 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_dlp_re_identifies_sensitive_information.yml)**

> Identifies when sensitive information is re-identified in google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud Re-identifies Sensitive Information
-- Sigma ID:     234f9f48-904b-4736-a34c-55d23919e4b7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1565
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_dlp_re_identifies_sensitive_information.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'projects.content.reidentify'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cloud.google.com/dlp/docs/reference/rest/v2/projects.content/reidentify

---

## Google Cloud DNS Zone Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `28268a8f-191f-4c17-85b2-f5aa4fa829c3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_dns_zone_modified_or_deleted.yml)**

> Identifies when a DNS Zone is modified or deleted in Google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud DNS Zone Modified or Deleted
-- Sigma ID:     28268a8f-191f-4c17-85b2-f5aa4fa829c3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_dns_zone_modified_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Dns.ManagedZones.Delete', 'Dns.ManagedZones.Update', 'Dns.ManagedZones.Patch')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://cloud.google.com/dns/docs/reference/v1/managedZones

---

## Google Cloud Firewall Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `fe513c69-734c-4d4a-8548-ac5f609be82b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_firewall_rule_modified_or_deleted.yml)**

> Detects  when a firewall rule is modified or deleted in Google Cloud Platform (GCP).

```sql
-- ============================================================
-- Title:        Google Cloud Firewall Modified or Deleted
-- Sigma ID:     fe513c69-734c-4d4a-8548-ac5f609be82b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_firewall_rule_modified_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Firewall rules being modified or deleted may be performed by a system administrator. Verify that the firewall configuration change was expected.; Exceptions can be added to this rule to filter expected behavior.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('v*.Compute.Firewalls.Delete', 'v*.Compute.Firewalls.Patch', 'v*.Compute.Firewalls.Update', 'v*.Compute.Firewalls.Insert')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Firewall rules being modified or deleted may be performed by a system administrator. Verify that the firewall configuration change was expected.; Exceptions can be added to this rule to filter expected behavior.

**References:**
- https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- https://developers.google.com/resources/api-libraries/documentation/compute/v1/java/latest/com/google/api/services/compute/Compute.Firewalls.html

---

## Google Full Network Traffic Packet Capture

| Field | Value |
|---|---|
| **Sigma ID** | `980a7598-1e7f-4962-9372-2d754c930d0e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1074 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_full_network_traffic_packet_capture.yml)**

> Identifies potential full network packet capture in gcp. This feature can potentially be abused to read sensitive data from unencrypted internal traffic.

```sql
-- ============================================================
-- Title:        Google Full Network Traffic Packet Capture
-- Sigma ID:     980a7598-1e7f-4962-9372-2d754c930d0e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1074
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_full_network_traffic_packet_capture.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Full Network Packet Capture may be done by a system or network administrator.; If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('v*.Compute.PacketMirrorings.Get', 'v*.Compute.PacketMirrorings.Delete', 'v*.Compute.PacketMirrorings.Insert', 'v*.Compute.PacketMirrorings.Patch', 'v*.Compute.PacketMirrorings.List', 'v*.Compute.PacketMirrorings.aggregatedList')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Full Network Packet Capture may be done by a system or network administrator.; If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- https://developers.google.com/resources/api-libraries/documentation/compute/v1/java/latest/com/google/api/services/compute/Compute.PacketMirrorings.html

---

## Google Cloud Kubernetes Admission Controller

| Field | Value |
|---|---|
| **Sigma ID** | `6ad91e31-53df-4826-bd27-0166171c8040` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1552, T1552.007 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_admission_controller.yml)**

> Identifies when an admission controller is executed in GCP Kubernetes.
A Kubernetes Admission controller intercepts, and possibly modifies, requests to the Kubernetes API server.
The behavior of this admission controller is determined by an admission webhook (MutatingAdmissionWebhook or ValidatingAdmissionWebhook) that the user deploys in the cluster.
An adversary can use such webhooks as the MutatingAdmissionWebhook for obtaining persistence in the cluster.
For example, attackers can intercept and modify the pod creation operations in the cluster and add their malicious container to every created pod. An adversary can use the webhook ValidatingAdmissionWebhook, which could be used to obtain access credentials.
An adversary could use the webhook to intercept the requests to the API server, record secrets, and other sensitive information.


```sql
-- ============================================================
-- Title:        Google Cloud Kubernetes Admission Controller
-- Sigma ID:     6ad91e31-53df-4826-bd27-0166171c8040
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078, T1552, T1552.007
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_admission_controller.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Google Cloud Kubernetes Admission Controller may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'admissionregistration.k8s.io.v%'
    AND (rawEventMsg LIKE '%.mutatingwebhookconfigurations.%' OR rawEventMsg LIKE '%.validatingwebhookconfigurations.%')
    AND (rawEventMsg LIKE '%create' OR rawEventMsg LIKE '%patch' OR rawEventMsg LIKE '%replace'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Google Cloud Kubernetes Admission Controller may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/kubernetes-engine/docs

---

## Google Cloud Kubernetes CronJob

| Field | Value |
|---|---|
| **Sigma ID** | `cd3a808c-c7b7-4c50-a2f3-f4cfcd436435` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_cronjob.yml)**

> Identifies when a Google Cloud Kubernetes CronJob runs in Azure Cloud. Kubernetes Job is a controller that creates one or more pods and ensures that a specified number of them successfully terminate.
Kubernetes Job can be used to run containers that perform finite tasks for batch jobs. Kubernetes CronJob is used to schedule Jobs.
An Adversary may use Kubernetes CronJob for scheduling execution of malicious code that would run as a container in the cluster.


```sql
-- ============================================================
-- Title:        Google Cloud Kubernetes CronJob
-- Sigma ID:     cd3a808c-c7b7-4c50-a2f3-f4cfcd436435
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_cronjob.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Google Cloud Kubernetes CronJob/Job may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('io.k8s.api.batch.v*.Job', 'io.k8s.api.batch.v*.CronJob')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Google Cloud Kubernetes CronJob/Job may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/kubernetes-engine/docs
- https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/
- https://kubernetes.io/docs/concepts/workloads/controllers/job/

---

## Google Cloud Kubernetes RoleBinding

| Field | Value |
|---|---|
| **Sigma ID** | `0322d9f2-289a-47c2-b5e1-b63c90901a3e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_rolebinding.yml)**

> Detects the creation or patching of potential malicious RoleBinding. This includes RoleBindings and ClusterRoleBinding.

```sql
-- ============================================================
-- Title:        Google Cloud Kubernetes RoleBinding
-- Sigma ID:     0322d9f2-289a-47c2-b5e1-b63c90901a3e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_rolebinding.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    RoleBindings and ClusterRoleBinding being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; RoleBindings and ClusterRoleBinding modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('io.k8s.authorization.rbac.v*.clusterrolebindings.create', 'io.k8s.authorization.rbac.v*.rolebindings.create', 'io.k8s.authorization.rbac.v*.clusterrolebindings.patch', 'io.k8s.authorization.rbac.v*.rolebindings.patch', 'io.k8s.authorization.rbac.v*.clusterrolebindings.update', 'io.k8s.authorization.rbac.v*.rolebindings.update', 'io.k8s.authorization.rbac.v*.clusterrolebindings.delete', 'io.k8s.authorization.rbac.v*.rolebindings.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** RoleBindings and ClusterRoleBinding being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; RoleBindings and ClusterRoleBinding modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/pull/1267
- https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/cluster-role-v1/#ClusterRole
- https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging

---

## Google Cloud Kubernetes Secrets Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `2f0bae2d-bf20-4465-be86-1311addebaa3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_secrets_modified_or_deleted.yml)**

> Identifies when the Secrets are Modified or Deleted.

```sql
-- ============================================================
-- Title:        Google Cloud Kubernetes Secrets Modified or Deleted
-- Sigma ID:     2f0bae2d-bf20-4465-be86-1311addebaa3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_kubernetes_secrets_modified_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Secrets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('io.k8s.core.v*.secrets.create', 'io.k8s.core.v*.secrets.update', 'io.k8s.core.v*.secrets.patch', 'io.k8s.core.v*.secrets.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Secrets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging

---

## Google Cloud Service Account Disabled or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `13f81a90-a69c-4fab-8f07-b5bb55416a9f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_service_account_disabled_or_deleted.yml)**

> Identifies when a service account is disabled or deleted in Google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud Service Account Disabled or Deleted
-- Sigma ID:     13f81a90-a69c-4fab-8f07-b5bb55416a9f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_service_account_disabled_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Service Account being disabled or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service Account disabled or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.serviceAccounts.disable' OR rawEventMsg LIKE '%.serviceAccounts.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service Account being disabled or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service Account disabled or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts

---

## Google Cloud Service Account Modified

| Field | Value |
|---|---|
| **Sigma ID** | `6b67c12e-5e40-47c6-b3b0-1e6b571184cc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_service_account_modified.yml)**

> Identifies when a service account is modified in Google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud Service Account Modified
-- Sigma ID:     6b67c12e-5e40-47c6-b3b0-1e6b571184cc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-14
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_service_account_modified.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    Service Account being modified may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service Account modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.serviceAccounts.patch' OR rawEventMsg LIKE '%.serviceAccounts.create' OR rawEventMsg LIKE '%.serviceAccounts.update' OR rawEventMsg LIKE '%.serviceAccounts.enable' OR rawEventMsg LIKE '%.serviceAccounts.undelete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service Account being modified may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service Account modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts

---

## Google Cloud SQL Database Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `f346bbd5-2c4e-4789-a221-72de7685090d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_sql_database_modified_or_deleted.yml)**

> Detect when a Cloud SQL DB has been modified or deleted.

```sql
-- ============================================================
-- Title:        Google Cloud SQL Database Modified or Deleted
-- Sigma ID:     f346bbd5-2c4e-4789-a221-72de7685090d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-10-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_sql_database_modified_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    SQL Database being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; SQL Database modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('cloudsql.instances.create', 'cloudsql.instances.delete', 'cloudsql.users.update', 'cloudsql.users.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** SQL Database being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; SQL Database modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/users/update

---

## Google Cloud VPN Tunnel Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `99980a85-3a61-43d3-ac0f-b68d6b4797b1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_vpn_tunnel_modified_or_deleted.yml)**

> Identifies when a VPN Tunnel Modified or Deleted in Google Cloud.

```sql
-- ============================================================
-- Title:        Google Cloud VPN Tunnel Modified or Deleted
-- Sigma ID:     99980a85-3a61-43d3-ac0f-b68d6b4797b1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/audit/gcp_vpn_tunnel_modified_or_deleted.yml
-- Unmapped:     gcp.audit.method_name
-- False Pos:    VPN Tunnel being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; VPN Tunnel modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: gcp.audit.method_name

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('GCP-AuditLog-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('compute.vpnTunnels.insert', 'compute.vpnTunnels.delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** VPN Tunnel being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; VPN Tunnel modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://any-api.com/googleapis_com/compute/docs/vpnTunnels

---
