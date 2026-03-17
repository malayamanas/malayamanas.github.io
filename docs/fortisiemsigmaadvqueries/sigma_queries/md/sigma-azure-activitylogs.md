# Sigma → FortiSIEM: Azure Activitylogs

> 42 rules · Generated 2026-03-17

## Table of Contents

- [Azure Active Directory Hybrid Health AD FS New Server](#azure-active-directory-hybrid-health-ad-fs-new-server)
- [Azure Active Directory Hybrid Health AD FS Service Delete](#azure-active-directory-hybrid-health-ad-fs-service-delete)
- [User Added to an Administrator's Azure AD Role](#user-added-to-an-administrators-azure-ad-role)
- [Azure Application Deleted](#azure-application-deleted)
- [Azure Application Gateway Modified or Deleted](#azure-application-gateway-modified-or-deleted)
- [Azure Application Security Group Modified or Deleted](#azure-application-security-group-modified-or-deleted)
- [Azure Container Registry Created or Deleted](#azure-container-registry-created-or-deleted)
- [Number Of Resource Creation Or Deployment Activities](#number-of-resource-creation-or-deployment-activities)
- [Azure Device No Longer Managed or Compliant](#azure-device-no-longer-managed-or-compliant)
- [Azure Device or Configuration Modified or Deleted](#azure-device-or-configuration-modified-or-deleted)
- [Azure DNS Zone Modified or Deleted](#azure-dns-zone-modified-or-deleted)
- [Azure Firewall Modified or Deleted](#azure-firewall-modified-or-deleted)
- [Azure Firewall Rule Collection Modified or Deleted](#azure-firewall-rule-collection-modified-or-deleted)
- [Granting Of Permissions To An Account](#granting-of-permissions-to-an-account)
- [Azure Keyvault Key Modified or Deleted](#azure-keyvault-key-modified-or-deleted)
- [Azure Key Vault Modified or Deleted](#azure-key-vault-modified-or-deleted)
- [Azure Keyvault Secrets Modified or Deleted](#azure-keyvault-secrets-modified-or-deleted)
- [Azure Kubernetes Admission Controller](#azure-kubernetes-admission-controller)
- [Azure Kubernetes Cluster Created or Deleted](#azure-kubernetes-cluster-created-or-deleted)
- [Azure Kubernetes CronJob](#azure-kubernetes-cronjob)
- [Azure Kubernetes Events Deleted](#azure-kubernetes-events-deleted)
- [Azure Kubernetes Network Policy Change](#azure-kubernetes-network-policy-change)
- [Azure Kubernetes Pods Deleted](#azure-kubernetes-pods-deleted)
- [Azure Kubernetes Sensitive Role Access](#azure-kubernetes-sensitive-role-access)
- [Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted](#azure-kubernetes-rolebindingclusterrolebinding-modified-and-deleted)
- [Azure Kubernetes Secret or Config Object Access](#azure-kubernetes-secret-or-config-object-access)
- [Azure Kubernetes Service Account Modified or Deleted](#azure-kubernetes-service-account-modified-or-deleted)
- [Disabled MFA to Bypass Authentication Mechanisms](#disabled-mfa-to-bypass-authentication-mechanisms)
- [Azure Network Firewall Policy Modified or Deleted](#azure-network-firewall-policy-modified-or-deleted)
- [Azure Firewall Rule Configuration Modified or Deleted](#azure-firewall-rule-configuration-modified-or-deleted)
- [Azure Point-to-site VPN Modified or Deleted](#azure-point-to-site-vpn-modified-or-deleted)
- [Azure Network Security Configuration Modified or Deleted](#azure-network-security-configuration-modified-or-deleted)
- [Azure Virtual Network Device Modified or Deleted](#azure-virtual-network-device-modified-or-deleted)
- [Azure New CloudShell Created](#azure-new-cloudshell-created)
- [Azure Owner Removed From Application or Service Principal](#azure-owner-removed-from-application-or-service-principal)
- [Rare Subscription-level Operations In Azure](#rare-subscription-level-operations-in-azure)
- [Azure Service Principal Created](#azure-service-principal-created)
- [Azure Service Principal Removed](#azure-service-principal-removed)
- [Azure Subscription Permission Elevation Via ActivityLogs](#azure-subscription-permission-elevation-via-activitylogs)
- [Azure Suppression Rule Created](#azure-suppression-rule-created)
- [Azure Virtual Network Modified or Deleted](#azure-virtual-network-modified-or-deleted)
- [Azure VPN Connection Modified or Deleted](#azure-vpn-connection-modified-or-deleted)

## Azure Active Directory Hybrid Health AD FS New Server

| Field | Value |
|---|---|
| **Sigma ID** | `288a39fc-4914-4831-9ada-270e9dc12cb4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1578 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_new_server.yml)**

> This detection uses azureactivity logs (Administrative category) to identify the creation or update of a server instance in an Azure AD Hybrid health AD FS service.
A threat actor can create a new AD Health ADFS service and create a fake server instance to spoof AD FS signing logs. There is no need to compromise an on-prem AD FS server.
This can be done programmatically via HTTP requests to Azure.


```sql
-- ============================================================
-- Title:        Azure Active Directory Hybrid Health AD FS New Server
-- Sigma ID:     288a39fc-4914-4831-9ada-270e9dc12cb4
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1578
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_new_server.yml
-- Unmapped:     CategoryValue, ResourceProviderValue, ResourceId, OperationNameValue
-- False Pos:    Legitimate AD FS servers added to an AAD Health AD FS service instance
-- ============================================================
-- UNMAPPED_FIELD: CategoryValue
-- UNMAPPED_FIELD: ResourceProviderValue
-- UNMAPPED_FIELD: ResourceId
-- UNMAPPED_FIELD: OperationNameValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Administrative'
    AND rawEventMsg = 'Microsoft.ADHybridHealthService'
    AND rawEventMsg LIKE '%AdFederationService%'
    AND rawEventMsg = 'Microsoft.ADHybridHealthService/services/servicemembers/action')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate AD FS servers added to an AAD Health AD FS service instance

**References:**
- https://o365blog.com/post/hybridhealthagent/

---

## Azure Active Directory Hybrid Health AD FS Service Delete

| Field | Value |
|---|---|
| **Sigma ID** | `48739819-8230-4ee3-a8ea-e0289d1fb0ff` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1578.003 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml)**

> This detection uses azureactivity logs (Administrative category) to identify the deletion of an Azure AD Hybrid health AD FS service instance in a tenant.
A threat actor can create a new AD Health ADFS service and create a fake server to spoof AD FS signing logs.
The health AD FS service can then be deleted after it is not longer needed via HTTP requests to Azure.


```sql
-- ============================================================
-- Title:        Azure Active Directory Hybrid Health AD FS Service Delete
-- Sigma ID:     48739819-8230-4ee3-a8ea-e0289d1fb0ff
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1578.003
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
-- Date:         2021-08-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml
-- Unmapped:     CategoryValue, ResourceProviderValue, ResourceId, OperationNameValue
-- False Pos:    Legitimate AAD Health AD FS service instances being deleted in a tenant
-- ============================================================
-- UNMAPPED_FIELD: CategoryValue
-- UNMAPPED_FIELD: ResourceProviderValue
-- UNMAPPED_FIELD: ResourceId
-- UNMAPPED_FIELD: OperationNameValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Administrative'
    AND rawEventMsg = 'Microsoft.ADHybridHealthService'
    AND rawEventMsg LIKE '%AdFederationService%'
    AND rawEventMsg = 'Microsoft.ADHybridHealthService/services/delete')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate AAD Health AD FS service instances being deleted in a tenant

**References:**
- https://o365blog.com/post/hybridhealthagent/

---

## User Added to an Administrator's Azure AD Role

| Field | Value |
|---|---|
| **Sigma ID** | `ebbeb024-5b1d-4e16-9c0c-917f86c708a7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.003, T1078 |
| **Author** | Raphaël CALVET, @MetallicHack |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_ad_user_added_to_admin_role.yml)**

> User Added to an Administrator's Azure AD Role

```sql
-- ============================================================
-- Title:        User Added to an Administrator's Azure AD Role
-- Sigma ID:     ebbeb024-5b1d-4e16-9c0c-917f86c708a7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098.003, T1078
-- Author:       Raphaël CALVET, @MetallicHack
-- Date:         2021-10-04
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_ad_user_added_to_admin_role.yml
-- Unmapped:     Operation, Workload, ModifiedProperties{}.NewValue
-- False Pos:    PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.
-- ============================================================
-- UNMAPPED_FIELD: Operation
-- UNMAPPED_FIELD: Workload
-- UNMAPPED_FIELD: ModifiedProperties{}.NewValue

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Add member to role.'
    AND rawEventMsg = 'AzureActiveDirectory'
    AND (rawEventMsg LIKE '%Admins' OR rawEventMsg LIKE '%Administrator'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.

**References:**
- https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/

---

## Azure Application Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `410d2a41-1e6d-452f-85e5-abdd8257a823` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_deleted.yml)**

> Identifies when a application is deleted in Azure.

```sql
-- ============================================================
-- Title:        Azure Application Deleted
-- Sigma ID:     410d2a41-1e6d-452f-85e5-abdd8257a823
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_deleted.yml
-- Unmapped:     properties.message
-- False Pos:    Application being deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Application deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Delete application', 'Hard Delete application')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application being deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Application deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#application-proxy

---

## Azure Application Gateway Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `ad87d14e-7599-4633-ba81-aeb60cfe8cd6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_gateway_modified_or_deleted.yml)**

> Identifies when a application gateway is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Application Gateway Modified or Deleted
-- Sigma ID:     ad87d14e-7599-4633-ba81-aeb60cfe8cd6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_gateway_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Application gateway being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Application gateway modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/APPLICATIONGATEWAYS/WRITE', 'MICROSOFT.NETWORK/APPLICATIONGATEWAYS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application gateway being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Application gateway modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Application Security Group Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `835747f1-9329-40b5-9cc3-97d465754ce6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml)**

> Identifies when a application security group is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Application Security Group Modified or Deleted
-- Sigma ID:     835747f1-9329-40b5-9cc3-97d465754ce6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Application security group being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Application security group modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/WRITE', 'MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Application security group being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Application security group modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Container Registry Created or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `93e0ef48-37c8-49ed-a02c-038aab23628e` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_container_registry_created_or_deleted.yml)**

> Detects when a Container Registry is created or deleted.

```sql
-- ============================================================
-- Title:        Azure Container Registry Created or Deleted
-- Sigma ID:     93e0ef48-37c8-49ed-a02c-038aab23628e
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_container_registry_created_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Container Registry being created or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Container Registry created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.CONTAINERREGISTRY/REGISTRIES/WRITE', 'MICROSOFT.CONTAINERREGISTRY/REGISTRIES/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Container Registry being created or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Container Registry created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Number Of Resource Creation Or Deployment Activities

| Field | Value |
|---|---|
| **Sigma ID** | `d2d901db-7a75-45a1-bc39-0cbf00812192` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | sawwinnnaung |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_creating_number_of_resources_detection.yml)**

> Number of VM creations or deployment activities occur in Azure via the azureactivity log.

```sql
-- ============================================================
-- Title:        Number Of Resource Creation Or Deployment Activities
-- Sigma ID:     d2d901db-7a75-45a1-bc39-0cbf00812192
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       sawwinnnaung
-- Date:         2020-05-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_creating_number_of_resources_detection.yml
-- Unmapped:     (none)
-- False Pos:    Valid change
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Microsoft.Compute/virtualMachines/write%' OR rawEventMsg LIKE '%Microsoft.Resources/deployments/write%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change

**References:**
- https://github.com/Azure/Azure-Sentinel/blob/e534407884b1ec5371efc9f76ead282176c9e8bb/Detections/AzureActivity/Creating_Anomalous_Number_Of_Resources_detection.yaml

---

## Azure Device No Longer Managed or Compliant

| Field | Value |
|---|---|
| **Sigma ID** | `542b9912-c01f-4e3f-89a8-014c48cdca7d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_device_no_longer_managed_or_compliant.yml)**

> Identifies when a device in azure is no longer managed or compliant

```sql
-- ============================================================
-- Title:        Azure Device No Longer Managed or Compliant
-- Sigma ID:     542b9912-c01f-4e3f-89a8-014c48cdca7d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_device_no_longer_managed_or_compliant.yml
-- Unmapped:     properties.message
-- False Pos:    Administrator may have forgotten to review the device.
-- ============================================================
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Device no longer compliant', 'Device no longer managed')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrator may have forgotten to review the device.

**References:**
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#core-directory

---

## Azure Device or Configuration Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `46530378-f9db-4af9-a9e5-889c177d3881` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1565.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml)**

> Identifies when a device or device configuration in azure is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Device or Configuration Modified or Deleted
-- Sigma ID:     46530378-f9db-4af9-a9e5-889c177d3881
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485, T1565.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml
-- Unmapped:     properties.message
-- False Pos:    Device or device configuration being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Device or device configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Delete device', 'Delete device configuration', 'Update device', 'Update device configuration')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Device or device configuration being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Device or device configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#core-directory

---

## Azure DNS Zone Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `af6925b0-8826-47f1-9324-337507a0babd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1565.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_dns_zone_modified_or_deleted.yml)**

> Identifies when DNS zone is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure DNS Zone Modified or Deleted
-- Sigma ID:     af6925b0-8826-47f1-9324-337507a0babd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1565.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_dns_zone_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    DNS zone modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; DNS zone modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE 'MICROSOFT.NETWORK/DNSZONES%'
    AND (rawEventMsg LIKE '%/WRITE' OR rawEventMsg LIKE '%/DELETE'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** DNS zone modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; DNS zone modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes

---

## Azure Firewall Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `512cf937-ea9b-4332-939c-4c2c94baadcd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1562.004 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_firewall_modified_or_deleted.yml)**

> Identifies when a firewall is created, modified, or deleted.

```sql
-- ============================================================
-- Title:        Azure Firewall Modified or Deleted
-- Sigma ID:     512cf937-ea9b-4332-939c-4c2c94baadcd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1562.004
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_firewall_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Firewall being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Firewall modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE', 'MICROSOFT.NETWORK/AZUREFIREWALLS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Firewall being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Firewall modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Firewall Rule Collection Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `025c9fe7-db72-49f9-af0d-31341dd7dd57` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1562.004 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_firewall_rule_collection_modified_or_deleted.yml)**

> Identifies when Rule Collections (Application, NAT, and Network) is being modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Firewall Rule Collection Modified or Deleted
-- Sigma ID:     025c9fe7-db72-49f9-af0d-31341dd7dd57
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1562.004
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_firewall_rule_collection_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Rule Collections (Application, NAT, and Network) being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Rule Collections (Application, NAT, and Network) modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/AZUREFIREWALLS/APPLICATIONRULECOLLECTIONS/WRITE', 'MICROSOFT.NETWORK/AZUREFIREWALLS/APPLICATIONRULECOLLECTIONS/DELETE', 'MICROSOFT.NETWORK/AZUREFIREWALLS/NATRULECOLLECTIONS/WRITE', 'MICROSOFT.NETWORK/AZUREFIREWALLS/NATRULECOLLECTIONS/DELETE', 'MICROSOFT.NETWORK/AZUREFIREWALLS/NETWORKRULECOLLECTIONS/WRITE', 'MICROSOFT.NETWORK/AZUREFIREWALLS/NETWORKRULECOLLECTIONS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rule Collections (Application, NAT, and Network) being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Rule Collections (Application, NAT, and Network) modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Granting Of Permissions To An Account

| Field | Value |
|---|---|
| **Sigma ID** | `a622fcd2-4b5a-436a-b8a2-a4171161833c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098.003 |
| **Author** | sawwinnnaung |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_granting_permission_detection.yml)**

> Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.

```sql
-- ============================================================
-- Title:        Granting Of Permissions To An Account
-- Sigma ID:     a622fcd2-4b5a-436a-b8a2-a4171161833c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098.003
-- Author:       sawwinnnaung
-- Date:         2020-05-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_granting_permission_detection.yml
-- Unmapped:     (none)
-- False Pos:    Valid change
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Microsoft.Authorization/roleAssignments/write%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change

**References:**
- https://github.com/Azure/Azure-Sentinel/blob/e534407884b1ec5371efc9f76ead282176c9e8bb/Detections/AzureActivity/Granting_Permissions_To_Account_detection.yaml

---

## Azure Keyvault Key Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `80eeab92-0979-4152-942d-96749e11df40` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1552, T1552.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_keyvault_key_modified_or_deleted.yml)**

> Identifies when a Keyvault Key is modified or deleted in Azure.

```sql
-- ============================================================
-- Title:        Azure Keyvault Key Modified or Deleted
-- Sigma ID:     80eeab92-0979-4152-942d-96749e11df40
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1552, T1552.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_keyvault_key_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Key being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Key modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KEYVAULT/VAULTS/KEYS/UPDATE/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/CREATE', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/CREATE/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/IMPORT/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/RECOVER/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/RESTORE/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/DELETE', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/BACKUP/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/KEYS/PURGE/ACTION')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Key being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Key modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Key Vault Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `459a2970-bb84-4e6a-a32e-ff0fbd99448d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1552, T1552.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_keyvault_modified_or_deleted.yml)**

> Identifies when a key vault is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Key Vault Modified or Deleted
-- Sigma ID:     459a2970-bb84-4e6a-a32e-ff0fbd99448d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1552, T1552.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_keyvault_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Key Vault being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Key Vault modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KEYVAULT/VAULTS/WRITE', 'MICROSOFT.KEYVAULT/VAULTS/DELETE', 'MICROSOFT.KEYVAULT/VAULTS/DEPLOY/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Key Vault being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Key Vault modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Keyvault Secrets Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `b831353c-1971-477b-abb6-2828edc3bca1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1552, T1552.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_keyvault_secrets_modified_or_deleted.yml)**

> Identifies when secrets are modified or deleted in Azure.

```sql
-- ============================================================
-- Title:        Azure Keyvault Secrets Modified or Deleted
-- Sigma ID:     b831353c-1971-477b-abb6-2828edc3bca1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1552, T1552.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_keyvault_secrets_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Secrets being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KEYVAULT/VAULTS/SECRETS/WRITE', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/DELETE', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/BACKUP/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/PURGE/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/UPDATE/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/RECOVER/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/RESTORE/ACTION', 'MICROSOFT.KEYVAULT/VAULTS/SECRETS/SETSECRET/ACTION')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Secrets being modified or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Kubernetes Admission Controller

| Field | Value |
|---|---|
| **Sigma ID** | `a61a3c56-4ce2-4351-a079-88ae4cbd2b58` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1552, T1552.007 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_admission_controller.yml)**

> Identifies when an admission controller is executed in Azure Kubernetes.
A Kubernetes Admission controller intercepts, and possibly modifies, requests to the Kubernetes API server.
The behavior of this admission controller is determined by an admission webhook (MutatingAdmissionWebhook or ValidatingAdmissionWebhook) that the user deploys in the cluster.
An adversary can use such webhooks as the MutatingAdmissionWebhook for obtaining persistence in the cluster.
For example, attackers can intercept and modify the pod creation operations in the cluster and add their malicious container to every created pod.
An adversary can use the webhook ValidatingAdmissionWebhook, which could be used to obtain access credentials.
An adversary could use the webhook to intercept the requests to the API server, record secrets, and other sensitive information.


```sql
-- ============================================================
-- Title:        Azure Kubernetes Admission Controller
-- Sigma ID:     a61a3c56-4ce2-4351-a079-88ae4cbd2b58
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078, T1552, T1552.007
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_admission_controller.yml
-- Unmapped:     operationName
-- False Pos:    Azure Kubernetes Admissions Controller may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/ADMISSIONREGISTRATION.K8S.IO%' OR rawEventMsg LIKE 'MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/ADMISSIONREGISTRATION.K8S.IO%')
    AND (rawEventMsg LIKE '%/MUTATINGWEBHOOKCONFIGURATIONS/WRITE' OR rawEventMsg LIKE '%/VALIDATINGWEBHOOKCONFIGURATIONS/WRITE'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Azure Kubernetes Admissions Controller may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes

---

## Azure Kubernetes Cluster Created or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `9541f321-7cba-4b43-80fc-fbd1fb922808` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_cluster_created_or_deleted.yml)**

> Detects when a Azure Kubernetes Cluster is created or deleted.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Cluster Created or Deleted
-- Sigma ID:     9541f321-7cba-4b43-80fc-fbd1fb922808
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_cluster_created_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Kubernetes cluster being created or  deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Kubernetes cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Kubernetes cluster being created or  deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Kubernetes cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Azure Kubernetes CronJob

| Field | Value |
|---|---|
| **Sigma ID** | `1c71e254-6655-42c1-b2d6-5e4718d7fc0a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1053.003 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_cronjob.yml)**

> Identifies when a Azure Kubernetes CronJob runs in Azure Cloud. Kubernetes Job is a controller that creates one or more pods and ensures that a specified number of them successfully terminate.
Kubernetes Job can be used to run containers that perform finite tasks for batch jobs. Kubernetes CronJob is used to schedule Jobs.
An Adversary may use Kubernetes CronJob for scheduling execution of malicious code that would run as a container in the cluster.


```sql
-- ============================================================
-- Title:        Azure Kubernetes CronJob
-- Sigma ID:     1c71e254-6655-42c1-b2d6-5e4718d7fc0a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution | T1053.003
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_cronjob.yml
-- Unmapped:     operationName
-- False Pos:    Azure Kubernetes CronJob/Job may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/BATCH%' OR rawEventMsg LIKE 'MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/BATCH%')
    AND (rawEventMsg LIKE '%/CRONJOBS/WRITE' OR rawEventMsg LIKE '%/JOBS/WRITE'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Azure Kubernetes CronJob/Job may be done by a system administrator.; If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/
- https://kubernetes.io/docs/concepts/workloads/controllers/job/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/

---

## Azure Kubernetes Events Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `225d8b09-e714-479c-a0e4-55e6f29adf35` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562, T1562.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_events_deleted.yml)**

> Detects when Events are deleted in Azure Kubernetes. An adversary may delete events in Azure Kubernetes in an attempt to evade detection.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Events Deleted
-- Sigma ID:     225d8b09-e714-479c-a0e4-55e6f29adf35
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562, T1562.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_events_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Event deletions may be done by a system or network administrator. Verify whether the username, hostname, and/or resource name should be making changes in your environment. Events deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Event deletions may be done by a system or network administrator. Verify whether the username, hostname, and/or resource name should be making changes in your environment. Events deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://github.com/elastic/detection-rules/blob/da3852b681cf1a33898b1535892eab1f3a76177a/rules/integrations/azure/defense_evasion_kubernetes_events_deleted.toml

---

## Azure Kubernetes Network Policy Change

| Field | Value |
|---|---|
| **Sigma ID** | `08d6ac24-c927-4469-b3b7-2e422d6e3c43` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_network_policy_change.yml)**

> Identifies when a Azure Kubernetes network policy is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Network Policy Change
-- Sigma ID:     08d6ac24-c927-4469-b3b7-2e422d6e3c43
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_network_policy_change.yml
-- Unmapped:     operationName
-- False Pos:    Network Policy being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Network Policy being modified and deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/NETWORKING.K8S.IO/NETWORKPOLICIES/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/NETWORKING.K8S.IO/NETWORKPOLICIES/DELETE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EXTENSIONS/NETWORKPOLICIES/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EXTENSIONS/NETWORKPOLICIES/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Network Policy being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Network Policy being modified and deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Azure Kubernetes Pods Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `b02f9591-12c3-4965-986a-88028629b2e1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_pods_deleted.yml)**

> Identifies the deletion of Azure Kubernetes Pods.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Pods Deleted
-- Sigma ID:     b02f9591-12c3-4965-986a-88028629b2e1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_pods_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Pods may be deleted by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Pods deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Pods may be deleted by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Pods deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://github.com/elastic/detection-rules/blob/065bf48a9987cd8bd826c098a30ce36e6868ee46/rules/integrations/azure/impact_kubernetes_pod_deleted.toml

---

## Azure Kubernetes Sensitive Role Access

| Field | Value |
|---|---|
| **Sigma ID** | `818fee0c-e0ec-4e45-824e-83e4817b0887` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_role_access.yml)**

> Identifies when ClusterRoles/Roles are being modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Sensitive Role Access
-- Sigma ID:     818fee0c-e0ec-4e45-824e-83e4817b0887
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_role_access.yml
-- Unmapped:     operationName
-- False Pos:    ClusterRoles/Roles being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; ClusterRoles/Roles modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/DELETE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/BIND/ACTION', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/ESCALATE/ACTION', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/DELETE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/BIND/ACTION', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/ESCALATE/ACTION')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** ClusterRoles/Roles being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; ClusterRoles/Roles modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `25cb259b-bbdc-4b87-98b7-90d7c72f8743` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_rolebinding_modified_or_deleted.yml)**

> Detects the creation or patching of potential malicious RoleBinding/ClusterRoleBinding.

```sql
-- ============================================================
-- Title:        Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted
-- Sigma ID:     25cb259b-bbdc-4b87-98b7-90d7c72f8743
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_rolebinding_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    RoleBinding/ClusterRoleBinding being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; RoleBinding/ClusterRoleBinding modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/DELETE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** RoleBinding/ClusterRoleBinding being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; RoleBinding/ClusterRoleBinding modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Azure Kubernetes Secret or Config Object Access

| Field | Value |
|---|---|
| **Sigma ID** | `7ee0b4aa-d8d4-4088-b661-20efdf41a04c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_secret_or_config_object_access.yml)**

> Identifies when a Kubernetes account access a sensitive objects such as configmaps or secrets.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Secret or Config Object Access
-- Sigma ID:     7ee0b4aa-d8d4-4088-b661-20efdf41a04c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_secret_or_config_object_access.yml
-- Unmapped:     operationName
-- False Pos:    Sensitive objects may be accessed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Sensitive objects accessed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/CONFIGMAPS/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/CONFIGMAPS/DELETE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SECRETS/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SECRETS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Sensitive objects may be accessed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Sensitive objects accessed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Azure Kubernetes Service Account Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `12d027c3-b48c-4d9d-8bb6-a732200034b2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531, T1485, T1496, T1489 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_service_account_modified_or_deleted.yml)**

> Identifies when a service account is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Kubernetes Service Account Modified or Deleted
-- Sigma ID:     12d027c3-b48c-4d9d-8bb6-a732200034b2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1531, T1485, T1496, T1489
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_kubernetes_service_account_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Service account being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service account modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SERVICEACCOUNTS/WRITE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SERVICEACCOUNTS/DELETE', 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/SERVICEACCOUNTS/IMPERSONATE/ACTION')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service account being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service account modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
- https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
- https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
- https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1

---

## Disabled MFA to Bypass Authentication Mechanisms

| Field | Value |
|---|---|
| **Sigma ID** | `7ea78478-a4f9-42a6-9dcd-f861816122bf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | @ionsor |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_mfa_disabled.yml)**

> Detection for when multi factor authentication has been disabled, which might indicate a malicious activity to bypass authentication mechanisms.

```sql
-- ============================================================
-- Title:        Disabled MFA to Bypass Authentication Mechanisms
-- Sigma ID:     7ea78478-a4f9-42a6-9dcd-f861816122bf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       @ionsor
-- Date:         2022-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_mfa_disabled.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Authorized modification by administrators
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'AzureActiveDirectory'
    AND rawEventMsg = 'Disable Strong Authentication.'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Authorized modification by administrators

**References:**
- https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates

---

## Azure Network Firewall Policy Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `83c17918-746e-4bd9-920b-8e098bf88c23` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1562.007 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_firewall_policy_modified_or_deleted.yml)**

> Identifies when a Firewall Policy is Modified or Deleted.

```sql
-- ============================================================
-- Title:        Azure Network Firewall Policy Modified or Deleted
-- Sigma ID:     83c17918-746e-4bd9-920b-8e098bf88c23
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1562.007
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_firewall_policy_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Firewall Policy being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Firewall Policy modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/FIREWALLPOLICIES/WRITE', 'MICROSOFT.NETWORK/FIREWALLPOLICIES/JOIN/ACTION', 'MICROSOFT.NETWORK/FIREWALLPOLICIES/CERTIFICATES/ACTION', 'MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Firewall Policy being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Firewall Policy modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Firewall Rule Configuration Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `2a7d64cf-81fa-4daf-ab1b-ab80b789c067` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_firewall_rule_modified_or_deleted.yml)**

> Identifies when a Firewall Rule Configuration is Modified or Deleted.

```sql
-- ============================================================
-- Title:        Azure Firewall Rule Configuration Modified or Deleted
-- Sigma ID:     2a7d64cf-81fa-4daf-ab1b-ab80b789c067
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_firewall_rule_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Firewall Rule Configuration being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Firewall Rule Configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/FIREWALLPOLICIES/RULECOLLECTIONGROUPS/WRITE', 'MICROSOFT.NETWORK/FIREWALLPOLICIES/RULECOLLECTIONGROUPS/DELETE', 'MICROSOFT.NETWORK/FIREWALLPOLICIES/RULEGROUPS/WRITE', 'MICROSOFT.NETWORK/FIREWALLPOLICIES/RULEGROUPS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Firewall Rule Configuration being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Firewall Rule Configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Point-to-site VPN Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `d9557b75-267b-4b43-922f-a775e2d1f792` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_p2s_vpn_modified_or_deleted.yml)**

> Identifies when a Point-to-site VPN is Modified or Deleted.

```sql
-- ============================================================
-- Title:        Azure Point-to-site VPN Modified or Deleted
-- Sigma ID:     d9557b75-267b-4b43-922f-a775e2d1f792
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_p2s_vpn_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Point-to-site VPN being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Point-to-site VPN modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/P2SVPNGATEWAYS/WRITE', 'MICROSOFT.NETWORK/P2SVPNGATEWAYS/DELETE', 'MICROSOFT.NETWORK/P2SVPNGATEWAYS/RESET/ACTION', 'MICROSOFT.NETWORK/P2SVPNGATEWAYS/GENERATEVPNPROFILE/ACTION', 'MICROSOFT.NETWORK/P2SVPNGATEWAYS/DISCONNECTP2SVPNCONNECTIONS/ACTION', 'MICROSOFT.NETWORK/P2SVPNGATEWAYS/PROVIDERS/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Point-to-site VPN being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Point-to-site VPN modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Network Security Configuration Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `d22b4df4-5a67-4859-a578-8c9a0b5af9df` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_security_modified_or_deleted.yml)**

> Identifies when a network security configuration is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure Network Security Configuration Modified or Deleted
-- Sigma ID:     d22b4df4-5a67-4859-a578-8c9a0b5af9df
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_security_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Network Security Configuration being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Network Security Configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE', 'MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE', 'MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE', 'MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE', 'MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/JOIN/ACTION', 'MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/PROVIDERS/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Network Security Configuration being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Network Security Configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Virtual Network Device Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `15ef3fac-f0f0-4dc4-ada0-660aa72980b3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_virtual_device_modified_or_deleted.yml)**

> Identifies when a virtual network device is being modified or deleted.
This can be a network interface, network virtual appliance, virtual hub, or virtual router.


```sql
-- ============================================================
-- Title:        Azure Virtual Network Device Modified or Deleted
-- Sigma ID:     15ef3fac-f0f0-4dc4-ada0-660aa72980b3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_virtual_device_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Virtual Network Device being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Virtual Network Device modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE', 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE', 'MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE', 'MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION', 'MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE', 'MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE', 'MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE', 'MICROSOFT.NETWORK/VIRTUALHUBS/DELETE', 'MICROSOFT.NETWORK/VIRTUALHUBS/WRITE', 'MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE', 'MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Virtual Network Device being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Virtual Network Device modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure New CloudShell Created

| Field | Value |
|---|---|
| **Sigma ID** | `72af37e2-ec32-47dc-992b-bc288a2708cb` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_new_cloudshell_created.yml)**

> Identifies when a new cloudshell is created inside of Azure portal.

```sql
-- ============================================================
-- Title:        Azure New CloudShell Created
-- Sigma ID:     72af37e2-ec32-47dc-992b-bc288a2708cb
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution | T1059
-- Author:       Austin Songer
-- Date:         2021-09-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_new_cloudshell_created.yml
-- Unmapped:     operationName
-- False Pos:    A new cloudshell may be created by a system administrator.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'MICROSOFT.PORTAL/CONSOLES/WRITE'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A new cloudshell may be created by a system administrator.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Owner Removed From Application or Service Principal

| Field | Value |
|---|---|
| **Sigma ID** | `636e30d5-3736-42ea-96b1-e6e2f8429fd6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_owner_removed_from_application_or_service_principal.yml)**

> Identifies when a owner is was removed from a application or service principal in Azure.

```sql
-- ============================================================
-- Title:        Azure Owner Removed From Application or Service Principal
-- Sigma ID:     636e30d5-3736-42ea-96b1-e6e2f8429fd6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_owner_removed_from_application_or_service_principal.yml
-- Unmapped:     properties.message
-- False Pos:    Owner being removed may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Owner removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('Remove owner from service principal', 'Remove owner from application')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Owner being removed may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Owner removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#application-proxy

---

## Rare Subscription-level Operations In Azure

| Field | Value |
|---|---|
| **Sigma ID** | `c1182e02-49a3-481c-b3de-0fadc4091488` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003 |
| **Author** | sawwinnnaung |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_rare_operations.yml)**

> Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.

```sql
-- ============================================================
-- Title:        Rare Subscription-level Operations In Azure
-- Sigma ID:     c1182e02-49a3-481c-b3de-0fadc4091488
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003
-- Author:       sawwinnnaung
-- Date:         2020-05-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_rare_operations.yml
-- Unmapped:     (none)
-- False Pos:    Valid change
-- ============================================================

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Microsoft.DocumentDB/databaseAccounts/listKeys/action%' OR rawEventMsg LIKE '%Microsoft.Maps/accounts/listKeys/action%' OR rawEventMsg LIKE '%Microsoft.Media/mediaservices/listKeys/action%' OR rawEventMsg LIKE '%Microsoft.CognitiveServices/accounts/listKeys/action%' OR rawEventMsg LIKE '%Microsoft.Storage/storageAccounts/listKeys/action%' OR rawEventMsg LIKE '%Microsoft.Compute/snapshots/write%' OR rawEventMsg LIKE '%Microsoft.Network/networkSecurityGroups/write%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change

**References:**
- https://github.com/Azure/Azure-Sentinel/blob/e534407884b1ec5371efc9f76ead282176c9e8bb/Detections/AzureActivity/RareOperations.yaml

---

## Azure Service Principal Created

| Field | Value |
|---|---|
| **Sigma ID** | `0ddcff6d-d262-40b0-804b-80eb592de8e3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_service_principal_created.yml)**

> Identifies when a service principal is created in Azure.

```sql
-- ============================================================
-- Title:        Azure Service Principal Created
-- Sigma ID:     0ddcff6d-d262-40b0-804b-80eb592de8e3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_service_principal_created.yml
-- Unmapped:     properties.message
-- False Pos:    Service principal being created may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service principal created from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Add service principal'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service principal being created may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service principal created from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#application-proxy

---

## Azure Service Principal Removed

| Field | Value |
|---|---|
| **Sigma ID** | `448fd1ea-2116-4c62-9cde-a92d120e0f08` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_service_principal_removed.yml)**

> Identifies when a service principal was removed in Azure.

```sql
-- ============================================================
-- Title:        Azure Service Principal Removed
-- Sigma ID:     448fd1ea-2116-4c62-9cde-a92d120e0f08
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-09-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_service_principal_removed.yml
-- Unmapped:     properties.message
-- False Pos:    Service principal being removed may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service principal removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: properties.message

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'Remove service principal'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Service principal being removed may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Service principal removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#application-proxy

---

## Azure Subscription Permission Elevation Via ActivityLogs

| Field | Value |
|---|---|
| **Sigma ID** | `09438caa-07b1-4870-8405-1dbafe3dad95` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_subscription_permissions_elevation_via_activitylogs.yml)**

> Detects when a user has been elevated to manage all Azure Subscriptions.
This change should be investigated immediately if it isn't planned.
This setting could allow an attacker access to Azure subscriptions in your environment.


```sql
-- ============================================================
-- Title:        Azure Subscription Permission Elevation Via ActivityLogs
-- Sigma ID:     09438caa-07b1-4870-8405-1dbafe3dad95
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       Austin Songer @austinsonger
-- Date:         2021-11-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_subscription_permissions_elevation_via_activitylogs.yml
-- Unmapped:     operationName
-- False Pos:    If this was approved by System Administrator.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** If this was approved by System Administrator.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftauthorization

---

## Azure Suppression Rule Created

| Field | Value |
|---|---|
| **Sigma ID** | `92cc3e5d-eb57-419d-8c16-5c63f325a401` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_suppression_rule_created.yml)**

> Identifies when a suppression rule is created in Azure. Adversary's could attempt this to evade detection.

```sql
-- ============================================================
-- Title:        Azure Suppression Rule Created
-- Sigma ID:     92cc3e5d-eb57-419d-8c16-5c63f325a401
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_suppression_rule_created.yml
-- Unmapped:     operationName
-- False Pos:    Suppression Rule being created may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Suppression Rule created from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Suppression Rule being created may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Suppression Rule created from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure Virtual Network Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `bcfcc962-0e4a-4fd9-84bb-a833e672df3f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_virtual_network_modified_or_deleted.yml)**

> Identifies when a Virtual Network is modified or deleted in Azure.

```sql
-- ============================================================
-- Title:        Azure Virtual Network Modified or Deleted
-- Sigma ID:     bcfcc962-0e4a-4fd9-84bb-a833e672df3f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_virtual_network_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    Virtual Network being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Virtual Network modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE 'MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/%' OR rawEventMsg LIKE 'MICROSOFT.NETWORK/VIRTUALNETWORKS/%')
    AND (rawEventMsg LIKE '%/WRITE' OR rawEventMsg LIKE '%/DELETE'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Virtual Network being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Virtual Network modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---

## Azure VPN Connection Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `61171ffc-d79c-4ae5-8e10-9323dba19cd3` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_vpn_connection_modified_or_deleted.yml)**

> Identifies when a VPN connection is modified or deleted.

```sql
-- ============================================================
-- Title:        Azure VPN Connection Modified or Deleted
-- Sigma ID:     61171ffc-d79c-4ae5-8e10-9323dba19cd3
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_vpn_connection_modified_or_deleted.yml
-- Unmapped:     operationName
-- False Pos:    VPN Connection being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; VPN Connection modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: operationName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Azure-Activity-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg IN ('MICROSOFT.NETWORK/VPNGATEWAYS/VPNCONNECTIONS/WRITE', 'MICROSOFT.NETWORK/VPNGATEWAYS/VPNCONNECTIONS/DELETE')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** VPN Connection being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; VPN Connection modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations

---
