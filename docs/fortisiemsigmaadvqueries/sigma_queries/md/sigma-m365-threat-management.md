# Sigma → FortiSIEM: M365 Threat Management

> 13 rules · Generated 2026-03-17

## Table of Contents

- [Activity Performed by Terminated User](#activity-performed-by-terminated-user)
- [Activity from Anonymous IP Addresses](#activity-from-anonymous-ip-addresses)
- [Activity from Infrequent Country](#activity-from-infrequent-country)
- [Data Exfiltration to Unsanctioned Apps](#data-exfiltration-to-unsanctioned-apps)
- [Microsoft 365 - Impossible Travel Activity](#microsoft-365-impossible-travel-activity)
- [Logon from a Risky IP Address](#logon-from-a-risky-ip-address)
- [Microsoft 365 - Potential Ransomware Activity](#microsoft-365-potential-ransomware-activity)
- [PST Export Alert Using eDiscovery Alert](#pst-export-alert-using-ediscovery-alert)
- [PST Export Alert Using New-ComplianceSearchAction](#pst-export-alert-using-new-compliancesearchaction)
- [Suspicious Inbox Forwarding](#suspicious-inbox-forwarding)
- [Suspicious OAuth App File Download Activities](#suspicious-oauth-app-file-download-activities)
- [Microsoft 365 - Unusual Volume of File Deletion](#microsoft-365-unusual-volume-of-file-deletion)
- [Microsoft 365 - User Restricted from Sending Email](#microsoft-365-user-restricted-from-sending-email)

## Activity Performed by Terminated User

| Field | Value |
|---|---|
| **Sigma ID** | `2e669ed8-742e-4fe5-b3c4-5a59b486c2ee` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_activity_by_terminated_user.yml)**

> Detects when a Microsoft Cloud App Security reported for users whose account were terminated in Azure AD, but still perform activities in other platforms such as AWS or Salesforce.
This is especially relevant for users who use another account to manage resources, since these accounts are often not terminated when a user leaves the company.


```sql
-- ============================================================
-- Title:        Activity Performed by Terminated User
-- Sigma ID:     2e669ed8-742e-4fe5-b3c4-5a59b486c2ee
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_activity_by_terminated_user.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Activity performed by terminated user'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Activity from Anonymous IP Addresses

| Field | Value |
|---|---|
| **Sigma ID** | `d8b0a4fe-07a8-41be-bd39-b14afa025d95` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1573 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_activity_from_anonymous_ip_addresses.yml)**

> Detects when a Microsoft Cloud App Security reported when users were active from an IP address that has been identified as an anonymous proxy IP address.

```sql
-- ============================================================
-- Title:        Activity from Anonymous IP Addresses
-- Sigma ID:     d8b0a4fe-07a8-41be-bd39-b14afa025d95
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1573
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_activity_from_anonymous_ip_addresses.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    User using a VPN or Proxy
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Activity from anonymous IP addresses'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** User using a VPN or Proxy

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Activity from Infrequent Country

| Field | Value |
|---|---|
| **Sigma ID** | `0f2468a2-5055-4212-a368-7321198ee706` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1573 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_activity_from_infrequent_country.yml)**

> Detects when a Microsoft Cloud App Security reported when an activity occurs from a location that wasn't recently or never visited by any user in the organization.

```sql
-- ============================================================
-- Title:        Activity from Infrequent Country
-- Sigma ID:     0f2468a2-5055-4212-a368-7321198ee706
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1573
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_activity_from_infrequent_country.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Activity from infrequent country'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Data Exfiltration to Unsanctioned Apps

| Field | Value |
|---|---|
| **Sigma ID** | `2b669496-d215-47d8-bd9a-f4a45bf07cda` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1537 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_data_exfiltration_to_unsanctioned_app.yml)**

> Detects when a Microsoft Cloud App Security reported when a user or IP address uses an app that is not sanctioned to perform an activity that resembles an attempt to exfiltrate information from your organization.

```sql
-- ============================================================
-- Title:        Data Exfiltration to Unsanctioned Apps
-- Sigma ID:     2b669496-d215-47d8-bd9a-f4a45bf07cda
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1537
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_data_exfiltration_to_unsanctioned_app.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Data exfiltration to unsanctioned apps'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Microsoft 365 - Impossible Travel Activity

| Field | Value |
|---|---|
| **Sigma ID** | `d7eab125-5f94-43df-8710-795b80fa1189` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_impossible_travel_activity.yml)**

> Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel.

```sql
-- ============================================================
-- Title:        Microsoft 365 - Impossible Travel Activity
-- Sigma ID:     d7eab125-5f94-43df-8710-795b80fa1189
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Austin Songer @austinsonger
-- Date:         2020-07-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_impossible_travel_activity.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Impossible travel activity'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Logon from a Risky IP Address

| Field | Value |
|---|---|
| **Sigma ID** | `c191e2fa-f9d6-4ccf-82af-4f2aba08359f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_logon_from_risky_ip_address.yml)**

> Detects when a Microsoft Cloud App Security reported when a user signs into your sanctioned apps from a risky IP address.

```sql
-- ============================================================
-- Title:        Logon from a Risky IP Address
-- Sigma ID:     c191e2fa-f9d6-4ccf-82af-4f2aba08359f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_logon_from_risky_ip_address.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Log on from a risky IP address'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Microsoft 365 - Potential Ransomware Activity

| Field | Value |
|---|---|
| **Sigma ID** | `bd132164-884a-48f1-aa2d-c6d646b04c69` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486 |
| **Author** | austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_potential_ransomware_activity.yml)**

> Detects when a Microsoft Cloud App Security reported when a user uploads files to the cloud that might be infected with ransomware.

```sql
-- ============================================================
-- Title:        Microsoft 365 - Potential Ransomware Activity
-- Sigma ID:     bd132164-884a-48f1-aa2d-c6d646b04c69
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1486
-- Author:       austinsonger
-- Date:         2021-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_potential_ransomware_activity.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Potential ransomware activity'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## PST Export Alert Using eDiscovery Alert

| Field | Value |
|---|---|
| **Sigma ID** | `18b88d08-d73e-4f21-bc25-4b9892a4fdd0` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1114 |
| **Author** | Sorina Ionescu |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_pst_export_alert.yml)**

> Alert on when a user has performed an eDiscovery search or exported a PST file from the search. This PST file usually has sensitive information including email body content

```sql
-- ============================================================
-- Title:        PST Export Alert Using eDiscovery Alert
-- Sigma ID:     18b88d08-d73e-4f21-bc25-4b9892a4fdd0
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1114
-- Author:       Sorina Ionescu
-- Date:         2022-02-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_pst_export_alert.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    PST export can be done for legitimate purposes but due to the sensitive nature of its content it must be monitored.
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'eDiscovery search started or exported'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** PST export can be done for legitimate purposes but due to the sensitive nature of its content it must be monitored.

**References:**
- https://learn.microsoft.com/en-us/microsoft-365/compliance/alert-policies?view=o365-worldwide

---

## PST Export Alert Using New-ComplianceSearchAction

| Field | Value |
|---|---|
| **Sigma ID** | `6897cd82-6664-11ed-9022-0242ac120002` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1114 |
| **Author** | Nikita Khalimonenkov |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_pst_export_alert_using_new_compliancesearchaction.yml)**

> Alert when a user has performed an export to a search using 'New-ComplianceSearchAction' with the '-Export' flag. This detection will detect PST export even if the 'eDiscovery search or exported' alert is disabled in the O365.This rule will apply to ExchangePowerShell usage and from the cloud.

```sql
-- ============================================================
-- Title:        PST Export Alert Using New-ComplianceSearchAction
-- Sigma ID:     6897cd82-6664-11ed-9022-0242ac120002
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1114
-- Author:       Nikita Khalimonenkov
-- Date:         2022-11-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_pst_export_alert_using_new_compliancesearchaction.yml
-- Unmapped:     eventSource, Payload
-- False Pos:    Exporting a PST can be done for legitimate purposes by legitimate sources, but due to the sensitive nature of PST content, it must be monitored.
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: Payload

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg LIKE '%New-ComplianceSearchAction%' AND rawEventMsg LIKE '%Export%' AND rawEventMsg LIKE '%pst%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Exporting a PST can be done for legitimate purposes by legitimate sources, but due to the sensitive nature of PST content, it must be monitored.

**References:**
- https://learn.microsoft.com/en-us/powershell/module/exchange/new-compliancesearchaction?view=exchange-ps

---

## Suspicious Inbox Forwarding

| Field | Value |
|---|---|
| **Sigma ID** | `6c220477-0b5b-4b25-bb90-66183b4089e8` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1020 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_susp_inbox_forwarding.yml)**

> Detects when a Microsoft Cloud App Security reported suspicious email forwarding rules, for example, if a user created an inbox rule that forwards a copy of all emails to an external address.

```sql
-- ============================================================
-- Title:        Suspicious Inbox Forwarding
-- Sigma ID:     6c220477-0b5b-4b25-bb90-66183b4089e8
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1020
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_susp_inbox_forwarding.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Suspicious inbox forwarding'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Suspicious OAuth App File Download Activities

| Field | Value |
|---|---|
| **Sigma ID** | `ee111937-1fe7-40f0-962a-0eb44d57d174` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_susp_oauth_app_file_download_activities.yml)**

> Detects when a Microsoft Cloud App Security reported when an app downloads multiple files from Microsoft SharePoint or Microsoft OneDrive in a manner that is unusual for the user.

```sql
-- ============================================================
-- Title:        Suspicious OAuth App File Download Activities
-- Sigma ID:     ee111937-1fe7-40f0-962a-0eb44d57d174
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_susp_oauth_app_file_download_activities.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Suspicious OAuth app file download activities'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Microsoft 365 - Unusual Volume of File Deletion

| Field | Value |
|---|---|
| **Sigma ID** | `78a34b67-3c39-4886-8fb4-61c46dc18ecd` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485 |
| **Author** | austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_unusual_volume_of_file_deletion.yml)**

> Detects when a Microsoft Cloud App Security reported a user has deleted a unusual a large volume of files.

```sql
-- ============================================================
-- Title:        Microsoft 365 - Unusual Volume of File Deletion
-- Sigma ID:     78a34b67-3c39-4886-8fb4-61c46dc18ecd
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485
-- Author:       austinsonger
-- Date:         2021-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_unusual_volume_of_file_deletion.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'Unusual volume of file deletion'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---

## Microsoft 365 - User Restricted from Sending Email

| Field | Value |
|---|---|
| **Sigma ID** | `ff246f56-7f24-402a-baca-b86540e3925c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1199 |
| **Author** | austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_user_restricted_from_sending_email.yml)**

> Detects when a Security Compliance Center reported a user who exceeded sending limits of the service policies and because of this has been restricted from sending email.

```sql
-- ============================================================
-- Title:        Microsoft 365 - User Restricted from Sending Email
-- Sigma ID:     ff246f56-7f24-402a-baca-b86540e3925c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1199
-- Author:       austinsonger
-- Date:         2021-08-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/m365/threat_management/microsoft365_user_restricted_from_sending_email.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: m365/threat_management
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
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SecurityComplianceCenter'
    AND rawEventMsg = 'User restricted from sending email'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- https://learn.microsoft.com/en-us/defender-cloud-apps/policy-template-reference

---
