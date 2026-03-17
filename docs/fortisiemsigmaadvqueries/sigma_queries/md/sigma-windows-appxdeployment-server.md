# Sigma → FortiSIEM: Windows Appxdeployment-Server

> 9 rules · Generated 2026-03-17

## Table of Contents

- [Deployment AppX Package Was Blocked By AppLocker](#deployment-appx-package-was-blocked-by-applocker)
- [Remote AppX Package Downloaded from File Sharing or CDN Domain](#remote-appx-package-downloaded-from-file-sharing-or-cdn-domain)
- [AppX Package Deployment Failed Due to Signing Requirements](#appx-package-deployment-failed-due-to-signing-requirements)
- [AppX Located in Known Staging Directory Added to Deployment Pipeline](#appx-located-in-known-staging-directory-added-to-deployment-pipeline)
- [Potential Malicious AppX Package Installation Attempts](#potential-malicious-appx-package-installation-attempts)
- [Deployment Of The AppX Package Was Blocked By The Policy](#deployment-of-the-appx-package-was-blocked-by-the-policy)
- [AppX Located in Uncommon Directory Added to Deployment Pipeline](#appx-located-in-uncommon-directory-added-to-deployment-pipeline)
- [Windows AppX Deployment Full Trust Package Installation](#windows-appx-deployment-full-trust-package-installation)
- [Windows AppX Deployment Unsigned Package Installation](#windows-appx-deployment-unsigned-package-installation)

## Deployment AppX Package Was Blocked By AppLocker

| Field | Value |
|---|---|
| **Sigma ID** | `6ae53108-c3a0-4bee-8f45-c7591a2c337f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml)**

> Detects an appx package deployment that was blocked by AppLocker policy.

```sql
-- ============================================================
-- Title:        Deployment AppX Package Was Blocked By AppLocker
-- Sigma ID:     6ae53108-c3a0-4bee-8f45-c7591a2c337f
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely, since this event notifies about blocked application deployment. Tune your applocker rules to avoid blocking legitimate applications.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '412'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely, since this event notifies about blocked application deployment. Tune your applocker rules to avoid blocking legitimate applications.

**References:**
- https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
- https://github.com/nasbench/EVTX-ETW-Resources/blob/7a806a148b3d9d381193d4a80356016e6e8b1ee8/ETWEventsList/CSV/Windows11/22H2/W11_22H2_Pro_20220920_22621.382/Providers/Microsoft-Windows-AppXDeployment-Server.csv

---

## Remote AppX Package Downloaded from File Sharing or CDN Domain

| Field | Value |
|---|---|
| **Sigma ID** | `8b48ad89-10d8-4382-a546-50588c410f0d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_downloaded_from_file_sharing_domains.yml)**

> Detects an appx package that was added to the pipeline of the "to be processed" packages which was downloaded from a file sharing or CDN domain.


```sql
-- ============================================================
-- Title:        Remote AppX Package Downloaded from File Sharing or CDN Domain
-- Sigma ID:     8b48ad89-10d8-4382-a546-50588c410f0d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_downloaded_from_file_sharing_domains.yml
-- Unmapped:     Path
-- False Pos:    Unlikely, unless the organization uses file sharing or CDN services to distribute internal applications.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server
-- UNMAPPED_FIELD: Path

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '854'
    AND (rawEventMsg LIKE '%.githubusercontent.com%' OR rawEventMsg LIKE '%anonfiles.com%' OR rawEventMsg LIKE '%cdn.discordapp.com%' OR rawEventMsg LIKE '%ddns.net%' OR rawEventMsg LIKE '%dl.dropboxusercontent.com%' OR rawEventMsg LIKE '%ghostbin.co%' OR rawEventMsg LIKE '%github.com%' OR rawEventMsg LIKE '%glitch.me%' OR rawEventMsg LIKE '%gofile.io%' OR rawEventMsg LIKE '%hastebin.com%' OR rawEventMsg LIKE '%mediafire.com%' OR rawEventMsg LIKE '%mega.nz%' OR rawEventMsg LIKE '%onrender.com%' OR rawEventMsg LIKE '%pages.dev%' OR rawEventMsg LIKE '%paste.ee%' OR rawEventMsg LIKE '%pastebin.com%' OR rawEventMsg LIKE '%pastebin.pl%' OR rawEventMsg LIKE '%pastetext.net%' OR rawEventMsg LIKE '%privatlab.com%' OR rawEventMsg LIKE '%privatlab.net%' OR rawEventMsg LIKE '%send.exploit.in%' OR rawEventMsg LIKE '%sendspace.com%' OR rawEventMsg LIKE '%storage.googleapis.com%' OR rawEventMsg LIKE '%storjshare.io%' OR rawEventMsg LIKE '%supabase.co%' OR rawEventMsg LIKE '%temp.sh%' OR rawEventMsg LIKE '%transfer.sh%' OR rawEventMsg LIKE '%trycloudflare.com%' OR rawEventMsg LIKE '%ufile.io%' OR rawEventMsg LIKE '%w3spaces.com%' OR rawEventMsg LIKE '%workers.dev%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely, unless the organization uses file sharing or CDN services to distribute internal applications.

**References:**
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
- https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
- https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/

---

## AppX Package Deployment Failed Due to Signing Requirements

| Field | Value |
|---|---|
| **Sigma ID** | `898d5fc9-fbc3-43de-93ad-38e97237c344` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_package_deployment_failed_signing_requirements.yml)**

> Detects an appx package deployment / installation with the error code "0x80073cff" which indicates that the package didn't meet the signing requirements.


```sql
-- ============================================================
-- Title:        AppX Package Deployment Failed Due to Signing Requirements
-- Sigma ID:     898d5fc9-fbc3-43de-93ad-38e97237c344
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_package_deployment_failed_signing_requirements.yml
-- Unmapped:     ErrorCode
-- False Pos:    Legitimate AppX packages not signed by MS used part of an enterprise.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server
-- UNMAPPED_FIELD: ErrorCode

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '401'
    AND rawEventMsg = '0x80073cff')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate AppX packages not signed by MS used part of an enterprise.

**References:**
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
- https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
- https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/

---

## AppX Located in Known Staging Directory Added to Deployment Pipeline

| Field | Value |
|---|---|
| **Sigma ID** | `5cdeaf3d-1489-477c-95ab-c318559fc051` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_package_in_staging_directory.yml)**

> Detects an appx package that was added to the pipeline of the "to be processed" packages that is located in a known folder often used as a staging directory.


```sql
-- ============================================================
-- Title:        AppX Located in Known Staging Directory Added to Deployment Pipeline
-- Sigma ID:     5cdeaf3d-1489-477c-95ab-c318559fc051
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_package_in_staging_directory.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '854'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
- https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
- https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/

---

## Potential Malicious AppX Package Installation Attempts

| Field | Value |
|---|---|
| **Sigma ID** | `09d3b48b-be17-47f5-bf4e-94e7e75d09ce` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_mal_appx_names.yml)**

> Detects potential installation or installation attempts of known malicious appx packages

```sql
-- ============================================================
-- Title:        Potential Malicious AppX Package Installation Attempts
-- Sigma ID:     09d3b48b-be17-47f5-bf4e-94e7e75d09ce
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_mal_appx_names.yml
-- Unmapped:     PackageFullName
-- False Pos:    Rare occasions where a malicious package uses the exact same name and version as a legitimate application.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server
-- UNMAPPED_FIELD: PackageFullName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId IN ('400', '401')
    AND rawEventMsg LIKE '%3669e262-ec02-4e9d-bcb4-3d008b4afac9%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare occasions where a malicious package uses the exact same name and version as a legitimate application.

**References:**
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
- https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/
- https://forensicitguy.github.io/analyzing-magnitude-magniber-appx/

---

## Deployment Of The AppX Package Was Blocked By The Policy

| Field | Value |
|---|---|
| **Sigma ID** | `e021bbb5-407f-41f5-9dc9-1864c45a7a51` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_policy_block.yml)**

> Detects an appx package deployment that was blocked by the local computer policy.
The following events indicate that an AppX package deployment was blocked by a policy:
- Event ID 441: The package deployment operation is blocked by the "Allow deployment operations in special profiles" policy
- Event ID 442: Deployments to non-system volumes are blocked by the "Disable deployment of Windows Store apps to non-system volumes" policy."
- Event ID 453: Package blocked by a platform policy.
- Event ID 454: Package blocked by a platform policy.


```sql
-- ============================================================
-- Title:        Deployment Of The AppX Package Was Blocked By The Policy
-- Sigma ID:     e021bbb5-407f-41f5-9dc9-1864c45a7a51
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_policy_block.yml
-- Unmapped:     (none)
-- False Pos:    Unlikely, since this event notifies about blocked application deployment. Tune your applocker rules to avoid blocking legitimate applications.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId IN ('441', '442', '453', '454')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely, since this event notifies about blocked application deployment. Tune your applocker rules to avoid blocking legitimate applications.

**References:**
- https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
- https://github.com/nasbench/EVTX-ETW-Resources/blob/7a806a148b3d9d381193d4a80356016e6e8b1ee8/ETWEventsList/CSV/Windows11/22H2/W11_22H2_Pro_20220920_22621.382/Providers/Microsoft-Windows-AppXDeployment-Server.csv

---

## AppX Located in Uncommon Directory Added to Deployment Pipeline

| Field | Value |
|---|---|
| **Sigma ID** | `c977cb50-3dff-4a9f-b873-9290f56132f1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_uncommon_package_locations.yml)**

> Detects an appx package that was added to the pipeline of the "to be processed" packages that is located in uncommon locations.


```sql
-- ============================================================
-- Title:        AppX Located in Uncommon Directory Added to Deployment Pipeline
-- Sigma ID:     c977cb50-3dff-4a9f-b873-9290f56132f1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2023-01-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_uncommon_package_locations.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND winEventId = '854'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- Internal Research
- https://www.sentinelone.com/labs/inside-malicious-windows-apps-for-malware-deployment/
- https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting
- https://news.sophos.com/en-us/2021/11/11/bazarloader-call-me-back-attack-abuses-windows-10-apps-mechanism/

---

## Windows AppX Deployment Full Trust Package Installation

| Field | Value |
|---|---|
| **Sigma ID** | `e54279c7-4910-4e2c-902c-c56a25b549f6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002, T1553.005 |
| **Author** | Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxpackaging_server_full_trust_package_installation.yml)**

> Detects the installation of MSIX/AppX packages with full trust privileges which run with elevated privileges outside normal AppX container restrictions

```sql
-- ============================================================
-- Title:        Windows AppX Deployment Full Trust Package Installation
-- Sigma ID:     e54279c7-4910-4e2c-902c-c56a25b549f6
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution | T1204.002, T1553.005
-- Author:       Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxpackaging_server_full_trust_package_installation.yml
-- Unmapped:     HasFullTrust
-- False Pos:    Some legitimate applications installation which have been missed from filtering can generate fps, thus baselining and tuning is recommended before deploying to production
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server
-- UNMAPPED_FIELD: HasFullTrust

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '400'
    AND rawEventMsg = 'True')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some legitimate applications installation which have been missed from filtering can generate fps, thus baselining and tuning is recommended before deploying to production

**References:**
- https://www.splunk.com/en_us/blog/security/msix-weaponization-threat-detection-splunk.html

---

## Windows AppX Deployment Unsigned Package Installation

| Field | Value |
|---|---|
| **Sigma ID** | `9a025188-6f2d-42f8-bb2f-d3a83d24a5af` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1204.002, T1553.005 |
| **Author** | Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxpackaging_server_unsigned_package_installation.yml)**

> Detects attempts to install unsigned MSIX/AppX packages using the -AllowUnsigned parameter via AppXDeployment-Server events

```sql
-- ============================================================
-- Title:        Windows AppX Deployment Unsigned Package Installation
-- Sigma ID:     9a025188-6f2d-42f8-bb2f-d3a83d24a5af
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        execution | T1204.002, T1553.005
-- Author:       Michael Haag, Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-11-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/appxdeployment_server/win_appxpackaging_server_unsigned_package_installation.yml
-- Unmapped:     Flags
-- False Pos:    Legitimate installation of unsigned packages for legitimate purposes such as development or testing
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/appxdeployment-server
-- UNMAPPED_FIELD: Flags

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  winEventId,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (winEventId = '603'
    AND rawEventMsg = '8388608')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate installation of unsigned packages for legitimate purposes such as development or testing

**References:**
- https://docs.microsoft.com/en-us/powershell/module/appx/add-appxpackage
- https://www.splunk.com/en_us/blog/security/msix-weaponization-threat-detection-splunk.html

---
