# Sigma → FortiSIEM: Windows Lsa-Server

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Standard User In High Privileged Group](#standard-user-in-high-privileged-group)

## Standard User In High Privileged Group

| Field | Value |
|---|---|
| **Sigma ID** | `7ac407cc-0f48-4328-aede-de1d2e6fef41` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/lsa_server/win_lsa_server_normal_user_admin.yml)**

> Detect standard users login that are part of high privileged groups such as the Administrator group

```sql
-- ============================================================
-- Title:        Standard User In High Privileged Group
-- Sigma ID:     7ac407cc-0f48-4328-aede-de1d2e6fef41
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        (none)
-- Author:       frack113
-- Date:         2023-01-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/lsa_server/win_lsa_server_normal_user_admin.yml
-- Unmapped:     TargetUserSid, SidList
-- False Pos:    Standard domain users who are part of the administrator group. These users shouldn't have these right. But in the case where it's necessary. They should be filtered out using the "TargetUserName" field
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/lsa-server
-- UNMAPPED_FIELD: TargetUserSid
-- UNMAPPED_FIELD: SidList

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
  AND (winEventId = '300'
    AND rawEventMsg LIKE 'S-1-5-21-%'
    AND (rawEventMsg LIKE '%S-1-5-32-544%' OR rawEventMsg LIKE '%-500}%' OR rawEventMsg LIKE '%-518}%' OR rawEventMsg LIKE '%-519}%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Standard domain users who are part of the administrator group. These users shouldn't have these right. But in the case where it's necessary. They should be filtered out using the "TargetUserName" field

**References:**
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- https://github.com/nasbench/EVTX-ETW-Resources/blob/7a806a148b3d9d381193d4a80356016e6e8b1ee8/ETWProvidersManifests/Windows11/22H2/W11_22H2_Pro_20221220_22621.963/WEPExplorer/LsaSrv.xml

---
