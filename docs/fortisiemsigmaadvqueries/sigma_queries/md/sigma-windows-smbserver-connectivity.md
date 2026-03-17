# Sigma → FortiSIEM: Windows Smbserver-Connectivity

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Unsigned or Unencrypted SMB Connection to Share Established](#unsigned-or-unencrypted-smb-connection-to-share-established)

## Unsigned or Unencrypted SMB Connection to Share Established

| Field | Value |
|---|---|
| **Sigma ID** | `8d91f6e4-9f3b-4c21-ae41-2c5b7d9f7a12` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.002 |
| **Author** | Mohamed Abdelghani |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/smbserver/connectivity/win_smbserver_connectivity_unsigned_and_unencrypted_share_connection.yml)**

> Detects SMB server connections to shares without signing or encryption enabled.
This could indicate potential lateral movement activity using unsecured SMB shares.


```sql
-- ============================================================
-- Title:        Unsigned or Unencrypted SMB Connection to Share Established
-- Sigma ID:     8d91f6e4-9f3b-4c21-ae41-2c5b7d9f7a12
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1021.002
-- Author:       Mohamed Abdelghani
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/smbserver/connectivity/win_smbserver_connectivity_unsigned_and_unencrypted_share_connection.yml
-- Unmapped:     (none)
-- False Pos:    Connections from local or private IP addresses to SMB shares without signing or encryption enabled for older systems or misconfigured environments. Apply additional tuning as needed.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/smbserver-connectivity

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Connections from local or private IP addresses to SMB shares without signing or encryption enabled for older systems or misconfigured environments. Apply additional tuning as needed.

**References:**
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing

---
