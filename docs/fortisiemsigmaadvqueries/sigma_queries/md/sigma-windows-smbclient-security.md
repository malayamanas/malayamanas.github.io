# Sigma → FortiSIEM: Windows Smbclient-Security

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious Rejected SMB Guest Logon From IP](#suspicious-rejected-smb-guest-logon-from-ip)

## Suspicious Rejected SMB Guest Logon From IP

| Field | Value |
|---|---|
| **Sigma ID** | `71886b70-d7b4-4dbf-acce-87d2ca135262` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1110.001 |
| **Author** | Florian Roth (Nextron Systems), KevTheHermit, fuzzyf10w |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/smbclient/security/win_smbclient_security_susp_failed_guest_logon.yml)**

> Detect Attempt PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service

```sql
-- ============================================================
-- Title:        Suspicious Rejected SMB Guest Logon From IP
-- Sigma ID:     71886b70-d7b4-4dbf-acce-87d2ca135262
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1110.001
-- Author:       Florian Roth (Nextron Systems), KevTheHermit, fuzzyf10w
-- Date:         2021-06-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/smbclient/security/win_smbclient_security_susp_failed_guest_logon.yml
-- Unmapped:     UserName, ServerName
-- False Pos:    Account fallback reasons (after failed login with specific account)
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/smbclient-security
-- UNMAPPED_FIELD: UserName
-- UNMAPPED_FIELD: ServerName

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
  AND (winEventId = '31017'
    AND rawEventMsg = ''
    AND rawEventMsg LIKE '\\1%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Account fallback reasons (after failed login with specific account)

**References:**
- https://twitter.com/KevTheHermit/status/1410203844064301056
- https://web.archive.org/web/20210629055600/https://github.com/hhlxf/PrintNightmare/
- https://web.archive.org/web/20210701042336/https://github.com/afwu/PrintNightmare

---
