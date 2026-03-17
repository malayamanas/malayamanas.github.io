# Sigma → FortiSIEM: Linux Vsftpd

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious VSFTPD Error Messages](#suspicious-vsftpd-error-messages)

## Suspicious VSFTPD Error Messages

| Field | Value |
|---|---|
| **Sigma ID** | `377f33a1-4b36-4ee1-acee-1dbe4b43cfbe` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml)**

> Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

```sql
-- ============================================================
-- Title:        Suspicious VSFTPD Error Messages
-- Sigma ID:     377f33a1-4b36-4ee1-acee-1dbe4b43cfbe
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-07-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux/vsftpd

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Connection refused: too many sessions for this address.%' OR rawEventMsg LIKE '%Connection refused: tcp\_wrappers denial.%' OR rawEventMsg LIKE '%Bad HTTP verb.%' OR rawEventMsg LIKE '%port and pasv both active%' OR rawEventMsg LIKE '%pasv and port both active%' OR rawEventMsg LIKE '%Transfer done (but failed to open directory).%' OR rawEventMsg LIKE '%Could not set file modification time.%' OR rawEventMsg LIKE '%bug: pid active in ptrace\_sandbox\_free%' OR rawEventMsg LIKE '%PTRACE\_SETOPTIONS failure%' OR rawEventMsg LIKE '%weird status:%' OR rawEventMsg LIKE '%couldn't handle sandbox event%' OR rawEventMsg LIKE '%syscall * out of bounds%' OR rawEventMsg LIKE '%syscall not permitted:%' OR rawEventMsg LIKE '%syscall validate failed:%' OR rawEventMsg LIKE '%Input line too long.%' OR rawEventMsg LIKE '%poor buffer accounting in str\_netfd\_alloc%' OR rawEventMsg LIKE '%vsf\_sysutil\_read\_loop%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/dagwieers/vsftpd/

---
