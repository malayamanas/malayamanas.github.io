# Sigma → FortiSIEM: Windows Openssh

> 1 rule · Generated 2026-03-17

## Table of Contents

- [OpenSSH Server Listening On Socket](#openssh-server-listening-on-socket)

## OpenSSH Server Listening On Socket

| Field | Value |
|---|---|
| **Sigma ID** | `3ce8e9a4-bc61-4c9b-8e69-d7e2492a8781` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.004 |
| **Author** | mdecrevoisier |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/openssh/win_sshd_openssh_server_listening_on_socket.yml)**

> Detects scenarios where an attacker enables the OpenSSH server and server starts to listening on SSH socket.

```sql
-- ============================================================
-- Title:        OpenSSH Server Listening On Socket
-- Sigma ID:     3ce8e9a4-bc61-4c9b-8e69-d7e2492a8781
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.004
-- Author:       mdecrevoisier
-- Date:         2022-10-25
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/openssh/win_sshd_openssh_server_listening_on_socket.yml
-- Unmapped:     process, payload
-- False Pos:    Legitimate administrator activity
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/openssh
-- UNMAPPED_FIELD: process
-- UNMAPPED_FIELD: payload

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
  AND (winEventId = '4'
    AND rawEventMsg = 'sshd'
    AND rawEventMsg LIKE 'Server listening on %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrator activity

**References:**
- https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH
- https://winaero.com/enable-openssh-server-windows-10/
- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
- https://virtualizationreview.com/articles/2020/05/21/ssh-server-on-windows-10.aspx
- https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16

---
