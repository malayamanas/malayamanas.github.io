# Sigma → FortiSIEM: Windows Ntlm

> 3 rules · Generated 2026-03-17

## Table of Contents

- [NTLM Logon](#ntlm-logon)
- [NTLM Brute Force](#ntlm-brute-force)
- [Potential Remote Desktop Connection to Non-Domain Host](#potential-remote-desktop-connection-to-non-domain-host)

## NTLM Logon

| Field | Value |
|---|---|
| **Sigma ID** | `98c3bcf1-56f2-49dc-9d8d-c66cf190238b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1550.002 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ntlm/win_susp_ntlm_auth.yml)**

> Detects logons using NTLM, which could be caused by a legacy source or attackers

```sql
-- ============================================================
-- Title:        NTLM Logon
-- Sigma ID:     98c3bcf1-56f2-49dc-9d8d-c66cf190238b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1550.002
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2018-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ntlm/win_susp_ntlm_auth.yml
-- Unmapped:     (none)
-- False Pos:    Legacy hosts
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ntlm

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
  AND winEventId = '8002'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legacy hosts

**References:**
- https://twitter.com/JohnLaTwC/status/1004895028995477505

---

## NTLM Brute Force

| Field | Value |
|---|---|
| **Sigma ID** | `9c8acf1a-cbf9-4db6-b63c-74baabe03e59` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1110 |
| **Author** | Jerry Shockley '@jsh0x' |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ntlm/win_susp_ntlm_brute_force.yml)**

> Detects common NTLM brute force device names

```sql
-- ============================================================
-- Title:        NTLM Brute Force
-- Sigma ID:     9c8acf1a-cbf9-4db6-b63c-74baabe03e59
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1110
-- Author:       Jerry Shockley '@jsh0x'
-- Date:         2022-02-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ntlm/win_susp_ntlm_brute_force.yml
-- Unmapped:     WorkstationName
-- False Pos:    Systems with names equal to the spoofed ones used by the brute force tools
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ntlm
-- UNMAPPED_FIELD: WorkstationName

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
  AND (winEventId = '8004'
  AND rawEventMsg IN ('Rdesktop', 'Remmina', 'Freerdp', 'Windows7', 'Windows8', 'Windows2012', 'Windows2016', 'Windows2019'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Systems with names equal to the spoofed ones used by the brute force tools

**References:**
- https://www.varonis.com/blog/investigate-ntlm-brute-force

---

## Potential Remote Desktop Connection to Non-Domain Host

| Field | Value |
|---|---|
| **Sigma ID** | `ce5678bb-b9aa-4fb5-be4b-e57f686256ad` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1219.002 |
| **Author** | James Pemberton |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ntlm/win_susp_ntlm_rdp.yml)**

> Detects logons using NTLM to hosts that are potentially not part of the domain.

```sql
-- ============================================================
-- Title:        Potential Remote Desktop Connection to Non-Domain Host
-- Sigma ID:     ce5678bb-b9aa-4fb5-be4b-e57f686256ad
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1219.002
-- Author:       James Pemberton
-- Date:         2020-05-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/ntlm/win_susp_ntlm_rdp.yml
-- Unmapped:     TargetName
-- False Pos:    Host connections to valid domains, exclude these.; Host connections not using host FQDN.; Host connections to external legitimate domains.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/ntlm
-- UNMAPPED_FIELD: TargetName

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
  AND (winEventId = '8001'
    AND rawEventMsg LIKE 'TERMSRV%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Host connections to valid domains, exclude these.; Host connections not using host FQDN.; Host connections to external legitimate domains.

**References:**
- n/a

---
