# Sigma → FortiSIEM: Linux Sshd

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious OpenSSH Daemon Error](#suspicious-openssh-daemon-error)

## Suspicious OpenSSH Daemon Error

| Field | Value |
|---|---|
| **Sigma ID** | `e76b413a-83d0-4b94-8e4c-85db4a5b8bdc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml)**

> Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts

```sql
-- ============================================================
-- Title:        Suspicious OpenSSH Daemon Error
-- Sigma ID:     e76b413a-83d0-4b94-8e4c-85db4a5b8bdc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2017-06-30
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: linux/sshd

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%unexpected internal error%' OR rawEventMsg LIKE '%unknown or unsupported key type%' OR rawEventMsg LIKE '%invalid certificate signing key%' OR rawEventMsg LIKE '%invalid elliptic curve value%' OR rawEventMsg LIKE '%incorrect signature%' OR rawEventMsg LIKE '%error in libcrypto%' OR rawEventMsg LIKE '%unexpected bytes remain after decoding%' OR rawEventMsg LIKE '%fatal: buffer\_get\_string: bad string%' OR rawEventMsg LIKE '%Local: crc32 compensation attack%' OR rawEventMsg LIKE '%bad client public DH value%' OR rawEventMsg LIKE '%Corrupted MAC on input%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/openssh/openssh-portable/blob/c483a5c0fb8e8b8915fad85c5f6113386a4341ca/ssherr.c
- https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/sshd_rules.xml

---
