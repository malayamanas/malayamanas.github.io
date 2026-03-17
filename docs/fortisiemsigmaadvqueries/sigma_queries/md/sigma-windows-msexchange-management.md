# Sigma → FortiSIEM: Windows Msexchange-Management

> 7 rules · Generated 2026-03-17

## Table of Contents

- [ProxyLogon MSExchange OabVirtualDirectory](#proxylogon-msexchange-oabvirtualdirectory)
- [Certificate Request Export to Exchange Webserver](#certificate-request-export-to-exchange-webserver)
- [Mailbox Export to Exchange Webserver](#mailbox-export-to-exchange-webserver)
- [Remove Exported Mailbox from Exchange Webserver](#remove-exported-mailbox-from-exchange-webserver)
- [Exchange Set OabVirtualDirectory ExternalUrl Property](#exchange-set-oabvirtualdirectory-externalurl-property)
- [MSExchange Transport Agent Installation - Builtin](#msexchange-transport-agent-installation-builtin)
- [Failed MSExchange Transport Agent Installation](#failed-msexchange-transport-agent-installation)

## ProxyLogon MSExchange OabVirtualDirectory

| Field | Value |
|---|---|
| **Sigma ID** | `550d3350-bb8a-4ff3-9533-2ba533f4a1c0` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Techniques** | T1587.001 |
| **Author** | Florian Roth (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxylogon_oabvirtualdir.yml)**

> Detects specific patterns found after a successful ProxyLogon exploitation in relation to a Commandlet invocation of Set-OabVirtualDirectory

```sql
-- ============================================================
-- Title:        ProxyLogon MSExchange OabVirtualDirectory
-- Sigma ID:     550d3350-bb8a-4ff3-9533-2ba533f4a1c0
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        T1587.001
-- Author:       Florian Roth (Nextron Systems)
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxylogon_oabvirtualdir.yml
-- Unmapped:     
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%OabVirtualDirectory%' OR rawEventMsg LIKE '% -ExternalUrl %')
  AND rawEventMsg LIKE '%eval(request%' OR rawEventMsg LIKE '%http://f/<script%' OR rawEventMsg LIKE '%"unsafe"};%' OR rawEventMsg LIKE '%function Page\_Load()%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://bi-zone.medium.com/hunting-down-ms-exchange-attacks-part-1-proxylogon-cve-2021-26855-26858-27065-26857-6e885c5f197c

---

## Certificate Request Export to Exchange Webserver

| Field | Value |
|---|---|
| **Sigma ID** | `b7bc7038-638b-4ffd-880c-292c692209ef` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Max Altgelt (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxyshell_certificate_generation.yml)**

> Detects a write of an Exchange CSR to an untypical directory or with aspx name suffix which can be used to place a webshell

```sql
-- ============================================================
-- Title:        Certificate Request Export to Exchange Webserver
-- Sigma ID:     b7bc7038-638b-4ffd-880c-292c692209ef
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Max Altgelt (Nextron Systems)
-- Date:         2021-08-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxyshell_certificate_generation.yml
-- Unmapped:     
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%New-ExchangeCertificate%' OR rawEventMsg LIKE '% -GenerateRequest%' OR rawEventMsg LIKE '% -BinaryEncoded%' OR rawEventMsg LIKE '% -RequestFile%')
  AND rawEventMsg LIKE '%\\\\\\\\localhost\\\\C$%' OR rawEventMsg LIKE '%\\\\\\\\127.0.0.1\\\\C$%' OR rawEventMsg LIKE '%C:\\\\inetpub%' OR rawEventMsg LIKE '%.aspx%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://twitter.com/GossiTheDog/status/1429175908905127938

---

## Mailbox Export to Exchange Webserver

| Field | Value |
|---|---|
| **Sigma ID** | `516376b4-05cd-4122-bae0-ad7641c38d48` |
| **Level** | critical |
| **FSM Severity** | 9 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Florian Roth (Nextron Systems), Rich Warren, Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxyshell_mailbox_export.yml)**

> Detects a successful export of an Exchange mailbox to untypical directory or with aspx name suffix which can be used to place a webshell or the needed role assignment for it

```sql
-- ============================================================
-- Title:        Mailbox Export to Exchange Webserver
-- Sigma ID:     516376b4-05cd-4122-bae0-ad7641c38d48
-- Level:        critical  |  FSM Severity: 9
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Florian Roth (Nextron Systems), Rich Warren, Christian Burkard (Nextron Systems)
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxyshell_mailbox_export.yml
-- Unmapped:     
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%New-MailboxExportRequest%' OR rawEventMsg LIKE '% -Mailbox %')
  AND rawEventMsg LIKE '%-FilePath "\\\\\\\\%' OR rawEventMsg LIKE '%.aspx%')
  OR (rawEventMsg LIKE '%New-ManagementRoleAssignment%' OR rawEventMsg LIKE '% -Role "Mailbox Import Export"%' OR rawEventMsg LIKE '% -User %')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html

---

## Remove Exported Mailbox from Exchange Webserver

| Field | Value |
|---|---|
| **Sigma ID** | `09570ae5-889e-43ea-aac0-0e1221fb3d95` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070 |
| **Author** | Christian Burkard (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxyshell_remove_mailbox_export.yml)**

> Detects removal of an exported Exchange mailbox which could be to cover tracks from ProxyShell exploit

```sql
-- ============================================================
-- Title:        Remove Exported Mailbox from Exchange Webserver
-- Sigma ID:     09570ae5-889e-43ea-aac0-0e1221fb3d95
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070
-- Author:       Christian Burkard (Nextron Systems)
-- Date:         2021-08-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_proxyshell_remove_mailbox_export.yml
-- Unmapped:     
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Remove-MailboxExportRequest%' OR rawEventMsg LIKE '% -Identity %' OR rawEventMsg LIKE '% -Confirm "False"%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/rapid7/metasploit-framework/blob/1416b5776d963f21b7b5b45d19f3e961201e0aed/modules/exploits/windows/http/exchange_proxyshell_rce.rb#L430

---

## Exchange Set OabVirtualDirectory ExternalUrl Property

| Field | Value |
|---|---|
| **Sigma ID** | `9db37458-4df2-46a5-95ab-307e7f29e675` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.003 |
| **Author** | Jose Rodriguez @Cyb3rPandaH |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_set_oabvirtualdirectory_externalurl.yml)**

> Rule to detect an adversary setting OabVirtualDirectory External URL property to a script in Exchange Management log

```sql
-- ============================================================
-- Title:        Exchange Set OabVirtualDirectory ExternalUrl Property
-- Sigma ID:     9db37458-4df2-46a5-95ab-307e7f29e675
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.003
-- Author:       Jose Rodriguez @Cyb3rPandaH
-- Date:         2021-03-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_set_oabvirtualdirectory_externalurl.yml
-- Unmapped:     
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management
-- UNSUPPORTED_MODIFIER: all

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%Set-OabVirtualDirectory%' OR rawEventMsg LIKE '%ExternalUrl%' OR rawEventMsg LIKE '%Page\_Load%' OR rawEventMsg LIKE '%script%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://twitter.com/OTR_Community/status/1371053369071132675

---

## MSExchange Transport Agent Installation - Builtin

| Field | Value |
|---|---|
| **Sigma ID** | `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.002 |
| **Author** | Tobias Michalski (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_transportagent.yml)**

> Detects the Installation of a Exchange Transport Agent

```sql
-- ============================================================
-- Title:        MSExchange Transport Agent Installation - Builtin
-- Sigma ID:     4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1505.002
-- Author:       Tobias Michalski (Nextron Systems)
-- Date:         2021-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_transportagent.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%Install-TransportAgent%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=7

---

## Failed MSExchange Transport Agent Installation

| Field | Value |
|---|---|
| **Sigma ID** | `c7d16cae-aaf3-42e5-9c1c-fb8553faa6fa` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1505.002 |
| **Author** | Tobias Michalski (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_transportagent_failed.yml)**

> Detects a failed installation of a Exchange Transport Agent

```sql
-- ============================================================
-- Title:        Failed MSExchange Transport Agent Installation
-- Sigma ID:     c7d16cae-aaf3-42e5-9c1c-fb8553faa6fa
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1505.002
-- Author:       Tobias Michalski (Nextron Systems)
-- Date:         2021-06-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/msexchange/win_exchange_transportagent_failed.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/msexchange-management

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
  AND (winEventId = '6'
    AND rawEventMsg LIKE '%Install-TransportAgent%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.

**References:**
- https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=8

---
