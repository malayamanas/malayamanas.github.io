# Sigma → FortiSIEM: Cisco Aaa

> 12 rules · Generated 2026-03-17

## Table of Contents

- [Cisco Clear Logs](#cisco-clear-logs)
- [Cisco Collect Data](#cisco-collect-data)
- [Cisco Crypto Commands](#cisco-crypto-commands)
- [Cisco Disabling Logging](#cisco-disabling-logging)
- [Cisco Discovery](#cisco-discovery)
- [Cisco Denial of Service](#cisco-denial-of-service)
- [Cisco File Deletion](#cisco-file-deletion)
- [Cisco Show Commands Input](#cisco-show-commands-input)
- [Cisco Local Accounts](#cisco-local-accounts)
- [Cisco Modify Configuration](#cisco-modify-configuration)
- [Cisco Stage Data](#cisco-stage-data)
- [Cisco Sniffing](#cisco-sniffing)

## Cisco Clear Logs

| Field | Value |
|---|---|
| **Sigma ID** | `ceb407f6-8277-439b-951f-e4210e3ed956` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1070.003 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_clear_logs.yml)**

> Clear command history in network OS which is used for defense evasion

```sql
-- ============================================================
-- Title:        Cisco Clear Logs
-- Sigma ID:     ceb407f6-8277-439b-951f-e4210e3ed956
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1070.003
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_clear_logs.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrators may run these commands
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%clear logging%' OR rawEventMsg LIKE '%clear archive%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrators may run these commands

**References:**
- https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/command/reference/sysmgmt/n5k-sysmgmt-cr/n5k-sm_cmds_c.html
- https://www.cisco.com/c/en/us/td/docs/ios/12_2sr/12_2sra/feature/guide/srmgtint.html#wp1127609

---

## Cisco Collect Data

| Field | Value |
|---|---|
| **Sigma ID** | `cd072b25-a418-4f98-8ebc-5093fb38fe1a` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery, collection |
| **MITRE Techniques** | T1087.001, T1552.001, T1005 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_collect_data.yml)**

> Collect pertinent data from the configuration files

```sql
-- ============================================================
-- Title:        Cisco Collect Data
-- Sigma ID:     cd072b25-a418-4f98-8ebc-5093fb38fe1a
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery, collection | T1087.001, T1552.001, T1005
-- Author:       Austin Clark
-- Date:         2019-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_collect_data.yml
-- Unmapped:     (none)
-- False Pos:    Commonly run by administrators
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%show running-config%' OR rawEventMsg LIKE '%show startup-config%' OR rawEventMsg LIKE '%show archive config%' OR rawEventMsg LIKE '%more%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Commonly run by administrators

**References:**
- https://blog.router-switch.com/2013/11/show-running-config/
- https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/show_startup-config.htm
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/config-mgmt/configuration/15-sy/config-mgmt-15-sy-book/cm-config-diff.html

---

## Cisco Crypto Commands

| Field | Value |
|---|---|
| **Sigma ID** | `1f978c6a-4415-47fb-aca5-736a44d7ca3d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1553.004, T1552.004 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_crypto_actions.yml)**

> Show when private keys are being exported from the device, or when new certificates are installed

```sql
-- ============================================================
-- Title:        Cisco Crypto Commands
-- Sigma ID:     1f978c6a-4415-47fb-aca5-736a44d7ca3d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1553.004, T1552.004
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_crypto_actions.yml
-- Unmapped:     (none)
-- False Pos:    Not commonly run by administrators. Also whitelist your known good certificates
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%crypto pki export%' OR rawEventMsg LIKE '%crypto pki import%' OR rawEventMsg LIKE '%crypto pki trustpoint%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Not commonly run by administrators. Also whitelist your known good certificates

**References:**
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-a1-cr-book_chapter_0111.html

---

## Cisco Disabling Logging

| Field | Value |
|---|---|
| **Sigma ID** | `9e8f6035-88bf-4a63-96b6-b17c0508257e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_disable_logging.yml)**

> Turn off logging locally or remote

```sql
-- ============================================================
-- Title:        Cisco Disabling Logging
-- Sigma ID:     9e8f6035-88bf-4a63-96b6-b17c0508257e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       Austin Clark
-- Date:         2019-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_disable_logging.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%no logging%' OR rawEventMsg LIKE '%no aaa new-model%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.cisco.com/en/US/docs/ios/security/command/reference/sec_a2.pdf

---

## Cisco Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `9705a6a1-6db6-4a16-a987-15b7151e299b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1083, T1201, T1057, T1018, T1082, T1016, T1049, T1033, T1124 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_discovery.yml)**

> Find information about network devices that is not stored in config files

```sql
-- ============================================================
-- Title:        Cisco Discovery
-- Sigma ID:     9705a6a1-6db6-4a16-a987-15b7151e299b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1083, T1201, T1057, T1018, T1082, T1016, T1049, T1033, T1124
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_discovery.yml
-- Unmapped:     (none)
-- False Pos:    Commonly used by administrators for troubleshooting
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%dir%' OR rawEventMsg LIKE '%show arp%' OR rawEventMsg LIKE '%show cdp%' OR rawEventMsg LIKE '%show clock%' OR rawEventMsg LIKE '%show ip interface%' OR rawEventMsg LIKE '%show ip route%' OR rawEventMsg LIKE '%show ip sockets%' OR rawEventMsg LIKE '%show processes%' OR rawEventMsg LIKE '%show ssh%' OR rawEventMsg LIKE '%show users%' OR rawEventMsg LIKE '%show version%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Commonly used by administrators for troubleshooting

**References:**
- https://www.cisco.com/c/en/us/td/docs/server_nw_virtual/2-5_release/command_reference/show.html

---

## Cisco Denial of Service

| Field | Value |
|---|---|
| **Sigma ID** | `d94a35f0-7a29-45f6-90a0-80df6159967c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1495, T1529, T1565.001 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_dos.yml)**

> Detect a system being shutdown or put into different boot mode

```sql
-- ============================================================
-- Title:        Cisco Denial of Service
-- Sigma ID:     d94a35f0-7a29-45f6-90a0-80df6159967c
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1495, T1529, T1565.001
-- Author:       Austin Clark
-- Date:         2019-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_dos.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrators may run these commands, though rarely.
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%shutdown%' OR rawEventMsg LIKE '%config-register 0x2100%' OR rawEventMsg LIKE '%config-register 0x2142%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrators may run these commands, though rarely.

---

## Cisco File Deletion

| Field | Value |
|---|---|
| **Sigma ID** | `71d65515-c436-43c0-841b-236b1f32c21e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1070.004, T1561.001, T1561.002 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_file_deletion.yml)**

> See what files are being deleted from flash file systems

```sql
-- ============================================================
-- Title:        Cisco File Deletion
-- Sigma ID:     71d65515-c436-43c0-841b-236b1f32c21e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1070.004, T1561.001, T1561.002
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_file_deletion.yml
-- Unmapped:     (none)
-- False Pos:    Will be used sometimes by admins to clean up local flash space
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%erase%' OR rawEventMsg LIKE '%delete%' OR rawEventMsg LIKE '%format%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Will be used sometimes by admins to clean up local flash space

---

## Cisco Show Commands Input

| Field | Value |
|---|---|
| **Sigma ID** | `b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552.003 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_input_capture.yml)**

> See what commands are being input into the device by other people, full credentials can be in the history

```sql
-- ============================================================
-- Title:        Cisco Show Commands Input
-- Sigma ID:     b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552.003
-- Author:       Austin Clark
-- Date:         2019-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_input_capture.yml
-- Unmapped:     (none)
-- False Pos:    Not commonly run by administrators, especially if remote logging is configured
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%show history%' OR rawEventMsg LIKE '%show history all%' OR rawEventMsg LIKE '%show logging%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Not commonly run by administrators, especially if remote logging is configured

---

## Cisco Local Accounts

| Field | Value |
|---|---|
| **Sigma ID** | `6d844f0f-1c18-41af-8f19-33e7654edfc3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001, T1098 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_local_accounts.yml)**

> Find local accounts being created or modified as well as remote authentication configurations

```sql
-- ============================================================
-- Title:        Cisco Local Accounts
-- Sigma ID:     6d844f0f-1c18-41af-8f19-33e7654edfc3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1136.001, T1098
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_local_accounts.yml
-- Unmapped:     (none)
-- False Pos:    When remote authentication is in place, this should not change often
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%username%' OR rawEventMsg LIKE '%aaa%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** When remote authentication is in place, this should not change often

---

## Cisco Modify Configuration

| Field | Value |
|---|---|
| **Sigma ID** | `671ffc77-50a7-464f-9e3d-9ea2b493b26b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | execution, persistence, impact |
| **MITRE Techniques** | T1490, T1505, T1565.002, T1053 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_modify_config.yml)**

> Modifications to a config that will serve an adversary's impacts or persistence

```sql
-- ============================================================
-- Title:        Cisco Modify Configuration
-- Sigma ID:     671ffc77-50a7-464f-9e3d-9ea2b493b26b
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        execution, persistence, impact | T1490, T1505, T1565.002, T1053
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_modify_config.yml
-- Unmapped:     (none)
-- False Pos:    Legitimate administrators may run these commands
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%ip http server%' OR rawEventMsg LIKE '%ip https server%' OR rawEventMsg LIKE '%kron policy-list%' OR rawEventMsg LIKE '%kron occurrence%' OR rawEventMsg LIKE '%policy-list%' OR rawEventMsg LIKE '%access-list%' OR rawEventMsg LIKE '%ip access-group%' OR rawEventMsg LIKE '%archive maximum%' OR rawEventMsg LIKE '%ntp server%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrators may run these commands

---

## Cisco Stage Data

| Field | Value |
|---|---|
| **Sigma ID** | `5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection, exfiltration |
| **MITRE Techniques** | T1074, T1105, T1560.001 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_moving_data.yml)**

> Various protocols maybe used to put data on the device for exfil or infil

```sql
-- ============================================================
-- Title:        Cisco Stage Data
-- Sigma ID:     5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection, exfiltration | T1074, T1105, T1560.001
-- Author:       Austin Clark
-- Date:         2019-08-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_moving_data.yml
-- Unmapped:     (none)
-- False Pos:    Generally used to copy configs or IOS images
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%tftp%' OR rawEventMsg LIKE '%rcp%' OR rawEventMsg LIKE '%puts%' OR rawEventMsg LIKE '%copy%' OR rawEventMsg LIKE '%configure replace%' OR rawEventMsg LIKE '%archive tar%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Generally used to copy configs or IOS images

---

## Cisco Sniffing

| Field | Value |
|---|---|
| **Sigma ID** | `b9e1f193-d236-4451-aaae-2f3d2102120d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1040 |
| **Author** | Austin Clark |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_net_sniff.yml)**

> Show when a monitor or a span/rspan is setup or modified

```sql
-- ============================================================
-- Title:        Cisco Sniffing
-- Sigma ID:     b9e1f193-d236-4451-aaae-2f3d2102120d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        discovery | T1040
-- Author:       Austin Clark
-- Date:         2019-08-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/cisco/aaa/cisco_cli_net_sniff.yml
-- Unmapped:     (none)
-- False Pos:    Admins may setup new or modify old spans, or use a monitor for troubleshooting
-- ============================================================
-- UNMAPPED_LOGSOURCE: cisco/aaa

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%monitor capture point%' OR rawEventMsg LIKE '%set span%' OR rawEventMsg LIKE '%set rspan%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Admins may setup new or modify old spans, or use a monitor for troubleshooting

---
