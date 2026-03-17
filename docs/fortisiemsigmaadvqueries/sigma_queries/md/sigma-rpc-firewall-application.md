# Sigma → FortiSIEM: Rpc_Firewall Application

> 17 rules · Generated 2026-03-17

## Table of Contents

- [Remote Schedule Task Lateral Movement via ATSvc](#remote-schedule-task-lateral-movement-via-atsvc)
- [Remote Schedule Task Recon via AtScv](#remote-schedule-task-recon-via-atscv)
- [Possible DCSync Attack](#possible-dcsync-attack)
- [Remote Encrypting File System Abuse](#remote-encrypting-file-system-abuse)
- [Remote Event Log Recon](#remote-event-log-recon)
- [Remote Schedule Task Lateral Movement via ITaskSchedulerService](#remote-schedule-task-lateral-movement-via-itaskschedulerservice)
- [Remote Schedule Task Recon via ITaskSchedulerService](#remote-schedule-task-recon-via-itaskschedulerservice)
- [Remote Printing Abuse for Lateral Movement](#remote-printing-abuse-for-lateral-movement)
- [Remote DCOM/WMI Lateral Movement](#remote-dcomwmi-lateral-movement)
- [Remote Registry Lateral Movement](#remote-registry-lateral-movement)
- [Remote Registry Recon](#remote-registry-recon)
- [Remote Server Service Abuse](#remote-server-service-abuse)
- [Remote Server Service Abuse for Lateral Movement](#remote-server-service-abuse-for-lateral-movement)
- [Remote Schedule Task Lateral Movement via SASec](#remote-schedule-task-lateral-movement-via-sasec)
- [Recon Activity via SASec](#recon-activity-via-sasec)
- [SharpHound Recon Account Discovery](#sharphound-recon-account-discovery)
- [SharpHound Recon Sessions](#sharphound-recon-sessions)

## Remote Schedule Task Lateral Movement via ATSvc

| Field | Value |
|---|---|
| **Sigma ID** | `0fcd1c79-4eeb-4746-aba9-1b458f7a79cb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053, T1053.002 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_atsvc_lateral_movement.yml)**

> Detects remote RPC calls to create or execute a scheduled task via ATSvc

```sql
-- ============================================================
-- Title:        Remote Schedule Task Lateral Movement via ATSvc
-- Sigma ID:     0fcd1c79-4eeb-4746-aba9-1b458f7a79cb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053, T1053.002
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_atsvc_lateral_movement.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '1ff70682-0a51-30e8-076d-740be8cee98b'
    AND rawEventMsg IN ('0', '1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Schedule Task Recon via AtScv

| Field | Value |
|---|---|
| **Sigma ID** | `f177f2bc-5f3e-4453-b599-57eefce9a59c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_atsvc_recon.yml)**

> Detects remote RPC calls to read information about scheduled tasks via AtScv

```sql
-- ============================================================
-- Title:        Remote Schedule Task Recon via AtScv
-- Sigma ID:     f177f2bc-5f3e-4453-b599-57eefce9a59c
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_atsvc_recon.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND ((rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '1ff70682-0a51-30e8-076d-740be8cee98b')
  AND NOT (rawEventMsg IN ('0', '1')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
- https://github.com/zeronetworks/rpcfirewall
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Possible DCSync Attack

| Field | Value |
|---|---|
| **Sigma ID** | `56fda488-113e-4ce9-8076-afc2457922c3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_dcsync_attack.yml)**

> Detects remote RPC calls to MS-DRSR from non DC hosts, which could indicate DCSync / DCShadow attacks.

```sql
-- ============================================================
-- Title:        Possible DCSync Attack
-- Sigma ID:     56fda488-113e-4ce9-8076-afc2457922c3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_dcsync_attack.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND ((rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2')
  AND NOT (rawEventMsg IN ('0', '1', '12')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47?redirectedfrom=MSDN
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-DRSR.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Encrypting File System Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `5f92fff9-82e2-48eb-8fc1-8b133556a551` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_efs_abuse.yml)**

> Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR

```sql
-- ============================================================
-- Title:        Remote Encrypting File System Abuse
-- Sigma ID:     5f92fff9-82e2-48eb-8fc1-8b133556a551
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_efs_abuse.yml
-- Unmapped:     EventLog, InterfaceUuid
-- False Pos:    Legitimate usage of remote file encryption
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg IN ('df1941c5-fe89-4e79-bf10-463657acf44d', 'c681d488-d850-11d0-8c52-00c04fd90f7e'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate usage of remote file encryption

**References:**
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-EFSR.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Event Log Recon

| Field | Value |
|---|---|
| **Sigma ID** | `2053961f-44c7-4a64-b62d-f6e72800af0d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_eventlog_recon.yml)**

> Detects remote RPC calls to get event log information via EVEN or EVEN6

```sql
-- ============================================================
-- Title:        Remote Event Log Recon
-- Sigma ID:     2053961f-44c7-4a64-b62d-f6e72800af0d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_eventlog_recon.yml
-- Unmapped:     EventLog, InterfaceUuid
-- False Pos:    Remote administrative tasks on Windows Events
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg IN ('82273fdc-e32a-18c3-3f78-827929dc23ea', 'f6beaff7-1e19-4fbb-9f8f-b89e2018337c'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Remote administrative tasks on Windows Events

**References:**
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Schedule Task Lateral Movement via ITaskSchedulerService

| Field | Value |
|---|---|
| **Sigma ID** | `ace3ff54-e7fd-46bd-8ea0-74b49a0aca1d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1053, T1053.002 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_itaskschedulerservice_lateral_movement.yml)**

> Detects remote RPC calls to create or execute a scheduled task

```sql
-- ============================================================
-- Title:        Remote Schedule Task Lateral Movement via ITaskSchedulerService
-- Sigma ID:     ace3ff54-e7fd-46bd-8ea0-74b49a0aca1d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence, execution | T1053, T1053.002
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_itaskschedulerservice_lateral_movement.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '86d35949-83c9-4044-b424-db363231fd0c'
    AND rawEventMsg IN ('1', '3', '4', '10', '11', '12', '13', '14', '15'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Schedule Task Recon via ITaskSchedulerService

| Field | Value |
|---|---|
| **Sigma ID** | `7f7c49eb-2977-4ac8-8ab0-ab1bae14730e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_itaskschedulerservice_recon.yml)**

> Detects remote RPC calls to read information about scheduled tasks

```sql
-- ============================================================
-- Title:        Remote Schedule Task Recon via ITaskSchedulerService
-- Sigma ID:     7f7c49eb-2977-4ac8-8ab0-ab1bae14730e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_itaskschedulerservice_recon.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND ((rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '86d35949-83c9-4044-b424-db363231fd0c')
  AND NOT (rawEventMsg IN ('1', '3', '4', '10', '11', '12', '13', '14', '15')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Printing Abuse for Lateral Movement

| Field | Value |
|---|---|
| **Sigma ID** | `bc3a4b0c-e167-48e1-aa88-b3020950e560` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_printing_lateral_movement.yml)**

> Detects remote RPC calls to possibly abuse remote printing service via MS-RPRN / MS-PAR

```sql
-- ============================================================
-- Title:        Remote Printing Abuse for Lateral Movement
-- Sigma ID:     bc3a4b0c-e167-48e1-aa88-b3020950e560
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_printing_lateral_movement.yml
-- Unmapped:     EventLog, InterfaceUuid
-- False Pos:    Actual printing
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg IN ('12345678-1234-abcd-ef00-0123456789ab', '76f03f96-cdfd-44fc-a22c-64950a001209', '0b6edbfa-4a24-4fc6-8a23-942b1eca65d1', 'ae33069b-a2a8-46ee-a235-ddfd339be281'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Actual printing

**References:**
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pan/e44d984c-07d3-414c-8ffc-f8c8ad8512a8
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-RPRN-PAR.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote DCOM/WMI Lateral Movement

| Field | Value |
|---|---|
| **Sigma ID** | `68050b10-e477-4377-a99b-3721b422d6ef` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1021.003, T1047 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_dcom_or_wmi.yml)**

> Detects remote RPC calls that performs remote DCOM operations. These could be abused for lateral movement via DCOM or WMI.

```sql
-- ============================================================
-- Title:        Remote DCOM/WMI Lateral Movement
-- Sigma ID:     68050b10-e477-4377-a99b-3721b422d6ef
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1021.003, T1047
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_dcom_or_wmi.yml
-- Unmapped:     EventLog, InterfaceUuid
-- False Pos:    Some administrative tasks on remote host
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg IN ('4d9f4ab8-7d1c-11cf-861e-0020af6e7c57', '99fcfec4-5260-101b-bbcb-00aa0021347a', '000001a0-0000-0000-c000-000000000046', '00000131-0000-0000-c000-000000000046', '00000143-0000-0000-c000-000000000046', '00000000-0000-0000-c000-000000000046'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Some administrative tasks on remote host

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Registry Lateral Movement

| Field | Value |
|---|---|
| **Sigma ID** | `35c55673-84ca-4e99-8d09-e334f3c29539` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1112 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_registry_lateral_movement.yml)**

> Detects remote RPC calls to modify the registry and possible execute code

```sql
-- ============================================================
-- Title:        Remote Registry Lateral Movement
-- Sigma ID:     35c55673-84ca-4e99-8d09-e334f3c29539
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1112
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_registry_lateral_movement.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Remote administration of registry values
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '338cd001-2244-31f1-aaaa-900038001003'
    AND rawEventMsg IN ('6', '7', '8', '13', '18', '19', '21', '22', '23', '35'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Remote administration of registry values

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-RRP.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Registry Recon

| Field | Value |
|---|---|
| **Sigma ID** | `d8ffe17e-04be-4886-beb9-c1dd1944b9a8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_registry_recon.yml)**

> Detects remote RPC calls to collect information

```sql
-- ============================================================
-- Title:        Remote Registry Recon
-- Sigma ID:     d8ffe17e-04be-4886-beb9-c1dd1944b9a8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_registry_recon.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Remote administration of registry values
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND ((rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '338cd001-2244-31f1-aaaa-900038001003')
  AND NOT (rawEventMsg IN ('6', '7', '8', '13', '18', '19', '21', '22', '23', '35')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Remote administration of registry values

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-RRP.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Server Service Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `b6ea3cc7-542f-43ef-bbe4-980fbed444c7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_server_service_abuse.yml)**

> Detects remote RPC calls to possibly abuse remote encryption service via MS-SRVS

```sql
-- ============================================================
-- Title:        Remote Server Service Abuse
-- Sigma ID:     b6ea3cc7-542f-43ef-bbe4-980fbed444c7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        (none)
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_server_service_abuse.yml
-- Unmapped:     EventLog, InterfaceUuid
-- False Pos:    Legitimate remote share creation
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '4b324fc8-1670-01d3-1278-5a47bf6ee188')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate remote share creation

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-SRVS.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Server Service Abuse for Lateral Movement

| Field | Value |
|---|---|
| **Sigma ID** | `10018e73-06ec-46ec-8107-9172f1e04ff2` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1569.002 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_service_lateral_movement.yml)**

> Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR

```sql
-- ============================================================
-- Title:        Remote Server Service Abuse for Lateral Movement
-- Sigma ID:     10018e73-06ec-46ec-8107-9172f1e04ff2
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1569.002
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_remote_service_lateral_movement.yml
-- Unmapped:     EventLog, InterfaceUuid
-- False Pos:    Administrative tasks on remote services
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '367abb81-9844-35f1-ad32-98f038001003')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrative tasks on remote services

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-SCMR.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Remote Schedule Task Lateral Movement via SASec

| Field | Value |
|---|---|
| **Sigma ID** | `aff229ab-f8cd-447b-b215-084d11e79eb0` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1053, T1053.002 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sasec_lateral_movement.yml)**

> Detects remote RPC calls to create or execute a scheduled task via SASec

```sql
-- ============================================================
-- Title:        Remote Schedule Task Lateral Movement via SASec
-- Sigma ID:     aff229ab-f8cd-447b-b215-084d11e79eb0
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1053, T1053.002
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sasec_lateral_movement.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '378e52b0-c0a9-11cf-822d-00aa0051e40f'
    AND rawEventMsg IN ('0', '1'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## Recon Activity via SASec

| Field | Value |
|---|---|
| **Sigma ID** | `0a3ff354-93fc-4273-8a03-1078782de5b7` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sasec_recon.yml)**

> Detects remote RPC calls to read information about scheduled tasks via SASec

```sql
-- ============================================================
-- Title:        Recon Activity via SASec
-- Sigma ID:     0a3ff354-93fc-4273-8a03-1078782de5b7
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sasec_recon.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND ((rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '378e52b0-c0a9-11cf-822d-00aa0051e40f')
  AND NOT (rawEventMsg IN ('0', '1')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## SharpHound Recon Account Discovery

| Field | Value |
|---|---|
| **Sigma ID** | `65f77b1e-8e79-45bf-bb67-5988a8ce45a5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sharphound_recon_account.yml)**

> Detects remote RPC calls useb by SharpHound to map remote connections and local group membership.

```sql
-- ============================================================
-- Title:        SharpHound Recon Account Discovery
-- Sigma ID:     65f77b1e-8e79-45bf-bb67-5988a8ce45a5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1087
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sharphound_recon_account.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '6bffd098-a112-3610-9833-46c3f87e345a'
    AND rawEventMsg = '2')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/55118c55-2122-4ef9-8664-0c1ff9e168f3
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-WKST.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---

## SharpHound Recon Sessions

| Field | Value |
|---|---|
| **Sigma ID** | `6d580420-ff3f-4e0e-b6b0-41b90c787e28` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1033 |
| **Author** | Sagie Dulce, Dekel Paz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sharphound_recon_sessions.yml)**

> Detects remote RPC calls useb by SharpHound to map remote connections and local group membership.

```sql
-- ============================================================
-- Title:        SharpHound Recon Sessions
-- Sigma ID:     6d580420-ff3f-4e0e-b6b0-41b90c787e28
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1033
-- Author:       Sagie Dulce, Dekel Paz
-- Date:         2022-01-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/rpc_firewall/rpc_firewall_sharphound_recon_sessions.yml
-- Unmapped:     EventLog, InterfaceUuid, OpNum
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: rpc_firewall/application
-- UNMAPPED_FIELD: EventLog
-- UNMAPPED_FIELD: InterfaceUuid
-- UNMAPPED_FIELD: OpNum

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
  AND (rawEventMsg = 'RPCFW'
    AND winEventId = '3'
    AND rawEventMsg = '4b324fc8-1670-01d3-1278-5a47bf6ee188'
    AND rawEventMsg = '12')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/02b1f559-fda2-4ba3-94c2-806eb2777183
- https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-SRVS.md
- https://github.com/zeronetworks/rpcfirewall
- https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/

---
