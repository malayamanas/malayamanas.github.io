# Sigma → FortiSIEM: Zeek Dce Rpc

> 3 rules · Generated 2026-03-17

## Table of Contents

- [MITRE BZAR Indicators for Execution](#mitre-bzar-indicators-for-execution)
- [MITRE BZAR Indicators for Persistence](#mitre-bzar-indicators-for-persistence)
- [Potential PetitPotam Attack Via EFS RPC Calls](#potential-petitpotam-attack-via-efs-rpc-calls)

## MITRE BZAR Indicators for Execution

| Field | Value |
|---|---|
| **Sigma ID** | `b640c0b8-87f8-4daa-aef8-95a24261dd1d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, execution |
| **MITRE Techniques** | T1047, T1053.002, T1569.002 |
| **Author** | @neu5ron, SOC Prime |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml)**

> Windows DCE-RPC functions which indicate an execution techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE

```sql
-- ============================================================
-- Title:        MITRE BZAR Indicators for Execution
-- Sigma ID:     b640c0b8-87f8-4daa-aef8-95a24261dd1d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence, execution | T1047, T1053.002, T1569.002
-- Author:       @neu5ron, SOC Prime
-- Date:         2020-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml
-- Unmapped:     endpoint, operation
-- False Pos:    Windows administrator tasks or troubleshooting; Windows management scripts or software
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dce_rpc
-- UNMAPPED_FIELD: endpoint
-- UNMAPPED_FIELD: operation

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'JobAdd'
    AND rawEventMsg = 'atsvc')
  OR (rawEventMsg = 'svcctl'
    AND rawEventMsg = 'StartServiceW')
  OR (rawEventMsg = 'ITaskSchedulerService'
    AND rawEventMsg = 'SchRpcEnableTask')
  OR (rawEventMsg = 'ITaskSchedulerService'
    AND rawEventMsg = 'SchRpcRegisterTask')
  OR (rawEventMsg = 'ITaskSchedulerService'
    AND rawEventMsg = 'SchRpcRun')
  OR (rawEventMsg = 'IWbemServices'
    AND rawEventMsg = 'ExecMethod')
  OR (rawEventMsg = 'IWbemServices'
    AND rawEventMsg = 'ExecMethodAsync')
  OR (rawEventMsg = 'svcctl'
    AND rawEventMsg = 'CreateServiceA')
  OR (rawEventMsg = 'svcctl'
    AND rawEventMsg = 'CreateServiceW')
  OR (rawEventMsg = 'svcctl'
    AND rawEventMsg = 'StartServiceA')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Windows administrator tasks or troubleshooting; Windows management scripts or software

**References:**
- https://github.com/mitre-attack/bzar#indicators-for-attck-execution

---

## MITRE BZAR Indicators for Persistence

| Field | Value |
|---|---|
| **Sigma ID** | `53389db6-ba46-48e3-a94c-e0f2cefe1583` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1547.004 |
| **Author** | @neu5ron, SOC Prime |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_mitre_bzar_persistence.yml)**

> Windows DCE-RPC functions which indicate a persistence techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE.

```sql
-- ============================================================
-- Title:        MITRE BZAR Indicators for Persistence
-- Sigma ID:     53389db6-ba46-48e3-a94c-e0f2cefe1583
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1547.004
-- Author:       @neu5ron, SOC Prime
-- Date:         2020-03-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_mitre_bzar_persistence.yml
-- Unmapped:     endpoint, operation
-- False Pos:    Windows administrator tasks or troubleshooting; Windows management scripts or software
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dce_rpc
-- UNMAPPED_FIELD: endpoint
-- UNMAPPED_FIELD: operation

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'spoolss'
    AND rawEventMsg = 'RpcAddMonitor')
  OR (rawEventMsg = 'spoolss'
    AND rawEventMsg = 'RpcAddPrintProcessor')
  OR (rawEventMsg = 'IRemoteWinspool'
    AND rawEventMsg = 'RpcAsyncAddMonitor')
  OR (rawEventMsg = 'IRemoteWinspool'
    AND rawEventMsg = 'RpcAsyncAddPrintProcessor')
  OR (rawEventMsg = 'ISecLogon'
    AND rawEventMsg = 'SeclCreateProcessWithLogonW')
  OR (rawEventMsg = 'ISecLogon'
    AND rawEventMsg = 'SeclCreateProcessWithLogonExW')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Windows administrator tasks or troubleshooting; Windows management scripts or software

**References:**
- https://github.com/mitre-attack/bzar#indicators-for-attck-persistence

---

## Potential PetitPotam Attack Via EFS RPC Calls

| Field | Value |
|---|---|
| **Sigma ID** | `4096842a-8f9f-4d36-92b4-d0b2a62f9b2a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1557.001, T1187 |
| **Author** | @neu5ron, @Antonlovesdnb, Mike Remen |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_potential_petit_potam_efs_rpc_call.yml)**

> Detects usage of the windows RPC library Encrypting File System Remote Protocol (MS-EFSRPC). Variations of this RPC are used within the attack refereed to as PetitPotam.
The usage of this RPC function should be rare if ever used at all.
Thus usage of this function is uncommon enough that any usage of this RPC function should warrant further investigation to determine if it is legitimate.
 View surrounding logs (within a few minutes before and after) from the Source IP to. Logs from from the Source IP would include dce_rpc, smb_mapping, smb_files, rdp, ntlm, kerberos, etc..'


```sql
-- ============================================================
-- Title:        Potential PetitPotam Attack Via EFS RPC Calls
-- Sigma ID:     4096842a-8f9f-4d36-92b4-d0b2a62f9b2a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        collection | T1557.001, T1187
-- Author:       @neu5ron, @Antonlovesdnb, Mike Remen
-- Date:         2021-08-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_dce_rpc_potential_petit_potam_efs_rpc_call.yml
-- Unmapped:     operation
-- False Pos:    Uncommon but legitimate windows administrator or software tasks that make use of the Encrypting File System RPC Calls. Verify if this is common activity (see description).
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/dce_rpc
-- UNMAPPED_FIELD: operation

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE 'efs%'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Uncommon but legitimate windows administrator or software tasks that make use of the Encrypting File System RPC Calls. Verify if this is common activity (see description).

**References:**
- https://github.com/topotam/PetitPotam/blob/d83ac8f2dd34654628c17490f99106eb128e7d1e/PetitPotam/PetitPotam.cpp
- https://msrc.microsoft.com/update-guide/vulnerability/ADV210003
- https://vx-underground.org/archive/Symantec/windows-vista-network-attack-07-en.pdf
- https://threatpost.com/microsoft-petitpotam-poc/168163/

---
