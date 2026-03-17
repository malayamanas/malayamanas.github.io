# Sigma → FortiSIEM: Fortigate Event

> 7 rules · Generated 2026-03-17

## Table of Contents

- [FortiGate - New Administrator Account Created](#fortigate-new-administrator-account-created)
- [FortiGate - Firewall Address Object Added](#fortigate-firewall-address-object-added)
- [FortiGate - New Firewall Policy Added](#fortigate-new-firewall-policy-added)
- [FortiGate - New Local User Created](#fortigate-new-local-user-created)
- [FortiGate - New VPN SSL Web Portal Added](#fortigate-new-vpn-ssl-web-portal-added)
- [FortiGate - User Group Modified](#fortigate-user-group-modified)
- [FortiGate - VPN SSL Settings Modified](#fortigate-vpn-ssl-settings-modified)

## FortiGate - New Administrator Account Created

| Field | Value |
|---|---|
| **Sigma ID** | `cd0a4943-0edd-42cf-b50c-06f77a10d4c1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_admin_account_created.yml)**

> Detects the creation of an administrator account on a Fortinet FortiGate Firewall.

```sql
-- ============================================================
-- Title:        FortiGate - New Administrator Account Created
-- Sigma ID:     cd0a4943-0edd-42cf-b50c-06f77a10d4c1
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1136.001
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_admin_account_created.yml
-- Unmapped:     action, cfgpath
-- False Pos:    An administrator account can be created for legitimate purposes. Investigate the account details to determine if it is authorized.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Add'
    AND rawEventMsg = 'system.admin')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** An administrator account can be created for legitimate purposes. Investigate the account details to determine if it is authorized.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/390485493/config-system-admin
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr

---

## FortiGate - Firewall Address Object Added

| Field | Value |
|---|---|
| **Sigma ID** | `5c8d7b41-3812-432f-a0bb-4cfb7c31827e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562 |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_firewall_address_object.yml)**

> Detects the addition of firewall address objects on a Fortinet FortiGate Firewall.

```sql
-- ============================================================
-- Title:        FortiGate - Firewall Address Object Added
-- Sigma ID:     5c8d7b41-3812-432f-a0bb-4cfb7c31827e
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1562
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_firewall_address_object.yml
-- Unmapped:     action, cfgpath
-- False Pos:    An address could be added or deleted for legitimate purposes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Add'
    AND rawEventMsg = 'firewall.address')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** An address could be added or deleted for legitimate purposes.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/306021697/config-firewall-address
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr

---

## FortiGate - New Firewall Policy Added

| Field | Value |
|---|---|
| **Sigma ID** | `f24ab7a8-f09a-4319-82c1-915586aa642b` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562 |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_firewall_policy_added.yml)**

> Detects the addition of a new firewall policy on a Fortinet FortiGate Firewall.

```sql
-- ============================================================
-- Title:        FortiGate - New Firewall Policy Added
-- Sigma ID:     f24ab7a8-f09a-4319-82c1-915586aa642b
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1562
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_firewall_policy_added.yml
-- Unmapped:     action, cfgpath
-- False Pos:    A firewall policy can be added for legitimate purposes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Add'
    AND rawEventMsg = 'firewall.policy')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A firewall policy can be added for legitimate purposes.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/333889629/config-firewall-policy
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr

---

## FortiGate - New Local User Created

| Field | Value |
|---|---|
| **Sigma ID** | `ddbbe845-1d74-43a8-8231-2156d180234d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136.001 |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_local_user_created.yml)**

> Detects the creation of a new local user on a Fortinet FortiGate Firewall.
The new local user could be used for VPN connections.


```sql
-- ============================================================
-- Title:        FortiGate - New Local User Created
-- Sigma ID:     ddbbe845-1d74-43a8-8231-2156d180234d
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1136.001
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_local_user_created.yml
-- Unmapped:     action, cfgpath
-- False Pos:    A local user can be created for legitimate purposes. Investigate the user details to determine if it is authorized.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Add'
    AND rawEventMsg = 'user.local')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A local user can be created for legitimate purposes. Investigate the user details to determine if it is authorized.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/109120963/config-user-local
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr

---

## FortiGate - New VPN SSL Web Portal Added

| Field | Value |
|---|---|
| **Sigma ID** | `2bfb6216-0c31-4d20-8501-2629b29a3fa2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_vpn_ssl_web_portal.yml)**

> Detects the addition of a VPN SSL Web Portal on a Fortinet FortiGate Firewall.
This behavior was observed in pair with modification of VPN SSL settings.


```sql
-- ============================================================
-- Title:        FortiGate - New VPN SSL Web Portal Added
-- Sigma ID:     2bfb6216-0c31-4d20-8501-2629b29a3fa2
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1133
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_new_vpn_ssl_web_portal.yml
-- Unmapped:     action, cfgpath
-- False Pos:    A VPN SSL Web Portal can be added for legitimate purposes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Add'
    AND rawEventMsg = 'vpn.ssl.web.portal')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A VPN SSL Web Portal can be added for legitimate purposes.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/113121765/config-vpn-ssl-web-portal
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr

---

## FortiGate - User Group Modified

| Field | Value |
|---|---|
| **Sigma ID** | `69ffc84e-8b1a-4024-8351-e018f66b8275` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_user_group_modified.yml)**

> Detects the modification of a user group on a Fortinet FortiGate Firewall.
The group could be used to grant VPN access to a network.


```sql
-- ============================================================
-- Title:        FortiGate - User Group Modified
-- Sigma ID:     69ffc84e-8b1a-4024-8351-e018f66b8275
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_user_group_modified.yml
-- Unmapped:     action, cfgpath
-- False Pos:    A group can be modified for legitimate purposes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Edit'
    AND rawEventMsg = 'user.group')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A group can be modified for legitimate purposes.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/328136827/config-user-group
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr

---

## FortiGate - VPN SSL Settings Modified

| Field | Value |
|---|---|
| **Sigma ID** | `8b5dacf2-aeb7-459d-b133-678eb696d410` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133 |
| **Author** | Marco Pedrinazzi @pedrinazziM (InTheCyber) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_vpn_ssl_settings_modified.yml)**

> Detects the modification of VPN SSL Settings (for example, the modification of authentication rules).
This behavior was observed in pair with the addition of a VPN SSL Web Portal.


```sql
-- ============================================================
-- Title:        FortiGate - VPN SSL Settings Modified
-- Sigma ID:     8b5dacf2-aeb7-459d-b133-678eb696d410
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1133
-- Author:       Marco Pedrinazzi @pedrinazziM (InTheCyber)
-- Date:         2025-11-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/fortinet/fortigate/fortinet_fortigate_vpn_ssl_settings_modified.yml
-- Unmapped:     action, cfgpath
-- False Pos:    VPN SSL settings can be changed for legitimate purposes.
-- ============================================================
-- UNMAPPED_LOGSOURCE: fortigate/event
-- UNMAPPED_FIELD: action
-- UNMAPPED_FIELD: cfgpath

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Edit'
    AND rawEventMsg = 'vpn.ssl.settings')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** VPN SSL settings can be changed for legitimate purposes.

**References:**
- https://www.fortiguard.com/psirt/FG-IR-24-535
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/398/event
- https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/114404382/config-vpn-ssl-settings
- https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/44546/44546-logid-event-config-attr

---
