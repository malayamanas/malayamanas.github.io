# Sigma → FortiSIEM: Opencanary Application

> 18 rules · Generated 2026-03-17

## Table of Contents

- [OpenCanary - FTP Login Attempt](#opencanary-ftp-login-attempt)
- [OpenCanary - GIT Clone Request](#opencanary-git-clone-request)
- [OpenCanary - HTTP GET Request](#opencanary-http-get-request)
- [OpenCanary - HTTP POST Login Attempt](#opencanary-http-post-login-attempt)
- [OpenCanary - HTTPPROXY Login Attempt](#opencanary-httpproxy-login-attempt)
- [OpenCanary - MSSQL Login Attempt Via SQLAuth](#opencanary-mssql-login-attempt-via-sqlauth)
- [OpenCanary - MSSQL Login Attempt Via Windows Authentication](#opencanary-mssql-login-attempt-via-windows-authentication)
- [OpenCanary - MySQL Login Attempt](#opencanary-mysql-login-attempt)
- [OpenCanary - NTP Monlist Request](#opencanary-ntp-monlist-request)
- [OpenCanary - REDIS Action Command Attempt](#opencanary-redis-action-command-attempt)
- [OpenCanary - SIP Request](#opencanary-sip-request)
- [OpenCanary - SMB File Open Request](#opencanary-smb-file-open-request)
- [OpenCanary - SNMP OID Request](#opencanary-snmp-oid-request)
- [OpenCanary - SSH Login Attempt](#opencanary-ssh-login-attempt)
- [OpenCanary - SSH New Connection Attempt](#opencanary-ssh-new-connection-attempt)
- [OpenCanary - Telnet Login Attempt](#opencanary-telnet-login-attempt)
- [OpenCanary - TFTP Request](#opencanary-tftp-request)
- [OpenCanary - VNC Connection Attempt](#opencanary-vnc-connection-attempt)

## OpenCanary - FTP Login Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `6991bc2b-ae2e-447f-bc55-3a1ba04c14e5` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1190, T1021 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ftp_login_attempt.yml)**

> Detects instances where an FTP service on an OpenCanary node has had a login attempt.

```sql
-- ============================================================
-- Title:        OpenCanary - FTP Login Attempt
-- Sigma ID:     6991bc2b-ae2e-447f-bc55-3a1ba04c14e5
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1190, T1021
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ftp_login_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '2000'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - GIT Clone Request

| Field | Value |
|---|---|
| **Sigma ID** | `4fe17521-aef3-4e6a-9d6b-4a7c8de155a8` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1213 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_git_clone_request.yml)**

> Detects instances where a GIT service on an OpenCanary node has had Git Clone request.

```sql
-- ============================================================
-- Title:        OpenCanary - GIT Clone Request
-- Sigma ID:     4fe17521-aef3-4e6a-9d6b-4a7c8de155a8
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1213
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_git_clone_request.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '16001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - HTTP GET Request

| Field | Value |
|---|---|
| **Sigma ID** | `af6c3078-84cd-4c68-8842-08b76bd81b13` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_http_get.yml)**

> Detects instances where an HTTP service on an OpenCanary node has received a GET request.

```sql
-- ============================================================
-- Title:        OpenCanary - HTTP GET Request
-- Sigma ID:     af6c3078-84cd-4c68-8842-08b76bd81b13
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_http_get.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '3000'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - HTTP POST Login Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `af1ac430-df6b-4b38-b976-0b52f07a0252` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1190 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_http_post_login_attempt.yml)**

> Detects instances where an HTTP service on an OpenCanary node has had login attempt via Form POST.


```sql
-- ============================================================
-- Title:        OpenCanary - HTTP POST Login Attempt
-- Sigma ID:     af1ac430-df6b-4b38-b976-0b52f07a0252
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1190
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_http_post_login_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '3001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - HTTPPROXY Login Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `5498fc09-adc6-4804-b9d9-5cca1f0b8760` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1090 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_httpproxy_login_attempt.yml)**

> Detects instances where an HTTPPROXY service on an OpenCanary node has had an attempt to proxy another page.


```sql
-- ============================================================
-- Title:        OpenCanary - HTTPPROXY Login Attempt
-- Sigma ID:     5498fc09-adc6-4804-b9d9-5cca1f0b8760
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1090
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_httpproxy_login_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '7001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - MSSQL Login Attempt Via SQLAuth

| Field | Value |
|---|---|
| **Sigma ID** | `3ec9a16d-0b4f-4967-9542-ebf38ceac7dd` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1003, T1213 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_mssql_login_sqlauth.yml)**

> Detects instances where an MSSQL service on an OpenCanary node has had a login attempt using SQLAuth.


```sql
-- ============================================================
-- Title:        OpenCanary - MSSQL Login Attempt Via SQLAuth
-- Sigma ID:     3ec9a16d-0b4f-4967-9542-ebf38ceac7dd
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1003, T1213
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_mssql_login_sqlauth.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '9001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - MSSQL Login Attempt Via Windows Authentication

| Field | Value |
|---|---|
| **Sigma ID** | `6e78f90f-0043-4a01-ac41-f97681613a66` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1003, T1213 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_mssql_login_winauth.yml)**

> Detects instances where an MSSQL service on an OpenCanary node has had a login attempt using Windows Authentication.


```sql
-- ============================================================
-- Title:        OpenCanary - MSSQL Login Attempt Via Windows Authentication
-- Sigma ID:     6e78f90f-0043-4a01-ac41-f97681613a66
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1003, T1213
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_mssql_login_winauth.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '9002'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - MySQL Login Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `e7d79a1b-25ed-4956-bd56-bd344fa8fd06` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1003, T1213 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_mysql_login_attempt.yml)**

> Detects instances where a MySQL service on an OpenCanary node has had a login attempt.

```sql
-- ============================================================
-- Title:        OpenCanary - MySQL Login Attempt
-- Sigma ID:     e7d79a1b-25ed-4956-bd56-bd344fa8fd06
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1003, T1213
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_mysql_login_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '8001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - NTP Monlist Request

| Field | Value |
|---|---|
| **Sigma ID** | `7cded4b3-f09e-405a-b96f-24248433ba44` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1498 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ntp_monlist.yml)**

> Detects instances where an NTP service on an OpenCanary node has had a NTP monlist request.

```sql
-- ============================================================
-- Title:        OpenCanary - NTP Monlist Request
-- Sigma ID:     7cded4b3-f09e-405a-b96f-24248433ba44
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        impact | T1498
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ntp_monlist.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '11001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - REDIS Action Command Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `547dfc53-ebf6-4afe-8d2e-793d9574975d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1003, T1213 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_redis_command.yml)**

> Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.

```sql
-- ============================================================
-- Title:        OpenCanary - REDIS Action Command Attempt
-- Sigma ID:     547dfc53-ebf6-4afe-8d2e-793d9574975d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1003, T1213
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_redis_command.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '17001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - SIP Request

| Field | Value |
|---|---|
| **Sigma ID** | `e30de276-68ec-435c-ab99-ef3befec6c61` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1123 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_sip_request.yml)**

> Detects instances where an SIP service on an OpenCanary node has had a SIP request.

```sql
-- ============================================================
-- Title:        OpenCanary - SIP Request
-- Sigma ID:     e30de276-68ec-435c-ab99-ef3befec6c61
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1123
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_sip_request.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '15001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - SMB File Open Request

| Field | Value |
|---|---|
| **Sigma ID** | `22777c9e-873a-4b49-855f-6072ab861a52` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | collection |
| **MITRE Techniques** | T1021, T1005 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_smb_file_open.yml)**

> Detects instances where an SMB service on an OpenCanary node has had a file open request.

```sql
-- ============================================================
-- Title:        OpenCanary - SMB File Open Request
-- Sigma ID:     22777c9e-873a-4b49-855f-6072ab861a52
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        collection | T1021, T1005
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_smb_file_open.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '5000'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - SNMP OID Request

| Field | Value |
|---|---|
| **Sigma ID** | `e9856028-fd4e-46e6-b3d1-10f7ceb95078` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1016, T1021 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_snmp_cmd.yml)**

> Detects instances where an SNMP service on an OpenCanary node has had an OID request.

```sql
-- ============================================================
-- Title:        OpenCanary - SNMP OID Request
-- Sigma ID:     e9856028-fd4e-46e6-b3d1-10f7ceb95078
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        discovery | T1016, T1021
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_snmp_cmd.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '13001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - SSH Login Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `ff7139bc-fdb1-4437-92f2-6afefe8884cb` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133, T1021, T1078 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ssh_login_attempt.yml)**

> Detects instances where an SSH service on an OpenCanary node has had a login attempt.

```sql
-- ============================================================
-- Title:        OpenCanary - SSH Login Attempt
-- Sigma ID:     ff7139bc-fdb1-4437-92f2-6afefe8884cb
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133, T1021, T1078
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ssh_login_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '4002'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - SSH New Connection Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `cd55f721-5623-4663-bd9b-5229cab5237d` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133, T1021, T1078 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ssh_new_connection.yml)**

> Detects instances where an SSH service on an OpenCanary node has had a connection attempt.

```sql
-- ============================================================
-- Title:        OpenCanary - SSH New Connection Attempt
-- Sigma ID:     cd55f721-5623-4663-bd9b-5229cab5237d
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133, T1021, T1078
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_ssh_new_connection.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '4000'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - Telnet Login Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `512cff7a-683a-43ad-afe0-dd398e872f36` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1133, T1078 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_telnet_login_attempt.yml)**

> Detects instances where a Telnet service on an OpenCanary node has had a login attempt.

```sql
-- ============================================================
-- Title:        OpenCanary - Telnet Login Attempt
-- Sigma ID:     512cff7a-683a-43ad-afe0-dd398e872f36
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1133, T1078
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_telnet_login_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '6001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - TFTP Request

| Field | Value |
|---|---|
| **Sigma ID** | `b4e6b016-a2ac-4759-ad85-8000b300d61e` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1041 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_tftp_request.yml)**

> Detects instances where a TFTP service on an OpenCanary node has had a request.

```sql
-- ============================================================
-- Title:        OpenCanary - TFTP Request
-- Sigma ID:     b4e6b016-a2ac-4759-ad85-8000b300d61e
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1041
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_tftp_request.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '10001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---

## OpenCanary - VNC Connection Attempt

| Field | Value |
|---|---|
| **Sigma ID** | `9db5446c-b44a-4291-8b89-fcab5609c3b3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1021 |
| **Author** | Security Onion Solutions |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_vnc_connection_attempt.yml)**

> Detects instances where a VNC service on an OpenCanary node has had a connection attempt.

```sql
-- ============================================================
-- Title:        OpenCanary - VNC Connection Attempt
-- Sigma ID:     9db5446c-b44a-4291-8b89-fcab5609c3b3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1021
-- Author:       Security Onion Solutions
-- Date:         2024-03-08
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/application/opencanary/opencanary_vnc_connection_attempt.yml
-- Unmapped:     logtype
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_LOGSOURCE: opencanary/application
-- UNMAPPED_FIELD: logtype

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = '12001'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://opencanary.readthedocs.io/en/latest/starting/configuration.html#services-configuration
- https://github.com/thinkst/opencanary/blob/a0896adfcaf0328cfd5829fe10d2878c7445138e/opencanary/logger.py#L52

---
