# Sigma → FortiSIEM: Windows File Access

> 7 rules · Generated 2026-03-17

## Table of Contents

- [Credential Manager Access By Uncommon Applications](#credential-manager-access-by-uncommon-applications)
- [Access To Windows Credential History File By Uncommon Applications](#access-to-windows-credential-history-file-by-uncommon-applications)
- [Access To Crypto Currency Wallets By Uncommon Applications](#access-to-crypto-currency-wallets-by-uncommon-applications)
- [Access To Windows DPAPI Master Keys By Uncommon Applications](#access-to-windows-dpapi-master-keys-by-uncommon-applications)
- [Access To Potentially Sensitive Sysvol Files By Uncommon Applications](#access-to-potentially-sensitive-sysvol-files-by-uncommon-applications)
- [Suspicious File Access to Browser Credential Storage](#suspicious-file-access-to-browser-credential-storage)
- [Microsoft Teams Sensitive File Access By Uncommon Applications](#microsoft-teams-sensitive-file-access-by-uncommon-applications)

## Credential Manager Access By Uncommon Applications

| Field | Value |
|---|---|
| **Sigma ID** | `407aecb1-e762-4acf-8c7b-d087bcff3bb6` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_credential_manager_access.yml)**

> Detects suspicious processes based on name and location that access the windows credential manager and vault.
Which can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::cred" function


```sql
-- ============================================================
-- Title:        Credential Manager Access By Uncommon Applications
-- Sigma ID:     407aecb1-e762-4acf-8c7b-d087bcff3bb6
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_credential_manager_access.yml
-- Unmapped:     FileName
-- False Pos:    Legitimate software installed by the users for example in the "AppData" directory may access these files (for any reason).
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access
-- UNMAPPED_FIELD: FileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\AppData\\Local\\Microsoft\\Credentials\\%' OR rawEventMsg LIKE '%\\AppData\\Roaming\\Microsoft\\Credentials\\%' OR rawEventMsg LIKE '%\\AppData\\Local\\Microsoft\\Vault\\%' OR rawEventMsg LIKE '%\\ProgramData\\Microsoft\\Vault\\%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate software installed by the users for example in the "AppData" directory may access these files (for any reason).

**References:**
- https://hunter2.gitbook.io/darthsidious/privilege-escalation/mimikatz
- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

---

## Access To Windows Credential History File By Uncommon Applications

| Field | Value |
|---|---|
| **Sigma ID** | `7a2a22ea-a203-4cd3-9abf-20eb1c5c6cd2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555.004 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_credhist.yml)**

> Detects file access requests to the Windows Credential History File by an uncommon application.
This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::credhist" function


```sql
-- ============================================================
-- Title:        Access To Windows Credential History File By Uncommon Applications
-- Sigma ID:     7a2a22ea-a203-4cd3-9abf-20eb1c5c6cd2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1555.004
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_credhist.yml
-- Unmapped:     FileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access
-- UNMAPPED_FIELD: FileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg LIKE '%\\Microsoft\\Protect\\CREDHIST'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://tools.thehacker.recipes/mimikatz/modules/dpapi/credhist
- https://www.passcape.com/windows_password_recovery_dpapi_credhist

---

## Access To Crypto Currency Wallets By Uncommon Applications

| Field | Value |
|---|---|
| **Sigma ID** | `f41b0311-44f9-44f0-816d-dd45e39d4bc8` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1003 |
| **Author** | X__Junior (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_crypto_currency_wallets.yml)**

> Detects file access requests to crypto currency files by uncommon processes.
Could indicate potential attempt of crypto currency wallet stealing.


```sql
-- ============================================================
-- Title:        Access To Crypto Currency Wallets By Uncommon Applications
-- Sigma ID:     f41b0311-44f9-44f0-816d-dd45e39d4bc8
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1003
-- Author:       X__Junior (Nextron Systems)
-- Date:         2024-07-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_crypto_currency_wallets.yml
-- Unmapped:     FileName
-- False Pos:    Antivirus, Anti-Spyware, Anti-Malware Software; Backup software; Legitimate software installed on partitions other than "C:\"; Searching software such as "everything.exe"
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access
-- UNMAPPED_FIELD: FileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%\\AppData\\Roaming\\Ethereum\\keystore\\%' OR rawEventMsg LIKE '%\\AppData\\Roaming\\EthereumClassic\\keystore\\%' OR rawEventMsg LIKE '%\\AppData\\Roaming\\monero\\wallets\\%'))
  OR ((rawEventMsg LIKE '%\\AppData\\Roaming\\Bitcoin\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\BitcoinABC\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\BitcoinSV\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\DashCore\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\DogeCoin\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\Litecoin\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\Ripple\\wallet.dat' OR rawEventMsg LIKE '%\\AppData\\Roaming\\Zcash\\wallet.dat'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Antivirus, Anti-Spyware, Anti-Malware Software; Backup software; Legitimate software installed on partitions other than "C:\"; Searching software such as "everything.exe"

**References:**
- Internal Research

---

## Access To Windows DPAPI Master Keys By Uncommon Applications

| Field | Value |
|---|---|
| **Sigma ID** | `46612ae6-86be-4802-bc07-39b59feb1309` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555.004 |
| **Author** | Nasreddine Bencherchali (Nextron Systems) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_dpapi_master_key_access.yml)**

> Detects file access requests to the the Windows Data Protection API Master keys by an uncommon application.
This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::masterkey" function


```sql
-- ============================================================
-- Title:        Access To Windows DPAPI Master Keys By Uncommon Applications
-- Sigma ID:     46612ae6-86be-4802-bc07-39b59feb1309
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1555.004
-- Author:       Nasreddine Bencherchali (Nextron Systems)
-- Date:         2022-10-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_dpapi_master_key_access.yml
-- Unmapped:     FileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access
-- UNMAPPED_FIELD: FileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\Microsoft\\Protect\\S-1-5-18\\%' OR rawEventMsg LIKE '%\\Microsoft\\Protect\\S-1-5-21-%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://blog.harmj0y.net/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords

---

## Access To Potentially Sensitive Sysvol Files By Uncommon Applications

| Field | Value |
|---|---|
| **Sigma ID** | `d51694fe-484a-46ac-92d6-969e76d60d10` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1552.006 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_gpo_files.yml)**

> Detects file access requests to potentially sensitive files hosted on the Windows Sysvol share.

```sql
-- ============================================================
-- Title:        Access To Potentially Sensitive Sysvol Files By Uncommon Applications
-- Sigma ID:     d51694fe-484a-46ac-92d6-969e76d60d10
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1552.006
-- Author:       frack113
-- Date:         2023-12-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_gpo_files.yml
-- Unmapped:     FileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access
-- UNMAPPED_FIELD: FileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '\\\\%'
    AND rawEventMsg LIKE '%\\sysvol\\%' AND rawEventMsg LIKE '%\\Policies\\%'
    AND (rawEventMsg LIKE '%audit.csv' OR rawEventMsg LIKE '%Files.xml' OR rawEventMsg LIKE '%GptTmpl.inf' OR rawEventMsg LIKE '%groups.xml' OR rawEventMsg LIKE '%Registry.pol' OR rawEventMsg LIKE '%Registry.xml' OR rawEventMsg LIKE '%scheduledtasks.xml' OR rawEventMsg LIKE '%scripts.ini' OR rawEventMsg LIKE '%services.xml'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/vletoux/pingcastle

---

## Suspicious File Access to Browser Credential Storage

| Field | Value |
|---|---|
| **Sigma ID** | `a1dfd976-4852-41d4-9507-dc6590a3ccd0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1555.003, T1217 |
| **Author** | frack113, X__Junior (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems), Parth-FourCore |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_process_access_browser_cred_files.yml)**

> Detects file access to browser credential storage paths by non-browser processes, which may indicate credential access attempts.
Adversaries may attempt to access browser credential storage to extract sensitive information such as usernames and passwords or cookies.
This behavior is often commonly observed in credential stealing malware.


```sql
-- ============================================================
-- Title:        Suspicious File Access to Browser Credential Storage
-- Sigma ID:     a1dfd976-4852-41d4-9507-dc6590a3ccd0
-- Level:        low  |  FSM Severity: 3
-- Status:       experimental
-- MITRE:        discovery | T1555.003, T1217
-- Author:       frack113, X__Junior (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems), Parth-FourCore
-- Date:         2025-05-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_process_access_browser_cred_files.yml
-- Unmapped:     (none)
-- False Pos:    Antivirus, Anti-Spyware, Anti-Malware Software; Legitimate software accessing browser data for synchronization or backup purposes.; Legitimate software installed on partitions other than "C:\"
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND 1=1
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Antivirus, Anti-Spyware, Anti-Malware Software; Legitimate software accessing browser data for synchronization or backup purposes.; Legitimate software installed on partitions other than "C:\"

**References:**
- https://github.com/splunk/security_content/blob/7283ba3723551f46b69dfeb23a63b358afb2cb0e/lookups/browser_app_list.csv?plain=1
- https://fourcore.io/blogs/threat-hunting-browser-credential-stealing

---

## Microsoft Teams Sensitive File Access By Uncommon Applications

| Field | Value |
|---|---|
| **Sigma ID** | `65744385-8541-44a6-8630-ffc824d7d4cc` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1528 |
| **Author** | @SerkinValery |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_teams_sensitive_files.yml)**

> Detects file access attempts to sensitive Microsoft teams files (leveldb, cookies) by an uncommon process.


```sql
-- ============================================================
-- Title:        Microsoft Teams Sensitive File Access By Uncommon Applications
-- Sigma ID:     65744385-8541-44a6-8630-ffc824d7d4cc
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1528
-- Author:       @SerkinValery
-- Date:         2024-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_teams_sensitive_files.yml
-- Unmapped:     FileName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_access
-- UNMAPPED_FIELD: FileName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%\\Microsoft\\Teams\\Cookies%' OR rawEventMsg LIKE '%\\Microsoft\\Teams\\Local Storage\\leveldb%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
- https://www.vectra.ai/blog/undermining-microsoft-teams-security-by-mining-tokens

---
