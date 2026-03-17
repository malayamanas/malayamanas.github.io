# Sigma → FortiSIEM: Windows File Rename

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Suspicious Appended Extension](#suspicious-appended-extension)

## Suspicious Appended Extension

| Field | Value |
|---|---|
| **Sigma ID** | `e3f673b3-65d1-4d80-9146-466f8b63fa99` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486 |
| **Author** | frack113 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_rename/file_rename_win_ransomware.yml)**

> Detects file renames where the target filename uses an uncommon double extension. Could indicate potential ransomware activity renaming files and adding a custom extension to the encrypted files, such as ".jpg.crypted", ".docx.locky", etc.

```sql
-- ============================================================
-- Title:        Suspicious Appended Extension
-- Sigma ID:     e3f673b3-65d1-4d80-9146-466f8b63fa99
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1486
-- Author:       frack113
-- Date:         2022-07-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_rename/file_rename_win_ransomware.yml
-- Unmapped:     SourceFilename
-- False Pos:    Backup software
-- ============================================================
-- UNMAPPED_FIELD: SourceFilename

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('Win-Sysmon-11-File-Create')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%.doc' OR rawEventMsg LIKE '%.docx' OR rawEventMsg LIKE '%.jpeg' OR rawEventMsg LIKE '%.jpg' OR rawEventMsg LIKE '%.lnk' OR rawEventMsg LIKE '%.pdf' OR rawEventMsg LIKE '%.png' OR rawEventMsg LIKE '%.pst' OR rawEventMsg LIKE '%.rtf' OR rawEventMsg LIKE '%.xls' OR rawEventMsg LIKE '%.xlsx')
    AND (indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.doc.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.docx.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpeg.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.jpg.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.lnk.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pdf.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.png.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.pst.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.rtf.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xls.%' OR metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.xlsx.%')))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Backup software

**References:**
- https://app.any.run/tasks/d66ead5a-faf4-4437-93aa-65785afaf9e5/
- https://blog.cyble.com/2022/08/10/onyx-ransomware-renames-its-leak-site-to-vsop/

---
