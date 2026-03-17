# Sigma → FortiSIEM: Windows File Executable Detected

> 1 rule · Generated 2026-03-17

## Table of Contents

- [Potentially Suspicious Self Extraction Directive File Created](#potentially-suspicious-self-extraction-directive-file-created)

## Potentially Suspicious Self Extraction Directive File Created

| Field | Value |
|---|---|
| **Sigma ID** | `ab90dab8-c7da-4010-9193-563528cfa347` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1218 |
| **Author** | Joseliyo Sanchez, @Joseliyo_Jstnk |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_executable_detected/file_executable_detected_win_susp_embeded_sed_file.yml)**

> Detects the creation of a binary file with the ".sed" extension. The ".sed" extension stand for Self Extraction Directive files.
These files are used by the "iexpress.exe" utility in order to create self extracting packages.
Attackers were seen abusing this utility and creating PE files with embedded ".sed" entries.
Usually ".sed" files are simple ini files and not PE binaries.


```sql
-- ============================================================
-- Title:        Potentially Suspicious Self Extraction Directive File Created
-- Sigma ID:     ab90dab8-c7da-4010-9193-563528cfa347
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1218
-- Author:       Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date:         2024-02-05
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_executable_detected/file_executable_detected_win_susp_embeded_sed_file.yml
-- Unmapped:     (none)
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: windows/file_executable_detected

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  metrics_string.value[indexOf(metrics_string.name,'fileName')] AS targetFilename,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND indexOf(metrics_string.name, 'fileName') > 0
    AND (metrics_string.value[indexOf(metrics_string.name,'fileName')] LIKE '%.sed')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://strontic.github.io/xcyclopedia/library/iexpress.exe-D594B2A33EFAFD0EABF09E3FDC05FCEA.html
- https://en.wikipedia.org/wiki/IExpress
- https://www.virustotal.com/gui/file/602f4ae507fa8de57ada079adff25a6c2a899bd25cd092d0af7e62cdb619c93c/behavior

---
