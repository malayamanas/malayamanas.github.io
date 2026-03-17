# Sigma → FortiSIEM: Zeek Http

> 3 rules · Generated 2026-03-17

## Table of Contents

- [Executable from Webdav](#executable-from-webdav)
- [HTTP Request to Low Reputation TLD or Suspicious File Extension](#http-request-to-low-reputation-tld-or-suspicious-file-extension)
- [WebDav Put Request](#webdav-put-request)

## Executable from Webdav

| Field | Value |
|---|---|
| **Sigma ID** | `aac2fd97-bcba-491b-ad66-a6edf89c71bf` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1105 |
| **Author** | SOC Prime, Adam Swan |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_http_executable_download_from_webdav.yml)**

> Detects executable access via webdav6. Can be seen in APT 29 such as from the emulated APT 29 hackathon https://github.com/OTRF/detection-hackathon-apt29/

```sql
-- ============================================================
-- Title:        Executable from Webdav
-- Sigma ID:     aac2fd97-bcba-491b-ad66-a6edf89c71bf
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1105
-- Author:       SOC Prime, Adam Swan
-- Date:         2020-05-01
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_http_executable_download_from_webdav.yml
-- Unmapped:     c-useragent, c-uri, resp_mime_types
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/http
-- UNMAPPED_FIELD: c-useragent
-- UNMAPPED_FIELD: c-uri
-- UNMAPPED_FIELD: resp_mime_types

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%WebDAV%')
  OR (rawEventMsg LIKE '%webdav%')
  AND (rawEventMsg LIKE '%dosexec%')
  OR (rawEventMsg LIKE '%.exe'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- http://carnal0wnage.attackresearch.com/2012/06/webdav-server-to-download-custom.html
- https://github.com/OTRF/detection-hackathon-apt29

---

## HTTP Request to Low Reputation TLD or Suspicious File Extension

| Field | Value |
|---|---|
| **Sigma ID** | `68c2c604-92ad-468b-bf4a-aac49adad08c` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | @signalblur, Corelight |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_http_susp_file_ext_from_susp_tld.yml)**

> Detects HTTP requests to low reputation TLDs (e.g. .xyz, .top, .ru) or ending in suspicious file extensions (.exe, .dll, .hta), which may indicate malicious activity.


```sql
-- ============================================================
-- Title:        HTTP Request to Low Reputation TLD or Suspicious File Extension
-- Sigma ID:     68c2c604-92ad-468b-bf4a-aac49adad08c
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        (none)
-- Author:       @signalblur, Corelight
-- Date:         2025-02-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_http_susp_file_ext_from_susp_tld.yml
-- Unmapped:     host
-- False Pos:    Rare legitimate software downloads from low quality TLDs
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/http
-- UNMAPPED_FIELD: host

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg LIKE '%.bid' OR rawEventMsg LIKE '%.by' OR rawEventMsg LIKE '%.cf' OR rawEventMsg LIKE '%.click' OR rawEventMsg LIKE '%.cm' OR rawEventMsg LIKE '%.ga' OR rawEventMsg LIKE '%.gq' OR rawEventMsg LIKE '%.ir' OR rawEventMsg LIKE '%.kp' OR rawEventMsg LIKE '%.loan' OR rawEventMsg LIKE '%.ml' OR rawEventMsg LIKE '%.mm' OR rawEventMsg LIKE '%.party' OR rawEventMsg LIKE '%.pw' OR rawEventMsg LIKE '%.ru' OR rawEventMsg LIKE '%.su' OR rawEventMsg LIKE '%.sy' OR rawEventMsg LIKE '%.tk' OR rawEventMsg LIKE '%.top' OR rawEventMsg LIKE '%.tv' OR rawEventMsg LIKE '%.ve' OR rawEventMsg LIKE '%.work' OR rawEventMsg LIKE '%.xyz')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Rare legitimate software downloads from low quality TLDs

**References:**
- https://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows
- https://www.spamhaus.org/reputation-statistics/cctlds/domains/

---

## WebDav Put Request

| Field | Value |
|---|---|
| **Sigma ID** | `705072a5-bb6f-4ced-95b6-ecfa6602090b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1048.003 |
| **Author** | Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_http_webdav_put_request.yml)**

> A General detection for WebDav user-agent being used to PUT files on a WebDav network share. This could be an indicator of exfiltration.

```sql
-- ============================================================
-- Title:        WebDav Put Request
-- Sigma ID:     705072a5-bb6f-4ced-95b6-ecfa6602090b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1048.003
-- Author:       Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date:         2020-05-02
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/network/zeek/zeek_http_webdav_put_request.yml
-- Unmapped:     user_agent, method, id.resp_h
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_LOGSOURCE: zeek/http
-- UNMAPPED_FIELD: user_agent
-- UNMAPPED_FIELD: method
-- UNMAPPED_FIELD: id.resp_h

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE rawEventMsg LIKE '%'
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg LIKE '%WebDAV%'
    AND rawEventMsg = 'PUT')
  AND NOT ((isIPAddressInRange(toString(rawEventMsg), '10.0.0.0/8') OR isIPAddressInRange(toString(rawEventMsg), '127.0.0.0/8') OR isIPAddressInRange(toString(rawEventMsg), '172.16.0.0/12') OR isIPAddressInRange(toString(rawEventMsg), '192.168.0.0/16') OR isIPAddressInRange(toString(rawEventMsg), '169.254.0.0/16'))))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/OTRF/detection-hackathon-apt29/issues/17

---
