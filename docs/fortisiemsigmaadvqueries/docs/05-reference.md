# Reference Appendix

<span class="level-badge level-all">All Levels</span>

Fast-lookup reference for working analysts. Use this while writing queries — you don't need to memorize it.

## Key Event Attributes

| Attribute | Data Type | Description | Example Value |
|---|---|---|---|
| `phRecvTime` | DateTime | When FortiSIEM received the event | `2024-11-15 14:30:00` |
| `phRecvHour` | UInt8 | Hour of receive time (0–23) | `14` |
| `reptDevName` | String | Reporting device hostname | `fw-edge-01` |
| `reptDevIpAddrV4` | IPv4 | Reporting device IP address | `10.0.1.1` |
| `reptDevIpAddrV6` | IPv6 | Reporting device IPv6 address | `::1` |
| `reptVendor` | String | Device vendor name | `Fortinet` |
| `reptModel` | String | Device model | `FortiGate-100F` |
| `srcIpAddrV4` | IPv4 | Source IP address | `192.168.1.50` |
| `srcIpAddrV6` | IPv6 | Source IPv6 address | — |
| `srcIpPort` | UInt16 | Source port | `54321` |
| `destIpAddrV4` | IPv4 | Destination IP address | `8.8.8.8` |
| `destIpAddrV6` | IPv6 | Destination IPv6 address | — |
| `destIpPort` | UInt16 | Destination port | `443` |
| `eventType` | String | FortiSIEM event type identifier | `PH_NET_FIREWALL_DENY` |
| `appName` | String | Application / process name | `sshd` |
| `appTransport` | String | Transport protocol | `TCP` |
| `eventName` | String | Human-readable event name | `Firewall Deny` |
| `eventSeverity` | String | Severity level | `HIGH` |
| `eventSeverityCat` | String | Severity category | `2` |
| `phEventCategory` | UInt8 | Event category (see table below) | `4` |
| `eventParsedOk` | UInt8 | 1 = parsed successfully | `1` |
| `user` | String | Username associated with event | `jsmith` |
| `domain` | String | Domain name | `corp.example.com` |
| `hostName` | String | Hostname in event payload | `workstation-42` |
| `fileName` | String | File name in event | `malware.exe` |
| `filePath` | String | Full file path | `C:\Users\jsmith\Downloads\` |
| `fileHash` | String | File hash (MD5/SHA256) | `d41d8cd98f00b204e9800998ecf8427e` |
| `procName` | String | Process name | `powershell.exe` |
| `parentProcName` | String | Parent process name | `winlogon.exe` |
| `cmdLine` | String | Command line arguments | `powershell.exe -enc SGVsbG8=` |
| `sentBytes` | UInt64 | Bytes sent | `10240` |
| `recvBytes` | UInt64 | Bytes received | `2048` |
| `sentPkts` | UInt64 | Packets sent | `15` |
| `recvPkts` | UInt64 | Packets received | `8` |
| `duration` | UInt32 | Connection duration in seconds | `120` |
| `natSrcIpAddrV4` | IPv4 | NAT source IP | `203.0.113.1` |
| `natDestIpAddrV4` | IPv4 | NAT destination IP | `10.0.1.5` |
| `natSrcIpPort` | UInt16 | NAT source port | `12345` |
| `natDestIpPort` | UInt16 | NAT destination port | `443` |
| `rawEvent` | String | Original unparsed log line | `Nov 15 14:30:00 fw deny...` |

> [NOTE] This is a representative list of commonly used attributes. Your FortiSIEM instance may have additional custom attributes. Browse the full list at Admin > Device Support > Event Attributes.

---

## phEventCategory Values

| Value | Name | Description | Typical Sources |
|---|---|---|---|
| `0` | Internal | FortiSIEM system-generated events | FortiSIEM supervisor, workers |
| `1` | Network | Network infrastructure events | Firewall, router, switch, VPN |
| `2` | Server | Server operating system events | Windows, Linux, Unix servers |
| `3` | Application | Application-level events | Web servers, databases, middleware |
| `4` | Security | Security tool events | IDS/IPS, AV, WAF, CASB |
| `5` | Cloud | Cloud platform events | AWS, Azure, GCP, SaaS |
| `6` | Endpoint | Endpoint agent events | EDR agents, FortiClient |

---

## Functions Quick Reference

### Aggregate Functions

| Function | Syntax | Backends | Example |
|---|---|---|---|
| `COUNT` | `COUNT(*)` | All | `COUNT(*)` |
| `COUNT DISTINCT` | `COUNT(DISTINCT attr)` | All | `COUNT(DISTINCT srcIpAddrV4)` |
| `SUM` | `SUM(attr)` | All | `SUM(sentBytes)` |
| `AVG` | `AVG(attr)` | All | `AVG(duration)` |
| `MAX` | `MAX(attr)` | All | `MAX(phRecvTime)` |
| `MIN` | `MIN(attr)` | All | `MIN(phRecvTime)` |
| `FIRST` | `FIRST(attr)` | EventDB, CH | `FIRST(srcIpAddrV4)` |
| `LAST` | `LAST(attr)` | EventDB, CH | `LAST(srcIpAddrV4)` |
| `STDDEV` | `STDDEV(attr)` | All | `STDDEV(sentBytes)` |
| `VARIANCE` | `VARIANCE(attr)` | All | `VARIANCE(sentBytes)` |
| `MEDIAN` | `MEDIAN(attr)` | CH | `MEDIAN(duration)` |
| `MODE` | `MODE(attr)` | CH | `MODE(destIpPort)` |

### Time Functions

| Function | Syntax | Description |
|---|---|---|
| `now()` | `now()` | Current timestamp |
| `toDate()` | `toDate(phRecvTime)` | Extract date portion |
| `HourOfDay()` | `HourOfDay(phRecvTime)` | Hour 0–23 |
| `DayOfWeek()` | `DayOfWeek(phRecvTime)` | Day 0 (Sun) – 6 (Sat) |

### String Functions

| Function | Syntax | Description |
|---|---|---|
| `LEN` | `LEN(attr)` | String length |
| `TRIM` | `TRIM(attr)` | Remove leading/trailing whitespace |
| `LTRIM` | `LTRIM(attr)` | Remove leading whitespace |
| `RTRIM` | `RTRIM(attr)` | Remove trailing whitespace |
| `TO_UPPER` | `TO_UPPER(attr)` | Convert to uppercase |
| `TO_LOWER` | `TO_LOWER(attr)` | Convert to lowercase |
| `SUB_STR` | `SUB_STR(attr, start, len)` | Extract substring |
| `REPLACE` | `REPLACE(attr, old, new)` | Replace substring |

### CMDB / Dictionary Functions

| Function | Syntax | Description |
|---|---|---|
| `dictHas()` | `dictHas('dict', key)` | True if key is in dictionary |
| `DeviceToCMDBAttr()` | `DeviceToCMDBAttr(ip, 'attr')` | Get CMDB attribute for device IP |
| `LookupTableHas()` | `LookupTableHas('table', value)` | True if value is in lookup table |
| `LookupTableGet()` | `LookupTableGet('table', key, 'col')` | Get column value from lookup table |

---

## Common Query Patterns — Cheat Sheet

### Top N by Count

```sql
SELECT reptDevName, COUNT(*) AS Total
FROM fsiem.events
WHERE phRecvTime > (now() - 3600) AND eventParsedOk = 1
GROUP BY reptDevName
ORDER BY Total DESC
LIMIT 10
```

### Time-Window Comparison (Today vs Yesterday)

```sql
SELECT DISTINCT reptDevName AS "New Today"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400) AND eventParsedOk = 1
AND reptDevName NOT IN (
    SELECT DISTINCT reptDevName FROM fsiem.events
    WHERE phRecvTime BETWEEN (now() - 172800) AND (now() - 86400)
      AND eventParsedOk = 1
)
```

### Multi-Condition Filter

```sql
SELECT srcIpAddrV4, destIpAddrV4, destIpPort, COUNT(*) AS C
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
  AND (reptDevName = 'fw-01' OR reptDevName = 'fw-02')
  AND destIpPort IN (22, 23, 3389, 5900)
GROUP BY srcIpAddrV4, destIpAddrV4, destIpPort
ORDER BY C DESC LIMIT 20
```

### CMDB Group Filter

```sql
SELECT reptDevName, eventType, COUNT(*) AS Total
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
  AND dictHas('DeviceIp2DeviceGroup', reptDevIpAddrV4)
GROUP BY reptDevName, eventType
ORDER BY Total DESC LIMIT 20
```

### IOC Sweep

```sql
SELECT srcIpAddrV4, eventType, COUNT(*) AS Hits, MAX(phRecvTime) AS Last
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND eventParsedOk = 1
  AND LookupTableHas('Threat_IOC_IPs', srcIpAddrV4)
GROUP BY srcIpAddrV4, eventType
ORDER BY Hits DESC LIMIT 50
```

### Top N Per Group (Window Function)

```sql
SELECT * FROM (
    SELECT reptDevName, eventType, COUNT(*) AS C,
           RANK() OVER (PARTITION BY reptDevName ORDER BY COUNT(*) DESC) AS rnk
    FROM fsiem.events
    WHERE phRecvTime > (now() - 3600) AND eventParsedOk = 1
    GROUP BY reptDevName, eventType
) t WHERE rnk <= 5 ORDER BY reptDevName, rnk LIMIT 100
```

### Baseline Deviation (Z-Score)

```sql
WITH avg_data AS (
    SELECT reptDevName, AVG(dc) AS avg_c, STDDEV(dc) AS std_c
    FROM (
        SELECT reptDevName, COUNT(*) AS dc
        FROM fsiem.events
        WHERE phRecvTime BETWEEN (now() - 604800) AND (now() - 86400)
          AND eventParsedOk = 1
        GROUP BY reptDevName, toDate(phRecvTime)
    ) d GROUP BY reptDevName
),
today AS (
    SELECT reptDevName, COUNT(*) AS tc
    FROM fsiem.events
    WHERE phRecvTime > (now() - 86400) AND eventParsedOk = 1
    GROUP BY reptDevName
)
SELECT t.reptDevName, t.tc AS Today, ROUND(a.avg_c,0) AS Avg,
       ROUND((t.tc - a.avg_c) / a.std_c, 2) AS ZScore
FROM today t JOIN avg_data a ON t.reptDevName = a.reptDevName
WHERE a.std_c > 0 AND ABS((t.tc - a.avg_c) / a.std_c) > 2
ORDER BY ABS((t.tc - a.avg_c) / a.std_c) DESC LIMIT 20
```

---

## Common Errors and Fixes

| Error | Likely Cause | Fix |
|---|---|---|
| `Table fsiem.events doesn't exist` | Not using ClickHouse backend | Confirm ClickHouse is active: Admin > ClickHouse Operational Overview |
| `Unknown column 'attrName'` | Attribute not in default schema | Add it via the Attributes used dropdown, then re-run |
| `Syntax error near '...'` | Typo in SQL | Use FortiAI Fix Errors or check the highlighted token |
| Results are empty | Time range too narrow or wrong filters | Verify `phRecvTime` range; start with `LIMIT 10` and `COUNT(*)` to check data exists |
| Query runs very slowly | No time bound or `SELECT *` | Add `phRecvTime > (now() - N)` and specify column names |
| `dictHas() error` | Wrong dictionary name | Use the CMDB Group Converter tool to auto-generate the correct `dictHas()` call |
| `LookupTableHas() returns no results` | Table name mismatch or empty table | Verify table name at Admin > General Settings > Lookup Tables |
| `RANK() / ROW_NUMBER() not supported` | Using EventDB backend | Window functions require ClickHouse; confirm backend version |

---

## Time Reference

| Description | Seconds |
|---|---|
| 1 minute | `60` |
| 15 minutes | `900` |
| 30 minutes | `1800` |
| 1 hour | `3600` |
| 6 hours | `21600` |
| 12 hours | `43200` |
| 24 hours | `86400` |
| 2 days | `172800` |
| 7 days | `604800` |
| 30 days | `2592000` |

---

## Official Documentation

- [Creating a New Advanced Search — FortiSIEM 7.4.2](https://docs.fortinet.com/document/fortisiem/7.4.2/user-guide/431900/creating-a-new-advanced-search)
- [Advanced Search Examples — FortiSIEM 7.4.0](https://docs.fortinet.com/document/fortisiem/7.4.0/user-guide/176480/advanced-search-examples)
- [Functions in Analytics — FortiSIEM 7.4.2](https://docs.fortinet.com/document/fortisiem/7.4.2/user-guide/909482/functions-in-analytics)
- [Working with Event Attributes — FortiSIEM 7.4.0](https://docs.fortinet.com/document/fortisiem/7.4.0/user-guide/42752/working-with-event-attributes)
- [ClickHouse Overview — FortiSIEM 7.4.2](https://docs.fortinet.com/document/fortisiem/7.4.2/fortisiem-reference-architecture-using-clickhouse/522282/clickhouse-overview)
