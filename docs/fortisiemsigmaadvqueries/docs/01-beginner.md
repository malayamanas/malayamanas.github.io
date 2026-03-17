# Beginner: Your First Queries

<span class="level-badge level-beginner">Beginner</span>

This module takes you from zero to writing functional FortiSIEM SQL queries. No prior SQL experience required — but if you have it, you'll move through this quickly.

## The Data Model

All events in FortiSIEM are stored in a single table:

```sql
fsiem.events
```

Every log line, network flow, authentication event, and system alert that FortiSIEM collects ends up as a row in this table. The columns are **event attributes** — parsed fields extracted from raw log data.

### The Database Schema Panel

In the Advanced Search UI, the **Database Schema** panel on the left lists the most frequently used attributes. These are the columns you can reference directly in queries. Less common attributes are available via the **Attributes used** dropdown.

### Core Attributes Reference

| Attribute | Type | Description | Example |
|---|---|---|---|
| `phRecvTime` | Timestamp | When FortiSIEM received the event | `2024-11-15 14:30:00` |
| `phRecvHour` | Integer | Hour component of receive time | `14` |
| `reptDevName` | String | Hostname of the reporting device | `fw-edge-01` |
| `reptDevIpAddrV4` | IPv4 | IP address of the reporting device | `10.0.1.1` |
| `srcIpAddrV4` | IPv4 | Source IP in the event | `192.168.1.50` |
| `destIpAddrV4` | IPv4 | Destination IP | `8.8.8.8` |
| `srcIpPort` | Integer | Source port | `54321` |
| `destIpPort` | Integer | Destination port | `443` |
| `eventType` | String | FortiSIEM event classification | `PH_AUDIT_ADMIN_LOGIN_SUCCEED` |
| `appName` | String | Application that generated the event | `sshd` |
| `reptVendor` | String | Device vendor | `Fortinet` |
| `reptModel` | String | Device model | `FortiGate` |
| `eventParsedOk` | Integer | 1 = successfully parsed, 0 = failed | `1` |
| `phEventCategory` | Integer | Event category (see Reference) | `1` |

> [NOTE] You can add more attributes to your query scope via the **Attributes used** dropdown in the UI. After selecting an attribute, it becomes available in your SQL.

## Basic SELECT Syntax

```sql
SELECT column1, column2
FROM fsiem.events
WHERE condition
ORDER BY column ASC|DESC
LIMIT N
```

### Your First Query

```sql
SELECT eventType, COUNT(*) AS Total
FROM fsiem.events
GROUP BY eventType
ORDER BY COUNT(*) DESC
LIMIT 10
```

This returns the top 10 event types by frequency — a useful first look at what your environment is generating.

> [TIP] **Always include `LIMIT`** when testing a new query. Without it, a query can return millions of rows and slow down the system. Start with `LIMIT 10`, verify the logic, then increase if needed.

## Filtering with WHERE

### Time Filtering — The Most Important Filter

Almost every production query should include a time filter. FortiSIEM uses **`phRecvTime`** as the event timestamp.

```sql
-- Events from the last hour
WHERE phRecvTime > (now() - 3600)

-- Events from the last 24 hours
WHERE phRecvTime > (now() - 86400)

-- Events from the last 7 days
WHERE phRecvTime > (now() - 604800)
```

> [TIP] Time in seconds: 1 hour = 3600, 1 day = 86400, 1 week = 604800.

### Filtering for Successfully Parsed Events

```sql
WHERE eventParsedOk = 1
```

Always add this in production queries — it excludes raw unparsed log lines that would skew your results.

### Combining Filters

```sql
SELECT reptDevName, eventType, COUNT(*) AS Total
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
GROUP BY reptDevName, eventType
ORDER BY Total DESC
LIMIT 20
```

## Aggregation

### COUNT

```sql
-- Count all events
SELECT COUNT(*) FROM fsiem.events WHERE phRecvTime > (now() - 3600)

-- Count events per device
SELECT reptDevName, COUNT(*) AS EventCount
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
GROUP BY reptDevName
```

### GROUP BY

`GROUP BY` collapses multiple rows with the same value into one summary row.

```sql
SELECT reptDevName, reptVendor, COUNT(*) AS Total
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
GROUP BY reptDevName, reptVendor
ORDER BY Total DESC
LIMIT 10
```

### ORDER BY

```sql
ORDER BY Total DESC   -- largest first
ORDER BY Total ASC    -- smallest first
ORDER BY reptDevName  -- alphabetical
```

### Aliasing with AS

```sql
SELECT
  reptDevName      AS "Device Name",
  reptDevIpAddrV4  AS "Device IP",
  COUNT(*)         AS "Event Count",
  MAX(phRecvTime)  AS "Last Seen"
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
GROUP BY reptDevName, reptDevIpAddrV4
ORDER BY COUNT(*) DESC
LIMIT 10
```

> [NOTE] Use backticks or double quotes around aliases that contain spaces: `` `Event Count` `` or `"Event Count"`.

## Lab Exercises — Module 1

> [LAB] Complete all three queries below. Run each one in FortiSIEM's Advanced Search UI and verify you get results before moving on.

### Lab 1.1 — Top Reporting Devices

**Task:** Find the top 10 reporting devices by event count in the last hour, showing device name, IP, and event count.

**Expected query:**

```sql
SELECT
  reptDevName         AS "Device Name",
  reptDevIpAddrV4     AS "Device IP",
  COUNT(*)            AS "Event Count"
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
GROUP BY reptDevName, reptDevIpAddrV4
ORDER BY COUNT(*) DESC
LIMIT 10
```

**Verify:** You should see a table with device names and counts. If all counts are 0, check that your time range covers when events were last received.

---

### Lab 1.2 — Event Type Breakdown (24 Hours)

**Task:** List every event type seen in the last 24 hours with its count and the most recent time it was seen. Sort by count descending.

```sql
SELECT
  eventType           AS "Event Type",
  COUNT(*)            AS "Count",
  MAX(phRecvTime)     AS "Last Seen"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND eventParsedOk = 1
GROUP BY eventType
ORDER BY COUNT(*) DESC
LIMIT 25
```

**Verify:** You should see multiple event types. Note which appear most frequently in your environment — this is your baseline.

---

### Lab 1.3 — Unique Source IPs (Last 6 Hours)

**Task:** List all unique source IP addresses seen in the last 6 hours, along with how many events each generated. Exclude empty/null source IPs.

```sql
SELECT
  srcIpAddrV4         AS "Source IP",
  COUNT(*)            AS "Event Count",
  MAX(phRecvTime)     AS "Last Seen"
FROM fsiem.events
WHERE phRecvTime > (now() - 21600)
  AND eventParsedOk = 1
  AND srcIpAddrV4 != ''
GROUP BY srcIpAddrV4
ORDER BY COUNT(*) DESC
LIMIT 30
```

**Verify:** You should see a list of IPs. A very high count from a single internal IP could indicate misconfiguration or a scanning host.

---

**Module 1 complete.** You can now write time-bounded, filtered, aggregated queries. Continue to [Intermediate](intermediate.html) to add operators, functions, and CMDB integration.
