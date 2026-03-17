# Intermediate: Operators, Functions & CMDB

<span class="level-badge level-intermediate">Intermediate</span>

This module covers the SQL building blocks that transform basic queries into precise investigation tools: logical operators, aggregate and time functions, string manipulation, and CMDB group integration.

## Logical Operators

### IN and NOT IN

Filter for multiple values without chaining OR conditions:

```sql
-- Events from specific devices
WHERE reptDevName IN ('fw-edge-01', 'fw-edge-02', 'vpn-gw-01')

-- Exclude specific event types
WHERE eventType NOT IN ('PH_SYS_HEARTBEAT', 'PH_SYS_HEALTH_CPU')

-- Filter by event category
WHERE phEventCategory IN (0, 4)
```

### LIKE — Pattern Matching

```sql
-- Events from any device starting with "fw-"
WHERE reptDevName LIKE 'fw-%'

-- Event types containing "LOGIN"
WHERE eventType LIKE '%LOGIN%'

-- Source IPs in the 10.0.x.x range
WHERE srcIpAddrV4 LIKE '10.0.%'
```

> [NOTE] `%` matches any sequence of characters. `_` matches exactly one character. LIKE is case-sensitive in ClickHouse by default.

### BETWEEN

```sql
-- Events on a specific port range
WHERE destIpPort BETWEEN 1024 AND 65535

-- Events in a time window
WHERE phRecvTime BETWEEN '2024-11-01 00:00:00' AND '2024-11-01 23:59:59'
```

### AND / OR with Parentheses

Use parentheses to control evaluation order:

```sql
WHERE (reptDevName = 'fw-edge-01' OR reptDevName = 'fw-edge-02')
  AND phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
```

> [WARN] Without parentheses, `AND` has higher precedence than `OR`. `A AND B OR C` evaluates as `(A AND B) OR C`, which is often not what you intend. Always use parentheses when mixing AND and OR.

## Aggregate Functions

| Function | Syntax | Description |
|---|---|---|
| `COUNT(*)` | `COUNT(*)` | Count all rows |
| `COUNT DISTINCT` | `COUNT(DISTINCT attr)` | Count unique values |
| `MAX` | `MAX(phRecvTime)` | Largest value / most recent time |
| `MIN` | `MIN(phRecvTime)` | Smallest value / earliest time |
| `SUM` | `SUM(sentBytes)` | Total of a numeric field |
| `AVG` | `AVG(sentBytes)` | Average of a numeric field |
| `FIRST` | `FIRST(srcIpAddrV4)` | Value from the earliest event |
| `LAST` | `LAST(srcIpAddrV4)` | Value from the most recent event |
| `STDDEV` | `STDDEV(sentBytes)` | Standard deviation |

### Example: Rich Device Summary

```sql
SELECT
  reptDevName                     AS "Device",
  reptVendor                      AS "Vendor",
  reptModel                       AS "Model",
  COUNT(*)                        AS "Event Count",
  COUNT(DISTINCT eventType)       AS "Unique Event Types",
  MAX(phRecvTime)                 AS "Last Seen",
  MIN(phRecvTime)                 AS "First Seen"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND eventParsedOk = 1
GROUP BY reptDevName, reptVendor, reptModel
ORDER BY COUNT(*) DESC
LIMIT 20
```

## Time Functions

### Relative Time with now()

```sql
now()                   -- current timestamp
now() - 3600            -- 1 hour ago
now() - 86400           -- 24 hours ago
now() - 604800          -- 7 days ago
```

### HourOfDay() and DayOfWeek()

Useful for identifying patterns tied to business hours or days:

```sql
-- Events by hour of day (spot after-hours activity)
SELECT
  HourOfDay(phRecvTime)   AS "Hour",
  COUNT(*)                AS "Events"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND eventParsedOk = 1
GROUP BY HourOfDay(phRecvTime)
ORDER BY HourOfDay(phRecvTime)
```

```sql
-- Events by day of week (0=Sunday, 6=Saturday)
SELECT
  DayOfWeek(phRecvTime)   AS "Day",
  COUNT(*)                AS "Events"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
GROUP BY DayOfWeek(phRecvTime)
ORDER BY DayOfWeek(phRecvTime)
```

## String Functions

| Function | Example | Result |
|---|---|---|
| `TO_UPPER(s)` | `TO_UPPER('admin')` | `'ADMIN'` |
| `TO_LOWER(s)` | `TO_LOWER('ADMIN')` | `'admin'` |
| `LEN(s)` | `LEN(reptDevName)` | Length as integer |
| `TRIM(s)` | `TRIM(' host ')` | `'host'` |
| `SUB_STR(s,start,len)` | `SUB_STR(srcIpAddrV4,1,3)` | First 3 chars |
| `REPLACE(s,old,new)` | `REPLACE(appName,'svc_','')` | Strips prefix |

```sql
-- Normalize event types for grouping
SELECT TO_UPPER(appName) AS App, COUNT(*) AS Total
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
GROUP BY TO_UPPER(appName)
ORDER BY Total DESC
LIMIT 15
```

## CMDB Integration

FortiSIEM's CMDB (Configuration Management Database) organizes devices into hierarchical groups. You can filter queries against these groups using dictionary functions.

### dictHas() — Group Membership Check

```sql
-- Events from devices in the "Devices > Server > Windows" CMDB group
SELECT reptDevName, eventType, COUNT(*)
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND dictHas('DeviceIp2DeviceGroup', reptDevIpAddrV4)
  AND eventParsedOk = 1
GROUP BY reptDevName, eventType
ORDER BY COUNT(*) DESC
LIMIT 20
```

> [NOTE] The CMDB group path syntax depends on your FortiSIEM configuration. Use the **CMDB Group Converter** tool in the Advanced Search UI (toolbar icon) to select a group and auto-generate the `dictHas()` call for your environment.

### DeviceToCMDBAttr() — Enrich Results with CMDB Data

```sql
SELECT
  reptDevName                             AS "Device",
  DeviceToCMDBAttr(reptDevIpAddrV4, 'Location') AS "Location",
  COUNT(*)                                AS "Events"
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
GROUP BY reptDevName, reptDevIpAddrV4
ORDER BY COUNT(*) DESC
LIMIT 15
```

## phEventCategory Values

| Value | Category | Description |
|---|---|---|
| `0` | Internal | FortiSIEM-generated system events |
| `1` | Network | Network device events (firewall, router, switch) |
| `2` | Server | Server OS events (Windows, Linux) |
| `3` | Application | Application-level events |
| `4` | Security | Security-specific events (IDS, AV, auth) |
| `5` | Cloud | Cloud service events |
| `6` | Endpoint | Endpoint agent events |

```sql
-- Security and network events only
WHERE phEventCategory IN (1, 4)
```

## SOC Workflow: Alert Investigation

When you receive an incident alert, Advanced Search lets you rapidly scope the event and gather evidence. Here is the standard pivot workflow:

**Step 1 — Confirm the alert exists in the data:**
```sql
SELECT phRecvTime, reptDevName, srcIpAddrV4, destIpAddrV4, eventType
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND srcIpAddrV4 = '10.0.5.44'
  AND eventParsedOk = 1
ORDER BY phRecvTime DESC
LIMIT 50
```

**Step 2 — What event types is this IP generating?**
```sql
SELECT eventType, COUNT(*) AS Count, MAX(phRecvTime) AS LastSeen
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND srcIpAddrV4 = '10.0.5.44'
  AND eventParsedOk = 1
GROUP BY eventType
ORDER BY Count DESC
```

**Step 3 — What destinations is it talking to?**
```sql
SELECT destIpAddrV4, destIpPort, COUNT(*) AS Count
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND srcIpAddrV4 = '10.0.5.44'
  AND eventParsedOk = 1
GROUP BY destIpAddrV4, destIpPort
ORDER BY Count DESC
LIMIT 30
```

> [SOC] During IR, always note the **phRecvTime** range of the suspicious activity — this helps you build a precise timeline and scope related events across other devices.

## Lab Exercise — Module 2

> [LAB] **Scenario:** You receive an alert for possible brute-force activity. The alerted source IP is `192.168.10.55`. Use the three queries below to investigate. Adapt the IP and time window to match your environment.

**Lab 2.1 — Scope the source IP activity:**

```sql
SELECT
  eventType                       AS "Event Type",
  COUNT(*)                        AS "Count",
  MIN(phRecvTime)                 AS "First Seen",
  MAX(phRecvTime)                 AS "Last Seen"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND srcIpAddrV4 = '192.168.10.55'
  AND eventParsedOk = 1
GROUP BY eventType
ORDER BY COUNT(*) DESC
```

**Lab 2.2 — Find targeted destination IPs and ports:**

```sql
SELECT
  destIpAddrV4                    AS "Destination IP",
  destIpPort                      AS "Port",
  COUNT(*)                        AS "Attempts",
  COUNT(DISTINCT eventType)       AS "Event Types"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND srcIpAddrV4 = '192.168.10.55'
  AND eventParsedOk = 1
GROUP BY destIpAddrV4, destIpPort
ORDER BY COUNT(*) DESC
LIMIT 20
```

**Lab 2.3 — Check activity by hour to identify the attack window:**

```sql
SELECT
  HourOfDay(phRecvTime)           AS "Hour",
  COUNT(*)                        AS "Event Count"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND srcIpAddrV4 = '192.168.10.55'
  AND eventParsedOk = 1
GROUP BY HourOfDay(phRecvTime)
ORDER BY HourOfDay(phRecvTime)
```

**Questions to answer from your results:**
1. Is the activity spread evenly across the day, or concentrated in a narrow window?
2. How many unique destination IPs/ports were targeted?
3. Are there any successful auth events (`SUCCEED`) mixed with failures?

---

**Module 2 complete.** Continue to [Advanced](advanced.html) for CTEs, subqueries, and window functions.
