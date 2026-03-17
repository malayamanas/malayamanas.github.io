# Advanced: CTEs, Subqueries & Window Functions

<span class="level-badge level-advanced">Advanced</span>

This module covers multi-step SQL techniques that unlock complex analytical workflows: Common Table Expressions for readable query composition, subqueries for temporal comparison, window functions for per-group ranking, and performance best practices.

## Common Table Expressions (CTEs)

A CTE defines a named, temporary result set you can reference later in the same query. It makes complex multi-step logic readable and maintainable.

### Syntax

```sql
WITH cte_name AS (
    SELECT ...
    FROM fsiem.events
    WHERE ...
),
second_cte AS (
    SELECT ...
    FROM cte_name
    WHERE ...
)
SELECT *
FROM second_cte
LIMIT 20
```

### Example: Two-Step Analysis

Find devices that had more than 1000 events in the last hour, then show their event type breakdown:

```sql
WITH high_volume_devices AS (
    SELECT reptDevName
    FROM fsiem.events
    WHERE phRecvTime > (now() - 3600)
      AND eventParsedOk = 1
    GROUP BY reptDevName
    HAVING COUNT(*) > 1000
)
SELECT
  e.reptDevName                   AS "Device",
  e.eventType                     AS "Event Type",
  COUNT(*)                        AS "Count"
FROM fsiem.events e
INNER JOIN high_volume_devices h ON e.reptDevName = h.reptDevName
WHERE e.phRecvTime > (now() - 3600)
  AND e.eventParsedOk = 1
GROUP BY e.reptDevName, e.eventType
ORDER BY COUNT(*) DESC
LIMIT 30
```

> [TIP] CTEs are not just organizational — they also prevent you from repeating the same subquery multiple times in a single query, which can significantly improve readability during review and incident handoffs.

## Subqueries and Temporal Comparison

### NOT IN — "Today But Not Yesterday"

One of the most powerful SOC patterns: find devices (or IPs) that appeared in a recent window but not in an earlier baseline window. This surfaces new or anomalous actors.

```sql
-- Devices reporting external events today but not yesterday
SELECT DISTINCT reptDevName AS "New Reporter Today"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND phEventCategory IN (0, 4)
  AND eventParsedOk = 1
  AND reptDevName NOT IN (
      SELECT DISTINCT reptDevName
      FROM fsiem.events
      WHERE phRecvTime BETWEEN (now() - 172800) AND (now() - 86400)
        AND phEventCategory IN (0, 4)
        AND eventParsedOk = 1
  )
ORDER BY reptDevName
```

### IN with Subquery — Filter to a Known Set

```sql
-- Show all events from source IPs that also appear as reporting device IPs
SELECT srcIpAddrV4, eventType, COUNT(*) AS Count
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
  AND srcIpAddrV4 IN (
      SELECT DISTINCT reptDevIpAddrV4
      FROM fsiem.events
      WHERE phRecvTime > (now() - 3600)
  )
GROUP BY srcIpAddrV4, eventType
ORDER BY Count DESC
LIMIT 20
```

## Window Functions

Window functions perform calculations across a set of rows related to the current row — without collapsing them into a single summary row like GROUP BY does.

### RANK() OVER (PARTITION BY … ORDER BY …)

Get the top N items **per group** — for example, the top 5 event types per reporting device:

```sql
SELECT *
FROM (
    SELECT
        reptDevName,
        eventType,
        COUNT(*)            AS EventCount,
        RANK() OVER (
            PARTITION BY reptDevName
            ORDER BY COUNT(*) DESC
        )                   AS rnk
    FROM fsiem.events
    WHERE phRecvTime > (now() - 3600)
      AND eventParsedOk = 1
    GROUP BY reptDevName, eventType
) ranked
WHERE rnk <= 5
ORDER BY reptDevName, rnk
LIMIT 100
```

> [NOTE] `PARTITION BY reptDevName` resets the rank counter for each device. `ORDER BY COUNT(*) DESC` ranks event types within each device by frequency. The outer `WHERE rnk <= 5` keeps only the top 5 per device.

### ROW_NUMBER() — Deduplicate or Get Latest

```sql
-- Get the single most recent event per source IP
SELECT *
FROM (
    SELECT
        srcIpAddrV4,
        eventType,
        phRecvTime,
        ROW_NUMBER() OVER (
            PARTITION BY srcIpAddrV4
            ORDER BY phRecvTime DESC
        ) AS rn
    FROM fsiem.events
    WHERE phRecvTime > (now() - 3600)
      AND eventParsedOk = 1
      AND srcIpAddrV4 != ''
) t
WHERE rn = 1
LIMIT 50
```

## Lookup Tables

FortiSIEM lookup tables let you enrich query results with external reference data (IOC lists, asset tags, custom mappings).

### LookupTableHas() — IOC Sweep

```sql
-- Find events where the source IP is in your IOC lookup table
SELECT
  srcIpAddrV4                     AS "IOC IP",
  eventType                       AS "Event Type",
  reptDevName                     AS "Reporting Device",
  COUNT(*)                        AS "Hit Count",
  MAX(phRecvTime)                 AS "Last Seen"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND eventParsedOk = 1
  AND LookupTableHas('Threat_IOC_IPs', srcIpAddrV4)
GROUP BY srcIpAddrV4, eventType, reptDevName
ORDER BY COUNT(*) DESC
LIMIT 50
```

> [SOC] Replace `'Threat_IOC_IPs'` with the actual name of your lookup table as configured in FortiSIEM (Admin > General Settings > Lookup Tables). Keep your IOC lookup tables updated via scheduled imports from your threat intel platform.

### LookupTableGet() — Enrich with Context

```sql
SELECT
  srcIpAddrV4,
  LookupTableGet('Asset_Register', srcIpAddrV4, 'owner')  AS "Owner",
  LookupTableGet('Asset_Register', srcIpAddrV4, 'team')   AS "Team",
  COUNT(*) AS Events
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
GROUP BY srcIpAddrV4
ORDER BY Events DESC
LIMIT 20
```

## Performance Optimization

> [WARN] Poorly written queries can impact FortiSIEM performance. Follow these rules before running queries on production.

### Rule 1: Always Time-Bound Queries

```sql
-- BAD: Scans entire event history
SELECT COUNT(*) FROM fsiem.events WHERE eventType = 'PH_NET_FIREWALL_DENY'

-- GOOD: Scans only last 24 hours
SELECT COUNT(*) FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND eventType = 'PH_NET_FIREWALL_DENY'
```

### Rule 2: Use LIMIT While Testing

Start with `LIMIT 10`. Once the logic is validated, remove or increase the limit for production.

### Rule 3: Filter Early — Use Primary Index

ClickHouse's primary index is on `phRecvTime`. Always include a `phRecvTime` filter to leverage index scans. Secondary conditions (like `srcIpAddrV4`) filter the result of the index scan.

### Rule 4: Avoid SELECT *

```sql
-- BAD
SELECT * FROM fsiem.events WHERE phRecvTime > (now() - 3600) LIMIT 10

-- GOOD
SELECT reptDevName, eventType, srcIpAddrV4, phRecvTime
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
LIMIT 10
```

### Rule 5: Validate with COUNT Before Full SELECT

```sql
-- First: check how many rows match
SELECT COUNT(*)
FROM fsiem.events
WHERE phRecvTime > (now() - 3600)
  AND eventParsedOk = 1
  AND reptDevName LIKE 'db-%'

-- If count is reasonable, then run the full query
```

## SOC Workflow: Threat Hunting

Threat hunting is proactive — you form a hypothesis about attacker behavior and use SQL to test it. Here are three hunting patterns.

### Hunt 1: Rare Process Names (LOLBins)

```sql
-- Processes seen fewer than 5 times in the last 7 days
WITH process_counts AS (
    SELECT
        appName,
        COUNT(*)    AS ExecCount,
        COUNT(DISTINCT reptDevName) AS DeviceCount
    FROM fsiem.events
    WHERE phRecvTime > (now() - 604800)
      AND eventParsedOk = 1
      AND appName != ''
    GROUP BY appName
)
SELECT appName, ExecCount, DeviceCount
FROM process_counts
WHERE ExecCount < 5
ORDER BY ExecCount ASC
LIMIT 50
```

### Hunt 2: Beaconing Detection (Regular Intervals)

```sql
-- Find source IPs with very consistent connection counts per hour
SELECT
  srcIpAddrV4                     AS "Source IP",
  destIpAddrV4                    AS "Destination IP",
  destIpPort                      AS "Port",
  COUNT(*)                        AS "Total Connections",
  COUNT(DISTINCT HourOfDay(phRecvTime)) AS "Active Hours",
  STDDEV(HourOfDay(phRecvTime))   AS "Hour Stddev"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND eventParsedOk = 1
  AND srcIpAddrV4 != ''
  AND destIpAddrV4 != ''
GROUP BY srcIpAddrV4, destIpAddrV4, destIpPort
HAVING COUNT(*) > 100
   AND STDDEV(HourOfDay(phRecvTime)) < 2.0
ORDER BY "Hour Stddev" ASC
LIMIT 30
```

> [SOC] Low `STDDEV` on hour-of-day means the connection happens at very consistent times — a hallmark of automated beaconing. Tune the thresholds (`> 100`, `< 2.0`) to your environment's baseline.

### Hunt 3: Baseline Deviation

```sql
-- Devices whose event count today deviates significantly from their 7-day average
WITH daily_avg AS (
    SELECT
        reptDevName,
        AVG(daily_count)    AS avg_events,
        STDDEV(daily_count) AS stddev_events
    FROM (
        SELECT reptDevName, COUNT(*) AS daily_count
        FROM fsiem.events
        WHERE phRecvTime BETWEEN (now() - 604800) AND (now() - 86400)
          AND eventParsedOk = 1
        GROUP BY reptDevName, toDate(phRecvTime)
    ) daily
    GROUP BY reptDevName
),
today AS (
    SELECT reptDevName, COUNT(*) AS today_count
    FROM fsiem.events
    WHERE phRecvTime > (now() - 86400)
      AND eventParsedOk = 1
    GROUP BY reptDevName
)
SELECT
    t.reptDevName                   AS "Device",
    t.today_count                   AS "Today",
    ROUND(d.avg_events, 0)          AS "7-Day Avg",
    ROUND(d.stddev_events, 0)       AS "Stddev",
    ROUND((t.today_count - d.avg_events) / d.stddev_events, 2) AS "Z-Score"
FROM today t
JOIN daily_avg d ON t.reptDevName = d.reptDevName
WHERE d.stddev_events > 0
  AND ABS((t.today_count - d.avg_events) / d.stddev_events) > 2
ORDER BY ABS((t.today_count - d.avg_events) / d.stddev_events) DESC
LIMIT 20
```

> [SOC] A Z-score above +2 or below -2 indicates the device is behaving significantly outside its normal range. Positive = spike (possible attack traffic, noisy tool). Negative = drop (possible device failure, log source going silent).

## Lab Exercise — Module 3

> [LAB] **Build a 3-query threat hunting playbook** for your environment. Use the templates above as a starting point. For each query: (1) run it, (2) note any findings, (3) document your hypothesis and result.

**Playbook Query 1: New External Communicators**

Adapt the "today but not yesterday" subquery to find source IPs that appeared in the last 24 hours but were absent in the prior 24 hours. What do you find?

**Playbook Query 2: Top Anomalous Devices by Z-Score**

Run the Baseline Deviation query. Identify the top 3 devices by absolute Z-score. For each, drill into their event types using a separate query.

**Playbook Query 3: IOC Sweep**

If your environment has a lookup table loaded with known-bad IPs or domains, run the `LookupTableHas()` IOC sweep. How many hits in the last 7 days?

---

**Module 3 complete.** Continue to [SOC Workflow](soc-workflow.html) to see how these queries fit into end-to-end SOC operations.
