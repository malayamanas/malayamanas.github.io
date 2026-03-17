# SOC Workflow: IR, Threat Hunting & Alert Tuning

<span class="level-badge level-all">All Levels</span>

This module shows how Advanced Search SQL integrates into the daily operations of a SOC analyst — from incident response pivoting to proactive threat hunting, alert tuning, and dashboard creation.

## Incident Response with Advanced Search

When an alert fires, your first goal is to **understand scope and timeline**. Advanced Search gives you a direct line to the raw event data.

### The IR Query Workflow

```
Alert fires
     │
     ▼
Step 1: Confirm — does the data match the alert?
     │
     ▼
Step 2: Scope — what other systems are involved?
     │
     ▼
Step 3: Timeline — when did it start/end?
     │
     ▼
Step 4: Evidence — export query results for the incident ticket
```

### Example: Ransomware Lateral Movement Scoping

**Scenario:** Your EDR fired a ransomware detection on host `10.0.2.15`. You need to determine if it has moved laterally.

**Step 1 — Confirm the host is in your event data:**

```sql
SELECT phRecvTime, reptDevName, reptDevIpAddrV4, eventType
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND (reptDevIpAddrV4 = '10.0.2.15' OR srcIpAddrV4 = '10.0.2.15')
  AND eventParsedOk = 1
ORDER BY phRecvTime DESC
LIMIT 20
```

**Step 2 — What internal IPs has it connected to?**

```sql
SELECT
  destIpAddrV4                    AS "Destination",
  destIpPort                      AS "Port",
  COUNT(*)                        AS "Connections",
  MIN(phRecvTime)                 AS "First",
  MAX(phRecvTime)                 AS "Last"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND srcIpAddrV4 = '10.0.2.15'
  AND destIpAddrV4 LIKE '10.%'
  AND eventParsedOk = 1
GROUP BY destIpAddrV4, destIpPort
ORDER BY COUNT(*) DESC
LIMIT 30
```

**Step 3 — Build an event timeline:**

```sql
SELECT
  phRecvTime                      AS "Time",
  reptDevName                     AS "Reporter",
  eventType                       AS "Event Type",
  srcIpAddrV4                     AS "Src IP",
  destIpAddrV4                    AS "Dst IP",
  destIpPort                      AS "Dst Port"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND (srcIpAddrV4 = '10.0.2.15' OR destIpAddrV4 = '10.0.2.15')
  AND eventParsedOk = 1
ORDER BY phRecvTime ASC
LIMIT 200
```

> [SOC] Export the timeline query results to CSV (use the download button in Query Results) and attach to your incident ticket as evidence. Include the SQL query itself so the evidence is reproducible.

**Step 4 — Identify other potentially compromised hosts:**

```sql
WITH contacted AS (
    SELECT DISTINCT destIpAddrV4 AS contacted_ip
    FROM fsiem.events
    WHERE phRecvTime > (now() - 86400)
      AND srcIpAddrV4 = '10.0.2.15'
      AND eventParsedOk = 1
)
SELECT
  e.srcIpAddrV4                   AS "Potentially Infected Host",
  e.destIpAddrV4                  AS "It Connected To",
  e.destIpPort                    AS "Port",
  COUNT(*)                        AS "Connections"
FROM fsiem.events e
INNER JOIN contacted c ON e.srcIpAddrV4 = c.contacted_ip
WHERE e.phRecvTime > (now() - 86400)
  AND e.destIpPort NOT IN (80, 443, 53, 123, 22)
  AND e.eventParsedOk = 1
GROUP BY e.srcIpAddrV4, e.destIpAddrV4, e.destIpPort
ORDER BY COUNT(*) DESC
LIMIT 30
```

## Threat Hunting Methodology

Threat hunting is structured, hypothesis-driven investigation. Follow this process:

```
1. Form a hypothesis
   (e.g., "An attacker is using living-off-the-land binaries")
        │
        ▼
2. Identify the data that would prove/disprove it
        │
        ▼
3. Write and run the query
        │
        ▼
4. Analyze results — find anomalies
        │
        ▼
5. Pivot: investigate anomalies with follow-up queries
        │
        ▼
6. Document findings (either close the hunt or open an incident)
```

### MITRE ATT&CK-Aligned Hunt Queries

**T1059 — Command and Scripting Interpreter:**

```sql
-- Look for scripting interpreters executed outside business hours
SELECT
  reptDevName                     AS "Host",
  appName                         AS "Process",
  COUNT(*)                        AS "Executions",
  MIN(phRecvTime)                 AS "First",
  MAX(phRecvTime)                 AS "Last"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND eventParsedOk = 1
  AND appName IN ('powershell.exe', 'cmd.exe', 'wscript.exe',
                  'cscript.exe', 'mshta.exe', 'certutil.exe')
  AND (HourOfDay(phRecvTime) < 7 OR HourOfDay(phRecvTime) > 19)
GROUP BY reptDevName, appName
ORDER BY COUNT(*) DESC
LIMIT 30
```

**T1071 — Application Layer Protocol (C2 over HTTP/S):**

```sql
SELECT
  srcIpAddrV4                     AS "Internal Host",
  destIpAddrV4                    AS "External Dest",
  COUNT(*)                        AS "Connections",
  COUNT(DISTINCT HourOfDay(phRecvTime)) AS "Active Hours"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND eventParsedOk = 1
  AND destIpPort IN (80, 443, 8080, 8443)
  AND srcIpAddrV4 LIKE '10.%'
  AND destIpAddrV4 NOT LIKE '10.%'
GROUP BY srcIpAddrV4, destIpAddrV4
HAVING COUNT(*) > 500
ORDER BY COUNT(*) DESC
LIMIT 20
```

**T1110 — Brute Force:**

```sql
SELECT
  srcIpAddrV4                     AS "Attacker IP",
  destIpAddrV4                    AS "Target IP",
  eventType                       AS "Event Type",
  COUNT(*)                        AS "Attempts",
  MIN(phRecvTime)                 AS "Start",
  MAX(phRecvTime)                 AS "End"
FROM fsiem.events
WHERE phRecvTime > (now() - 86400)
  AND eventParsedOk = 1
  AND eventType LIKE '%LOGIN_FAIL%'
GROUP BY srcIpAddrV4, destIpAddrV4, eventType
HAVING COUNT(*) > 50
ORDER BY COUNT(*) DESC
LIMIT 20
```

## Alert Tuning with Advanced Search

Before you can tune an alert rule, you need to understand why it's firing. Advanced Search helps you identify false positive patterns.

### Step 1: Find the False Positive Source

```sql
SELECT
  reptDevName                     AS "Device",
  srcIpAddrV4                     AS "Source IP",
  destIpAddrV4                    AS "Dest IP",
  COUNT(*)                        AS "Hits",
  MIN(phRecvTime)                 AS "First",
  MAX(phRecvTime)                 AS "Last"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND eventParsedOk = 1
  AND eventType = 'PH_RULE_YOUR_RULE_NAME_HERE'
GROUP BY reptDevName, srcIpAddrV4, destIpAddrV4
ORDER BY COUNT(*) DESC
LIMIT 20
```

### Step 2: Confirm the Source is Legitimate

```sql
SELECT eventType, COUNT(*) AS Count
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND reptDevName = 'scanner-host-01'
  AND eventParsedOk = 1
GROUP BY eventType
ORDER BY Count DESC
LIMIT 20
```

> [SOC] If you confirm a device is a legitimate scanner, vulnerability assessment tool, or monitoring system, document this in CMDB and add it to an exception group that your rule already filters — rather than rewriting the rule.

### Step 3: Quantify the Tuning Impact

```sql
SELECT
  CASE
    WHEN reptDevIpAddrV4 = '10.0.8.5' THEN 'Scanner (FP)'
    ELSE 'Other Sources'
  END                             AS "Source Category",
  COUNT(*)                        AS "Alert Count"
FROM fsiem.events
WHERE phRecvTime > (now() - 604800)
  AND eventType = 'PH_RULE_YOUR_RULE_NAME_HERE'
  AND eventParsedOk = 1
GROUP BY "Source Category"
```

## Dashboard Building from Saved Searches

Advanced Search queries can be saved and scheduled as recurring reports that feed dashboards.

**To save a query:**
1. Write and validate your query in the Query Console
2. Click **Save** in the toolbar
3. Give it a descriptive name (e.g., `SOC_Top_Talkers_1H`)
4. It appears under Resources > Reports > Advanced Search

**To schedule a report:**
1. Navigate to Resources > Reports > Advanced Search
2. Select your saved query → **Schedule**
3. Set frequency, recipients, and output format (PDF/CSV)

**To add to a dashboard:**
1. Navigate to Dashboard
2. Add widget → Report → select your saved Advanced Search
3. Set refresh interval

> [SOC] Build a "Morning Brief" dashboard with 3-4 key Advanced Search widgets: top event sources, overnight anomalies (Z-score query), IOC hits, and failed auth attempts. Run it first thing every shift.

## FortiAI in SOC Investigations

FortiSIEM 7.4 integrates FortiAI across the investigation workflow:

| FortiAI Feature | How to Use It | SOC Value |
|---|---|---|
| Generate SQL | Describe query in English → get SQL | Fast query drafting for novel scenarios |
| Fix Errors | Click Fix Errors on a failed query | Recover from syntax mistakes quickly |
| Summarize Results | Click Summarize after query runs | Quick natural-language summary for reports |
| Event Analysis | In Incidents view → Analyze with FortiAI | Contextual explanation of event chains |

> [WARN] FortiAI is a productivity accelerator, not a replacement for analyst judgment. Always review AI-generated SQL for correctness, appropriate time bounds, and logical accuracy before running against production.

## SOAR Integration (FortiSIEM 7.4)

FortiSIEM 7.4 introduced native SOAR automation. Advanced Search queries can trigger or feed into automated playbooks:

- **Incident enrichment:** SOAR playbooks auto-run scoping queries when an incident is created
- **Evidence collection:** Query results attached automatically to incident tickets
- **Automated triage:** Low-severity incidents auto-resolved if follow-up queries confirm known-good patterns

> [NOTE] SOAR playbook configuration is beyond the scope of this training guide. Refer to the FortiSIEM 7.4 Administration Guide for playbook authoring documentation.

---

**Module 4 complete.** See the [Reference](reference.html) appendix for quick lookups, cheat sheets, and common error fixes.
