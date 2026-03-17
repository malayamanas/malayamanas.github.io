# FortiSIEM Advanced Search SQL — Training Guide

<span class="level-badge level-all">All Levels</span>

Welcome to the FortiSIEM Advanced Search SQL training guide. This resource covers everything from your first query to advanced threat hunting techniques, with hands-on lab exercises throughout.

## What Is Advanced Search?

FortiSIEM Advanced Search is a **ClickHouse-powered SQL query interface** introduced in FortiSIEM 7.3 and expanded in 7.4.x. It allows SOC analysts to write free-form SQL queries directly against the FortiSIEM event database — giving you full analytical power beyond what the Structured Search interface provides.

| Feature | Structured Search | Advanced Search |
|---|---|---|
| Interface | Drag-and-drop filters | SQL query editor |
| Flexibility | Moderate | Full SQL power |
| Learning curve | Low | Moderate |
| Use case | Quick lookups | Complex analytics, threat hunting |
| Backend | EventDB / ClickHouse | ClickHouse only |

> [NOTE] Advanced Search requires a **ClickHouse** event database backend. Verify this with your FortiSIEM admin before proceeding. Navigate to Admin > ClickHouse Operational Overview to confirm.

## Navigating to Advanced Search

1. Log in to FortiSIEM
2. Click **Analytics** in the top navigation bar
3. Select **Advanced Search** from the left sidebar

The interface loads with three main panels:

```
┌─────────────────────────────────────────────────────┐
│  QUERY CONSOLE                                      │
│  [ SQL query editor — type your query here ]        │
├──────────────────┬──────────────────────────────────┤
│  DATABASE SCHEMA │  QUERY RESULTS                   │
│  fsiem.events    │  [ Results appear here after     │
│  ├ phRecvTime    │    running the query ]            │
│  ├ reptDevName   │                                   │
│  └ ...           │                                   │
└──────────────────┴──────────────────────────────────┘
```

### Panel Descriptions

| Panel | Purpose |
|---|---|
| Query Console | Write and run SQL queries. Use the run button or `Ctrl+Enter`. |
| Database Schema | Browse available columns in `fsiem.events`. Click to insert attribute names. |
| Attributes used | Dropdown to add less-common attributes to your query scope. |
| Query Results | Displays result rows, supports full-screen and export. |

## Running a Built-In Search

FortiSIEM ships with 30+ built-in Advanced Search queries for common SOC tasks.

**Method 1 — From Resources:**
1. Go to **Resources > Reports > Advanced Search** in the left sidebar
2. Select a report and click **Run**
3. The SQL query loads into the Query Console — inspect it to learn

**Method 2 — From Analytics:**
1. Go to **Analytics > Advanced Search**
2. Click the **folder icon** in the Query Console toolbar
3. Select a report, click the dropdown → **Run**

> [TIP] Reading built-in queries is one of the fastest ways to learn FortiSIEM SQL patterns. Open each built-in search, read the SQL, and trace what each clause does before writing your own.

## FortiAI SQL Assistant

FortiSIEM 7.4 integrates FortiAI directly into Advanced Search for two workflows:

### Generate SQL from Natural Language
Click **FortiAI > Generate SQL** and describe your query in plain English:

- *"Show me the top 10 source IPs by event count in the last hour"*
- *"Find all failed login attempts grouped by username in the last 24 hours"*
- *"List devices in the Windows Server group that reported external events today"*

FortiAI generates the SQL — review it, adjust it, then run it.

### Fix Syntax Errors
If your query returns a syntax error, click **Fix Errors** and FortiAI will attempt to correct the SQL automatically.

> [WARN] FortiAI-generated queries should always be **reviewed before running** on a production system. Validate the logic, check time ranges, and verify attribute names match your environment.

## Data Privacy Notice

> [WARN] Advanced Search results are **not anonymized**. Event data including IP addresses, usernames, hostnames, and other PII is displayed in full. Handle query results according to your organization's data handling policy before sharing screenshots or exports.

## What's Next

Use the navigation above to begin at your skill level:

- **New to FortiSIEM SQL?** → Start with [Beginner](beginner.html)
- **Know the basics?** → Jump to [Intermediate](intermediate.html)
- **Ready for complex queries?** → Go to [Advanced](advanced.html)
- **SOC workflow focus?** → See [SOC Workflow](soc-workflow.html)
- **Quick reference?** → See [Reference](reference.html)
