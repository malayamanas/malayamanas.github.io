# FortiSIEM Advanced Search SQL Training Document — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a complete FortiSIEM 7.4.x Advanced Search SQL training site — six Markdown source files converted to a linked HTML site via a Python build script, covering beginner through advanced SQL with SOC workflow integration.

**Architecture:** Six Markdown modules (skill-progression: intro → beginner → intermediate → advanced → SOC workflow → reference) live in `docs/`. A `scripts/build.py` script reads each `.md`, injects a shared navigation bar and CSS link, and writes `.html` to `site/`. A single `style.css` in `site/assets/` provides consistent styling with SQL syntax highlighting via a lightweight JS library (highlight.js CDN — no build tooling needed).

**Tech Stack:** Python 3 stdlib + `markdown` package (pip), highlight.js via CDN (no npm), plain HTML/CSS output.

---

## Pre-flight Check

Before starting, verify Python 3 is available:

```bash
python3 --version
pip3 install markdown
```

Expected: Python 3.x.x and successful install of `markdown` package.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `docs/assets/style.css`
- Create: `site/` (directory)
- Create: `site/assets/` (directory)
- Create: `scripts/build.py`

**Step 1: Create directory structure**

```bash
mkdir -p /Users/apple/FortiSIEM_Advanced_Search_SQL/docs/assets
mkdir -p /Users/apple/FortiSIEM_Advanced_Search_SQL/site/assets
mkdir -p /Users/apple/FortiSIEM_Advanced_Search_SQL/scripts
```

**Step 2: Create `docs/assets/style.css`**

```css
/* =============================================
   FortiSIEM Advanced Search SQL Training Site
   ============================================= */

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 16px;
  line-height: 1.7;
  color: #1a1a2e;
  background: #f8f9fa;
}

/* ---- Navigation ---- */
nav {
  background: #0d1b2a;
  padding: 0 2rem;
  display: flex;
  align-items: center;
  gap: 0;
  flex-wrap: wrap;
  box-shadow: 0 2px 8px rgba(0,0,0,0.3);
}

nav .nav-brand {
  color: #e94560;
  font-weight: 700;
  font-size: 1rem;
  padding: 1rem 1.5rem 1rem 0;
  text-decoration: none;
  white-space: nowrap;
  border-right: 1px solid #1e3a5f;
  margin-right: 0.5rem;
}

nav a {
  color: #a8c0d6;
  text-decoration: none;
  padding: 1rem 0.85rem;
  font-size: 0.88rem;
  transition: color 0.2s, background 0.2s;
  white-space: nowrap;
}

nav a:hover, nav a.active {
  color: #ffffff;
  background: #1e3a5f;
}

/* ---- Page layout ---- */
.page-wrapper {
  max-width: 960px;
  margin: 0 auto;
  padding: 2.5rem 2rem 4rem;
}

/* ---- Headings ---- */
h1 { font-size: 2rem; color: #0d1b2a; margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 3px solid #e94560; }
h2 { font-size: 1.5rem; color: #0d1b2a; margin: 2.5rem 0 0.75rem; padding-bottom: 0.3rem; border-bottom: 1px solid #dee2e6; }
h3 { font-size: 1.2rem; color: #1e3a5f; margin: 2rem 0 0.5rem; }
h4 { font-size: 1rem; color: #1e3a5f; margin: 1.5rem 0 0.4rem; text-transform: uppercase; letter-spacing: 0.05em; }

.module-subtitle {
  color: #6c757d;
  font-size: 1.1rem;
  margin-bottom: 2rem;
}

/* ---- Body text ---- */
p { margin-bottom: 1rem; }
ul, ol { margin: 0.5rem 0 1rem 1.5rem; }
li { margin-bottom: 0.3rem; }
strong { color: #0d1b2a; }
a { color: #e94560; }
a:hover { color: #c73652; }

/* ---- Tables ---- */
table {
  width: 100%;
  border-collapse: collapse;
  margin: 1.5rem 0;
  font-size: 0.9rem;
}
th {
  background: #0d1b2a;
  color: #ffffff;
  padding: 0.65rem 1rem;
  text-align: left;
  font-weight: 600;
}
td {
  padding: 0.6rem 1rem;
  border-bottom: 1px solid #dee2e6;
  vertical-align: top;
}
tr:nth-child(even) td { background: #f0f4f8; }
tr:hover td { background: #e8eef4; }

/* ---- Code ---- */
code {
  font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", Consolas, monospace;
  font-size: 0.88em;
  background: #1e3a5f12;
  color: #c73652;
  padding: 0.15em 0.4em;
  border-radius: 4px;
}

pre {
  background: #0d1b2a;
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  overflow-x: auto;
  margin: 1.2rem 0;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

pre code {
  background: none;
  color: #cdd6f4;
  padding: 0;
  font-size: 0.88rem;
  line-height: 1.6;
}

/* ---- Callout boxes ---- */
.callout {
  border-left: 4px solid;
  padding: 1rem 1.25rem;
  margin: 1.5rem 0;
  border-radius: 0 6px 6px 0;
}

.callout-note   { border-color: #3b82f6; background: #eff6ff; }
.callout-warn   { border-color: #f59e0b; background: #fffbeb; }
.callout-lab    { border-color: #10b981; background: #f0fdf4; }
.callout-soc    { border-color: #e94560; background: #fff1f3; }
.callout-tip    { border-color: #8b5cf6; background: #f5f3ff; }

.callout strong { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.06em; }
.callout-note   strong { color: #1d4ed8; }
.callout-warn   strong { color: #b45309; }
.callout-lab    strong { color: #047857; }
.callout-soc    strong { color: #c73652; }
.callout-tip    strong { color: #6d28d9; }

/* ---- Skill level badge ---- */
.level-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 1rem;
}
.level-beginner     { background: #d1fae5; color: #065f46; }
.level-intermediate { background: #dbeafe; color: #1e40af; }
.level-advanced     { background: #fce7f3; color: #9d174d; }
.level-all          { background: #f3e8ff; color: #5b21b6; }

/* ---- Footer ---- */
footer {
  text-align: center;
  padding: 2rem;
  color: #6c757d;
  font-size: 0.85rem;
  border-top: 1px solid #dee2e6;
  margin-top: 4rem;
}
```

**Step 3: Create `scripts/build.py`**

```python
#!/usr/bin/env python3
"""
FortiSIEM Advanced Search SQL Training Site Builder
Converts docs/*.md -> site/*.html with shared navigation and syntax highlighting.

Usage:
    python3 scripts/build.py

Requirements:
    pip3 install markdown
"""

import re
import shutil
from pathlib import Path

import markdown
from markdown.extensions.tables import TableExtension
from markdown.extensions.fenced_code import FencedCodeExtension

# ── Configuration ──────────────────────────────────────────────────────────────

DOCS_DIR   = Path(__file__).parent.parent / "docs"
SITE_DIR   = Path(__file__).parent.parent / "site"
ASSETS_SRC = DOCS_DIR / "assets"
ASSETS_DST = SITE_DIR / "assets"

PAGES = [
    ("00-introduction.md",  "index.html",         "Introduction"),
    ("01-beginner.md",      "beginner.html",       "Beginner"),
    ("02-intermediate.md",  "intermediate.html",   "Intermediate"),
    ("03-advanced.md",      "advanced.html",       "Advanced"),
    ("04-soc-workflow.md",  "soc-workflow.html",   "SOC Workflow"),
    ("05-reference.md",     "reference.html",      "Reference"),
]

HIGHLIGHT_JS = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0"

# ── Navigation ─────────────────────────────────────────────────────────────────

def build_nav(active_html: str) -> str:
    links = []
    for _, html_name, label in PAGES:
        active = ' class="active"' if html_name == active_html else ""
        links.append(f'<a href="{html_name}"{active}>{label}</a>')
    return (
        "<nav>\n"
        '  <a class="nav-brand" href="index.html">FortiSIEM&#8202;|&#8202;Advanced Search SQL</a>\n'
        + "\n".join(f"  {l}" for l in links)
        + "\n</nav>"
    )

# ── Callout post-processing ─────────────────────────────────────────────────────
# Converts blockquotes that start with [NOTE], [WARN], [LAB], [SOC], [TIP]

CALLOUT_MAP = {
    "[NOTE]": ("callout-note",  "Note"),
    "[WARN]": ("callout-warn",  "Warning"),
    "[LAB]":  ("callout-lab",   "Lab Exercise"),
    "[SOC]":  ("callout-soc",   "SOC Tip"),
    "[TIP]":  ("callout-tip",   "Tip"),
}

def process_callouts(html: str) -> str:
    for tag, (css_class, label) in CALLOUT_MAP.items():
        pattern = (
            r'<blockquote>\s*<p>'
            + re.escape(tag)
            + r'\s*(.*?)</p>\s*</blockquote>'
        )
        replacement = (
            f'<div class="callout {css_class}">'
            f'<strong>{label}</strong>\\1</div>'
        )
        html = re.sub(pattern, replacement, html, flags=re.DOTALL)
    return html

# ── HTML template ──────────────────────────────────────────────────────────────

def render_page(title: str, nav: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — FortiSIEM Advanced Search SQL</title>
  <link rel="stylesheet" href="assets/style.css">
  <link rel="stylesheet" href="{HIGHLIGHT_JS}/styles/atom-one-dark.min.css">
</head>
<body>
{nav}
<div class="page-wrapper">
{body}
</div>
<footer>
  FortiSIEM Advanced Search SQL Training &mdash; FortiSIEM 7.4.x &mdash;
  Built with <a href="https://python-markdown.github.io/">Python-Markdown</a>
</footer>
<script src="{HIGHLIGHT_JS}/highlight.min.js"></script>
<script>
  document.querySelectorAll('pre code').forEach(el => {{
    hljs.highlightElement(el);
  }});
</script>
</body>
</html>"""

# ── Build ──────────────────────────────────────────────────────────────────────

def extract_title(md_source: str) -> str:
    for line in md_source.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return "FortiSIEM Advanced Search SQL"

def convert_md(md_source: str) -> str:
    return markdown.markdown(
        md_source,
        extensions=[
            TableExtension(),
            FencedCodeExtension(),
            "toc",
            "attr_list",
        ],
    )

def build():
    SITE_DIR.mkdir(parents=True, exist_ok=True)

    # Copy assets
    if ASSETS_SRC.exists():
        shutil.copytree(ASSETS_SRC, ASSETS_DST, dirs_exist_ok=True)
        print(f"  Copied assets -> {ASSETS_DST}")

    for md_name, html_name, _label in PAGES:
        md_path = DOCS_DIR / md_name
        if not md_path.exists():
            print(f"  SKIP {md_name} (not found)")
            continue

        md_source = md_path.read_text(encoding="utf-8")
        title     = extract_title(md_source)
        body      = convert_md(md_source)
        body      = process_callouts(body)
        nav       = build_nav(html_name)
        page      = render_page(title, nav, body)

        out_path  = SITE_DIR / html_name
        out_path.write_text(page, encoding="utf-8")
        print(f"  Built {md_name} -> {out_path.relative_to(Path.cwd())}")

    print("\nDone. Open site/index.html in a browser.")

if __name__ == "__main__":
    build()
```

**Step 4: Verify build script syntax**

```bash
python3 -c "import ast; ast.parse(open('scripts/build.py').read()); print('Syntax OK')"
```

Expected: `Syntax OK`

**Step 5: Commit scaffolding**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git init
git add scripts/build.py docs/assets/style.css docs/plans/
git commit -m "feat: project scaffolding — build script, CSS, design docs"
```

---

### Task 2: Module 0 — Introduction & Interface Navigation

**Files:**
- Create: `docs/00-introduction.md`

**Step 1: Create `docs/00-introduction.md`**

Full content below — copy exactly:

````markdown
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
````

**Step 2: Do a partial build to verify Module 0 renders**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 scripts/build.py
```

Expected output includes: `Built 00-introduction.md -> site/index.html`

**Step 3: Commit**

```bash
git add docs/00-introduction.md
git commit -m "feat: Module 0 — introduction and interface navigation"
```

---

### Task 3: Module 1 — Beginner

**Files:**
- Create: `docs/01-beginner.md`

**Step 1: Create `docs/01-beginner.md`**

````markdown
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
````

**Step 2: Build and verify**

```bash
python3 scripts/build.py
```

Expected: `Built 01-beginner.md -> site/beginner.html`

**Step 3: Commit**

```bash
git add docs/01-beginner.md
git commit -m "feat: Module 1 — beginner queries with lab exercises"
```

---

### Task 4: Module 2 — Intermediate

**Files:**
- Create: `docs/02-intermediate.md`

**Step 1: Create `docs/02-intermediate.md`**

````markdown
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

-- Events in a time window (epoch seconds)
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
  AND srcIpAddrV4 = '10.0.5.44'   -- replace with alerted IP
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
````

**Step 2: Build and verify**

```bash
python3 scripts/build.py
```

**Step 3: Commit**

```bash
git add docs/02-intermediate.md
git commit -m "feat: Module 2 — intermediate operators, functions, CMDB, IR workflow"
```

---

### Task 5: Module 3 — Advanced

**Files:**
- Create: `docs/03-advanced.md`

**Step 1: Create `docs/03-advanced.md`**

````markdown
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
-- (i.e., internal devices acting as sources — useful for lateral movement detection)
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
-- Low frequency = potentially anomalous execution
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
-- (beacons maintain regular cadence unlike human traffic)
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
````

**Step 2: Build and commit**

```bash
python3 scripts/build.py
git add docs/03-advanced.md
git commit -m "feat: Module 3 — CTEs, subqueries, window functions, threat hunting"
```

---

### Task 6: Module 4 — SOC Workflow

**Files:**
- Create: `docs/04-soc-workflow.md`

**Step 1: Create `docs/04-soc-workflow.md`**

````markdown
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
  AND destIpAddrV4 LIKE '10.%'        -- internal IPs only
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
-- Hosts that received connections from the compromised IP
-- AND then made outbound connections to uncommon ports (possible infection propagation)
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
   (e.g., process execution events from endpoints)
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
-- Destinations receiving high connection counts to web ports
-- from a single internal host (possible C2 beaconing)
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
-- Which devices/IPs are generating the most hits for a noisy alert?
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

Once you've identified the top false-positive source, look at what that device normally does:

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

Before applying an exception, quantify how much noise it removes:

```sql
-- How much of the total alert volume comes from the false positive source?
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
````

**Step 2: Build and commit**

```bash
python3 scripts/build.py
git add docs/04-soc-workflow.md
git commit -m "feat: Module 4 — SOC workflow IR, threat hunting, alert tuning, dashboards"
```

---

### Task 7: Module 5 — Reference Appendix

**Files:**
- Create: `docs/05-reference.md`

**Step 1: Create `docs/05-reference.md`**

````markdown
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
````

**Step 2: Build and commit**

```bash
python3 scripts/build.py
git add docs/05-reference.md
git commit -m "feat: Module 5 — reference appendix, cheat sheet, error guide"
```

---

### Task 8: Final Build Verification

**Step 1: Run full build and verify all pages generated**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 scripts/build.py
```

Expected output:
```
  Copied assets -> site/assets
  Built 00-introduction.md -> site/index.html
  Built 01-beginner.md -> site/beginner.html
  Built 02-intermediate.md -> site/intermediate.html
  Built 03-advanced.md -> site/advanced.html
  Built 04-soc-workflow.md -> site/soc-workflow.html
  Built 05-reference.md -> site/reference.html

Done. Open site/index.html in a browser.
```

**Step 2: Verify all 6 HTML files exist**

```bash
ls -la /Users/apple/FortiSIEM_Advanced_Search_SQL/site/
```

Expected: 6 `.html` files + `assets/` directory.

**Step 3: Verify HTML is well-formed (quick check)**

```bash
python3 -c "
from pathlib import Path
for f in Path('site').glob('*.html'):
    content = f.read_text()
    assert '<nav>' in content, f'Missing nav in {f}'
    assert 'highlight.js' in content, f'Missing highlight.js in {f}'
    assert '</html>' in content, f'Malformed HTML in {f}'
    print(f'OK: {f.name}')
"
```

Expected: `OK: index.html` through `OK: reference.html`

**Step 4: Open in browser and verify navigation works**

```bash
open site/index.html
```

Click each nav link and verify:
- All 6 pages load
- Navigation bar highlights the active page
- Code blocks have syntax highlighting
- Tables render correctly
- Callout boxes (Note, Warning, Lab, SOC Tip) display correctly

**Step 5: Final commit**

```bash
git add site/
git commit -m "feat: complete training site — all 6 modules built to HTML"
```

---

### Task 9: Save Memory

**Step 1: Create memory directory and save project context**

```bash
mkdir -p /Users/apple/.claude/projects/-Users-apple-FortiSIEM-Advanced-Search-SQL/memory/
```

Then write `MEMORY.md` with project context for future sessions.

---

## Summary

| Task | Deliverable |
|---|---|
| 1 | Project scaffolding: `build.py`, `style.css`, design docs |
| 2 | `docs/00-introduction.md` — interface, navigation, FortiAI |
| 3 | `docs/01-beginner.md` — first queries, aggregation, 3 labs |
| 4 | `docs/02-intermediate.md` — operators, functions, CMDB, IR lab |
| 5 | `docs/03-advanced.md` — CTEs, subqueries, window functions, threat hunting lab |
| 6 | `docs/04-soc-workflow.md` — IR, threat hunting, alert tuning, dashboards |
| 7 | `docs/05-reference.md` — attribute table, functions, cheat sheet, errors |
| 8 | Full build verification + browser test |
| 9 | Memory saved for future sessions |
