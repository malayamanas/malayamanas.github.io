# Design: FortiSIEM Advanced Search SQL Training Document

**Date:** 2026-02-23
**Author:** SOC Training Initiative
**Status:** Approved

---

## Overview

A comprehensive training document for FortiSIEM 7.4.x Advanced Search SQL, targeting mixed SOC analyst skill levels (beginner through advanced). Delivered as Markdown source files converted to a linked HTML site via a build script.

---

## Requirements

| Requirement | Decision |
|---|---|
| Target version | FortiSIEM 7.4.x |
| Audience | All levels (beginner → advanced) |
| Output formats | Markdown (.md) source + HTML site |
| Build method | Python script converts .md → .html with navigation |
| Content scope | SQL syntax + SOC workflow integration |
| Exercises | Lab exercises at the end of each skill-level module |

---

## Structure Approach

**Option A — Skill-Progression Track** (selected)

Organized by analyst skill level: Beginner → Intermediate → Advanced. SQL reference tables are inline with the content. SOC workflow context is woven into each level. Labs live at the end of each module.

---

## File Layout

```
FortiSIEM_Advanced_Search_SQL/
├── docs/
│   ├── 00-introduction.md
│   ├── 01-beginner.md
│   ├── 02-intermediate.md
│   ├── 03-advanced.md
│   ├── 04-soc-workflow.md
│   ├── 05-reference.md
│   └── assets/
│       └── style.css
├── site/
│   ├── index.html            ← generated from 00-introduction.md
│   ├── beginner.html
│   ├── intermediate.html
│   ├── advanced.html
│   ├── soc-workflow.html
│   ├── reference.html
│   └── assets/
│       └── style.css
└── scripts/
    └── build.py              ← Markdown → HTML converter with nav injection
```

---

## Module Content Design

### Module 0 — Introduction & Interface Navigation (`00-introduction.md` → `index.html`)

**Purpose:** Orient all readers to the tool before any SQL.

**Sections:**
- What is FortiSIEM Advanced Search? (ClickHouse SQL engine, use it vs Structured Search)
- Navigating to Analytics > Advanced Search
- UI panels: Query Console, Database Schema panel, Query Results, Attributes dropdown
- Running a built-in search (30+ pre-built queries via Resources > Reports > Advanced Search)
- FortiAI SQL assist: Generate SQL from natural language, Fix Errors button
- Data privacy note: results are not anonymized

---

### Module 1 — Beginner: First Queries (`01-beginner.md` → `beginner.html`)

**Purpose:** Enable an analyst with no FortiSIEM SQL experience to write functional queries.

**Sections:**
- The `fsiem.events` table and the FortiSIEM data model
- Basic `SELECT … FROM fsiem.events`
- Filtering with `WHERE`: time ranges using `phRecvTime`, `eventParsedOk=1`
- Aggregation: `COUNT(*)`, `GROUP BY`, `ORDER BY ASC/DESC`, `LIMIT`
- Aliasing columns with `AS`
- Always use `LIMIT` when testing a new query
- Key beginner attributes: `reptDevName`, `reptDevIpAddrV4`, `srcIpAddrV4`, `destIpPort`, `eventType`, `appName`

**Lab Exercises (3 queries):**
1. Top 10 reporting devices by event count in the last hour
2. Event type breakdown across all devices (last 24 hours)
3. List unique source IPs seen in the last 6 hours

---

### Module 2 — Intermediate: Operators, Functions & CMDB (`02-intermediate.md` → `intermediate.html`)

**Purpose:** Enable analysts to write targeted investigation queries.

**Sections:**
- Operators: `IN`, `NOT IN`, `LIKE`, `BETWEEN`, `AND`/`OR`, parentheses grouping
- Aggregate functions: `MAX`, `MIN`, `SUM`, `AVG`, `COUNT DISTINCT`, `FIRST`, `LAST`
- Time functions: `now()`, relative offsets `(now() - N)`, `HourOfDay()`, `DayOfWeek()`
- String functions: `TO_UPPER`, `TRIM`, `SUB_STR`, `REPLACE`, `LEN`
- CMDB integration: `dictHas()` for group membership, `DeviceToCMDBAttr()`
- `phEventCategory` values and filtering by category
- SOC workflow: Writing alert investigation queries from an active incident ticket
  - Pivot from IP → all events → event types → timeframe scoping

**Lab Exercise:**
- Investigate a simulated brute-force login scenario: scope affected accounts, source IPs, timeframe, and success/failure ratio

---

### Module 3 — Advanced: CTEs, Subqueries & Window Functions (`03-advanced.md` → `advanced.html`)

**Purpose:** Enable power users to write complex multi-step analytical queries.

**Sections:**
- CTEs (`WITH … AS (…) SELECT …`) for readable multi-step queries
- Subqueries: `NOT IN` for temporal comparison (devices active today but not yesterday)
- Window functions: `RANK() OVER (PARTITION BY … ORDER BY …)` — top N per group
- Lookup tables: `LookupTableGet()`, `LookupTableHas()` for IOC enrichment
- ClickHouse-specific: `dictHas()` dictionary lookups
- Performance optimization:
  - Always time-bound queries with `phRecvTime`
  - Use ClickHouse primary and data-skipping indices
  - Avoid `SELECT *`; specify columns
  - Use `LIMIT` to validate before full runs
- SOC workflow: Threat hunting patterns
  - LOLBins detection (rare process names)
  - Beaconing detection (regular interval connections)
  - Baseline deviation using `AVG`/`STDDEV`

**Lab Exercise:**
- Build a 3-query threat hunting playbook: (1) identify baseline, (2) find deviations, (3) rank top anomalies per device

---

### Module 4 — SOC Workflow Integration (`04-soc-workflow.md` → `soc-workflow.html`)

**Purpose:** Show how Advanced Search SQL fits into real SOC operations.

**Sections:**
- **Incident Response:** alert → pivot query → scope → containment evidence gathering
  - Example: ransomware lateral movement scoping query
- **Threat Hunting:** hypothesis-driven workflow, building hunting queries from TTPs (MITRE ATT&CK mapping)
  - Baselining normal with `AVG`/`STDDEV`, hunting outliers
- **Alert Tuning:** identifying false positive sources, building suppression candidate queries
- **Dashboard Building:** saving Advanced Searches, scheduling reports, sharing with team
- **FortiAI in investigations:** natural language → SQL, result summarization, iterative query refinement
- SOAR integration overview: how query results feed into automated playbooks (FortiSIEM 7.4 native SOAR)

---

### Module 5 — Reference Appendix (`05-reference.md` → `reference.html`)

**Purpose:** Fast lookup for working analysts.

**Sections:**
- Key event attributes table (name, data type, description, example value)
- `phEventCategory` values table (value, meaning, use case)
- All functions quick-reference table (function, syntax, backend support, example)
- Common query patterns cheat sheet (copy-paste ready)
  - Top N by count
  - Time-window comparison
  - Multi-condition filter
  - CMDB group filter
  - IOC sweep
- Common SQL errors and fixes

---

## Build Script Design (`scripts/build.py`)

**Input:** All `.md` files in `docs/`
**Output:** Corresponding `.html` files in `site/` with:
- Injected navigation bar linking all modules
- Injected `<link>` to `assets/style.css`
- Syntax-highlighted code blocks
- Proper `<title>` from first `#` heading

**Dependencies:** Python standard library + `markdown` package (or `mistune`)

---

## Style Design (`docs/assets/style.css`)

- Clean, readable sans-serif body font
- Dark syntax highlighting for SQL code blocks
- Responsive layout (readable on laptop and tablet)
- Navigation bar at top with links to all modules
- Callout boxes for: Note, Warning, Lab Exercise, SOC Tip

---

## Success Criteria

- An analyst new to FortiSIEM SQL can write a working query after completing Module 1
- An intermediate analyst can investigate an active alert using Module 2 queries
- An advanced analyst can build a threat hunting playbook using Module 3 techniques
- All queries are tested against FortiSIEM 7.4.x syntax
- The HTML site builds cleanly from a single `python scripts/build.py` command
