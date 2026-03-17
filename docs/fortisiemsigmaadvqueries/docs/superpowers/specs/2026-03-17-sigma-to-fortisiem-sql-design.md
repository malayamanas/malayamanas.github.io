# Design Spec: Sigma → FortiSIEM Advanced SQL Converter

**Date:** 2026-03-17
**Status:** Approved
**Scope:** Convert all Sigma rules in the cloned `sigma/` repo to FortiSIEM ClickHouse SQL queries, with a JSON index, per-category markdown docs, and a searchable dark-theme HTML site.

---

## 1. Overview

The converter reads every `.yml` Sigma rule file from the cloned `sigma/` repo, maps Sigma detection fields to FortiSIEM ClickHouse column expressions, generates annotated ready-to-paste SQL queries, and renders three **independent** output artefacts:

1. **`sigma_queries.json`** — machine-readable index
2. **`md/sigma-{product}-{category}.md`** — per-category markdown reference docs
3. **`html/sigma-{product}-{category}.html`** + **`index.html`** — searchable dark-theme HTML site

Markdown and HTML are both independent final outputs; neither is an intermediate step for the other.

---

## 2. Directory Layout

```
FortiSIEM_Advanced_Search_SQL/
└── sigma_queries/
    ├── scripts/
    │   ├── sigma_to_fortisiem.py        ← CLI entry point
    │   └── converter/
    │       ├── __init__.py
    │       ├── field_map.py             ← Sigma field → FSM column expression mapping
    │       ├── rule_parser.py           ← YAML → SigmaRule dataclass
    │       ├── sql_builder.py           ← SigmaRule → ClickHouse SQL string
    │       └── renderer.py             ← SQL → markdown + HTML + JSON
    ├── md/
    │   └── sigma-{product}-{category}.md
    ├── html/
    │   └── sigma-{product}-{category}.html
    ├── index.html
    └── sigma_queries.json
```

**Filename convention:** `sigma-{product}-{category}` where product and category come from `logsource.product` and `logsource.category` (lowercased, spaces replaced with hyphens).

**Collision handling:** Rules sharing the same product+category key are merged into one file (natural grouping — no counter suffixes needed).

**Default path resolution:** All default paths are resolved relative to `__file__` (the script's own location), not `os.getcwd()`:
- `--sigma-dir` default: `Path(__file__).parent.parent.parent / 'sigma'`
- `--output-dir` default: `Path(__file__).parent.parent.parent / 'sigma_queries'`

---

## 3. FortiSIEM ClickHouse Schema — Three-Tier Column Rules

`field_map.py` must emit the correct expression per tier. Every WHERE clause referencing a Tier 2 or Tier 3 field **must include an `indexOf > 0` guard** to prevent silent empty-string matches on absent fields:

```sql
-- Tier 2 guarded access (required pattern):
indexOf(metrics_string.name, 'command') > 0
AND metrics_string.value[indexOf(metrics_string.name, 'command')] LIKE '%val%'
```

For SELECT projections, no guard is needed — the bare expression is acceptable.

### Tier 1 — Direct EAT Columns (complete whitelist)

```
eventType, phRecvTime, reptDevName, reptDevIpAddrV4, reptDevIpAddr,
user, targetUser, domain, procName, shortProcName, appName,
srcIpAddrV4, destIpAddrV4,        ← IP columns ARE Tier 1 (direct columns)
srcIpPort, destIpPort,
winEventId, winLogonType, serviceName,
rawEventMsg, eventSeverity, eventSeverityCat, phEventCategory,
hostName, hostIpAddrV4,
destGeoCountry, srcGeoCountry,
rawEventSize, lineNumber, fileName, count,
procId, sessionId, ipProto, eventAction,
incidentSrc, incidentTarget
```

`DestinationIp` → `destIpAddrV4` (Tier 1 direct column).
`SourceIp` → `srcIpAddrV4` (Tier 1 direct column).
Tier 3 (`metrics_ip`) is used only for CIDR range checks via `isIPAddressInRange(toString(metrics_ip.value[indexOf(...)]), 'cidr')` when a Sigma field maps to an IP not in the Tier 1 whitelist.

### Tier 2 — `metrics_string` Array

Access pattern (with required WHERE guard):
```sql
indexOf(metrics_string.name, 'eatName') > 0
AND metrics_string.value[indexOf(metrics_string.name, 'eatName')] <op> 'value'
```

SELECT alias (use original Sigma field name in camelCase, lowercased first letter):
```sql
metrics_string.value[indexOf(metrics_string.name, 'command')] AS command
```

### Tier 3 — `metrics_ip` Array

Only used for `cidr` modifier on IP fields not in Tier 1:
```sql
isIPAddressInRange(toString(metrics_ip.value[indexOf(metrics_ip.name, 'eatName')]), 'cidr')
```

---

## 4. Architecture — Four Modules

### 4.1 `field_map.py` — Sigma Field → FSM Column Expression

**Return type:** `tuple[str, str]` → `(fsm_expression, tier)` where tier is `"1"`, `"2"`, or `"3"`.

**Complete Sigma field → FSM expression mapping table:**

| Sigma Field | FSM Expression | Tier |
|---|---|---|
| `Image` | `procName` | 1 |
| `CommandLine` | `metrics_string.value[indexOf(metrics_string.name,'command')]` | 2 |
| `ParentImage` | `metrics_string.value[indexOf(metrics_string.name,'parentProcName')]` | 2 |
| `ParentCommandLine` | `metrics_string.value[indexOf(metrics_string.name,'parentCommand')]` | 2 |
| `User` | `user` | 1 |
| `TargetUser` | `targetUser` | 1 |
| `SubjectUserName` | `metrics_string.value[indexOf(metrics_string.name,'subjectUsername')]` | 2 |
| `TargetUserName` | `metrics_string.value[indexOf(metrics_string.name,'targetUser')]` | 2 |
| `EventID` | `winEventId` | 1 |
| `ProcessId` | `procId` | 1 |
| `LogonType` | `winLogonType` | 1 |
| `ServiceName` | `serviceName` | 1 |
| `Domain` | `domain` | 1 |
| `DestinationIp` | `destIpAddrV4` | 1 |
| `DestinationPort` | `destIpPort` | 1 |
| `SourceIp` | `srcIpAddrV4` | 1 |
| `SourcePort` | `srcIpPort` | 1 |
| `DestinationHostname` | `metrics_string.value[indexOf(metrics_string.name,'destHostName')]` | 2 |
| `TargetFilename` | `metrics_string.value[indexOf(metrics_string.name,'fileName')]` | 2 |
| `TargetObject` | `metrics_string.value[indexOf(metrics_string.name,'regKey')]` | 2 |
| `Details` | `metrics_string.value[indexOf(metrics_string.name,'regValue')]` | 2 |
| `ScriptBlockText` | `metrics_string.value[indexOf(metrics_string.name,'script')]` | 2 |
| `Hashes` | `metrics_string.value[indexOf(metrics_string.name,'hashMD5')]` | 2 |
| `Initiated` | `metrics_string.value[indexOf(metrics_string.name,'initiated')]` | 2 |
| `ImageLoaded` | `metrics_string.value[indexOf(metrics_string.name,'imageLoaded')]` | 2 |
| `OriginalFileName` | `metrics_string.value[indexOf(metrics_string.name,'originalFileName')]` | 2 |
| `Product` | `metrics_string.value[indexOf(metrics_string.name,'product')]` | 2 |
| `Company` | `metrics_string.value[indexOf(metrics_string.name,'company')]` | 2 |
| `PipeName` | `metrics_string.value[indexOf(metrics_string.name,'pipeName')]` | 2 |
| `Provider_Name` | `metrics_string.value[indexOf(metrics_string.name,'provider')]` | 2 |
| `Channel` | `metrics_string.value[indexOf(metrics_string.name,'channel')]` | 2 |
| `TargetUserGrp` | `metrics_string.value[indexOf(metrics_string.name,'targetUserGrp')]` | 2 |
| `CurrentDirectory` | `metrics_string.value[indexOf(metrics_string.name,'currentDirectory')]` | 2 |
| `IntegrityLevel` | `metrics_string.value[indexOf(metrics_string.name,'integrityLevel')]` | 2 |
| `Signature` | `metrics_string.value[indexOf(metrics_string.name,'signature')]` | 2 |
| `SignatureStatus` | `metrics_string.value[indexOf(metrics_string.name,'signatureStatus')]` | 2 |
| `Data` | `rawEventMsg` | 1 |
| `keywords` | `rawEventMsg` | 1 |

**Unmapped fields:** Any Sigma field not in the table → `rawEventMsg LIKE '%val%'` fallback, with `-- UNMAPPED_FIELD: <field>` comment, and the field name added to `unmapped_fields`.

**Sigma modifier → SQL translation (complete):**

| Modifier | SQL output |
|---|---|
| *(none / equality)* | `field = 'val'` or `field IN ('v1','v2')` for lists |
| `contains` | `field LIKE '%val%'` |
| `contains\|all` | `field LIKE '%v1%' AND field LIKE '%v2%'` |
| `endswith` | `field LIKE '%val'` |
| `startswith` | `field LIKE 'val%'` |
| `re` | `match(field, 'regex')` |
| `windash` | `(field LIKE '% val%' OR field LIKE '%-val%' OR field LIKE '%/val%' OR field LIKE '%–val%')` — 4 variants: space-prefixed original, `-` dash, `/` slash, `–` en-dash (U+2013) |
| `cidr` | `isIPAddressInRange(toString(field), 'cidr_string')` |
| `base64offset\|contains` | `match(field, 'variant0\|variant1\|variant2')` — compute 3 variants: for offset in [0,1,2]: encode `b'\x00'*offset + value.encode('utf-8')` in base64, take the slice `[offset : len - (offset % 3 or 3) % 3]` to get the aligned inner portion; join all 3 with `\|` in one `match()` |
| `lt` | `field < val` |
| `lte` | `field <= val` |
| `gt` | `field > val` |
| `gte` | `field >= val` |
| `exists\|true` | `field IS NOT NULL AND field != ''` |
| `exists\|false` | `(field IS NULL OR field = '')` |
| unknown modifier | `rawEventMsg LIKE '%val%'` fallback + `-- UNSUPPORTED_MODIFIER: <mod>` comment |

---

### 4.2 `rule_parser.py` — YAML → `SigmaRule` Dataclass

**`detection_selections` data structure (contract between `rule_parser.py` and `sql_builder.py`):**

```python
# Type: dict[str, list[dict[str, Any]]]
#
# Key   = selection name string (e.g. "selection", "filter_main_chrome", "keywords")
# Value = list of field-condition maps (maps in the list are OR'd together)
#         within each map, multiple keys are AND'd together
#
# Field keys include the modifier suffix, e.g. "CommandLine|contains"
# Values are always lists (even single values are wrapped in a list)
#
# Special key "_keyword" is used for bare keyword selections:
#   {"_keyword": ["term1", "term2"]}  → rawEventMsg LIKE '%term1%' OR rawEventMsg LIKE '%term2%'
#
# Wildcard conditions (e.g. "1 of selection_*") are resolved at parse time:
# rule_parser.py expands all wildcards against detection_selections.keys()
# and stores the resolved selection name lists in SigmaRule.condition_resolved.
# sql_builder.py NEVER resolves wildcards itself.
#
# Examples:
#
# YAML:                                    Python detection_selections value:
# selection:                               {"selection": [
#   CommandLine|contains:                      {"CommandLine|contains": ["-nop", "-enc"]}
#     - '-nop'                              ]}
#     - '-enc'
#
# YAML (multiple maps = OR):               {"selection": [
#   selection:                                 {"Image|endswith": ["\\cmd.exe"]},
#     - Image|endswith: '\cmd.exe'             {"CommandLine|contains": ["/c "]}
#     - CommandLine|contains: '/c '        ]}
#
# YAML (keyword):                          {"keywords": [{"_keyword": ["HybridConn", "sb://"]}]}
#   keywords:
#     - 'HybridConn'
#     - 'sb://'
```

**`condition_resolved` field** (additional field on `SigmaRule`): stores the pre-expanded condition as a nested structure. `rule_parser.py` resolves all `*` wildcards against `detection_selections.keys()` so `sql_builder.py` receives concrete lists, not wildcard strings.

```python
# condition_resolved: list of OR-groups, each OR-group is list of AND-terms
# Each AND-term is (selection_name: str, negated: bool)
#
# "selection and not 1 of filter_*" where filter_* expands to [filter_a, filter_b]:
# [
#   [("selection", False), ("filter_a", True), ("filter_b", True)]
# ]
# → WHERE (selection_conds) AND NOT(filter_a_conds) AND NOT(filter_b_conds)
#
# "1 of selection_*" where selection_* expands to [sel_x, sel_y]:
# [
#   [("sel_x", False)],
#   [("sel_y", False)]
# ]
# → WHERE (sel_x_conds) OR (sel_y_conds)
```

**`SigmaRule` dataclass (complete field list):**

```python
@dataclass
class SigmaRule:
    # Identity
    id: str
    title: str
    description: str
    author: str
    date: str                          # raw string as in YAML, e.g. "2024-12-19"
    status: str                        # stable / test / experimental

    # Severity
    level: str                         # low / medium / high / critical
    fsm_severity: int                  # low→3, medium→5, high→7, critical→9

    # Classification
    tags: list[str]
    mitre_tactics: list[str]           # extracted from tags, e.g. ["execution"]
    mitre_techniques: list[str]        # extracted from tags, e.g. ["T1059.001"]

    # Logsource
    logsource_product: str
    logsource_category: str
    logsource_service: str             # may be empty string
    fsm_event_types: list[str]         # always a list; derived from logsource mapping

    # Detection (structured, for sql_builder)
    detection_selections: dict[str, list[dict[str, Any]]]   # see contract above
    condition: str                     # raw condition string from YAML
    condition_resolved: list[list[tuple[str, bool]]]        # pre-expanded, see above

    # Metadata
    falsepositives: list[str]
    references: list[str]

    # Provenance
    sigma_file_path: str               # relative to sigma repo root, e.g. "rules/windows/..."
    github_url: str                    # https://github.com/SigmaHQ/sigma/blob/main/{sigma_file_path}

    # Populated by sql_builder after conversion
    unmapped_fields: list[str]
    unmapped_logsource: bool
```

**`fsm_event_types` derivation rules:**

1. Look up `(logsource_product, logsource_category)` in the logsource table → returns `list[str]`
2. If logsource has a `service` but no `category`, look up `(logsource_product, logsource_service)` instead
3. If the detection block contains `EventID:` field, append `EventID` values to generate specific type names:
   - `windows` + service `security` + `EventID: [4624, 4625]` → `["Win-Security-4624", "Win-Security-4625"]`
   - `windows` + service `system` + `EventID: [7045]` → `["Win-System-7045"]`
   - Wildcard `Win-Security-*` is used when EventID is absent for service-based logsources
4. If no match → `fsm_event_types = []` and `unmapped_logsource = True`

**Logsource → FortiSIEM event type mapping table:**

| product | category / service | FSM eventType(s) |
|---|---|---|
| `windows` | `process_creation` | `["Win-Sysmon-1-Create-Process", "Win-Security-4688"]` |
| `windows` | `network_connection` | `["Win-Sysmon-3-Network-Connect-IPv4"]` |
| `windows` | `ps_script` | `["Win-PowerShell-4104"]` |
| `windows` | `ps_classic_provider_start` | `["Win-PowerShell-400"]` |
| `windows` | `ps_module` | `["Win-PowerShell-4103"]` |
| `windows` | `registry_add`, `registry_set`, `registry_delete`, `registry_event` | `["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"]` |
| `windows` | `file_event` | `["Win-Sysmon-11-File-Create"]` |
| `windows` | `file_delete` | `["Win-Sysmon-23-File-Delete"]` |
| `windows` | `file_rename` | `["Win-Sysmon-11-File-Create"]` |
| `windows` | `dns_query` | `["Win-Sysmon-22-DNS-Query"]` |
| `windows` | `image_load` | `["Win-Sysmon-7-Image-Load"]` |
| `windows` | `driver_load` | `["Win-Sysmon-6-Driver-Load"]` |
| `windows` | `pipe_created` | `["Win-Sysmon-17-Pipe-Created"]` |
| `windows` | `create_remote_thread` | `["Win-Sysmon-8-Create-Remote-Thread"]` |
| `windows` | `wmi_event` | `["Win-Sysmon-19-WMI-Event-Filter"]` |
| `windows` | `process_access` | `["Win-Sysmon-10-Process-Access"]` |
| `windows` | `create_stream_hash` | `["Win-Sysmon-15-FileCreateStreamHash"]` |
| `windows` | service `security` | `["Win-Security-*"]` (+ EventID specialization per rule 3 above) |
| `windows` | service `system` | `["Win-System-*"]` (+ EventID specialization) |
| `windows` | service `application` | `["Win-Application-*"]` (+ EventID specialization) |
| `windows` | service `sysmon` | `["Win-Sysmon-*"]` (+ EventID specialization) |
| `windows` | service `taskscheduler` | `["Win-TaskScheduler-*"]` |
| `windows` | service `powershell` | `["Win-PowerShell-*"]` |
| `linux` | `process_creation` | `["LINUX_PROCESS_EXEC"]` |
| `linux` | `file_event` | `["LINUX_FILE_CREATE"]` |
| `linux` | `network_connection` | `["LINUX_NET_CONN"]` |
| `linux` | `syslog` | `["Generic_Syslog"]` |
| `linux` | `auditd` | `["Linux-Audit-*"]` |
| `macos` | `process_creation` | `["macOS-Exec-*"]` |
| `cloud` / `aws` | `cloudtrail` | `["AWS-CloudTrail-*"]` |
| `cloud` / `azure` | `activitylogs` | `["Azure-Activity-*"]` |
| `cloud` / `gcp` | `gcp.audit` | `["GCP-AuditLog-*"]` |
| `cloud` / `m365` | any | `["O365-*"]` |
| anything else | — | `[]` + `unmapped_logsource = True` |

---

### 4.3 `sql_builder.py` — `SigmaRule` → ClickHouse SQL

**Call sequence:**
1. For each Sigma field in `detection_selections`, call `field_map.get_field(sigma_field_name)` → `(expression, tier)`
2. Build WHERE clause from `condition_resolved` (pre-expanded by `rule_parser`) using `detection_selections` values
3. Collect all Tier 1 columns and Tier 2 expressions referenced → build SELECT list
4. Populate `rule.unmapped_fields` during step 1

**WHERE clause construction for Tier 2 fields (required guard pattern):**
```sql
indexOf(metrics_string.name, 'eatName') > 0
AND metrics_string.value[indexOf(metrics_string.name, 'eatName')] LIKE '%val%'
```

**SQL comment block format (exact `--` line comment template):**
```sql
-- ============================================================
-- Title:        <title>
-- Sigma ID:     <id>
-- Level:        <level>  |  FSM Severity: <fsm_severity>
-- Status:       <status>
-- MITRE:        <tactics joined by ', '> | <techniques joined by ', '>
-- Author:       <author>
-- Date:         <date>
-- GitHub:       <github_url>
-- Unmapped:     <unmapped_fields joined by ', '> (or "(none)")
-- False Pos:    <falsepositives joined by '; '>
-- ============================================================
```

**SELECT column list:**
- Always include: `phRecvTime`, `reptDevName`, `reptDevIpAddrV4`, `user`, `rawEventMsg`
- Add each referenced Tier 1 column (deduplicated)
- Add each referenced Tier 2/3 expression with alias: `metrics_string.value[...] AS <sigma_field_name_camelCase>`

**Full query template:**
```sql
<comment_block>
SELECT
    phRecvTime,
    reptDevName,
    reptDevIpAddrV4,
    user,
    <additional Tier 1 columns>,
    <Tier 2 expressions AS alias>,
    rawEventMsg
FROM fsiem.events
WHERE eventType IN (<fsm_event_types as quoted CSV>)
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND <translated detection conditions>
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**Severity mapping:** `low`→3, `medium`→5, `high`→7, `critical`→9

---

### 4.4 `renderer.py` — Three Independent Output Writers

**Writer A — `sigma_queries.json` (schema):**
```json
{
  "generated": "2026-03-17",
  "sigma_repo_path": "<absolute path>",
  "total_rules_found": 3106,
  "total_converted": 2950,
  "unmapped_logsource_count": 45,
  "unmapped_field_count": 312,
  "entries": [
    {
      "sigma_id": "string",
      "name": "string",
      "description": "string",
      "status": "string",
      "level": "string",
      "fsm_severity": 3,
      "mitre_tactics": ["string"],
      "mitre_techniques": ["string"],
      "logsource": "product/category",
      "fsm_event_types": ["string"],
      "unmapped_fields": ["string"],
      "unmapped_logsource": false,
      "github_url": "string",
      "references": ["string"],
      "author": "string",
      "date": "string",
      "sql": "string"
    }
  ]
}
```

`detection_selections` and `condition_resolved` are **not** serialized to JSON — they are internal dataclass fields only.

**Writer B — Per-category markdown (`md/sigma-windows-process-creation.md`):**
```markdown
# Sigma → FortiSIEM: Windows Process Creation
> 1167 rules · Generated 2026-03-17

## Table of Contents
- [QuickAssist Execution](#quickassist-execution) `low` `T1219.002`

---

## QuickAssist Execution
**Sigma ID:** `e20b5b14-...` | **Level:** `low` | **FSM Severity:** 3
**MITRE:** command-and-control · T1219.002
**Author:** Muhammad Faisal | **Status:** experimental
**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/...)**

> Detects the execution of Microsoft Quick Assist tool...

\```sql
SELECT phRecvTime, ...
\```

**False Positives:** Legitimate use of Quick Assist
**References:** [1](url)

---
```

**Writer C — HTML site:**
- `html/sigma-*.html`: each corresponds to a `md/sigma-*.md` with identical content rendered as HTML
- Syntax highlighting: `highlight.js` CDN `<script>` tag embedded in HTML template (no Python dependency)
- Dark theme: background `#0d1117`, surface `#161b22`, accent `#58a6ff`, border `#30363d`
- Every rule entry: **"View on GitHub ↗"** badge link
- `index.html`:
  - Stats bar (total rules, converted, unmapped fields, platforms)
  - Client-side fuzzy search on title + description (pure JS, no library)
  - Filter pills: Platform · Level (colour-coded: low=green, medium=yellow, high=orange, critical=red) · MITRE Tactic
  - Rule cards grid with hover SQL preview
  - Links to per-category HTML pages

---

## 5. CLI Interface (`sigma_to_fortisiem.py`)

All filter flags are **case-insensitive**. `--level` accepts comma-separated values. `--category` matches `logsource.category`. `--product` matches `logsource.product`.

```bash
# Full conversion (all rules in sigma-dir)
python3 sigma_to_fortisiem.py

# Single Sigma logsource category
python3 sigma_to_fortisiem.py --category process_creation

# Single product
python3 sigma_to_fortisiem.py --product windows

# One or more severity levels (comma-separated)
python3 sigma_to_fortisiem.py --level high,critical

# Single rule by Sigma ID (UUID)
python3 sigma_to_fortisiem.py --id e20b5b14-ce93-4230-88af-981983ef6e74

# Custom paths (resolved as given, supports absolute or relative to cwd)
python3 sigma_to_fortisiem.py \
    --sigma-dir /path/to/sigma \
    --output-dir /path/to/sigma_queries

# JSON index only (skip HTML/markdown rebuild)
python3 sigma_to_fortisiem.py --json-only
```

---

## 6. Error Handling

| Condition | Behaviour |
|---|---|
| Malformed / unparseable YAML | Skip rule, print `WARN: <filepath>: <error>`, continue |
| Unknown logsource | Generate SQL with `rawEventMsg LIKE '%'` fallback; prepend `-- UNMAPPED_LOGSOURCE` comment |
| Unmapped Sigma field | Fall back to `rawEventMsg LIKE '%val%'`; prepend `-- UNMAPPED_FIELD: <field>` comment |
| Unsupported modifier | Fall back to `rawEventMsg LIKE '%val%'`; prepend `-- UNSUPPORTED_MODIFIER: <mod>` comment |
| Empty or missing detection block | Skip rule, print `WARN: <filepath>: empty detection` |
| Unparseable condition string | Emit `-- CONDITION_TOO_COMPLEX: <raw_condition>` + `rawEventMsg LIKE '%'` fallback |
| Output directory not writable | Abort with error message |

**End-of-run summary printed to stdout:**
```
Converted:                  2950 / 3106 rules
Skipped (errors):             23 rules
Unmapped logsource:           45 rules (rawEventMsg fallback used)
Rules with unmapped fields:  312 rules
Output: /path/to/sigma_queries/
```

---

## 7. Dependencies

- **Python 3.9+**
- **`pyyaml`** — YAML parsing (`pip install pyyaml`)
- **`highlight.js`** — SQL syntax highlighting via CDN `<script>` tag embedded in HTML templates (no Python install)
- No other external dependencies

---

## 8. Out of Scope

- Live FortiSIEM API integration
- Automated sigma repo update polling
- Query performance tuning per rule
- False positive suppression logic in SQL
- Sigma rule validation (assumes cloned sigma repo is valid)
