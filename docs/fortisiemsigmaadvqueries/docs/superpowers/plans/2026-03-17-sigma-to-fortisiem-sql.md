# Sigma → FortiSIEM Advanced SQL Converter — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert all 3,000+ Sigma rules from the cloned `sigma/` repo into FortiSIEM ClickHouse SQL queries with a JSON index, per-category markdown docs, and a searchable dark-theme HTML site.

**Architecture:** Four focused pipeline modules (`field_map` → `rule_parser` → `sql_builder` → `renderer`) plus a CLI entry point. Each module has well-defined input/output types and is independently testable. The CLI wires them together and handles filtering, batching, and summary output.

**Tech Stack:** Python 3.9+, PyYAML, highlight.js via CDN (no Python install), stdlib only for everything else.

---

## File Structure

| Action | Path | Responsibility |
|---|---|---|
| Create | `sigma_queries/scripts/__init__.py` | Package marker (empty) |
| Create | `sigma_queries/scripts/converter/__init__.py` | Package marker (empty) |
| Create | `sigma_queries/scripts/converter/field_map.py` | Sigma field → FSM column expression + modifier → SQL operator |
| Create | `sigma_queries/scripts/converter/rule_parser.py` | YAML → `SigmaRule` dataclass (including wildcard expansion in conditions) |
| Create | `sigma_queries/scripts/converter/sql_builder.py` | `SigmaRule` → ClickHouse SQL string with comment block |
| Create | `sigma_queries/scripts/converter/renderer.py` | SQL → JSON index + per-category markdown + HTML site |
| Create | `sigma_queries/scripts/sigma_to_fortisiem.py` | CLI entry point; wires pipeline; prints summary |
| Create | `sigma_queries/tests/__init__.py` | Package marker (empty) |
| Create | `sigma_queries/tests/fixtures/win_proc_create.yml` | Sample process_creation rule (multi-value contains) |
| Create | `sigma_queries/tests/fixtures/win_net_conn.yml` | Sample network_connection rule (windash modifier) |
| Create | `sigma_queries/tests/fixtures/win_powershell.yml` | Sample ps_script rule (base64offset modifier) |
| Create | `sigma_queries/tests/fixtures/win_registry.yml` | Sample registry rule (negated filter, wildcard condition) |
| Create | `sigma_queries/tests/fixtures/linux_proc.yml` | Sample Linux process_creation rule |
| Create | `sigma_queries/tests/fixtures/unmapped.yml` | Rule with unknown logsource + unknown field |
| Create | `sigma_queries/tests/test_field_map.py` | Unit tests: all 38 field mappings + all modifiers |
| Create | `sigma_queries/tests/test_rule_parser.py` | Unit tests: YAML parsing, dataclass population, wildcard expansion |
| Create | `sigma_queries/tests/test_sql_builder.py` | Unit tests: SQL output correctness per schema tier |
| Create | `sigma_queries/tests/test_renderer.py` | Unit tests: JSON schema, markdown structure, HTML presence |
| Create | `sigma_queries/tests/test_integration.py` | End-to-end: run CLI against fixtures dir, verify all outputs |

**Output directories** (created at runtime by the script, not pre-created):
```
sigma_queries/md/
sigma_queries/html/
sigma_queries/index.html        (generated)
sigma_queries/sigma_queries.json  (generated)
```

---

## Chunk 1: Foundation — Project Scaffold + Field Map

### Task 1: Project Scaffold

**Files:**
- Create: `sigma_queries/scripts/converter/__init__.py`
- Create: `sigma_queries/tests/__init__.py`
- Create: `sigma_queries/tests/fixtures/win_proc_create.yml`
- Create: `sigma_queries/tests/fixtures/win_net_conn.yml`
- Create: `sigma_queries/tests/fixtures/win_powershell.yml`
- Create: `sigma_queries/tests/fixtures/win_registry.yml`
- Create: `sigma_queries/tests/fixtures/linux_proc.yml`
- Create: `sigma_queries/tests/fixtures/unmapped.yml`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p sigma_queries/scripts/converter
mkdir -p sigma_queries/tests/fixtures
touch sigma_queries/scripts/__init__.py
touch sigma_queries/scripts/converter/__init__.py
touch sigma_queries/tests/__init__.py
```

- [ ] **Step 2: Create `win_proc_create.yml` fixture**

```yaml
# sigma_queries/tests/fixtures/win_proc_create.yml
title: Suspicious PowerShell Encoded Command
id: a2b0b9e0-1234-4567-89ab-cdef01234567
status: stable
description: Detects suspicious PowerShell execution with encoded command
author: Test Author
date: 2024-01-15
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection
falsepositives:
  - Legitimate admin scripts
references:
  - https://example.com/ref1
```

- [ ] **Step 3: Create `win_net_conn.yml` fixture**

```yaml
# sigma_queries/tests/fixtures/win_net_conn.yml
title: Certutil Network Connection
id: b3c1d0e1-2345-5678-9abc-def012345678
status: experimental
description: Detects certutil making outbound connections
author: Test Author
date: 2024-02-20
level: medium
tags:
  - attack.defense_evasion
  - attack.t1140
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    Image|endswith: '\certutil.exe'
    Initiated: 'true'
  condition: selection
falsepositives:
  - Windows update activity
references: []
```

- [ ] **Step 4: Create `win_powershell.yml` fixture**

```yaml
# sigma_queries/tests/fixtures/win_powershell.yml
title: Base64 Encoded PowerShell Script
id: c4d2e1f2-3456-6789-abcd-ef0123456789
status: test
description: Detects base64 encoded powershell in script block
author: Test Author
date: 2024-03-10
level: medium
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|base64offset|contains:
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection
falsepositives:
  - Legitimate obfuscated scripts
references: []
```

- [ ] **Step 5: Create `win_registry.yml` fixture**

```yaml
# sigma_queries/tests/fixtures/win_registry.yml
title: Registry Run Key Persistence
id: d5e3f2a3-4567-789a-bcde-f01234567890
status: stable
description: Detects adding a registry run key for persistence
author: Test Author
date: 2024-04-05
level: high
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  product: windows
  category: registry_set
detection:
  selection_main:
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\'
  filter_legit:
    Image|contains:
      - '\OneDrive.exe'
      - '\Teams.exe'
  condition: selection_main and not filter_legit
falsepositives:
  - Legitimate software installations
references: []
```

- [ ] **Step 6: Create `linux_proc.yml` fixture**

```yaml
# sigma_queries/tests/fixtures/linux_proc.yml
title: Linux Reverse Shell
id: e6f4a3b4-5678-89ab-cdef-012345678901
status: experimental
description: Detects common reverse shell patterns on Linux
author: Test Author
date: 2024-05-01
level: high
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '/dev/tcp/'
      - 'bash -i'
      - 'nc -e /bin/bash'
  condition: selection
falsepositives:
  - Penetration testing
references: []
```

- [ ] **Step 7: Create `unmapped.yml` fixture**

```yaml
# sigma_queries/tests/fixtures/unmapped.yml
title: Unknown Source Alert
id: f7a5b4c5-6789-9abc-def0-123456789012
status: experimental
description: Uses an unsupported logsource and unmapped field
author: Test Author
date: 2024-06-01
level: low
tags: []
logsource:
  product: vendor_xyz
  category: custom_event
detection:
  selection:
    SomeUnknownField|contains: suspicious_value
  condition: selection
falsepositives: []
references: []
```

- [ ] **Step 8: Commit scaffold**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git add sigma_queries/
git commit -m "chore: scaffold sigma_queries project structure and test fixtures"
```

---

### Task 2: `field_map.py` — Field Mapping Module

**Files:**
- Create: `sigma_queries/scripts/converter/field_map.py`
- Create: `sigma_queries/tests/test_field_map.py`

- [ ] **Step 1: Write failing tests for field lookups**

Create `sigma_queries/tests/test_field_map.py`:

```python
"""Tests for field_map.py — Sigma field → FSM expression mapping."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from converter.field_map import get_field, apply_modifier


class TestGetField:
    """Test Sigma field → (fsm_expression, tier) mapping."""

    def test_tier1_image(self):
        expr, tier = get_field("Image")
        assert expr == "procName"
        assert tier == "1"

    def test_tier1_user(self):
        expr, tier = get_field("User")
        assert expr == "user"
        assert tier == "1"

    def test_tier1_event_id(self):
        expr, tier = get_field("EventID")
        assert expr == "winEventId"
        assert tier == "1"

    def test_tier1_destination_ip(self):
        expr, tier = get_field("DestinationIp")
        assert expr == "destIpAddrV4"
        assert tier == "1"

    def test_tier1_source_ip(self):
        expr, tier = get_field("SourceIp")
        assert expr == "srcIpAddrV4"
        assert tier == "1"

    def test_tier1_destination_port(self):
        expr, tier = get_field("DestinationPort")
        assert expr == "destIpPort"
        assert tier == "1"

    def test_tier1_data_maps_to_raw_event_msg(self):
        expr, tier = get_field("Data")
        assert expr == "rawEventMsg"
        assert tier == "1"

    def test_tier1_keywords(self):
        expr, tier = get_field("keywords")
        assert expr == "rawEventMsg"
        assert tier == "1"

    def test_tier2_commandline(self):
        expr, tier = get_field("CommandLine")
        assert "metrics_string" in expr
        assert "command" in expr
        assert tier == "2"

    def test_tier2_parent_image(self):
        expr, tier = get_field("ParentImage")
        assert "parentProcName" in expr
        assert tier == "2"

    def test_tier2_target_object(self):
        expr, tier = get_field("TargetObject")
        assert "regKey" in expr
        assert tier == "2"

    def test_tier2_script_block_text(self):
        expr, tier = get_field("ScriptBlockText")
        assert "script" in expr
        assert tier == "2"

    def test_tier2_initiated(self):
        expr, tier = get_field("Initiated")
        assert "initiated" in expr
        assert tier == "2"

    def test_unmapped_field_falls_back_to_rawmsg(self):
        expr, tier = get_field("SomeUnknownField")
        assert expr == "rawEventMsg"
        assert tier == "1"


class TestApplyModifier:
    """Test modifier → SQL fragment translation."""

    # --- Tier 1 field tests ---
    def test_no_modifier_single_value_tier1(self):
        sql, comments = apply_modifier("procName", "1", None, ["powershell.exe"])
        assert "procName = 'powershell.exe'" in sql
        assert comments == []

    def test_no_modifier_multi_value_tier1_uses_in(self):
        sql, comments = apply_modifier("procName", "1", None, ["cmd.exe", "powershell.exe"])
        assert "procName IN ('cmd.exe', 'powershell.exe')" in sql

    def test_contains_tier1(self):
        sql, comments = apply_modifier("procName", "1", "contains", ["powershell"])
        assert "procName LIKE '%powershell%'" in sql

    def test_endswith_tier1(self):
        sql, comments = apply_modifier("procName", "1", "endswith", ["\\powershell.exe"])
        assert "procName LIKE '%\\\\powershell.exe'" in sql

    def test_startswith_tier1(self):
        sql, comments = apply_modifier("procName", "1", "startswith", ["C:\\Windows"])
        assert "procName LIKE 'C:\\\\Windows%'" in sql

    def test_re_modifier_tier1(self):
        sql, comments = apply_modifier("procName", "1", "re", [".*powershell.*"])
        assert "match(procName, '.*powershell.*')" in sql

    # --- Tier 2 field tests (must include indexOf guard) ---
    def test_no_modifier_tier2_includes_guard(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", None, ["whoami"])
        assert "indexOf(metrics_string.name, 'command') > 0" in sql
        assert expr in sql

    def test_contains_tier2_includes_guard(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", "contains", ["-nop"])
        assert "indexOf(metrics_string.name, 'command') > 0" in sql
        assert "LIKE '%-nop%'" in sql

    # --- windash modifier ---
    def test_windash_produces_four_variants(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", "windash", ["-nop"])
        assert "% -nop%" in sql   # space-prefixed
        assert "%-nop%" in sql    # dash
        assert "%/-nop%" in sql   # slash variant (the value with / prefix) — actually check pattern
        # windash: space-val, -val, /val, en-dash-val
        assert sql.count("LIKE") == 4

    # --- base64offset modifier ---
    def test_base64offset_produces_match_with_three_variants(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'script')]"
        sql, comments = apply_modifier(expr, "2", "base64offset|contains", ["IEX"])
        assert "match(" in sql
        assert "|" in sql   # variants joined by pipe in regex

    # --- cidr modifier ---
    def test_cidr_modifier(self):
        expr = "destIpAddrV4"
        sql, comments = apply_modifier(expr, "1", "cidr", ["192.168.0.0/16"])
        assert "isIPAddressInRange" in sql
        assert "192.168.0.0/16" in sql

    # --- numeric comparisons ---
    def test_lt_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "lt", ["3"])
        assert "winLogonType < 3" in sql

    def test_lte_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "lte", ["3"])
        assert "winLogonType <= 3" in sql

    def test_gt_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "gt", ["3"])
        assert "winLogonType > 3" in sql

    def test_gte_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "gte", ["3"])
        assert "winLogonType >= 3" in sql

    # --- exists modifier ---
    def test_exists_true(self):
        sql, comments = apply_modifier("procName", "1", "exists|true", [True])
        assert "IS NOT NULL" in sql
        assert "!= ''" in sql

    def test_exists_false(self):
        sql, comments = apply_modifier("procName", "1", "exists|false", [False])
        assert "IS NULL" in sql or "= ''" in sql

    # --- unknown modifier fallback ---
    def test_unknown_modifier_fallback(self):
        sql, comments = apply_modifier("procName", "1", "zz_unknown", ["value"])
        assert "rawEventMsg LIKE '%value%'" in sql
        assert any("UNSUPPORTED_MODIFIER" in c for c in comments)

    # --- unmapped field comment ---
    def test_unmapped_field_generates_comment(self):
        expr, tier = get_field("SomeUnknownField")
        sql, comments = apply_modifier(expr, tier, "contains", ["test"])
        assert any("UNMAPPED_FIELD" in c for c in comments)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_field_map.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError` or `ImportError` — `field_map` does not exist yet.

- [ ] **Step 3: Implement `field_map.py`**

Create `sigma_queries/scripts/converter/field_map.py`:

```python
"""
field_map.py — Sigma field → FortiSIEM ClickHouse expression mapping.

Returns (fsm_expression, tier) where tier is "1", "2", or "3".
apply_modifier(expr, tier, modifier, values) → (sql_fragment, [comments])
"""
import base64
from typing import Optional

# ---------------------------------------------------------------------------
# Field mapping table
# ---------------------------------------------------------------------------

_TIER1 = {
    "Image":          "procName",
    "User":           "user",
    "TargetUser":     "targetUser",
    "EventID":        "winEventId",
    "ProcessId":      "procId",
    "LogonType":      "winLogonType",
    "ServiceName":    "serviceName",
    "Domain":         "domain",
    "DestinationIp":  "destIpAddrV4",
    "DestinationPort":"destIpPort",
    "SourceIp":       "srcIpAddrV4",
    "SourcePort":     "srcIpPort",
    "Data":           "rawEventMsg",
    "keywords":       "rawEventMsg",
}

def _tier2(eat_name: str) -> str:
    return f"metrics_string.value[indexOf(metrics_string.name,'{eat_name}')]"

_TIER2 = {
    "CommandLine":        _tier2("command"),
    "ParentImage":        _tier2("parentProcName"),
    "ParentCommandLine":  _tier2("parentCommand"),
    "SubjectUserName":    _tier2("subjectUsername"),
    "TargetUserName":     _tier2("targetUser"),
    "DestinationHostname":_tier2("destHostName"),
    "TargetFilename":     _tier2("fileName"),
    "TargetObject":       _tier2("regKey"),
    "Details":            _tier2("regValue"),
    "ScriptBlockText":    _tier2("script"),
    "Hashes":             _tier2("hashMD5"),
    "Initiated":          _tier2("initiated"),
    "ImageLoaded":        _tier2("imageLoaded"),
    "OriginalFileName":   _tier2("originalFileName"),
    "Product":            _tier2("product"),
    "Company":            _tier2("company"),
    "PipeName":           _tier2("pipeName"),
    "Provider_Name":      _tier2("provider"),
    "Channel":            _tier2("channel"),
    "TargetUserGrp":      _tier2("targetUserGrp"),
    "CurrentDirectory":   _tier2("currentDirectory"),
    "IntegrityLevel":     _tier2("integrityLevel"),
    "Signature":          _tier2("signature"),
    "SignatureStatus":    _tier2("signatureStatus"),
}

def get_field(sigma_field: str) -> tuple[str, str]:
    """Return (fsm_expression, tier) for a Sigma field name."""
    if sigma_field in _TIER1:
        return _TIER1[sigma_field], "1"
    if sigma_field in _TIER2:
        return _TIER2[sigma_field], "2"
    # Unmapped fallback
    return "rawEventMsg", "1"


def is_unmapped(sigma_field: str) -> bool:
    """Return True if field was not found in the mapping table."""
    return sigma_field not in _TIER1 and sigma_field not in _TIER2


def _extract_eat_name(expr: str) -> Optional[str]:
    """Extract eat_name from a Tier 2 expression string, e.g. 'command' from indexOf(...)."""
    import re
    m = re.search(r"indexOf\(metrics_string\.name,'([^']+)'\)", expr)
    return m.group(1) if m else None


def _tier2_guard(eat_name: str) -> str:
    return f"indexOf(metrics_string.name, '{eat_name}') > 0"


def _build_single_comparison(expr: str, tier: str, op: str, value: str) -> str:
    """Build a single comparison SQL fragment (no guard logic)."""
    if op == "LIKE_CONTAINS":
        return f"{expr} LIKE '%{_escape_like(value)}%'"
    elif op == "LIKE_ENDS":
        return f"{expr} LIKE '%{_escape_like(value)}'"
    elif op == "LIKE_STARTS":
        return f"{expr} LIKE '{_escape_like(value)}%'"
    elif op == "MATCH":
        return f"match({expr}, '{value}')"
    elif op == "EQ":
        return f"{expr} = '{value}'"
    elif op == "LT":
        return f"{expr} < {value}"
    elif op == "LTE":
        return f"{expr} <= {value}"
    elif op == "GT":
        return f"{expr} > {value}"
    elif op == "GTE":
        return f"{expr} >= {value}"
    else:
        return f"{expr} = '{value}'"


def _escape_like(value: str) -> str:
    """Escape backslashes in LIKE values (ClickHouse uses \\ for literal backslash)."""
    return value.replace("\\", "\\\\")


def _wrap_tier2(eat_name: str, inner_sql: str) -> str:
    """Wrap a Tier 2 comparison with the required indexOf > 0 guard."""
    return f"{_tier2_guard(eat_name)}\n    AND {inner_sql}"


def _compute_base64_variants(value: str) -> list[str]:
    """Compute 3 base64offset variants of value (offsets 0, 1, 2)."""
    variants = []
    for offset in range(3):
        padded = b'\x00' * offset + value.encode('utf-8')
        encoded = base64.b64encode(padded).decode('ascii')
        # Trim offset chars from start, trim trailing chars based on offset % 3
        trim_end = (offset % 3) or 3
        if trim_end == 3:
            trim_end = 0
        inner = encoded[offset: len(encoded) - trim_end if trim_end else len(encoded)]
        if inner:
            variants.append(inner)
    return variants


def apply_modifier(
    expr: str,
    tier: str,
    modifier: Optional[str],
    values: list,
    sigma_field: str = "",
) -> tuple[str, list[str]]:
    """
    Translate a Sigma field condition (expr + modifier + values) → (sql_fragment, comments).

    sql_fragment: a self-contained SQL boolean expression, ready to AND into WHERE.
    comments: list of SQL comment strings (e.g. -- UNMAPPED_FIELD: X) to prepend.
    """
    comments: list[str] = []

    # Inject UNMAPPED_FIELD comment if needed
    if sigma_field and is_unmapped(sigma_field):
        comments.append(f"-- UNMAPPED_FIELD: {sigma_field}")

    eat_name = _extract_eat_name(expr) if tier == "2" else None

    def _with_guard(inner: str) -> str:
        if tier == "2" and eat_name:
            return _wrap_tier2(eat_name, inner)
        return inner

    # Normalise modifier to lowercase
    mod = (modifier or "").lower().strip()

    # --- contains|all (special compound) ---
    if mod == "contains|all":
        parts = [_build_single_comparison(expr, tier, "LIKE_CONTAINS", str(v)) for v in values]
        inner = " AND ".join(parts)
        return _with_guard(inner), comments

    # --- base64offset|contains ---
    if mod == "base64offset|contains":
        all_variants: list[str] = []
        for v in values:
            all_variants.extend(_compute_base64_variants(str(v)))
        # Deduplicate, join with pipe for regex alternation
        pattern = "|".join(dict.fromkeys(all_variants))
        inner = f"match({expr}, '{pattern}')"
        return _with_guard(inner), comments

    # --- exists|true / exists|false ---
    if mod == "exists|true":
        inner = f"{expr} IS NOT NULL AND {expr} != ''"
        return _with_guard(inner), comments

    if mod == "exists|false":
        inner = f"({expr} IS NULL OR {expr} = '')"
        return _with_guard(inner), comments

    # --- windash ---
    if mod == "windash":
        parts = []
        for v in values:
            sv = str(v)
            # 4 variants: space-prefixed, dash-prefixed, slash-prefixed, en-dash-prefixed
            for prefix in [" ", "-", "/", "\u2013"]:
                parts.append(_build_single_comparison(expr, tier, "LIKE_CONTAINS", f"{prefix}{sv}"))
        inner = "(\n      " + "\n      OR ".join(parts) + "\n    )"
        return _with_guard(inner), comments

    # --- re ---
    if mod == "re":
        parts = [_build_single_comparison(expr, tier, "MATCH", str(v)) for v in values]
        inner = " OR ".join(parts) if len(parts) > 1 else parts[0]
        return _with_guard(inner), comments

    # --- cidr ---
    if mod == "cidr":
        parts = [f"isIPAddressInRange(toString({expr}), '{v}')" for v in values]
        inner = " OR ".join(parts) if len(parts) > 1 else parts[0]
        return inner, comments  # cidr: no tier-2 guard needed (IP cols are Tier 1)

    # --- numeric comparisons ---
    op_map = {"lt": "LT", "lte": "LTE", "gt": "GT", "gte": "GTE"}
    if mod in op_map:
        # Numeric — use single value (if multiple, first one)
        val = str(values[0]) if values else "0"
        inner = _build_single_comparison(expr, tier, op_map[mod], val)
        return _with_guard(inner), comments

    # --- endswith / startswith / contains (single modifier, multi-value OR) ---
    op_lookup = {
        "endswith":  "LIKE_ENDS",
        "startswith":"LIKE_STARTS",
        "contains":  "LIKE_CONTAINS",
    }
    if mod in op_lookup:
        parts = [_build_single_comparison(expr, tier, op_lookup[mod], str(v)) for v in values]
        inner = "(\n      " + "\n      OR ".join(parts) + "\n    )" if len(parts) > 1 else parts[0]
        return _with_guard(inner), comments

    # --- no modifier (equality) ---
    if not mod:
        if len(values) == 1:
            inner = _build_single_comparison(expr, tier, "EQ", str(values[0]))
        else:
            quoted = ", ".join(f"'{v}'" for v in values)
            inner = f"{expr} IN ({quoted})"
        return _with_guard(inner), comments

    # --- unknown modifier fallback ---
    comments.append(f"-- UNSUPPORTED_MODIFIER: {modifier}")
    parts = [f"rawEventMsg LIKE '%{_escape_like(str(v))}%'" for v in values]
    inner = " OR ".join(parts)
    return inner, comments
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_field_map.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git add sigma_queries/scripts/converter/field_map.py sigma_queries/tests/test_field_map.py
git commit -m "feat: implement field_map with Sigma→FSM mapping and modifier translation"
```

---

## Chunk 2: Rule Parser

### Task 3: `rule_parser.py` — YAML → SigmaRule Dataclass

**Files:**
- Create: `sigma_queries/scripts/converter/rule_parser.py`
- Create: `sigma_queries/tests/test_rule_parser.py`

- [ ] **Step 1: Write failing tests**

Create `sigma_queries/tests/test_rule_parser.py`:

```python
"""Tests for rule_parser.py — YAML → SigmaRule dataclass."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from pathlib import Path
from converter.rule_parser import parse_rule, SigmaRule

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseRuleBasic:
    """Test basic field population from YAML."""

    def setup_method(self):
        self.rule = parse_rule(FIXTURES / "win_proc_create.yml")

    def test_returns_sigma_rule_instance(self):
        assert isinstance(self.rule, SigmaRule)

    def test_id_extracted(self):
        assert self.rule.id == "a2b0b9e0-1234-4567-89ab-cdef01234567"

    def test_title_extracted(self):
        assert self.rule.title == "Suspicious PowerShell Encoded Command"

    def test_author_extracted(self):
        assert self.rule.author == "Test Author"

    def test_status_extracted(self):
        assert self.rule.status == "stable"

    def test_level_extracted(self):
        assert self.rule.level == "high"

    def test_fsm_severity_high_is_7(self):
        assert self.rule.fsm_severity == 7

    def test_tags_extracted(self):
        assert "attack.execution" in self.rule.tags
        assert "attack.t1059.001" in self.rule.tags

    def test_mitre_tactics_extracted(self):
        assert "execution" in self.rule.mitre_tactics

    def test_mitre_techniques_extracted(self):
        assert "T1059.001" in self.rule.mitre_techniques

    def test_logsource_product(self):
        assert self.rule.logsource_product == "windows"

    def test_logsource_category(self):
        assert self.rule.logsource_category == "process_creation"

    def test_logsource_service_empty(self):
        assert self.rule.logsource_service == ""

    def test_fsm_event_types_process_creation(self):
        assert "Win-Sysmon-1-Create-Process" in self.rule.fsm_event_types

    def test_sigma_file_path_set(self):
        assert "win_proc_create.yml" in self.rule.sigma_file_path

    def test_github_url_uses_main_branch(self):
        assert "blob/main" in self.rule.github_url

    def test_falsepositives_extracted(self):
        assert "Legitimate admin scripts" in self.rule.falsepositives

    def test_references_extracted(self):
        assert "https://example.com/ref1" in self.rule.references


class TestSeverityMapping:
    """Test level → fsm_severity mapping."""

    def test_low_maps_to_3(self):
        rule = parse_rule(FIXTURES / "unmapped.yml")
        assert rule.level == "low"
        assert rule.fsm_severity == 3

    def test_medium_maps_to_5(self):
        rule = parse_rule(FIXTURES / "win_net_conn.yml")
        assert rule.level == "medium"
        assert rule.fsm_severity == 5

    def test_high_maps_to_7(self):
        rule = parse_rule(FIXTURES / "linux_proc.yml")
        assert rule.level == "high"
        assert rule.fsm_severity == 7


class TestDetectionSelections:
    """Test detection_selections structure contract."""

    def setup_method(self):
        self.rule = parse_rule(FIXTURES / "win_proc_create.yml")

    def test_selection_key_exists(self):
        assert "selection" in self.rule.detection_selections

    def test_values_are_list_of_dicts(self):
        sel = self.rule.detection_selections["selection"]
        assert isinstance(sel, list)
        assert all(isinstance(item, dict) for item in sel)

    def test_all_values_are_lists(self):
        """Per contract: all condition values are wrapped in lists."""
        for sel_name, maps in self.rule.detection_selections.items():
            for m in maps:
                for v in m.values():
                    assert isinstance(v, list), f"{sel_name}: value {v!r} is not a list"

    def test_modifier_suffix_in_key(self):
        """Keys should include modifier suffix, e.g. 'CommandLine|contains'."""
        sel = self.rule.detection_selections["selection"]
        all_keys = [k for m in sel for k in m.keys()]
        assert any("|" in k for k in all_keys)

    def test_negated_filter_in_registry(self):
        rule = parse_rule(FIXTURES / "win_registry.yml")
        assert "selection_main" in rule.detection_selections
        assert "filter_legit" in rule.detection_selections


class TestConditionResolved:
    """Test condition_resolved wildcard expansion."""

    def test_simple_condition_no_wildcard(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        # "condition: selection" → [[ ("selection", False) ]]
        assert rule.condition_resolved == [[("selection", False)]]

    def test_negated_filter(self):
        rule = parse_rule(FIXTURES / "win_registry.yml")
        # "condition: selection_main and not filter_legit"
        # → [[ ("selection_main", False), ("filter_legit", True) ]]
        assert len(rule.condition_resolved) == 1
        and_group = rule.condition_resolved[0]
        assert ("selection_main", False) in and_group
        assert ("filter_legit", True) in and_group

    def test_condition_raw_preserved(self):
        rule = parse_rule(FIXTURES / "win_registry.yml")
        assert "selection_main" in rule.condition


class TestLogsourceMapping:
    """Test fsm_event_types derivation."""

    def test_windows_process_creation(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        assert "Win-Sysmon-1-Create-Process" in rule.fsm_event_types
        assert "Win-Security-4688" in rule.fsm_event_types

    def test_windows_network_connection(self):
        rule = parse_rule(FIXTURES / "win_net_conn.yml")
        assert "Win-Sysmon-3-Network-Connect-IPv4" in rule.fsm_event_types

    def test_linux_process_creation(self):
        rule = parse_rule(FIXTURES / "linux_proc.yml")
        assert "LINUX_PROCESS_EXEC" in rule.fsm_event_types

    def test_unknown_logsource_empty_event_types(self):
        rule = parse_rule(FIXTURES / "unmapped.yml")
        assert rule.fsm_event_types == []
        assert rule.unmapped_logsource is True

    def test_windows_registry_set(self):
        rule = parse_rule(FIXTURES / "win_registry.yml")
        assert any("Sysmon-12" in et or "Sysmon-13" in et for et in rule.fsm_event_types)


class TestErrorHandling:
    """Test graceful handling of malformed input."""

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_rule(Path("/nonexistent/path.yml"))

    def test_empty_detection_returns_none(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text("title: bad\nid: aaa\ndetection:\ncondition: all of them\n")
        result = parse_rule(bad)
        assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_rule_parser.py -v 2>&1 | head -30
```

Expected: `ImportError` — `rule_parser` does not exist yet.

- [ ] **Step 3: Implement `rule_parser.py`**

Create `sigma_queries/scripts/converter/rule_parser.py`:

```python
"""
rule_parser.py — YAML Sigma rule → SigmaRule dataclass.

Handles:
- All SigmaRule fields from YAML
- detection_selections: typed dict[str, list[dict[str, Any]]]
- condition_resolved: pre-expanded list[list[tuple[str, bool]]]
- fsm_event_types derivation from logsource mapping
- Wildcard expansion in conditions (e.g. "1 of selection_*")
"""
from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    # Identity
    id: str
    title: str
    description: str
    author: str
    date: str
    status: str

    # Severity
    level: str
    fsm_severity: int

    # Classification
    tags: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]

    # Logsource
    logsource_product: str
    logsource_category: str
    logsource_service: str
    fsm_event_types: list[str]

    # Detection (structured)
    detection_selections: dict[str, list[dict[str, Any]]]
    condition: str
    condition_resolved: list[list[tuple[str, bool]]]

    # Metadata
    falsepositives: list[str]
    references: list[str]

    # Provenance
    sigma_file_path: str
    github_url: str

    # Populated by sql_builder
    unmapped_fields: list[str] = field(default_factory=list)
    unmapped_logsource: bool = False


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY = {"low": 3, "medium": 5, "high": 7, "critical": 9}


# ---------------------------------------------------------------------------
# Logsource → FSM event type mapping
# ---------------------------------------------------------------------------

_LOGSOURCE_MAP: dict[tuple[str, str], list[str]] = {
    ("windows", "process_creation"):      ["Win-Sysmon-1-Create-Process", "Win-Security-4688"],
    ("windows", "network_connection"):    ["Win-Sysmon-3-Network-Connect-IPv4"],
    ("windows", "ps_script"):             ["Win-PowerShell-4104"],
    ("windows", "ps_classic_provider_start"): ["Win-PowerShell-400"],
    ("windows", "ps_module"):             ["Win-PowerShell-4103"],
    ("windows", "registry_add"):          ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "registry_set"):          ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "registry_delete"):       ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "registry_event"):        ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "file_event"):            ["Win-Sysmon-11-File-Create"],
    ("windows", "file_delete"):           ["Win-Sysmon-23-File-Delete"],
    ("windows", "file_rename"):           ["Win-Sysmon-11-File-Create"],
    ("windows", "dns_query"):             ["Win-Sysmon-22-DNS-Query"],
    ("windows", "image_load"):            ["Win-Sysmon-7-Image-Load"],
    ("windows", "driver_load"):           ["Win-Sysmon-6-Driver-Load"],
    ("windows", "pipe_created"):          ["Win-Sysmon-17-Pipe-Created"],
    ("windows", "create_remote_thread"):  ["Win-Sysmon-8-Create-Remote-Thread"],
    ("windows", "wmi_event"):             ["Win-Sysmon-19-WMI-Event-Filter"],
    ("windows", "process_access"):        ["Win-Sysmon-10-Process-Access"],
    ("windows", "create_stream_hash"):    ["Win-Sysmon-15-FileCreateStreamHash"],
    # Windows service-based
    ("windows", "security"):              ["Win-Security-*"],
    ("windows", "system"):                ["Win-System-*"],
    ("windows", "application"):           ["Win-Application-*"],
    ("windows", "sysmon"):                ["Win-Sysmon-*"],
    ("windows", "taskscheduler"):         ["Win-TaskScheduler-*"],
    ("windows", "powershell"):            ["Win-PowerShell-*"],
    # Linux
    ("linux", "process_creation"):        ["LINUX_PROCESS_EXEC"],
    ("linux", "file_event"):              ["LINUX_FILE_CREATE"],
    ("linux", "network_connection"):      ["LINUX_NET_CONN"],
    ("linux", "syslog"):                  ["Generic_Syslog"],
    ("linux", "auditd"):                  ["Linux-Audit-*"],
    # macOS
    ("macos", "process_creation"):        ["macOS-Exec-*"],
    # Cloud
    ("aws", "cloudtrail"):               ["AWS-CloudTrail-*"],
    ("azure", "activitylogs"):           ["Azure-Activity-*"],
    ("gcp", "gcp.audit"):               ["GCP-AuditLog-*"],
    ("m365", "any"):                     ["O365-*"],
}

_SERVICE_PREFIX = {
    "security":      "Win-Security",
    "system":        "Win-System",
    "application":   "Win-Application",
    "sysmon":        "Win-Sysmon",
    "taskscheduler": "Win-TaskScheduler",
    "powershell":    "Win-PowerShell",
}


def _derive_fsm_event_types(
    product: str,
    category: str,
    service: str,
    detection_selections: dict[str, list[dict[str, Any]]],
) -> tuple[list[str], bool]:
    """
    Derive fsm_event_types from logsource fields.
    Returns (event_types_list, unmapped_logsource).
    """
    key_cat = (product.lower(), category.lower()) if category else None
    key_svc = (product.lower(), service.lower()) if service else None

    base_types: list[str] = []
    unmapped = False

    if key_cat and key_cat in _LOGSOURCE_MAP:
        base_types = list(_LOGSOURCE_MAP[key_cat])
    elif key_svc and key_svc in _LOGSOURCE_MAP:
        base_types = list(_LOGSOURCE_MAP[key_svc])
    elif (product.lower(), "any") in _LOGSOURCE_MAP:
        base_types = list(_LOGSOURCE_MAP[(product.lower(), "any")])
    else:
        unmapped = True
        return [], unmapped

    # EventID specialization (rule 3 from spec)
    if service and service.lower() in _SERVICE_PREFIX:
        prefix = _SERVICE_PREFIX[service.lower()]
        event_ids = _collect_event_ids(detection_selections)
        if event_ids:
            base_types = [f"{prefix}-{eid}" for eid in event_ids]

    return base_types, unmapped


def _collect_event_ids(detection_selections: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Extract EventID values from detection selections."""
    ids = []
    for maps in detection_selections.values():
        for m in maps:
            for k, v in m.items():
                field_name = k.split("|")[0]
                if field_name.lower() == "eventid":
                    ids.extend(str(x) for x in v)
    return ids


# ---------------------------------------------------------------------------
# detection_selections parsing
# ---------------------------------------------------------------------------

def _parse_detection_selections(
    detection: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """
    Parse detection block → detection_selections.

    The returned dict maps selection_name → list[dict[str, list[Any]]].
    Each list item represents an OR-alternative within the selection.
    Within each dict, all keys are AND'd.
    All values are lists.
    """
    result: dict[str, list[dict[str, Any]]] = {}

    for key, value in detection.items():
        if key == "condition":
            continue
        if key == "timeframe":
            continue

        if isinstance(value, list):
            # Could be keyword list OR list of maps
            if all(isinstance(item, str) for item in value):
                # Keyword selection
                result[key] = [{"_keyword": value}]
            elif all(isinstance(item, dict) for item in value):
                # List of field-condition maps (each map is an OR alternative)
                result[key] = [_normalise_field_map(item) for item in value]
            else:
                # Mixed: treat strings as keywords, dicts as field maps
                maps = []
                keywords = []
                for item in value:
                    if isinstance(item, str):
                        keywords.append(item)
                    elif isinstance(item, dict):
                        maps.append(_normalise_field_map(item))
                if keywords:
                    maps.append({"_keyword": keywords})
                result[key] = maps
        elif isinstance(value, dict):
            # Single field-condition map (all keys AND'd)
            result[key] = [_normalise_field_map(value)]
        else:
            # Scalar or None — skip
            continue

    return result


def _normalise_field_map(m: dict) -> dict[str, list[Any]]:
    """Ensure all values in a field-condition map are lists."""
    out: dict[str, list[Any]] = {}
    for k, v in m.items():
        if isinstance(v, list):
            out[k] = v
        elif v is None:
            out[k] = []
        else:
            out[k] = [v]
    return out


# ---------------------------------------------------------------------------
# Condition parsing + wildcard expansion
# ---------------------------------------------------------------------------

def _expand_condition(
    condition: str,
    selection_names: set[str],
) -> list[list[tuple[str, bool]]]:
    """
    Parse a Sigma condition string into a structured list of OR-groups.
    Each OR-group is a list of (selection_name, negated) AND-terms.
    Wildcards (e.g. "1 of selection_*") are expanded against selection_names.
    """
    # Normalise whitespace
    cond = condition.strip()

    # Handle OR at the top level by splitting on " or "
    or_parts = re.split(r'\bor\b', cond, flags=re.IGNORECASE)

    result: list[list[tuple[str, bool]]] = []

    for or_part in or_parts:
        and_terms = _parse_and_group(or_part.strip(), selection_names)
        if and_terms:
            result.append(and_terms)

    return result if result else [[("all", False)]]


def _parse_and_group(
    expr: str,
    selection_names: set[str],
) -> list[tuple[str, bool]]:
    """Parse a single AND-group string into (name, negated) tuples."""
    tokens = re.split(r'\band\b', expr, flags=re.IGNORECASE)
    terms: list[tuple[str, bool]] = []

    for token in tokens:
        token = token.strip()
        negated = False

        # Strip "not " prefix
        if re.match(r'^not\s+', token, re.IGNORECASE):
            negated = True
            token = re.sub(r'^not\s+', '', token, flags=re.IGNORECASE).strip()

        # Handle "N of name*" or "all of name*"
        wildcard_match = re.match(
            r'^(?:\d+|all|1)\s+of\s+(\S+)$', token, re.IGNORECASE
        )
        if wildcard_match:
            pattern = wildcard_match.group(1)
            expanded = _expand_wildcard(pattern, selection_names)
            for name in expanded:
                terms.append((name, negated))
        elif token and token.lower() not in ("them",):
            terms.append((token, negated))

    return terms


def _expand_wildcard(pattern: str, selection_names: set[str]) -> list[str]:
    """Expand a wildcard pattern like 'selection_*' against known selection names."""
    if "*" not in pattern:
        return [pattern] if pattern in selection_names else [pattern]

    regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
    matched = sorted(name for name in selection_names if regex.match(name))
    return matched if matched else [pattern]


# ---------------------------------------------------------------------------
# MITRE tag parsing
# ---------------------------------------------------------------------------

def _parse_mitre_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Extract tactics and techniques from Sigma tags."""
    tactics: list[str] = []
    techniques: list[str] = []

    known_tactics = {
        "initial_access", "execution", "persistence", "privilege_escalation",
        "defense_evasion", "credential_access", "discovery", "lateral_movement",
        "collection", "command_and_control", "exfiltration", "impact",
        "reconnaissance", "resource_development",
    }

    for tag in tags:
        if not tag.startswith("attack."):
            continue
        val = tag[len("attack."):]
        # Technique: starts with 't' followed by digits
        if re.match(r'^t\d{4}', val, re.IGNORECASE):
            techniques.append(val.upper())
        elif val.lower() in known_tactics:
            tactics.append(val.lower())

    return tactics, techniques


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def parse_rule(
    path: Path,
    sigma_repo_root: Optional[Path] = None,
) -> Optional[SigmaRule]:
    """
    Parse a Sigma YAML rule file into a SigmaRule dataclass.
    Returns None if the rule has an empty/missing detection block.
    Raises FileNotFoundError if path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        return None

    detection = raw.get("detection") or {}
    if not detection or not any(k != "condition" for k in detection):
        return None

    detection_selections = _parse_detection_selections(detection)
    condition = str(detection.get("condition", ""))

    if not condition:
        return None

    condition_resolved = _expand_condition(condition, set(detection_selections.keys()))

    # Logsource
    ls = raw.get("logsource") or {}
    product = str(ls.get("product") or "")
    category = str(ls.get("category") or "")
    service = str(ls.get("service") or "")

    fsm_event_types, unmapped_logsource = _derive_fsm_event_types(
        product, category, service, detection_selections
    )

    # Tags / MITRE
    tags = list(raw.get("tags") or [])
    mitre_tactics, mitre_techniques = _parse_mitre_tags(tags)

    # Severity
    level = str(raw.get("level") or "medium").lower()
    fsm_severity = _SEVERITY.get(level, 5)

    # Provenance
    sigma_file_path = str(path)
    if sigma_repo_root:
        try:
            sigma_file_path = str(path.relative_to(sigma_repo_root))
        except ValueError:
            pass

    github_url = f"https://github.com/SigmaHQ/sigma/blob/main/{sigma_file_path.lstrip('/')}"

    # Scalar fields with safe defaults
    def _strlist(v: Any) -> list[str]:
        if isinstance(v, list):
            return [str(x) for x in v if x is not None]
        if v:
            return [str(v)]
        return []

    return SigmaRule(
        id=str(raw.get("id") or ""),
        title=str(raw.get("title") or ""),
        description=str(raw.get("description") or ""),
        author=str(raw.get("author") or ""),
        date=str(raw.get("date") or ""),
        status=str(raw.get("status") or ""),
        level=level,
        fsm_severity=fsm_severity,
        tags=tags,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        logsource_product=product,
        logsource_category=category,
        logsource_service=service,
        fsm_event_types=fsm_event_types,
        detection_selections=detection_selections,
        condition=condition,
        condition_resolved=condition_resolved,
        falsepositives=_strlist(raw.get("falsepositives")),
        references=_strlist(raw.get("references")),
        sigma_file_path=sigma_file_path,
        github_url=github_url,
        unmapped_fields=[],
        unmapped_logsource=unmapped_logsource,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_rule_parser.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git add sigma_queries/scripts/converter/rule_parser.py sigma_queries/tests/test_rule_parser.py
git commit -m "feat: implement rule_parser YAML→SigmaRule with condition wildcard expansion"
```

---

## Chunk 3: SQL Builder

### Task 4: `sql_builder.py` — SigmaRule → ClickHouse SQL

**Files:**
- Create: `sigma_queries/scripts/converter/sql_builder.py`
- Create: `sigma_queries/tests/test_sql_builder.py`

- [ ] **Step 1: Write failing tests**

Create `sigma_queries/tests/test_sql_builder.py`:

```python
"""Tests for sql_builder.py — SigmaRule → ClickHouse SQL string."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from pathlib import Path
from converter.rule_parser import parse_rule
from converter.sql_builder import build_sql

FIXTURES = Path(__file__).parent / "fixtures"


class TestSQLStructure:
    """Test that generated SQL has required structural elements."""

    def setup_method(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        self.sql = build_sql(rule)

    def test_has_select(self):
        assert "SELECT" in self.sql

    def test_has_from_fsiem_events(self):
        assert "FROM fsiem.events" in self.sql

    def test_has_where(self):
        assert "WHERE" in self.sql

    def test_has_event_type_filter(self):
        assert "eventType IN" in self.sql

    def test_has_time_filter(self):
        assert "phRecvTime >= now() - INTERVAL 24 HOUR" in self.sql

    def test_has_order_by(self):
        assert "ORDER BY phRecvTime DESC" in self.sql

    def test_has_limit(self):
        assert "LIMIT 1000" in self.sql


class TestCommentBlock:
    """Test SQL comment block format."""

    def setup_method(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        self.sql = build_sql(rule)

    def test_has_title_comment(self):
        assert "-- Title:" in self.sql
        assert "Suspicious PowerShell" in self.sql

    def test_has_sigma_id_comment(self):
        assert "-- Sigma ID:" in self.sql
        assert "a2b0b9e0" in self.sql

    def test_has_level_comment(self):
        assert "-- Level:" in self.sql
        assert "high" in self.sql

    def test_has_fsm_severity_comment(self):
        assert "FSM Severity: 7" in self.sql

    def test_has_mitre_comment(self):
        assert "-- MITRE:" in self.sql

    def test_has_github_url_comment(self):
        assert "-- GitHub:" in self.sql
        assert "blob/main" in self.sql

    def test_has_unmapped_comment(self):
        assert "-- Unmapped:" in self.sql


class TestSelectColumns:
    """Test SELECT column list."""

    def setup_method(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        self.sql = build_sql(rule)

    def test_always_includes_phrecvtime(self):
        assert "phRecvTime" in self.sql

    def test_always_includes_reptdevname(self):
        assert "reptDevName" in self.sql

    def test_always_includes_rawEventMsg(self):
        assert "rawEventMsg" in self.sql

    def test_tier2_field_has_alias(self):
        # CommandLine is Tier 2 — should appear with AS alias
        assert "AS command" in self.sql or "AS commandLine" in self.sql.lower()


class TestWhereClause:
    """Test WHERE clause correctness per detection."""

    def test_contains_modifier_uses_like(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        sql = build_sql(rule)
        assert "LIKE '%-EncodedCommand%'" in sql or "LIKE '%EncodedCommand%'" in sql

    def test_tier2_field_has_indexof_guard(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        sql = build_sql(rule)
        assert "indexOf(metrics_string.name, 'command') > 0" in sql

    def test_negated_filter_uses_not(self):
        rule = parse_rule(FIXTURES / "win_registry.yml")
        sql = build_sql(rule)
        assert "NOT" in sql

    def test_unmapped_logsource_uses_rawmsg_fallback(self):
        rule = parse_rule(FIXTURES / "unmapped.yml")
        sql = build_sql(rule)
        assert "rawEventMsg LIKE" in sql or "UNMAPPED_LOGSOURCE" in sql

    def test_unmapped_field_generates_comment(self):
        rule = parse_rule(FIXTURES / "unmapped.yml")
        build_sql(rule)
        assert "SomeUnknownField" in rule.unmapped_fields


class TestEventTypes:
    """Test event type IN clause."""

    def test_windows_proc_create_event_types(self):
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        sql = build_sql(rule)
        assert "Win-Sysmon-1-Create-Process" in sql

    def test_unmapped_logsource_uses_rawmsg_event_type(self):
        rule = parse_rule(FIXTURES / "unmapped.yml")
        sql = build_sql(rule)
        # No real event types → SQL should still be valid but with rawEventMsg fallback
        assert "FROM fsiem.events" in sql
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_sql_builder.py -v 2>&1 | head -30
```

Expected: `ImportError` — `sql_builder` does not exist yet.

- [ ] **Step 3: Implement `sql_builder.py`**

Create `sigma_queries/scripts/converter/sql_builder.py`:

```python
"""
sql_builder.py — SigmaRule → FortiSIEM ClickHouse SQL string.

Builds a complete SELECT/FROM/WHERE/ORDER BY/LIMIT query with a
formatted comment block header.
"""
from __future__ import annotations

from typing import Any
from converter.rule_parser import SigmaRule
from converter import field_map as fm

# ---------------------------------------------------------------------------
# Always-included SELECT columns
# ---------------------------------------------------------------------------

_BASE_SELECT = [
    "phRecvTime",
    "reptDevName",
    "reptDevIpAddrV4",
    "user",
]

_SELECT_TRAILING = ["rawEventMsg"]


# ---------------------------------------------------------------------------
# Comment block builder
# ---------------------------------------------------------------------------

def _comment_block(rule: SigmaRule) -> str:
    mitre_line = (
        f"{', '.join(rule.mitre_tactics)} | {', '.join(rule.mitre_techniques)}"
        if rule.mitre_tactics or rule.mitre_techniques
        else "(none)"
    )
    unmapped_line = ", ".join(rule.unmapped_fields) if rule.unmapped_fields else "(none)"
    fp_line = "; ".join(rule.falsepositives) if rule.falsepositives else "(none)"

    lines = [
        "-- " + "=" * 60,
        f"-- Title:        {rule.title}",
        f"-- Sigma ID:     {rule.id}",
        f"-- Level:        {rule.level}  |  FSM Severity: {rule.fsm_severity}",
        f"-- Status:       {rule.status}",
        f"-- MITRE:        {mitre_line}",
        f"-- Author:       {rule.author}",
        f"-- Date:         {rule.date}",
        f"-- GitHub:       {rule.github_url}",
        f"-- Unmapped:     {unmapped_line}",
        f"-- False Pos:    {fp_line}",
        "-- " + "=" * 60,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Detection condition → WHERE fragment
# ---------------------------------------------------------------------------

def _selection_to_sql(
    sel_name: str,
    detection_selections: dict[str, list[dict[str, Any]]],
    extra_select_cols: list[str],
    extra_select_tier2: list[tuple[str, str]],
    unmapped_fields: list[str],
) -> tuple[str, list[str]]:
    """
    Convert one selection's conditions to a SQL WHERE fragment.
    Returns (sql_fragment, [comment_strings]).
    Updates extra_select_cols / extra_select_tier2 / unmapped_fields in-place.
    """
    all_comments: list[str] = []
    maps = detection_selections.get(sel_name, [])

    if not maps:
        return "1=1", []

    # Each map in the list is an OR alternative; within a map, keys are AND'd
    or_fragments: list[str] = []

    for field_map in maps:
        and_fragments: list[str] = []

        for key, values in field_map.items():
            if key == "_keyword":
                # Bare keyword search on rawEventMsg
                kw_parts = [f"rawEventMsg LIKE '%{fm._escape_like(str(v))}%'" for v in values]
                and_fragments.append(
                    "(" + " OR ".join(kw_parts) + ")" if len(kw_parts) > 1 else kw_parts[0]
                )
                continue

            # Split field name and modifier
            parts = key.split("|", 1)
            sigma_field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None

            expr, tier = fm.get_field(sigma_field)

            # Track for SELECT
            if tier == "1" and expr != "rawEventMsg":
                if expr not in _BASE_SELECT and expr not in extra_select_cols:
                    extra_select_cols.append(expr)
            elif tier == "2":
                alias = _camel_alias(sigma_field)
                entry = (expr, alias)
                if entry not in extra_select_tier2:
                    extra_select_tier2.append(entry)

            # Track unmapped fields
            if fm.is_unmapped(sigma_field) and sigma_field not in unmapped_fields:
                unmapped_fields.append(sigma_field)

            sql_frag, comments = fm.apply_modifier(
                expr, tier, modifier, values, sigma_field=sigma_field
            )
            all_comments.extend(comments)

            and_fragments.append(sql_frag)

        if and_fragments:
            combined = "\n    AND ".join(and_fragments)
            or_fragments.append(f"({combined})" if len(and_fragments) > 1 else combined)

    if not or_fragments:
        return "1=1", all_comments

    if len(or_fragments) == 1:
        return or_fragments[0], all_comments

    return "(\n    " + "\n    OR ".join(or_fragments) + "\n  )", all_comments


def _camel_alias(sigma_field: str) -> str:
    """Convert SigmaFieldName to camelCase alias (lowercase first letter)."""
    if not sigma_field:
        return sigma_field
    return sigma_field[0].lower() + sigma_field[1:]


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_sql(rule: SigmaRule) -> str:
    """Convert a SigmaRule to a ClickHouse SQL query string."""

    extra_select_cols: list[str] = []
    extra_select_tier2: list[tuple[str, str]] = []
    unmapped_fields: list[str] = []
    header_comments: list[str] = []

    # Unmapped logsource
    if rule.unmapped_logsource:
        header_comments.append("-- UNMAPPED_LOGSOURCE: "
                                f"{rule.logsource_product}/{rule.logsource_category or rule.logsource_service}")

    # Build WHERE from condition_resolved
    # condition_resolved: list[list[tuple[str, bool]]]
    # outer list = OR groups; inner list = AND terms

    or_where_parts: list[str] = []

    for and_group in rule.condition_resolved:
        and_parts: list[str] = []

        for sel_name, negated in and_group:
            frag, comments = _selection_to_sql(
                sel_name,
                rule.detection_selections,
                extra_select_cols,
                extra_select_tier2,
                unmapped_fields,
            )
            header_comments.extend(comments)

            if negated:
                and_parts.append(f"NOT ({frag})")
            else:
                and_parts.append(frag)

        if and_parts:
            combined = "\n  AND ".join(and_parts)
            or_where_parts.append(f"({combined})" if len(and_parts) > 1 else combined)

    # Populate rule's unmapped_fields (in-place for comment block)
    rule.unmapped_fields = unmapped_fields

    # Generate comment block (after unmapped_fields is populated)
    comment_block = _comment_block(rule)

    # Event type IN clause
    if rule.fsm_event_types:
        et_list = ", ".join(f"'{et}'" for et in rule.fsm_event_types)
        event_type_clause = f"eventType IN ({et_list})"
    else:
        event_type_clause = "rawEventMsg LIKE '%'"  # unmapped logsource fallback

    # Assemble WHERE
    detection_where = (
        "\n  AND ".join(or_where_parts) if or_where_parts else "rawEventMsg LIKE '%'"
    )

    # Build SELECT list
    select_cols = list(_BASE_SELECT)
    for col in extra_select_cols:
        if col not in select_cols:
            select_cols.append(col)
    tier2_select = [f"{expr} AS {alias}" for expr, alias in extra_select_tier2]
    all_select = select_cols + tier2_select + _SELECT_TRAILING
    select_str = ",\n    ".join(all_select)

    # Header comment lines (unmapped field/modifier comments)
    header_extra = "\n".join(header_comments) + "\n" if header_comments else ""

    query = (
        f"{comment_block}\n"
        f"{header_extra}"
        f"SELECT\n"
        f"    {select_str}\n"
        f"FROM fsiem.events\n"
        f"WHERE {event_type_clause}\n"
        f"  AND phRecvTime >= now() - INTERVAL 24 HOUR\n"
        f"  AND {detection_where}\n"
        f"ORDER BY phRecvTime DESC\n"
        f"LIMIT 1000;"
    )

    return query
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_sql_builder.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git add sigma_queries/scripts/converter/sql_builder.py sigma_queries/tests/test_sql_builder.py
git commit -m "feat: implement sql_builder SigmaRule→ClickHouse SQL with comment block"
```

---

## Chunk 4: Renderer

### Task 5: `renderer.py` — JSON + Markdown + HTML Writers

**Files:**
- Create: `sigma_queries/scripts/converter/renderer.py`
- Create: `sigma_queries/tests/test_renderer.py`

- [ ] **Step 1: Write failing tests**

Create `sigma_queries/tests/test_renderer.py`:

```python
"""Tests for renderer.py — JSON/Markdown/HTML output writers."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from pathlib import Path
from converter.rule_parser import parse_rule
from converter.sql_builder import build_sql
from converter.renderer import render_json, render_markdown, render_html_page, render_index_html

FIXTURES = Path(__file__).parent / "fixtures"


def _make_entries(filenames):
    """Helper: parse + build SQL for a list of fixture filenames."""
    entries = []
    for fn in filenames:
        rule = parse_rule(FIXTURES / fn)
        sql = build_sql(rule)
        entries.append((rule, sql))
    return entries


class TestRenderJSON:
    """Test sigma_queries.json output schema."""

    def setup_method(self):
        entries = _make_entries(["win_proc_create.yml", "linux_proc.yml"])
        self.doc = render_json(entries, sigma_repo_path="/sigma", output_path=None)

    def test_has_generated_field(self):
        assert "generated" in self.doc

    def test_has_total_rules_found(self):
        assert "total_rules_found" in self.doc

    def test_has_total_converted(self):
        assert "total_converted" in self.doc

    def test_has_unmapped_logsource_count(self):
        assert "unmapped_logsource_count" in self.doc

    def test_has_entries_list(self):
        assert isinstance(self.doc["entries"], list)
        assert len(self.doc["entries"]) == 2

    def test_entry_has_sigma_id(self):
        assert "sigma_id" in self.doc["entries"][0]

    def test_entry_has_sql(self):
        assert "sql" in self.doc["entries"][0]
        assert "SELECT" in self.doc["entries"][0]["sql"]

    def test_entry_has_github_url(self):
        assert "github_url" in self.doc["entries"][0]
        assert "blob/main" in self.doc["entries"][0]["github_url"]

    def test_entry_has_fsm_event_types(self):
        assert "fsm_event_types" in self.doc["entries"][0]

    def test_entry_has_mitre_tactics(self):
        assert "mitre_tactics" in self.doc["entries"][0]

    def test_entry_no_detection_selections(self):
        """detection_selections must NOT appear in JSON output."""
        entry = self.doc["entries"][0]
        assert "detection_selections" not in entry
        assert "condition_resolved" not in entry

    def test_json_serializable(self):
        assert json.dumps(self.doc)  # should not raise


class TestRenderMarkdown:
    """Test per-category markdown output."""

    def setup_method(self):
        entries = _make_entries(["win_proc_create.yml"])
        self.md = render_markdown(entries, product="windows", category="process_creation")

    def test_has_h1_header(self):
        assert "# Sigma → FortiSIEM" in self.md

    def test_has_rule_count(self):
        assert "1 rule" in self.md or "rules" in self.md

    def test_has_table_of_contents(self):
        assert "## Table of Contents" in self.md

    def test_has_rule_section(self):
        assert "## " in self.md

    def test_has_sigma_id(self):
        assert "a2b0b9e0" in self.md

    def test_has_github_link(self):
        assert "View on GitHub" in self.md
        assert "https://github.com" in self.md

    def test_has_sql_code_block(self):
        assert "```sql" in self.md

    def test_has_false_positives(self):
        assert "False Positive" in self.md


class TestRenderHTMLPage:
    """Test per-category HTML page output."""

    def setup_method(self):
        entries = _make_entries(["win_proc_create.yml"])
        self.html = render_html_page(entries, product="windows", category="process_creation")

    def test_is_valid_html_shell(self):
        assert "<!DOCTYPE html>" in self.html
        assert "<html" in self.html
        assert "</html>" in self.html

    def test_has_dark_background(self):
        assert "#0d1117" in self.html

    def test_has_highlightjs(self):
        assert "highlight.js" in self.html or "highlightjs" in self.html.lower()

    def test_has_rule_title(self):
        assert "Suspicious PowerShell" in self.html

    def test_has_github_link(self):
        assert "View on GitHub" in self.html
        assert "blob/main" in self.html

    def test_has_sql_content(self):
        assert "SELECT" in self.html

    def test_has_level_indicator(self):
        assert "high" in self.html.lower()


class TestRenderIndexHTML:
    """Test index.html generation."""

    def setup_method(self):
        entries = _make_entries(["win_proc_create.yml", "linux_proc.yml"])
        categories = [
            ("windows", "process_creation", "sigma-windows-process-creation.html"),
            ("linux", "process_creation", "sigma-linux-process-creation.html"),
        ]
        self.html = render_index_html(entries, categories)

    def test_is_valid_html(self):
        assert "<!DOCTYPE html>" in self.html

    def test_has_dark_background(self):
        assert "#0d1117" in self.html

    def test_has_stats_bar(self):
        assert "total" in self.html.lower() or "converted" in self.html.lower()

    def test_has_search_input(self):
        assert "<input" in self.html
        assert "search" in self.html.lower()

    def test_has_category_links(self):
        assert "sigma-windows-process-creation.html" in self.html
        assert "sigma-linux-process-creation.html" in self.html

    def test_has_filter_pills(self):
        assert "high" in self.html or "medium" in self.html

    def test_has_client_side_search_js(self):
        assert "<script>" in self.html
        assert "search" in self.html.lower()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_renderer.py -v 2>&1 | head -30
```

Expected: `ImportError` — `renderer` does not exist yet.

- [ ] **Step 3: Implement `renderer.py`**

Create `sigma_queries/scripts/converter/renderer.py`:

```python
"""
renderer.py — Three independent output writers.

Writer A: render_json()        → sigma_queries.json document (dict, caller writes to disk)
Writer B: render_markdown()    → per-category markdown string
Writer C: render_html_page()   → per-category HTML string
          render_index_html()  → index.html string
"""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Optional

from converter.rule_parser import SigmaRule

# ---------------------------------------------------------------------------
# Dark theme colours
# ---------------------------------------------------------------------------

_BG = "#0d1117"
_SURFACE = "#161b22"
_ACCENT = "#58a6ff"
_BORDER = "#30363d"
_TEXT = "#e6edf3"
_TEXT_MUTED = "#8b949e"
_LEVEL_COLORS = {
    "low":      "#3fb950",
    "medium":   "#d29922",
    "high":     "#f0883e",
    "critical": "#f85149",
}

# ---------------------------------------------------------------------------
# Writer A — JSON
# ---------------------------------------------------------------------------

def render_json(
    entries: list[tuple[SigmaRule, str]],
    sigma_repo_path: str,
    output_path: Optional[Path],
) -> dict[str, Any]:
    """Build the sigma_queries.json document (as a dict; caller writes to disk)."""
    today = str(date.today())
    unmapped_ls_count = sum(1 for rule, _ in entries if rule.unmapped_logsource)
    unmapped_field_count = sum(1 for rule, _ in entries if rule.unmapped_fields)

    serialised_entries = []
    for rule, sql in entries:
        serialised_entries.append({
            "sigma_id":             rule.id,
            "name":                 rule.title,
            "description":          rule.description,
            "status":               rule.status,
            "level":                rule.level,
            "fsm_severity":         rule.fsm_severity,
            "mitre_tactics":        rule.mitre_tactics,
            "mitre_techniques":     rule.mitre_techniques,
            "logsource":            f"{rule.logsource_product}/{rule.logsource_category or rule.logsource_service}",
            "fsm_event_types":      rule.fsm_event_types,
            "unmapped_fields":      rule.unmapped_fields,
            "unmapped_logsource":   rule.unmapped_logsource,
            "github_url":           rule.github_url,
            "references":           rule.references,
            "author":               rule.author,
            "date":                 rule.date,
            "sql":                  sql,
        })

    doc = {
        "generated":               today,
        "sigma_repo_path":         sigma_repo_path,
        "total_rules_found":       len(entries),
        "total_converted":         len(entries),
        "unmapped_logsource_count":unmapped_ls_count,
        "unmapped_field_count":    unmapped_field_count,
        "entries":                 serialised_entries,
    }

    if output_path:
        output_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    return doc


# ---------------------------------------------------------------------------
# Writer B — Markdown
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    """Generate a GitHub-style heading anchor slug."""
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text.strip("-")


def render_markdown(
    entries: list[tuple[SigmaRule, str]],
    product: str,
    category: str,
) -> str:
    """Generate per-category markdown document."""
    category_title = f"{product.title()} {category.replace('_', ' ').title()}"
    today = str(date.today())
    rule_count = len(entries)
    plural = "rule" if rule_count == 1 else "rules"

    lines: list[str] = [
        f"# Sigma → FortiSIEM: {category_title}",
        f"> {rule_count} {plural} · Generated {today}",
        "",
        "## Table of Contents",
    ]

    # TOC
    for rule, _ in entries:
        slug = _slug(rule.title)
        technique_tags = " ".join(f"`{t}`" for t in rule.mitre_techniques[:2])
        lines.append(f"- [{rule.title}](#{slug}) `{rule.level}` {technique_tags}".strip())

    lines.append("")
    lines.append("---")
    lines.append("")

    # Rule entries
    for rule, sql in entries:
        mitre_str = (
            " · ".join(rule.mitre_tactics) +
            (" · " + " · ".join(rule.mitre_techniques) if rule.mitre_techniques else "")
        ) or "(none)"
        refs_str = " ".join(f"[{i+1}]({r})" for i, r in enumerate(rule.references)) or "(none)"
        fp_str = "; ".join(rule.falsepositives) or "(none)"

        lines.extend([
            f"## {rule.title}",
            f"**Sigma ID:** `{rule.id}` | **Level:** `{rule.level}` | **FSM Severity:** {rule.fsm_severity}",
            f"**MITRE:** {mitre_str}",
            f"**Author:** {rule.author} | **Status:** {rule.status}",
            f"**[View on GitHub ↗]({rule.github_url})**",
            "",
            f"> {rule.description}",
            "",
            "```sql",
            sql,
            "```",
            "",
            f"**False Positives:** {fp_str}",
            f"**References:** {refs_str}",
            "",
            "---",
            "",
        ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Writer C — HTML (shared template helpers)
# ---------------------------------------------------------------------------

_CSS = f"""
:root {{
  --bg: {_BG};
  --surface: {_SURFACE};
  --accent: {_ACCENT};
  --border: {_BORDER};
  --text: {_TEXT};
  --muted: {_TEXT_MUTED};
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px; }}
header {{
  border-bottom: 1px solid var(--border);
  padding: 16px 0 20px;
  margin-bottom: 28px;
}}
header h1 {{ font-size: 22px; font-weight: 600; color: var(--text); }}
header p {{ color: var(--muted); margin-top: 4px; font-size: 13px; }}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}
.badge-low      {{ background: #1a3a22; color: #3fb950; }}
.badge-medium   {{ background: #2d2208; color: #d29922; }}
.badge-high     {{ background: #2d1b0e; color: #f0883e; }}
.badge-critical {{ background: #2d0f0e; color: #f85149; }}
.rule-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 24px;
}}
.rule-card h2 {{
  font-size: 17px;
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--text);
}}
.rule-meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
  font-size: 12px;
  color: var(--muted);
}}
.rule-desc {{
  color: var(--muted);
  font-size: 13px;
  margin-bottom: 14px;
  font-style: italic;
}}
.rule-github {{ font-size: 12px; margin-bottom: 12px; }}
.sql-block {{ border-radius: 6px; overflow: auto; max-height: 400px; font-size: 12px; }}
.sql-block pre {{ margin: 0; }}
.fp-line {{ font-size: 12px; color: var(--muted); margin-top: 10px; }}
code.hljs {{ border-radius: 6px; }}
"""

_HIGHLIGHTJS_CDN = """
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>
<script>document.addEventListener('DOMContentLoaded', () => hljs.highlightAll());</script>
"""


def _html_escape(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _level_badge(level: str) -> str:
    cls = f"badge badge-{level.lower()}"
    return f'<span class="{cls}">{_html_escape(level)}</span>'


def _rule_card_html(rule: SigmaRule, sql: str) -> str:
    mitre_str = _html_escape(
        (", ".join(rule.mitre_tactics) +
         (" | " + ", ".join(rule.mitre_techniques) if rule.mitre_techniques else ""))
        or "(none)"
    )
    fp_str = _html_escape("; ".join(rule.falsepositives) or "(none)")
    refs_html = " ".join(
        f'<a href="{_html_escape(r)}" target="_blank">[{i+1}]</a>'
        for i, r in enumerate(rule.references)
    ) or "(none)"

    return f"""
<div class="rule-card" data-level="{_html_escape(rule.level)}" data-title="{_html_escape(rule.title.lower())}">
  <h2>{_html_escape(rule.title)} {_level_badge(rule.level)}</h2>
  <div class="rule-meta">
    <span>Sigma ID: <code>{_html_escape(rule.id)}</code></span>
    <span>FSM Severity: <strong>{rule.fsm_severity}</strong></span>
    <span>MITRE: {mitre_str}</span>
    <span>Author: {_html_escape(rule.author)}</span>
    <span>Status: {_html_escape(rule.status)}</span>
  </div>
  <p class="rule-desc">{_html_escape(rule.description)}</p>
  <p class="rule-github"><a href="{_html_escape(rule.github_url)}" target="_blank">View on GitHub ↗</a></p>
  <div class="sql-block"><pre><code class="language-sql">{_html_escape(sql)}</code></pre></div>
  <p class="fp-line"><strong>False Positives:</strong> {fp_str}</p>
  <p class="fp-line"><strong>References:</strong> {refs_html}</p>
</div>"""


def _html_page_template(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_html_escape(title)}</title>
  {_HIGHLIGHTJS_CDN}
  <style>{_CSS}</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>"""


def render_html_page(
    entries: list[tuple[SigmaRule, str]],
    product: str,
    category: str,
) -> str:
    """Generate per-category HTML page."""
    category_title = f"{product.title()} {category.replace('_', ' ').title()}"
    today = str(date.today())
    rule_count = len(entries)
    plural = "rule" if rule_count == 1 else "rules"

    header = f"""<header>
  <h1>Sigma → FortiSIEM: {_html_escape(category_title)}</h1>
  <p>{rule_count} {plural} · Generated {today} · <a href="../index.html">← Back to Index</a></p>
</header>"""

    cards = "\n".join(_rule_card_html(rule, sql) for rule, sql in entries)
    body = header + "\n" + cards
    return _html_page_template(f"Sigma → FSM: {category_title}", body)


# ---------------------------------------------------------------------------
# Writer C — index.html
# ---------------------------------------------------------------------------

_INDEX_SEARCH_JS = """
<script>
(function() {
  const input = document.getElementById('search');
  const levelFilter = document.getElementById('level-filter');
  const cards = Array.from(document.querySelectorAll('.rule-card'));

  function filter() {
    const q = input.value.toLowerCase().trim();
    const lvl = levelFilter.value.toLowerCase();
    cards.forEach(card => {
      const titleMatch = !q || card.dataset.title.includes(q);
      const levelMatch = !lvl || card.dataset.level === lvl;
      card.style.display = (titleMatch && levelMatch) ? '' : 'none';
    });
  }

  input.addEventListener('input', filter);
  levelFilter.addEventListener('change', filter);
})();
</script>
"""

_INDEX_EXTRA_CSS = """
.stats-bar {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 24px;
}
.stat-item { text-align: center; }
.stat-num { font-size: 28px; font-weight: 700; color: var(--accent); display: block; }
.stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.filter-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
  align-items: center;
}
.filter-bar input, .filter-bar select {
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
}
.filter-bar input { flex: 1; min-width: 200px; }
.category-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}
.category-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  transition: border-color 0.15s;
}
.category-card:hover { border-color: var(--accent); }
.category-card h3 { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.category-card p { font-size: 12px; color: var(--muted); }
"""


def render_index_html(
    all_entries: list[tuple[SigmaRule, str]],
    categories: list[tuple[str, str, str]],
) -> str:
    """
    Generate index.html.

    categories: list of (product, category, html_filename) tuples
    """
    today = str(date.today())
    total = len(all_entries)
    unmapped_ls = sum(1 for r, _ in all_entries if r.unmapped_logsource)
    unmapped_fields = sum(1 for r, _ in all_entries if r.unmapped_fields)
    platforms = len({r.logsource_product for r, _ in all_entries})

    # Stats bar
    stats_bar = f"""<div class="stats-bar">
  <div class="stat-item"><span class="stat-num">{total}</span><span class="stat-label">Total Rules</span></div>
  <div class="stat-item"><span class="stat-num">{total - unmapped_ls}</span><span class="stat-label">Converted</span></div>
  <div class="stat-item"><span class="stat-num">{unmapped_ls}</span><span class="stat-label">Unmapped Logsource</span></div>
  <div class="stat-item"><span class="stat-num">{unmapped_fields}</span><span class="stat-label">Rules w/ Unmapped Fields</span></div>
  <div class="stat-item"><span class="stat-num">{platforms}</span><span class="stat-label">Platforms</span></div>
</div>"""

    # Filter bar
    filter_bar = """<div class="filter-bar">
  <input type="text" id="search" placeholder="Search rules by title or description...">
  <select id="level-filter">
    <option value="">All Levels</option>
    <option value="low">Low</option>
    <option value="medium">Medium</option>
    <option value="high">High</option>
    <option value="critical">Critical</option>
  </select>
</div>"""

    # Category grid
    cat_cards = ""
    cat_counts: dict[tuple[str, str], int] = {}
    for rule, _ in all_entries:
        key = (rule.logsource_product, rule.logsource_category or rule.logsource_service)
        cat_counts[key] = cat_counts.get(key, 0) + 1

    for product, category, html_file in categories:
        count = cat_counts.get((product, category), 0)
        cat_title = f"{product.title()} / {category.replace('_', ' ').title()}"
        cat_cards += f"""<a href="html/{html_file}" class="category-card">
  <h3>{_html_escape(cat_title)}</h3>
  <p>{count} rules</p>
</a>\n"""

    category_section = f'<h2 style="font-size:16px;margin-bottom:16px;color:var(--muted)">Categories ({len(categories)})</h2>\n<div class="category-grid">\n{cat_cards}</div>'

    # All rule cards (for search filtering)
    all_cards = "\n".join(_rule_card_html(rule, sql) for rule, sql in all_entries[:200])
    # NOTE: limit to first 200 in index for page performance; full data in JSON

    header = f"""<header>
  <h1>Sigma → FortiSIEM SQL Queries</h1>
  <p>Generated {today} · FortiSIEM ClickHouse Advanced Search</p>
</header>"""

    body = (header + "\n" + stats_bar + "\n" +
            category_section + "\n" +
            filter_bar + "\n" +
            '<div id="cards">' + all_cards + "</div>\n" +
            _INDEX_SEARCH_JS)

    extra_style = f"<style>{_INDEX_EXTRA_CSS}</style>"
    full_css = f"<style>{_CSS}</style>\n{extra_style}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sigma → FortiSIEM SQL Queries</title>
  {_HIGHLIGHTJS_CDN}
  {full_css}
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>"""
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_renderer.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git add sigma_queries/scripts/converter/renderer.py sigma_queries/tests/test_renderer.py
git commit -m "feat: implement renderer with JSON/markdown/HTML writers and dark theme"
```

---

## Chunk 5: CLI + Integration

### Task 6: `sigma_to_fortisiem.py` — CLI Entry Point

**Files:**
- Create: `sigma_queries/scripts/sigma_to_fortisiem.py`
- Create: `sigma_queries/tests/test_integration.py`

- [ ] **Step 1: Write failing integration test**

Create `sigma_queries/tests/test_integration.py`:

```python
"""Integration tests: run sigma_to_fortisiem.py against fixture dir, verify all outputs."""
import sys, os, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).parent.parent / "scripts" / "sigma_to_fortisiem.py"
REPO_ROOT = Path(__file__).parent.parent.parent.parent


class TestCLIEndToEnd:
    """Run the CLI against the fixtures directory and verify output artifacts."""

    @pytest.fixture(autouse=True)
    def run_cli(self, tmp_path):
        """Run the converter CLI against fixtures dir, outputting to tmp_path."""
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--sigma-dir", str(FIXTURES),
                "--output-dir", str(tmp_path),
            ],
            capture_output=True,
            text=True,
        )
        self.output_dir = tmp_path
        self.stdout = result.stdout
        self.stderr = result.stderr
        self.returncode = result.returncode

    def test_exits_zero(self):
        assert self.returncode == 0, f"CLI failed:\n{self.stderr}"

    def test_json_file_created(self):
        assert (self.output_dir / "sigma_queries.json").exists()

    def test_json_is_valid(self):
        data = json.loads((self.output_dir / "sigma_queries.json").read_text())
        assert "entries" in data
        assert len(data["entries"]) > 0

    def test_json_no_detection_selections(self):
        data = json.loads((self.output_dir / "sigma_queries.json").read_text())
        for entry in data["entries"]:
            assert "detection_selections" not in entry
            assert "condition_resolved" not in entry

    def test_md_files_created(self):
        md_dir = self.output_dir / "md"
        assert md_dir.exists()
        md_files = list(md_dir.glob("*.md"))
        assert len(md_files) > 0

    def test_md_filenames_follow_convention(self):
        md_dir = self.output_dir / "md"
        for f in md_dir.glob("*.md"):
            assert f.name.startswith("sigma-"), f"Unexpected filename: {f.name}"

    def test_html_files_created(self):
        html_dir = self.output_dir / "html"
        assert html_dir.exists()
        html_files = list(html_dir.glob("*.html"))
        assert len(html_files) > 0

    def test_index_html_created(self):
        assert (self.output_dir / "index.html").exists()

    def test_index_html_has_dark_theme(self):
        content = (self.output_dir / "index.html").read_text()
        assert "#0d1117" in content

    def test_stdout_summary_has_converted_count(self):
        assert "Converted" in self.stdout or "converted" in self.stdout

    def test_stdout_summary_has_output_path(self):
        assert str(self.output_dir) in self.stdout


class TestCLIFilters:
    """Test --level, --product, --category, --id filters."""

    def test_level_filter_high_only(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--sigma-dir", str(FIXTURES),
                "--output-dir", str(tmp_path),
                "--level", "high",
                "--json-only",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "sigma_queries.json").read_text())
        for entry in data["entries"]:
            assert entry["level"] == "high"

    def test_product_filter_windows_only(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--sigma-dir", str(FIXTURES),
                "--output-dir", str(tmp_path),
                "--product", "windows",
                "--json-only",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "sigma_queries.json").read_text())
        for entry in data["entries"]:
            assert entry["logsource"].startswith("windows/")

    def test_id_filter_single_rule(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--sigma-dir", str(FIXTURES),
                "--output-dir", str(tmp_path),
                "--id", "a2b0b9e0-1234-4567-89ab-cdef01234567",
                "--json-only",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "sigma_queries.json").read_text())
        assert len(data["entries"]) == 1
        assert data["entries"][0]["sigma_id"] == "a2b0b9e0-1234-4567-89ab-cdef01234567"

    def test_json_only_skips_html_and_md(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--sigma-dir", str(FIXTURES),
                "--output-dir", str(tmp_path),
                "--json-only",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert not (tmp_path / "index.html").exists()
        assert not (tmp_path / "md").exists()
        assert not (tmp_path / "html").exists()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_integration.py -v 2>&1 | head -30
```

Expected: FileNotFoundError or subprocess error — script does not exist yet.

- [ ] **Step 3: Implement `sigma_to_fortisiem.py`**

Create `sigma_queries/scripts/sigma_to_fortisiem.py`:

```python
#!/usr/bin/env python3
"""
sigma_to_fortisiem.py — Convert Sigma rules to FortiSIEM ClickHouse SQL queries.

Usage:
  python3 sigma_to_fortisiem.py [options]

Options:
  --sigma-dir DIR      Path to cloned sigma repo (default: ../../../sigma relative to this script)
  --output-dir DIR     Output directory (default: ../../../sigma_queries relative to this script)
  --category CAT       Filter by logsource.category (case-insensitive)
  --product PROD       Filter by logsource.product (case-insensitive)
  --level LEVELS       Comma-separated severity levels: low,medium,high,critical
  --id UUID            Single rule ID (UUID)
  --json-only          Skip markdown and HTML, write sigma_queries.json only
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# Ensure converter package is importable when called from any CWD
_THIS_DIR = Path(__file__).parent
sys.path.insert(0, str(_THIS_DIR))

from converter.rule_parser import parse_rule
from converter.sql_builder import build_sql
from converter import renderer as _renderer


def _default_sigma_dir() -> Path:
    return _THIS_DIR.parent.parent.parent / "sigma"


def _default_output_dir() -> Path:
    return _THIS_DIR.parent.parent.parent / "sigma_queries"


def _collect_yaml_files(sigma_dir: Path) -> list[Path]:
    """Recursively collect all .yml files under sigma_dir/rules."""
    rules_dir = sigma_dir / "rules"
    if rules_dir.exists():
        return sorted(rules_dir.rglob("*.yml"))
    # Fallback: search from sigma_dir directly (e.g. for test fixtures dir)
    return sorted(sigma_dir.rglob("*.yml"))


def _parse_args(argv=None):
    p = argparse.ArgumentParser(description="Convert Sigma rules to FortiSIEM ClickHouse SQL")
    p.add_argument("--sigma-dir", type=Path, default=None)
    p.add_argument("--output-dir", type=Path, default=None)
    p.add_argument("--category", default=None)
    p.add_argument("--product", default=None)
    p.add_argument("--level", default=None)
    p.add_argument("--id", dest="rule_id", default=None)
    p.add_argument("--json-only", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)

    sigma_dir = args.sigma_dir or _default_sigma_dir()
    output_dir = args.output_dir or _default_output_dir()

    if not sigma_dir.exists():
        print(f"ERROR: sigma-dir does not exist: {sigma_dir}", file=sys.stderr)
        sys.exit(1)

    # Ensure output dirs exist
    output_dir.mkdir(parents=True, exist_ok=True)
    if not args.json_only:
        (output_dir / "md").mkdir(exist_ok=True)
        (output_dir / "html").mkdir(exist_ok=True)

    # Parse level filter
    level_filter: set[str] | None = None
    if args.level:
        level_filter = {l.strip().lower() for l in args.level.split(",")}

    yaml_files = _collect_yaml_files(sigma_dir)

    # --- Pass 1: Parse all rules ---
    total_found = 0
    skipped_errors = 0
    all_entries: list[tuple] = []   # (rule, sql)

    for yml_path in yaml_files:
        total_found += 1
        try:
            rule = parse_rule(yml_path, sigma_repo_root=sigma_dir)
        except FileNotFoundError:
            skipped_errors += 1
            continue
        except Exception as e:
            print(f"WARN: {yml_path}: {e}", file=sys.stderr)
            skipped_errors += 1
            continue

        if rule is None:
            print(f"WARN: {yml_path}: empty detection", file=sys.stderr)
            skipped_errors += 1
            continue

        # Apply filters
        if args.rule_id and rule.id != args.rule_id:
            continue
        if args.product and rule.logsource_product.lower() != args.product.lower():
            continue
        if args.category and rule.logsource_category.lower() != args.category.lower():
            continue
        if level_filter and rule.level.lower() not in level_filter:
            continue

        try:
            sql = build_sql(rule)
        except Exception as e:
            print(f"WARN: {yml_path}: sql_builder error: {e}", file=sys.stderr)
            skipped_errors += 1
            continue

        all_entries.append((rule, sql))

    # --- Write JSON ---
    json_path = output_dir / "sigma_queries.json"
    json_doc = _renderer.render_json(
        all_entries,
        sigma_repo_path=str(sigma_dir),
        output_path=json_path,
    )
    # Patch total_rules_found to actual count before filters
    json_doc["total_rules_found"] = total_found
    json_path.write_text(json.dumps(json_doc, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json_only:
        _print_summary(all_entries, skipped_errors, total_found, output_dir)
        return

    # --- Group by (product, category) for per-file rendering ---
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for rule, sql in all_entries:
        key = (
            rule.logsource_product.lower(),
            (rule.logsource_category or rule.logsource_service).lower(),
        )
        groups[key].append((rule, sql))

    # --- Write markdown + HTML per category ---
    categories_meta: list[tuple[str, str, str]] = []

    for (product, category), entries in sorted(groups.items()):
        slug = f"sigma-{product}-{category}".replace("_", "-").replace(" ", "-")
        md_path = output_dir / "md" / f"{slug}.md"
        html_path = output_dir / "html" / f"{slug}.html"

        md_path.write_text(
            _renderer.render_markdown(entries, product=product, category=category),
            encoding="utf-8",
        )
        html_path.write_text(
            _renderer.render_html_page(entries, product=product, category=category),
            encoding="utf-8",
        )
        categories_meta.append((product, category, f"{slug}.html"))

    # --- Write index.html ---
    index_path = output_dir / "index.html"
    index_path.write_text(
        _renderer.render_index_html(all_entries, categories_meta),
        encoding="utf-8",
    )

    _print_summary(all_entries, skipped_errors, total_found, output_dir)


def _print_summary(
    all_entries: list,
    skipped: int,
    total_found: int,
    output_dir: Path,
):
    converted = len(all_entries)
    unmapped_ls = sum(1 for r, _ in all_entries if r.unmapped_logsource)
    unmapped_fields = sum(1 for r, _ in all_entries if r.unmapped_fields)

    print(f"\nConverted:                  {converted} / {total_found} rules")
    print(f"Skipped (errors):           {skipped} rules")
    print(f"Unmapped logsource:         {unmapped_ls} rules (rawEventMsg fallback used)")
    print(f"Rules with unmapped fields: {unmapped_fields} rules")
    print(f"Output: {output_dir}/")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run integration tests to verify they pass**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/test_integration.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 -m pytest sigma_queries/tests/ -v
```

Expected: All tests pass across all 5 test files.

- [ ] **Step 6: Commit**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
git add sigma_queries/scripts/sigma_to_fortisiem.py sigma_queries/tests/test_integration.py
git commit -m "feat: implement CLI entry point with filtering, summary, and integration tests"
```

---

### Task 7: Smoke Test Against Real Sigma Repo

- [ ] **Step 1: Verify sigma/ repo exists**

```bash
ls /Users/apple/FortiSIEM_Advanced_Search_SQL/sigma/rules/ | head -10
```

Expected: Directories like `windows`, `linux`, `cloud`, etc.

- [ ] **Step 2: Run converter against real sigma repo (windows only to test at scale)**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 sigma_queries/scripts/sigma_to_fortisiem.py \
    --product windows \
    --level high,critical \
    --output-dir /tmp/sigma_test_out
```

Expected: Output summary like:
```
Converted:                  NNN / NNN rules
Skipped (errors):           NN rules
Unmapped logsource:         NN rules (rawEventMsg fallback used)
Rules with unmapped fields: NN rules
Output: /tmp/sigma_test_out/
```

- [ ] **Step 3: Spot-check output files**

```bash
ls /tmp/sigma_test_out/
ls /tmp/sigma_test_out/md/ | head -10
ls /tmp/sigma_test_out/html/ | head -10
python3 -c "import json; d=json.load(open('/tmp/sigma_test_out/sigma_queries.json')); print(f'Entries: {len(d[\"entries\"])}')"
```

Expected: `index.html`, `sigma_queries.json`, several `.md` and `.html` files.

- [ ] **Step 4: Run full conversion (all rules)**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
python3 sigma_queries/scripts/sigma_to_fortisiem.py
```

Expected: Runs without crashing, final summary printed, outputs written to `sigma_queries/`.

- [ ] **Step 5: Commit final outputs note**

```bash
cd /Users/apple/FortiSIEM_Advanced_Search_SQL
# Add sigma_queries/ to .gitignore if generated outputs are large, OR commit the scripts only
git add sigma_queries/
git status
git commit -m "feat: complete sigma→FortiSIEM SQL converter pipeline"
```

---

## Summary

| Chunk | Tasks | Outcome |
|---|---|---|
| 1 — Foundation | Scaffold + `field_map.py` | All 38 field mappings + 14 modifiers tested |
| 2 — Rule Parser | `rule_parser.py` | YAML→dataclass with wildcard expansion |
| 3 — SQL Builder | `sql_builder.py` | ClickHouse SQL with comment block, tier guards |
| 4 — Renderer | `renderer.py` | JSON/MD/HTML all independently tested |
| 5 — CLI + Integration | `sigma_to_fortisiem.py` | End-to-end CLI with filters + smoke test |

**Dependencies required:**
```bash
pip install pyyaml
```
