"""rule_parser.py — YAML → SigmaRule dataclass.

Public API:
    parse_rule(path, sigma_repo_root=None) -> Optional[SigmaRule]
    SigmaRule  — dataclass containing all extracted fields
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, int] = {
    "low": 3,
    "medium": 5,
    "high": 7,
    "critical": 9,
}

# ---------------------------------------------------------------------------
# MITRE tactic names (used to distinguish tactics from techniques in tags)
# ---------------------------------------------------------------------------

_MITRE_TACTICS = {
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
    "reconnaissance",
    "resource_development",
}

# ---------------------------------------------------------------------------
# Logsource → FSM event type mapping
# Key: (product, category_or_service)
# ---------------------------------------------------------------------------

_LOGSOURCE_MAP: dict[tuple[str, str], list[str]] = {
    # Windows category-based
    ("windows", "process_creation"):           ["Win-Sysmon-1-Create-Process", "Win-Security-4688"],
    ("windows", "network_connection"):         ["Win-Sysmon-3-Network-Connect-IPv4"],
    ("windows", "ps_script"):                  ["Win-PowerShell-4104"],
    ("windows", "ps_classic_provider_start"):  ["Win-PowerShell-400"],
    ("windows", "ps_module"):                  ["Win-PowerShell-4103"],
    ("windows", "registry_add"):               ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "registry_set"):               ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "registry_delete"):            ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "registry_event"):             ["Win-Sysmon-12-Reg-Create-Delete", "Win-Sysmon-13-Reg-Value-Set"],
    ("windows", "file_event"):                 ["Win-Sysmon-11-File-Create"],
    ("windows", "file_delete"):                ["Win-Sysmon-23-File-Delete"],
    ("windows", "file_rename"):                ["Win-Sysmon-11-File-Create"],
    ("windows", "dns_query"):                  ["Win-Sysmon-22-DNS-Query"],
    ("windows", "image_load"):                 ["Win-Sysmon-7-Image-Load"],
    ("windows", "driver_load"):                ["Win-Sysmon-6-Driver-Load"],
    ("windows", "pipe_created"):               ["Win-Sysmon-17-Pipe-Created"],
    ("windows", "create_remote_thread"):       ["Win-Sysmon-8-Create-Remote-Thread"],
    ("windows", "wmi_event"):                  ["Win-Sysmon-19-WMI-Event-Filter"],
    ("windows", "process_access"):             ["Win-Sysmon-10-Process-Access"],
    ("windows", "create_stream_hash"):         ["Win-Sysmon-15-FileCreateStreamHash"],
    # Windows service-based
    ("windows", "security"):                   ["Win-Security-*"],
    ("windows", "system"):                     ["Win-System-*"],
    ("windows", "application"):                ["Win-Application-*"],
    ("windows", "sysmon"):                     ["Win-Sysmon-*"],
    ("windows", "taskscheduler"):              ["Win-TaskScheduler-*"],
    ("windows", "powershell"):                 ["Win-PowerShell-*"],
    # Linux
    ("linux", "process_creation"):             ["LINUX_PROCESS_EXEC"],
    ("linux", "file_event"):                   ["LINUX_FILE_CREATE"],
    ("linux", "network_connection"):           ["LINUX_NET_CONN"],
    ("linux", "syslog"):                       ["Generic_Syslog"],
    ("linux", "auditd"):                       ["Linux-Audit-*"],
    # macOS
    ("macos", "process_creation"):             ["macOS-Exec-*"],
    # Cloud
    ("aws", "cloudtrail"):                     ["AWS-CloudTrail-*"],
    ("azure", "activitylogs"):                 ["Azure-Activity-*"],
    ("gcp", "gcp.audit"):                      ["GCP-AuditLog-*"],
    ("m365", "any"):                           ["O365-*"],
}

# ---------------------------------------------------------------------------
# SigmaRule dataclass
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    author: str
    date: str
    status: str
    level: str
    fsm_severity: int
    tags: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    logsource_product: str
    logsource_category: str
    logsource_service: str
    fsm_event_types: list[str]
    detection_selections: dict[str, list[dict[str, Any]]]
    condition: str
    condition_resolved: list[list[tuple[str, bool]]]
    falsepositives: list[str]
    references: list[str]
    sigma_file_path: str
    github_url: str
    unmapped_fields: list[str] = field(default_factory=list)
    unmapped_logsource: bool = False


# ---------------------------------------------------------------------------
# Detection normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_value(v: Any) -> list:
    """Wrap a scalar or existing list into a list."""
    if isinstance(v, list):
        return v
    return [v]


def _normalise_selection(raw: Any) -> list[dict[str, Any]]:
    """Convert a raw YAML detection selection value into the contract form.

    Contract: list[dict[str, list]]  — OR-list of AND-maps, all values lists.

    Cases:
      dict  → single AND-map: [normalised_dict]
      list of dicts → each dict is one OR alternative (list of AND-maps)
      list of scalars → bare keyword list: [{"_keyword": [items]}]
      scalar → bare keyword: [{"_keyword": [scalar]}]
    """
    if isinstance(raw, dict):
        # Single AND-map: normalise all values to lists
        norm = {k: _normalise_value(v) for k, v in raw.items()}
        return [norm]

    if isinstance(raw, list):
        if not raw:
            return []
        # Check if any item is a dict (OR-list of AND-maps) vs all scalars (keywords)
        has_dict = any(isinstance(item, dict) for item in raw)
        if has_dict:
            # Mixed or all-dicts: treat each item as an OR alternative.
            # Scalars in a mixed list become {"_keyword": [scalar]}.
            result = []
            for item in raw:
                if isinstance(item, dict):
                    result.append({k: _normalise_value(v) for k, v in item.items()})
                else:
                    result.append({"_keyword": [item]})
            return result
        # All scalars → keyword list
        return [{"_keyword": raw}]

    # Scalar
    return [{"_keyword": [raw]}]


def _parse_detection_selections(detection: dict) -> dict[str, list[dict[str, Any]]]:
    """Extract all named selections from the detection block.

    Skips 'condition' and 'timeframe' keys.
    """
    result: dict[str, list[dict[str, Any]]] = {}
    skip = {"condition", "timeframe"}
    for key, val in detection.items():
        if key in skip:
            continue
        result[key] = _normalise_selection(val)
    return result


# ---------------------------------------------------------------------------
# Condition parsing
# ---------------------------------------------------------------------------

def _expand_wildcard(pattern: str, known_names: set[str]) -> list[str]:
    """Expand a glob pattern (e.g. 'selection_*') against known selection names."""
    return [n for n in sorted(known_names) if fnmatch.fnmatch(n, pattern)]


def _parse_condition(condition_str: str, known_names: set[str]) -> list[list[tuple[str, bool]]]:
    """Parse a Sigma condition string into condition_resolved.

    Returns list[list[tuple[str, bool]]]:
      Outer list = OR groups
      Inner list = AND terms
      Each term = (selection_name, is_negated)

    Handles:
      "selection"                            → [[("selection", False)]]
      "selection_main and not filter_legit"  → [[("selection_main", False), ("filter_legit", True)]]
      "1 of selection_*"                     → [[("selection_foo", False)], [("selection_bar", False)]] etc.
      "all of selection_*"                   → [[("selection_foo", False), ("selection_bar", False)]]
      "A or B"                               → [[("A", False)], [("B", False)]]
    """
    condition_str = condition_str.strip()

    # Split on top-level OR first (handles "A or B")
    or_parts = _split_on_or(condition_str)

    or_groups: list[list[tuple[str, bool]]] = []
    for or_part in or_parts:
        and_terms = _parse_and_clause(or_part.strip(), known_names)
        or_groups.extend(and_terms)

    return or_groups


def _split_on_or(s: str) -> list[str]:
    """Split condition string on ' or ' keyword (case-insensitive), respecting grouping.

    Uses whitespace-bounded split to avoid matching 'or' embedded in selection names
    such as 'filter_or_exclusion'.
    """
    parts = re.split(r'\s+or\s+', s, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]


def _parse_and_clause(clause: str, known_names: set[str]) -> list[list[tuple[str, bool]]]:
    """Parse an AND clause, handling '1 of X*', 'all of X*', and 'not X'.

    Returns list of OR groups (a single AND clause typically returns one group,
    but '1 of X*' expands to multiple OR groups — one per matched name).
    """
    # Handle "1 of <pattern>"
    m_one = re.match(r'^1\s+of\s+(\S+)$', clause, re.IGNORECASE)
    if m_one:
        pattern = m_one.group(1)
        if pattern.lower() == "them":
            matched = sorted(known_names)
        else:
            matched = _expand_wildcard(pattern, known_names)
        # Each matched name becomes its own OR group
        return [[(name, False)] for name in matched]

    # Handle "all of <pattern>"
    m_all = re.match(r'^all\s+of\s+(\S+)$', clause, re.IGNORECASE)
    if m_all:
        pattern = m_all.group(1)
        if pattern.lower() == "them":
            matched = sorted(known_names)
        else:
            matched = _expand_wildcard(pattern, known_names)
        # All names combined into a single AND group
        return [[(name, False) for name in matched]]

    # Handle AND terms — use whitespace-bounded split to avoid matching 'and'
    # embedded inside selection names like 'filter_and_exclusion'.
    and_parts = re.split(r'\s+and\s+', clause, flags=re.IGNORECASE)
    and_group: list[tuple[str, bool]] = []
    for part in and_parts:
        part = part.strip()
        if not part:
            continue
        negated = False
        # Check for "not <name>"
        m_not = re.match(r'^not\s+(\S+)$', part, re.IGNORECASE)
        if m_not:
            negated = True
            name = m_not.group(1)
        else:
            name = part
        # Strip any surrounding parentheses (e.g. "(selection_main" or "selection_main)")
        name = name.strip("()")
        # If the name contains a wildcard, expand it
        if '*' in name or '?' in name:
            for expanded_name in _expand_wildcard(name, known_names):
                and_group.append((expanded_name, negated))
        else:
            and_group.append((name, negated))

    if and_group:
        return [and_group]
    return []


# ---------------------------------------------------------------------------
# Tag / MITRE parsing
# ---------------------------------------------------------------------------

def _parse_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Parse MITRE ATT&CK tags into (tactics, techniques).

    Tags like "attack.execution" → tactics
    Tags like "attack.t1059.001" → techniques (uppercased, dot→dot preserved)
    """
    tactics: list[str] = []
    techniques: list[str] = []

    for tag in tags:
        if not tag.startswith("attack."):
            continue
        rest = tag[len("attack."):]
        # Technique: starts with 't' followed by digits (e.g. t1059 or t1059.001)
        if re.match(r'^t\d', rest, re.IGNORECASE):
            # Uppercase the T-number: t1059.001 → T1059.001
            techniques.append(rest.upper())
        else:
            # Tactic name
            if rest in _MITRE_TACTICS:
                tactics.append(rest)

    return tactics, techniques


# ---------------------------------------------------------------------------
# Logsource → FSM event types
# ---------------------------------------------------------------------------

def _derive_fsm_event_types(
    product: str,
    category: str,
    service: str,
    detection_selections: dict[str, list[dict[str, Any]]],
) -> tuple[list[str], bool]:
    """Derive FSM event type list from logsource fields.

    Returns (event_types, unmapped_logsource).
    """
    product_l = product.lower()

    # Try (product, category) first
    if category:
        key = (product_l, category.lower())
        if key in _LOGSOURCE_MAP:
            return list(_LOGSOURCE_MAP[key]), False

    # Try (product, service) next
    if service:
        key = (product_l, service.lower())
        if key in _LOGSOURCE_MAP:
            event_types = list(_LOGSOURCE_MAP[key])
            # If service-based and EventID detected in selections: generate specific names
            event_ids = _extract_event_ids(detection_selections)
            if event_ids and any("*" in et for et in event_types):
                prefix = event_types[0].rstrip("*")
                # Deduplicate while preserving order
                seen: set[str] = set()
                specific: list[str] = []
                for eid in event_ids:
                    name = f"{prefix}{eid}"
                    if name not in seen:
                        seen.add(name)
                        specific.append(name)
                return specific, False
            return event_types, False

    return [], True


def _extract_event_ids(detection_selections: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Extract EventID values from detection selections (used for service-based mappings)."""
    ids: list[str] = []
    for maps in detection_selections.values():
        for m in maps:
            for k, v in m.items():
                field_name = k.split("|")[0]
                if field_name == "EventID":
                    ids.extend(str(x) for x in v)
    return ids


# ---------------------------------------------------------------------------
# Main parse_rule function
# ---------------------------------------------------------------------------

def parse_rule(
    path: Path,
    sigma_repo_root: Optional[Path] = None,
) -> Optional[SigmaRule]:
    """Parse a Sigma YAML rule file into a SigmaRule dataclass.

    Parameters
    ----------
    path            Path to the Sigma YAML rule file.
    sigma_repo_root Optional root path; if provided, sigma_file_path is made relative.

    Returns
    -------
    SigmaRule if successful, None if the detection block is empty or missing.

    Raises
    ------
    FileNotFoundError if path does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None

    # --- detection block ---
    detection_raw = data.get("detection")
    if not detection_raw or not isinstance(detection_raw, dict):
        return None

    # Extract condition before building selections
    condition_str = str(detection_raw.get("condition", "")).strip()
    if not condition_str:
        return None

    detection_selections = _parse_detection_selections(detection_raw)

    # If no actual selections exist (only condition/timeframe keys were present)
    if not detection_selections:
        return None

    # --- condition_resolved ---
    known_names = set(detection_selections.keys())
    condition_resolved = _parse_condition(condition_str, known_names)

    # --- basic fields ---
    rule_id = str(data.get("id", ""))
    title = str(data.get("title", ""))
    description = str(data.get("description", ""))
    author = str(data.get("author", ""))
    date = str(data.get("date", ""))
    status = str(data.get("status", ""))
    level = str(data.get("level", "")).lower()
    fsm_severity = _SEVERITY_MAP.get(level, 5)

    # --- tags + MITRE ---
    raw_tags = data.get("tags") or []
    tags = [str(t) for t in raw_tags]
    mitre_tactics, mitre_techniques = _parse_tags(tags)

    # --- logsource ---
    logsource = data.get("logsource") or {}
    logsource_product = str(logsource.get("product", ""))
    logsource_category = str(logsource.get("category", ""))
    logsource_service = str(logsource.get("service", ""))

    # --- FSM event types ---
    fsm_event_types, unmapped_logsource = _derive_fsm_event_types(
        logsource_product,
        logsource_category,
        logsource_service,
        detection_selections,
    )

    # --- falsepositives / references ---
    raw_fp = data.get("falsepositives") or []
    falsepositives = [str(x) for x in raw_fp] if isinstance(raw_fp, list) else [str(raw_fp)]

    raw_refs = data.get("references") or []
    references = [str(x) for x in raw_refs] if isinstance(raw_refs, list) else [str(raw_refs)]

    # --- file path + github URL ---
    if sigma_repo_root is not None:
        try:
            sigma_file_path = str(path.relative_to(sigma_repo_root))
        except ValueError:
            sigma_file_path = str(path)
    else:
        sigma_file_path = str(path)

    clean_path = sigma_file_path.replace(os.sep, "/").lstrip("/")
    github_url = f"https://github.com/SigmaHQ/sigma/blob/main/{clean_path}"

    return SigmaRule(
        id=rule_id,
        title=title,
        description=description,
        author=author,
        date=date,
        status=status,
        level=level,
        fsm_severity=fsm_severity,
        tags=tags,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        logsource_product=logsource_product,
        logsource_category=logsource_category,
        logsource_service=logsource_service,
        fsm_event_types=fsm_event_types,
        detection_selections=detection_selections,
        condition=condition_str,
        condition_resolved=condition_resolved,
        falsepositives=falsepositives,
        references=references,
        sigma_file_path=sigma_file_path,
        github_url=github_url,
        unmapped_logsource=unmapped_logsource,
    )
