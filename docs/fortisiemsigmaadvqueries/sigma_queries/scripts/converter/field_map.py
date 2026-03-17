"""field_map.py — Sigma field → FortiSIEM SQL expression mapping and modifier translation.

Tiers:
  "1" — direct EAT column (e.g. procName, user, winEventId)
  "2" — metrics_string array lookup (e.g. command, regKey, script)

Public API:
  get_field(sigma_field) -> (expr: str, tier: str)
  is_unmapped(sigma_field) -> bool
  apply_modifier(expr, tier, modifier, values, sigma_field="") -> (sql: str, comments: list[str])
"""

import base64
import re as _re
from typing import Optional

# ---------------------------------------------------------------------------
# Field mapping tables
# ---------------------------------------------------------------------------

# Tier 1: direct EAT column names
_TIER1: dict[str, str] = {
    "Image":           "procName",
    "User":            "user",
    "TargetUser":      "targetUser",
    "EventID":         "winEventId",
    "ProcessId":       "procId",
    "LogonType":       "winLogonType",
    "ServiceName":     "serviceName",
    "Domain":          "domain",
    "DestinationIp":   "destIpAddrV4",
    "DestinationPort": "destIpPort",
    "SourceIp":        "srcIpAddrV4",
    "SourcePort":      "srcIpPort",
    "Data":            "rawEventMsg",
    "keywords":        "rawEventMsg",
}

# Tier 2: metrics_string array EAT names
_TIER2: dict[str, str] = {
    "CommandLine":        "command",
    "ParentImage":        "parentProcName",
    "ParentCommandLine":  "parentCommand",
    "SubjectUserName":    "subjectUsername",
    "TargetUserName":     "targetUser",
    "DestinationHostname":"destHostName",
    "TargetFilename":     "fileName",
    "TargetObject":       "regKey",
    "Details":            "regValue",
    "ScriptBlockText":    "script",
    "Hashes":             "hashMD5",
    "Initiated":          "initiated",
    "ImageLoaded":        "imageLoaded",
    "OriginalFileName":   "originalFileName",
    "Product":            "product",
    "Company":            "company",
    "PipeName":           "pipeName",
    "Provider_Name":      "provider",
    "Channel":            "channel",
    "TargetUserGrp":      "targetUserGrp",
    "CurrentDirectory":   "currentDirectory",
    "IntegrityLevel":     "integrityLevel",
    "Signature":          "signature",
    "SignatureStatus":    "signatureStatus",
}

_UNMAPPED_FALLBACK = "rawEventMsg"
_UNMAPPED_TIER = "1"


def _tier2_expr(eat_name: str) -> str:
    """Build the metrics_string array accessor expression for a tier-2 EAT name."""
    return f"metrics_string.value[indexOf(metrics_string.name,'{eat_name}')]"


def get_field(sigma_field: str) -> tuple[str, str]:
    """Return (fsm_expression, tier) for a Sigma field name.

    Falls back to ("rawEventMsg", "1") for unmapped fields.
    """
    if sigma_field in _TIER1:
        return _TIER1[sigma_field], "1"
    if sigma_field in _TIER2:
        return _tier2_expr(_TIER2[sigma_field]), "2"
    return _UNMAPPED_FALLBACK, _UNMAPPED_TIER


def is_unmapped(sigma_field: str) -> bool:
    """Return True if sigma_field has no mapping in either tier."""
    return sigma_field not in _TIER1 and sigma_field not in _TIER2


# ---------------------------------------------------------------------------
# Helper: extract the EAT name from a tier-2 expression
# ---------------------------------------------------------------------------

_TIER2_PATTERN = _re.compile(r"indexOf\(metrics_string\.name,'([^']+)'\)")


def _eat_name_from_expr(expr: str) -> Optional[str]:
    """Extract the EAT name from a tier-2 metrics_string expression, or None."""
    m = _TIER2_PATTERN.search(expr)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Helper: backslash escaping for LIKE values
# ---------------------------------------------------------------------------

def _like_escape(value: str) -> str:
    """Escape backslashes, % and _ in a value for use in a SQL LIKE pattern.

    In ClickHouse LIKE patterns:
      %  matches any sequence of characters (wildcard)
      _  matches any single character (wildcard)
      \\  is the escape character

    Backslashes must be escaped first so that subsequent replacements do not
    double-escape the backslashes already introduced by the % and _ steps.
    """
    value = value.replace("\\", "\\\\")
    value = value.replace("%", "\\%")
    value = value.replace("_", "\\_")
    return value


def like_escape(value: str) -> str:
    """Public alias for _like_escape.

    Escape special LIKE characters (\\, %, _) in value so it can be safely
    interpolated into a ClickHouse LIKE pattern.
    """
    return _like_escape(value)


# ---------------------------------------------------------------------------
# Helper: build tier-2 guard + inner condition
# ---------------------------------------------------------------------------

def _wrap_tier2(expr: str, inner: str) -> str:
    """Wrap an inner SQL condition with the tier-2 indexOf > 0 guard.

    The guard ensures the metrics_string array contains the key before
    testing its value, avoiding false positives from array index 0.

    inner is parenthesized so that when the result is AND-joined with other
    fragments by _selection_to_sql, SQL operator precedence (AND > OR) does
    not incorrectly absorb only the first term of a multi-value OR chain.
    """
    eat = _eat_name_from_expr(expr)
    if eat is None:
        # expr is not a recognised tier-2 expression; return inner as-is
        return inner
    guard = f"indexOf(metrics_string.name, '{eat}') > 0"
    # Parenthesize inner so AND binds guard+inner, not guard+inner-first-term
    return f"{guard}\n    AND ({inner})"


# ---------------------------------------------------------------------------
# base64offset helpers
# ---------------------------------------------------------------------------

def _base64_variants(value: str) -> list[str]:
    """Compute 3 base64-offset variants of value (offsets 0, 1, 2).

    For each offset:
      - prepend `offset` NUL bytes, encode as base64
      - strip leading `offset` chars and trailing padding-related chars
    """
    variants: list[str] = []
    raw = value.encode("utf-8")
    for offset in range(3):
        padded = b"\x00" * offset + raw
        b64 = base64.b64encode(padded).decode("ascii")
        # strip the `offset` leading chars introduced by the NUL prefix
        start = offset
        # trim trailing chars: (offset % 3) positions, but 0 if offset%3 == 0
        trim_end = offset % 3
        if trim_end == 0:
            trimmed = b64[start:]
        else:
            trimmed = b64[start: len(b64) - trim_end]
        # remove any remaining '=' padding
        trimmed = trimmed.rstrip("=")
        if trimmed:
            variants.append(trimmed)
    return variants


# ---------------------------------------------------------------------------
# Core: apply_modifier
# ---------------------------------------------------------------------------

def apply_modifier(
    expr: str,
    tier: str,
    modifier: Optional[str],
    values: list,
    sigma_field: str = "",
) -> tuple[str, list[str]]:
    """Translate a Sigma detection condition into a ClickHouse SQL fragment.

    Parameters
    ----------
    expr        FSM expression returned by get_field()
    tier        "1" or "2"
    modifier    Sigma modifier string (e.g. "contains", "endswith", None).
                Compound modifiers like "contains|all" are supported.
    values      List of match values from the Sigma rule.
    sigma_field Original Sigma field name (used to emit UNMAPPED_FIELD comment).

    Returns
    -------
    (sql_fragment, comments)  where comments is a list of SQL comment strings.
    """
    comments: list[str] = []

    # Guard: empty values list would produce invalid SQL (e.g. IN ()).
    if not values:
        return "1=1", comments

    # Emit UNMAPPED_FIELD comment when the caller passes the original field name
    # and it resolves to the fallback.
    if sigma_field and is_unmapped(sigma_field):
        comments.append(f"-- UNMAPPED_FIELD: {sigma_field}")

    def _wrap(inner: str) -> str:
        if tier == "2":
            return _wrap_tier2(expr, inner)
        return inner

    # Normalise modifier to lower-case for matching
    mod = modifier.lower() if modifier else None

    # --- no modifier -------------------------------------------------------
    if mod is None:
        str_values = [str(v) for v in values]
        if len(str_values) == 1:
            inner = f"{expr} = '{str_values[0]}'"
        else:
            joined = ", ".join(f"'{v}'" for v in str_values)
            inner = f"{expr} IN ({joined})"
        return _wrap(inner), comments

    # --- contains|all -------------------------------------------------------
    if mod == "contains|all":
        str_values = [str(v) for v in values]
        parts = [f"{expr} LIKE '%{_like_escape(v)}%'" for v in str_values]
        inner = " AND ".join(parts)
        return _wrap(inner), comments

    # --- contains -----------------------------------------------------------
    if mod == "contains":
        str_values = [str(v) for v in values]
        parts = [f"{expr} LIKE '%{_like_escape(v)}%'" for v in str_values]
        inner = " OR ".join(parts)
        return _wrap(inner), comments

    # --- endswith -----------------------------------------------------------
    if mod == "endswith":
        str_values = [str(v) for v in values]
        parts = [f"{expr} LIKE '%{_like_escape(v)}'" for v in str_values]
        inner = " OR ".join(parts)
        return _wrap(inner), comments

    # --- startswith ---------------------------------------------------------
    if mod == "startswith":
        str_values = [str(v) for v in values]
        parts = [f"{expr} LIKE '{_like_escape(v)}%'" for v in str_values]
        inner = " OR ".join(parts)
        return _wrap(inner), comments

    # --- re (regex) ---------------------------------------------------------
    if mod == "re":
        str_values = [str(v) for v in values]
        parts = [f"match({expr}, '{v}')" for v in str_values]
        inner = " OR ".join(parts)
        return _wrap(inner), comments

    # --- windash ------------------------------------------------------------
    if mod == "windash":
        # windash produces 4 LIKE variants per value, covering the common ways
        # Windows command-line switches are passed.  The Sigma convention is
        # that windash values are written with a leading dash (e.g. "-nop").
        #
        # Variant construction:
        #   space:   "% <original>%"  — space separator keeps the leading dash
        #                               so " -nop" distinguishes it from a flag
        #   dash:    "%-<bare>%"       — redundant leading dash stripped; bare="nop"
        #   slash:   "%/<bare>%"       — forward-slash alternative
        #   en-dash: "%\u2013<bare>%"  — en-dash (U+2013) alternative
        #
        # For value "-nop":
        #   space variant  -> LIKE '% -nop%'
        #   dash variant   -> LIKE '%-nop%'
        #   slash variant  -> LIKE '%/nop%'
        #   en-dash variant-> LIKE '%\u2013nop%'
        all_parts: list[str] = []
        for v in values:
            str_v = str(v)
            # bare: strip one leading dash or slash (the canonical Sigma form)
            bare = str_v.lstrip("-").lstrip("/") if str_v.startswith(("-", "/")) else str_v
            # space variant keeps the original value (so "% -nop%" not "% nop%")
            all_parts.append(f"{expr} LIKE '% {_like_escape(str_v)}%'")
            # dash, slash, en-dash variants use the bare value
            all_parts.append(f"{expr} LIKE '%-{_like_escape(bare)}%'")
            all_parts.append(f"{expr} LIKE '%/{_like_escape(bare)}%'")
            all_parts.append(f"{expr} LIKE '%\u2013{_like_escape(bare)}%'")
        inner = " OR ".join(all_parts)
        return _wrap(inner), comments

    # --- base64offset|contains ----------------------------------------------
    if mod == "base64offset|contains":
        all_variants: list[str] = []
        for v in values:
            all_variants.extend(_base64_variants(str(v)))
        pattern = "|".join(all_variants)
        inner = f"match({expr}, '{pattern}')"
        return _wrap(inner), comments

    # --- cidr ---------------------------------------------------------------
    if mod == "cidr":
        # cidr does not need a tier-2 guard; it wraps the expression directly.
        parts = [f"isIPAddressInRange(toString({expr}), '{v}')" for v in values]
        inner = " OR ".join(parts)
        return inner, comments

    # --- numeric comparisons ------------------------------------------------
    _NUMERIC_OPS = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
    if mod in _NUMERIC_OPS:
        op = _NUMERIC_OPS[mod]
        # Take the first value; Sigma numeric comparisons are single-value.
        inner = f"{expr} {op} {values[0]}"
        return _wrap(inner), comments

    # --- exists|true / exists|false -----------------------------------------
    if mod == "exists|true":
        inner = f"{expr} IS NOT NULL AND {expr} != ''"
        return _wrap(inner), comments

    if mod == "exists|false":
        inner = f"({expr} IS NULL OR {expr} = '')"
        return _wrap(inner), comments

    # --- unknown modifier fallback ------------------------------------------
    comments.append(f"-- UNSUPPORTED_MODIFIER: {modifier}")
    str_values = [str(v) for v in values]
    parts = [f"rawEventMsg LIKE '%{_like_escape(v)}%'" for v in str_values]
    inner = " OR ".join(parts)
    return inner, comments
