"""sql_builder.py — SigmaRule → ClickHouse SQL string.

Public API:
    build_sql(rule: SigmaRule) -> str
"""

from __future__ import annotations

from typing import Any

from converter.rule_parser import SigmaRule
from converter import field_map

# ---------------------------------------------------------------------------
# Base SELECT columns (always present, in this order)
# ---------------------------------------------------------------------------

_BASE_COLS = ["phRecvTime", "reptDevName", "reptDevIpAddrV4", "user"]
_TAIL_COL = "rawEventMsg"

# ---------------------------------------------------------------------------
# camelCase alias helper
# ---------------------------------------------------------------------------


def _camel_alias(sigma_field: str) -> str:
    """Return camelCase alias for a Sigma field name.

    E.g. CommandLine → commandLine, ScriptBlockText → scriptBlockText.
    """
    if not sigma_field:
        return sigma_field
    return sigma_field[0].lower() + sigma_field[1:]


# ---------------------------------------------------------------------------
# Selection → SQL fragment builder
# ---------------------------------------------------------------------------


def _selection_to_sql(
    selection_maps: list[dict[str, Any]],
    rule: SigmaRule,
    extra_comments: list[str],
    tier2_aliases: dict[str, str],
    extra_tier1_cols: list[str],
) -> str:
    """Convert a list of OR-alternative AND-maps into a SQL fragment.

    Side effects:
      - Appends UNMAPPED/UNSUPPORTED comments to extra_comments.
      - Populates tier2_aliases with eat_name → alias entries.
      - Populates extra_tier1_cols with any tier-1 column names beyond base set.
      - Appends to rule.unmapped_fields for any unmapped sigma fields.
    """
    or_parts: list[str] = []

    for and_map in selection_maps:
        and_frags: list[str] = []

        # Check for bare keyword selection
        if list(and_map.keys()) == ["_keyword"]:
            kw_values = and_map["_keyword"]
            parts = [f"rawEventMsg LIKE '%{field_map.like_escape(str(v))}%'" for v in kw_values]
            and_frags.append(" OR ".join(parts))
        else:
            for key, values in and_map.items():
                # Split field name and modifier on '|'
                parts_key = key.split("|", 1)
                sigma_field = parts_key[0]
                modifier = parts_key[1] if len(parts_key) > 1 else None

                # Track unmapped fields
                if field_map.is_unmapped(sigma_field):
                    if sigma_field not in rule.unmapped_fields:
                        rule.unmapped_fields.append(sigma_field)

                # Get FSM expression and tier
                expr, tier = field_map.get_field(sigma_field)

                # Track tier-1 extra columns for SELECT
                if tier == "1" and expr not in _BASE_COLS and expr != _TAIL_COL:
                    if expr not in extra_tier1_cols:
                        extra_tier1_cols.append(expr)

                # Track tier-2 aliases for SELECT
                if tier == "2":
                    # extract eat_name from expression to build alias
                    eat_name = field_map._eat_name_from_expr(expr)
                    if eat_name:
                        alias = _camel_alias(sigma_field)
                        tier2_aliases[eat_name] = alias

                # Build SQL fragment
                sql_frag, comments = field_map.apply_modifier(
                    expr, tier, modifier, values, sigma_field=sigma_field
                )
                extra_comments.extend(comments)
                # Parenthesize any OR-chain so it does not interfere with
                # AND-joins (SQL AND binds tighter than OR).
                if " OR " in sql_frag:
                    sql_frag = f"({sql_frag})"
                and_frags.append(sql_frag)

        if and_frags:
            if len(and_frags) == 1:
                or_parts.append(and_frags[0])
            else:
                joined = "\n    AND ".join(and_frags)
                or_parts.append(f"({joined})")

    if not or_parts:
        return "1=1"

    if len(or_parts) == 1:
        return or_parts[0]

    return "\n  OR ".join(f"({p})" if "\n  OR " not in p else p for p in or_parts)


# ---------------------------------------------------------------------------
# Main build_sql function
# ---------------------------------------------------------------------------


def build_sql(rule: SigmaRule) -> str:
    """Build a ClickHouse SQL query string from a SigmaRule.

    Parameters
    ----------
    rule    A fully-populated SigmaRule (from rule_parser.parse_rule).

    Returns
    -------
    str — complete ClickHouse SQL query with comment block header.
    """
    # Reset unmapped_fields so each call is idempotent
    rule.unmapped_fields = []

    extra_comments: list[str] = []
    tier2_aliases: dict[str, str] = {}   # eat_name → camelCase alias
    extra_tier1_cols: list[str] = []     # tier-1 cols beyond base set

    # -----------------------------------------------------------------------
    # Build WHERE clause from condition_resolved
    # -----------------------------------------------------------------------
    # condition_resolved: list[list[tuple[str, bool]]]
    #   Outer = OR groups; inner = AND terms; tuple = (selection_name, negated)

    or_group_frags: list[str] = []

    for and_terms in rule.condition_resolved:
        and_frags: list[str] = []

        for sel_name, negated in and_terms:
            sel_maps = rule.detection_selections.get(sel_name)
            if sel_maps is None:
                continue

            frag = _selection_to_sql(
                sel_maps, rule, extra_comments, tier2_aliases, extra_tier1_cols
            )

            if negated:
                frag = f"NOT ({frag})"

            and_frags.append(frag)

        if and_frags:
            if len(and_frags) == 1:
                or_group_frags.append(and_frags[0])
            else:
                joined = "\n  AND ".join(and_frags)
                or_group_frags.append(f"({joined})")

    if or_group_frags:
        detection_where = "\n  OR ".join(or_group_frags)
        if len(or_group_frags) > 1:
            detection_where = f"(\n  {detection_where}\n)"
    else:
        detection_where = "1=1"

    # -----------------------------------------------------------------------
    # Build eventType IN clause
    # -----------------------------------------------------------------------
    unmapped_logsource_comment = ""

    if rule.fsm_event_types:
        et_list = ", ".join(f"'{et}'" for et in rule.fsm_event_types)
        event_type_clause = f"eventType IN ({et_list})"
    else:
        # Unmapped logsource fallback
        src = "/".join(filter(None, [rule.logsource_product, rule.logsource_category or rule.logsource_service]))
        unmapped_logsource_comment = f"-- UNMAPPED_LOGSOURCE: {src}"
        event_type_clause = "rawEventMsg LIKE '%'"

    # -----------------------------------------------------------------------
    # Build SELECT column list
    # -----------------------------------------------------------------------
    select_cols: list[str] = list(_BASE_COLS)

    # Add extra tier-1 columns (deduplicated, not already in base)
    for col in extra_tier1_cols:
        if col not in select_cols and col != _TAIL_COL:
            select_cols.append(col)

    # Add tier-2 expressions with aliases
    for eat_name, alias in tier2_aliases.items():
        expr = f"metrics_string.value[indexOf(metrics_string.name,'{eat_name}')]"
        select_cols.append(f"{expr} AS {alias}")

    # Always append rawEventMsg last
    select_cols.append(_TAIL_COL)

    select_str = ",\n  ".join(select_cols)

    # -----------------------------------------------------------------------
    # Assemble core query
    # -----------------------------------------------------------------------
    core_query = (
        f"SELECT\n  {select_str}\n"
        f"FROM fsiem.events\n"
        f"WHERE {event_type_clause}\n"
        f"  AND phRecvTime >= now() - INTERVAL 24 HOUR\n"
        f"  AND {detection_where}\n"
        f"ORDER BY phRecvTime DESC\n"
        f"LIMIT 1000;"
    )

    # -----------------------------------------------------------------------
    # Build comment block (after WHERE so unmapped_fields is populated)
    # -----------------------------------------------------------------------
    unmapped_str = ", ".join(rule.unmapped_fields) if rule.unmapped_fields else "(none)"
    mitre_parts: list[str] = []
    if rule.mitre_tactics:
        mitre_parts.append(", ".join(rule.mitre_tactics))
    if rule.mitre_techniques:
        mitre_parts.append(", ".join(rule.mitre_techniques))
    mitre_str = " | ".join(mitre_parts) if mitre_parts else "(none)"

    fp_str = "; ".join(rule.falsepositives) if rule.falsepositives else "(none)"

    comment_block_lines = [
        "-- ============================================================",
        f"-- Title:        {rule.title}",
        f"-- Sigma ID:     {rule.id}",
        f"-- Level:        {rule.level}  |  FSM Severity: {rule.fsm_severity}",
        f"-- Status:       {rule.status}",
        f"-- MITRE:        {mitre_str}",
        f"-- Author:       {rule.author}",
        f"-- Date:         {rule.date}",
        f"-- GitHub:       {rule.github_url}",
        f"-- Unmapped:     {unmapped_str}",
        f"-- False Pos:    {fp_str}",
        "-- ============================================================",
    ]
    comment_block = "\n".join(comment_block_lines)

    # -----------------------------------------------------------------------
    # Prepend any extra diagnostic comments (UNMAPPED_FIELD, UNSUPPORTED_MODIFIER)
    # -----------------------------------------------------------------------
    prefix_parts: list[str] = []
    if unmapped_logsource_comment:
        prefix_parts.append(unmapped_logsource_comment)
    if extra_comments:
        # Deduplicate while preserving order
        seen: set[str] = set()
        for c in extra_comments:
            if c not in seen:
                seen.add(c)
                prefix_parts.append(c)

    if prefix_parts:
        diagnostic_block = "\n".join(prefix_parts) + "\n"
    else:
        diagnostic_block = ""

    return f"{comment_block}\n{diagnostic_block}\n{core_query}"
