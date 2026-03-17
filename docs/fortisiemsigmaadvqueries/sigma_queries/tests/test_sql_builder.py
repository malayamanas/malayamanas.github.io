"""Tests for sql_builder.py — SigmaRule → ClickHouse SQL string."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from pathlib import Path
from converter.rule_parser import SigmaRule, parse_rule
from converter.sql_builder import build_sql

FIXTURES = Path(__file__).parent / "fixtures"


def _make_rule(
    detection_selections: dict,
    condition_resolved: list,
    logsource_category: str = "process_creation",
    logsource_product: str = "windows",
    fsm_event_types: list | None = None,
) -> SigmaRule:
    """Construct a minimal SigmaRule for unit-testing sql_builder."""
    return SigmaRule(
        id="test-id",
        title="Test Rule",
        description="",
        author="",
        date="",
        status="test",
        level="high",
        fsm_severity=7,
        tags=[],
        mitre_tactics=[],
        mitre_techniques=[],
        logsource_product=logsource_product,
        logsource_category=logsource_category,
        logsource_service="",
        fsm_event_types=fsm_event_types if fsm_event_types is not None else ["Win-Sysmon-1-Create-Process"],
        detection_selections=detection_selections,
        condition="selection_a or selection_b",
        condition_resolved=condition_resolved,
        falsepositives=[],
        references=[],
        sigma_file_path="test.yml",
        github_url="https://github.com/test",
    )


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
        assert " AS " in self.sql


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

    def test_unmapped_field_tracked(self):
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
        # No real event types → SQL should still be valid
        assert "FROM fsiem.events" in sql


class TestOperatorPrecedence:
    """Test that multi-value OR fragments are parenthesized before AND-joining."""

    def test_where_clause_parenthesizes_or_groups(self):
        """Multi-value fields must be wrapped in parens to preserve AND precedence.

        win_proc_create.yml has:
          Image|endswith: ['\powershell.exe', '\pwsh.exe']   <- 2-value OR
          CommandLine|contains: ['-EncodedCommand', '-enc '] <- 2-value OR (tier-2)

        Without parenthesization SQL parses as:
          procName LIKE A OR (procName LIKE B AND indexOf... AND cmd LIKE C) OR cmd LIKE D

        Correct output must be:
          (procName LIKE A OR procName LIKE B)
          AND (indexOf... AND (cmd LIKE C OR cmd LIKE D))
        """
        rule = parse_rule(FIXTURES / "win_proc_create.yml")
        sql = build_sql(rule)

        # Locate the detection portion (after the time filter line)
        assert "AND phRecvTime >= now() - INTERVAL 24 HOUR" in sql
        detection_part = sql.split("AND phRecvTime >= now() - INTERVAL 24 HOUR", 1)[1]

        # The two endswith alternatives for Image must appear inside parentheses
        # i.e. "(procName LIKE '%\\powershell.exe' OR procName LIKE '%\\pwsh.exe')"
        assert "(procName LIKE" in detection_part, (
            "Image endswith OR-chain should be wrapped in parentheses"
        )

        # The tier-2 guard for CommandLine should be present
        assert "indexOf(metrics_string.name, 'command') > 0" in detection_part

        # The CommandLine contains alternatives must be inside parentheses
        # i.e. "(commandExpr LIKE '%-EncodedCommand%' OR commandExpr LIKE '%-enc %')"
        # The tier-2 guard form is: indexOf... AND (expr LIKE ... OR expr LIKE ...)
        assert "AND (" in detection_part, (
            "Tier-2 inner OR-chain should be wrapped in parentheses after AND"
        )

        # Confirm there is no bare top-level OR that would break precedence:
        # A bare "... OR ... AND ..." pattern (without outer parens around the OR)
        # would look like "LIKE '%\\pwsh.exe'\n    AND indexOf" in the raw SQL,
        # meaning the second LIKE is not parenthesized with the first.
        # After our fix both LIKE patterns must be inside a "(" before the AND.
        powershell_like = "procName LIKE '%\\\\powershell.exe'"
        pwsh_like = "procName LIKE '%\\\\pwsh.exe'"
        assert powershell_like in sql, "Expected escaped endswith pattern for powershell.exe"
        assert pwsh_like in sql, "Expected escaped endswith pattern for pwsh.exe"
        # Both must appear between the same pair of parentheses — verify they are
        # within the parenthesized block by checking the block contains both.
        open_paren_idx = detection_part.find("(procName LIKE")
        assert open_paren_idx != -1
        close_paren_idx = detection_part.find(")", open_paren_idx)
        assert close_paren_idx != -1
        paren_block = detection_part[open_paren_idx: close_paren_idx + 1]
        assert "powershell.exe" in paren_block
        assert "pwsh.exe" in paren_block


class TestTopLevelOrGroupsParenthesized:
    """Test that multiple top-level OR groups are wrapped in parentheses."""

    def test_top_level_or_groups_parenthesized(self):
        """Multiple top-level OR groups must be parenthesized to preserve AND guards."""
        rule = _make_rule(
            detection_selections={
                "selection_a": [{"CommandLine": ["cmd.exe"]}],
                "selection_b": [{"CommandLine": ["powershell.exe"]}],
            },
            condition_resolved=[[("selection_a", False)], [("selection_b", False)]],
        )
        sql = build_sql(rule)
        # The detection block must be wrapped so AND guards aren't bypassed
        # Expected pattern: "AND (\n  ..." or similar containing both groups AND'd correctly
        assert "AND (" in sql or "AND(\n" in sql, "detection block must be parenthesized when multiple OR groups exist"
        # Both values must appear inside the parenthesized block
        lines = sql.split("\n")
        and_paren_idx = next(i for i, l in enumerate(lines) if "AND (" in l or l.strip() == "AND (")
        rest = "\n".join(lines[and_paren_idx:])
        assert "cmd.exe" in rest
        assert "powershell.exe" in rest
