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
        bad.write_text("title: bad\nid: aaa\ndetection:\n  condition: all of them\n")
        result = parse_rule(bad)
        assert result is None
