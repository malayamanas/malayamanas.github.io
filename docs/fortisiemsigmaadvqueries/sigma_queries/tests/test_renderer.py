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

    def test_output_path_writes_file(self, tmp_path):
        """render_json should write JSON to disk when output_path is provided."""
        entries = _make_entries(["win_proc_create.yml"])
        output_file = tmp_path / "out.json"
        render_json(entries, sigma_repo_path="/sigma", output_path=output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "entries" in data


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
