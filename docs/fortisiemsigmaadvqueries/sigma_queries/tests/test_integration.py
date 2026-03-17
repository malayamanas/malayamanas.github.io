"""Integration tests: run sigma_to_fortisiem.py against fixture dir, verify all outputs."""
import sys, os, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).parent.parent / "scripts" / "sigma_to_fortisiem.py"


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
            assert entry["logsource"].split("/")[0] == "windows"

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

    def test_category_filter_process_creation_only(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--sigma-dir", str(FIXTURES),
                "--output-dir", str(tmp_path),
                "--category", "process_creation",
                "--json-only",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads((tmp_path / "sigma_queries.json").read_text())
        for entry in data["entries"]:
            assert "process_creation" in entry["logsource"], f"Expected process_creation but got {entry['logsource']}"
