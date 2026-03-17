#!/usr/bin/env python3
"""
sigma_to_fortisiem.py — Convert Sigma rules to FortiSIEM ClickHouse SQL.

Usage:
  python3 sigma_to_fortisiem.py [options]

Options:
  --sigma-dir DIR      Path to sigma repo (default: ../../../sigma relative to script)
  --output-dir DIR     Output directory (default: ../../../sigma_queries relative to script)
  --category CAT       Filter by logsource.category (case-insensitive)
  --product PROD       Filter by logsource.product (case-insensitive)
  --level LEVELS       Comma-separated: low,medium,high,critical
  --id UUID            Single rule ID
  --json-only          Skip markdown+HTML, write JSON only
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

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
    """Recursively collect all .yml files. Look under rules/ first, then sigma_dir itself."""
    rules_dir = sigma_dir / "rules"
    if rules_dir.exists():
        return sorted(rules_dir.rglob("*.yml"))
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

    output_dir.mkdir(parents=True, exist_ok=True)
    if not args.json_only:
        (output_dir / "md").mkdir(exist_ok=True)
        (output_dir / "html").mkdir(exist_ok=True)

    level_filter: set[str] | None = None
    if args.level:
        level_filter = {lvl.strip().lower() for lvl in args.level.split(",")}

    yaml_files = _collect_yaml_files(sigma_dir)
    total_found = len(yaml_files)

    skipped_errors = 0
    skipped_no_detection = 0
    all_entries: list[tuple] = []

    for yml_path in yaml_files:
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
            skipped_no_detection += 1
            continue

        # Apply filters (all case-insensitive)
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
            print(f"WARN: {yml_path}: sql_builder: {e}", file=sys.stderr)
            skipped_errors += 1
            continue

        all_entries.append((rule, sql))

    # Write JSON (always)
    json_path = output_dir / "sigma_queries.json"
    json_doc = _renderer.render_json(
        all_entries,
        sigma_repo_path=str(sigma_dir),
        output_path=json_path,
        total_found=total_found,
    )

    if args.json_only:
        _print_summary(all_entries, skipped_no_detection, skipped_errors, total_found, output_dir)
        return

    # Group by (product, category) for per-file rendering
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for rule, sql in all_entries:
        key = (
            rule.logsource_product.lower(),
            (rule.logsource_category or rule.logsource_service).lower(),
        )
        groups[key].append((rule, sql))

    # Write markdown + HTML per category
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

    # Write index.html
    (output_dir / "index.html").write_text(
        _renderer.render_index_html(all_entries, categories_meta),
        encoding="utf-8",
    )

    _print_summary(all_entries, skipped_no_detection, skipped_errors, total_found, output_dir)


def _print_summary(all_entries, skipped_no_detection, skipped, total_found, output_dir):
    converted = len(all_entries)
    unmapped_ls = sum(1 for r, _ in all_entries if r.unmapped_logsource)
    unmapped_fields = sum(1 for r, _ in all_entries if r.unmapped_fields)
    print(f"\nConverted:                  {converted} / {total_found} rules")
    print(f"Skipped (no detection):     {skipped_no_detection} rules")
    print(f"Skipped (errors):           {skipped} rules")
    print(f"Unmapped logsource:         {unmapped_ls} rules (rawEventMsg fallback used)")
    print(f"Rules with unmapped fields: {unmapped_fields} rules")
    print(f"Output: {output_dir}/")


if __name__ == "__main__":
    main()
