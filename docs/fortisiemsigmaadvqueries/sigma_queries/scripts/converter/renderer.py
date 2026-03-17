"""renderer.py — JSON, Markdown, and HTML output writers for Sigma → FortiSIEM.

Public API:
    render_json(entries, sigma_repo_path, output_path, total_found=None) -> dict
    render_markdown(entries, product, category) -> str
    render_html_page(entries, product, category) -> str
    render_index_html(all_entries, categories) -> str
"""

from __future__ import annotations

import json
import re as _re
from datetime import date
from pathlib import Path
from typing import Optional

from converter.rule_parser import SigmaRule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _today() -> str:
    return date.today().isoformat()


def _h(text: str) -> str:
    """HTML-escape user-provided text."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _level_colour(level: str) -> str:
    """Return hex colour for a Sigma level."""
    return {
        "low": "#3fb950",
        "medium": "#d29922",
        "high": "#f0883e",
        "critical": "#f85149",
    }.get(level.lower(), "#8b949e")


def _logsource_str(rule: SigmaRule) -> str:
    """Return a concise logsource string like 'windows/process_creation'."""
    product = rule.logsource_product or ""
    cat_or_svc = rule.logsource_category or rule.logsource_service or ""
    parts = [p for p in [product, cat_or_svc] if p]
    return "/".join(parts) if parts else "unknown"


def _github_url(rule: SigmaRule) -> str:
    """Return the GitHub permalink for a rule."""
    return rule.github_url


# ---------------------------------------------------------------------------
# render_json
# ---------------------------------------------------------------------------

def render_json(
    entries: list[tuple[SigmaRule, str]],
    sigma_repo_path: Optional[str],
    output_path: Optional[Path],
    total_found: Optional[int] = None,
) -> dict:
    """Build and optionally write the sigma_queries.json document.

    Parameters
    ----------
    entries         List of (SigmaRule, sql_str) tuples (already-converted rules).
    sigma_repo_path Optional path to the sigma repository (recorded in output).
    output_path     If not None, write JSON to this file path.
    total_found     Total rules scanned before filtering/errors.  When None,
                    defaults to len(entries) so both counts are equal.

    Returns
    -------
    dict — the full JSON-serialisable document.
    """
    unmapped_logsource_count = sum(1 for rule, _ in entries if rule.unmapped_logsource)
    unmapped_field_count = sum(len(rule.unmapped_fields) for rule, _ in entries)

    entry_list = []
    for rule, sql in entries:
        entry_list.append({
            "sigma_id": rule.id,
            "name": rule.title,
            "description": rule.description,
            "status": rule.status,
            "level": rule.level,
            "fsm_severity": rule.fsm_severity,
            "mitre_tactics": rule.mitre_tactics,
            "mitre_techniques": rule.mitre_techniques,
            "logsource": _logsource_str(rule),
            "fsm_event_types": rule.fsm_event_types,
            "unmapped_fields": rule.unmapped_fields,
            "unmapped_logsource": rule.unmapped_logsource,
            "github_url": _github_url(rule),
            "references": rule.references,
            "author": rule.author,
            "date": rule.date,
            "sql": sql,
        })

    doc = {
        "generated": _today(),
        "sigma_repo_path": sigma_repo_path or "",
        "total_rules_found": total_found if total_found is not None else len(entries),
        "total_converted": len(entries),
        "unmapped_logsource_count": unmapped_logsource_count,
        "unmapped_field_count": unmapped_field_count,
        "entries": entry_list,
    }

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

    return doc


# ---------------------------------------------------------------------------
# render_markdown
# ---------------------------------------------------------------------------

def render_markdown(
    entries: list[tuple[SigmaRule, str]],
    product: str,
    category: str,
) -> str:
    """Generate a per-category Markdown document.

    Parameters
    ----------
    entries  List of (SigmaRule, sql_str) tuples for this category.
    product  Logsource product (e.g. 'windows').
    category Logsource category (e.g. 'process_creation').

    Returns
    -------
    str — complete Markdown document.
    """
    product_title = product.title()
    category_title = category.replace("_", " ").title()
    count = len(entries)
    rule_word = "rule" if count == 1 else "rules"

    lines: list[str] = []

    # H1 header
    lines.append(f"# Sigma → FortiSIEM: {product_title} {category_title}")
    lines.append("")
    lines.append(f"> {count} {rule_word} · Generated {_today()}")
    lines.append("")

    # Table of Contents
    lines.append("## Table of Contents")
    lines.append("")
    for rule, _ in entries:
        anchor = _re.sub(r'[^a-z0-9\s-]', '', rule.title.lower())
        anchor = anchor.replace(" ", "-")
        anchor = _re.sub(r'-{2,}', '-', anchor).strip('-')
        lines.append(f"- [{rule.title}](#{anchor})")
    lines.append("")

    # Per-rule sections
    for rule, sql in entries:
        lines.append(f"## {rule.title}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| **Sigma ID** | `{_md_cell(rule.id)}` |")
        lines.append(f"| **Level** | {_md_cell(rule.level)} |")
        lines.append(f"| **FSM Severity** | {_md_cell(str(rule.fsm_severity))} |")
        if rule.mitre_tactics:
            lines.append(f"| **MITRE Tactics** | {_md_cell(', '.join(rule.mitre_tactics))} |")
        if rule.mitre_techniques:
            lines.append(f"| **MITRE Techniques** | {_md_cell(', '.join(rule.mitre_techniques))} |")
        lines.append(f"| **Author** | {_md_cell(rule.author)} |")
        lines.append(f"| **Status** | {_md_cell(rule.status)} |")
        lines.append("")
        lines.append(f"**[View on GitHub ↗]({_github_url(rule)})**")
        lines.append("")
        if rule.description:
            lines.append(f"> {rule.description}")
            lines.append("")
        lines.append("```sql")
        lines.append(sql)
        lines.append("```")
        lines.append("")
        if rule.falsepositives:
            lines.append(f"**False Positives:** {'; '.join(rule.falsepositives)}")
            lines.append("")
        if rule.references:
            lines.append("**References:**")
            for ref in rule.references:
                lines.append(f"- {ref}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# _html_shell helpers
# ---------------------------------------------------------------------------

_HIGHLIGHT_CSS = (
    '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/'
    '11.9.0/styles/github-dark.min.css">'
)
_HIGHLIGHT_JS = (
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>\n'
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/sql.min.js"></script>\n'
    '<script>document.addEventListener(\'DOMContentLoaded\', () => hljs.highlightAll());</script>'
)

_BASE_CSS = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    line-height: 1.6;
  }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  .page-header {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 16px 0;
    margin-bottom: 32px;
  }
  .page-header .container { padding-top: 0; padding-bottom: 0; }
  h1 { font-size: 1.6rem; color: #e6edf3; }
  h2 { font-size: 1.2rem; color: #e6edf3; margin-bottom: 8px; }
  .meta { font-size: 0.85rem; color: #8b949e; margin-bottom: 24px; }
  .rule-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 20px;
    margin-bottom: 24px;
  }
  .rule-card h2 { margin-bottom: 6px; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-right: 6px;
    text-transform: uppercase;
  }
  .badge-low    { background: #3fb950; color: #0d1117; }
  .badge-medium { background: #d29922; color: #0d1117; }
  .badge-high   { background: #f0883e; color: #0d1117; }
  .badge-critical { background: #f85149; color: #fff; }
  .badge-default  { background: #8b949e; color: #0d1117; }
  .rule-meta { font-size: 0.82rem; color: #8b949e; margin: 8px 0 12px; }
  .rule-meta span { margin-right: 16px; }
  .description { font-size: 0.9rem; color: #8b949e; margin-bottom: 12px; font-style: italic; }
  .github-link { font-size: 0.85rem; margin-bottom: 12px; display: inline-block; }
  .fp-block { font-size: 0.82rem; color: #8b949e; margin-top: 12px; }
  pre { margin: 0; }
  code.language-sql { font-size: 0.82rem; }
  .stats-bar {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 24px;
    display: flex;
    gap: 32px;
    flex-wrap: wrap;
  }
  .stat-item { text-align: center; }
  .stat-value { font-size: 1.4rem; font-weight: 700; color: #58a6ff; }
  .stat-label { font-size: 0.75rem; color: #8b949e; }
  .search-bar { margin-bottom: 20px; }
  .search-bar input {
    width: 100%;
    padding: 10px 14px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 0.9rem;
    outline: none;
  }
  .search-bar input:focus { border-color: #58a6ff; }
  .filter-pills { margin-bottom: 20px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  .pill {
    padding: 4px 12px;
    border-radius: 20px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #c9d1d9;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .pill:hover { border-color: #58a6ff; color: #58a6ff; }
  .pill.active { background: #58a6ff; color: #0d1117; border-color: #58a6ff; }
  .category-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .category-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px;
  }
  .category-card h3 { font-size: 0.95rem; color: #e6edf3; margin-bottom: 4px; }
  .category-card .cat-meta { font-size: 0.78rem; color: #8b949e; }
"""


def _md_cell(value: str) -> str:
    """Escape pipe characters in Markdown table cells."""
    return str(value).replace("|", "\\|")


def _badge(level: str) -> str:
    lvl = level.lower()
    cls = f"badge-{lvl}" if lvl in ("low", "medium", "high", "critical") else "badge-default"
    return f'<span class="badge {cls}">{_h(level)}</span>'


def _rule_card_html(rule: SigmaRule, sql: str) -> str:
    """Render one rule as an HTML card."""
    mitre_str = ""
    if rule.mitre_tactics or rule.mitre_techniques:
        parts = rule.mitre_tactics + rule.mitre_techniques
        mitre_str = f'<span>MITRE: {_h(", ".join(parts))}</span>'

    fp_html = ""
    if rule.falsepositives:
        fp_html = (
            f'<div class="fp-block"><strong>False Positives:</strong> '
            f'{_h("; ".join(rule.falsepositives))}</div>'
        )

    desc_html = ""
    if rule.description:
        desc_html = f'<div class="description">{_h(rule.description)}</div>'

    return (
        f'<div class="rule-card" data-level="{_h(rule.level)}" data-title="{_h(rule.title)}">\n'
        f'  <h2>{_h(rule.title)}</h2>\n'
        f'  <div class="rule-meta">\n'
        f'    {_badge(rule.level)}\n'
        f'    <span>FSM Severity: {rule.fsm_severity}</span>\n'
        f'    {mitre_str}\n'
        f'    <span>Author: {_h(rule.author)}</span>\n'
        f'    <span>Status: {_h(rule.status)}</span>\n'
        f'  </div>\n'
        f'  {desc_html}\n'
        f'  <a class="github-link" href="{_h(_github_url(rule))}" target="_blank" rel="noopener">'
        f'View on GitHub ↗</a>\n'
        f'  <pre><code class="language-sql">{_h(sql)}</code></pre>\n'
        f'  {fp_html}\n'
        f'</div>\n'
    )


# ---------------------------------------------------------------------------
# render_html_page
# ---------------------------------------------------------------------------

def render_html_page(
    entries: list[tuple[SigmaRule, str]],
    product: str,
    category: str,
) -> str:
    """Generate a per-category HTML page.

    Parameters
    ----------
    entries  List of (SigmaRule, sql_str) tuples for this category.
    product  Logsource product (e.g. 'windows').
    category Logsource category (e.g. 'process_creation').

    Returns
    -------
    str — complete HTML document.
    """
    product_title = product.title()
    category_title = category.replace("_", " ").title()
    count = len(entries)
    rule_word = "rule" if count == 1 else "rules"

    cards_html = "".join(_rule_card_html(rule, sql) for rule, sql in entries)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sigma → FortiSIEM: {_h(product_title)} {_h(category_title)}</title>
  {_HIGHLIGHT_CSS}
  <style>{_BASE_CSS}</style>
</head>
<body>
  <div class="page-header">
    <div class="container">
      <h1>Sigma → FortiSIEM: {_h(product_title)} {_h(category_title)}</h1>
    </div>
  </div>
  <div class="container">
    <p class="meta">{count} {rule_word} · Generated {_today()} · <a href="../index.html">← Back to Index</a></p>
    {cards_html}
  </div>
  {_HIGHLIGHT_JS}
</body>
</html>"""


# ---------------------------------------------------------------------------
# render_index_html
# ---------------------------------------------------------------------------

def render_index_html(
    all_entries: list[tuple[SigmaRule, str]],
    categories: list[tuple[str, str, str]],
) -> str:
    """Generate the index.html page.

    Parameters
    ----------
    all_entries  All (SigmaRule, sql_str) tuples across all categories.
    categories   List of (product, category, html_filename) tuples.

    Returns
    -------
    str — complete HTML document.
    """
    total = len(all_entries)
    converted = total
    unmapped_ls = sum(1 for r, _ in all_entries if r.unmapped_logsource)
    unmapped_f = sum(len(r.unmapped_fields) for r, _ in all_entries)

    # Collect distinct platforms
    platforms: list[str] = []
    seen_platforms: set[str] = set()
    for rule, _ in all_entries:
        p = rule.logsource_product
        if p and p not in seen_platforms:
            seen_platforms.add(p)
            platforms.append(p)

    # Stats bar
    stats_html = (
        f'<div class="stats-bar">'
        f'  <div class="stat-item"><div class="stat-value">{total}</div>'
        f'    <div class="stat-label">Total Rules</div></div>'
        f'  <div class="stat-item"><div class="stat-value">{converted}</div>'
        f'    <div class="stat-label">Converted</div></div>'
        f'  <div class="stat-item"><div class="stat-value">{unmapped_ls}</div>'
        f'    <div class="stat-label">Unmapped Logsource</div></div>'
        f'  <div class="stat-item"><div class="stat-value">{unmapped_f}</div>'
        f'    <div class="stat-label">Unmapped Fields</div></div>'
        f'  <div class="stat-item"><div class="stat-value">{len(platforms)}</div>'
        f'    <div class="stat-label">Platforms</div></div>'
        f'</div>'
    )

    # Filter pills for levels
    all_levels = sorted({rule.level for rule, _ in all_entries if rule.level})
    pills_html = (
        '<div class="filter-pills">'
        '<span style="font-size:0.82rem;color:#8b949e;margin-right:4px;">Filter:</span>'
        '<span class="pill active" data-level="all">All</span>'
        + "".join(f'<span class="pill" data-level="{_h(lv)}">{_h(lv)}</span>' for lv in all_levels)
        + "</div>"
    )

    # Category cards
    cat_cards_html = '<div class="category-grid">'
    for product, category, filename in categories:
        cat_count = sum(
            1 for rule, _ in all_entries
            if rule.logsource_product == product
            and (rule.logsource_category == category or rule.logsource_service == category)
        )
        cat_cards_html += (
            f'<div class="category-card">'
            f'<h3><a href="html/{_h(filename)}">{_h(product.title())} / {_h(category.replace("_", " ").title())}</a></h3>'
            f'<div class="cat-meta">{cat_count} rules</div>'
            f'</div>'
        )
    cat_cards_html += "</div>"

    # Rule cards (limit to first 200)
    display_entries = all_entries[:200]
    rule_cards_html = "".join(
        (lambda data_title=rule.title.lower().replace('"', '&quot;'): (
            f'<div class="rule-card" data-level="{_h(rule.level)}" data-title="{data_title}">'
            f'  <h2>{_h(rule.title)}</h2>'
            f'  <div class="rule-meta">'
            f'    {_badge(rule.level)}'
            f'    <span>FSM Severity: {rule.fsm_severity}</span>'
            f'    <span>{_h(_logsource_str(rule))}</span>'
            f'  </div>'
            f'  <a class="github-link" href="{_h(_github_url(rule))}" target="_blank" rel="noopener">'
            f'View on GitHub ↗</a>'
            f'</div>'
        ))()
        for rule, _ in display_entries
    )

    # Client-side search + filter JS
    search_js = """
<script>
  (function() {
    var searchInput = document.getElementById('rule-search');
    var filterPills = document.querySelectorAll('.pill[data-level]');
    var cards = document.querySelectorAll('.rule-card[data-title]');
    var activeLevel = 'all';

    function filterCards() {
      var query = searchInput ? searchInput.value.toLowerCase() : '';
      cards.forEach(function(card) {
        var title = (card.dataset.title || '').toLowerCase();
        var level = (card.dataset.level || '').toLowerCase();
        var matchesSearch = !query || title.indexOf(query) !== -1;
        var matchesLevel = activeLevel === 'all' || level === activeLevel;
        card.style.display = (matchesSearch && matchesLevel) ? '' : 'none';
      });
    }

    if (searchInput) {
      searchInput.addEventListener('input', filterCards);
    }

    filterPills.forEach(function(pill) {
      pill.addEventListener('click', function() {
        filterPills.forEach(function(p) { p.classList.remove('active'); });
        pill.classList.add('active');
        activeLevel = pill.dataset.level;
        filterCards();
      });
    });
  })();
</script>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sigma → FortiSIEM Query Library</title>
  {_HIGHLIGHT_CSS}
  <style>{_BASE_CSS}</style>
</head>
<body>
  <div class="page-header">
    <div class="container">
      <h1>Sigma → FortiSIEM Query Library</h1>
    </div>
  </div>
  <div class="container">
    <p class="meta">Generated {_today()}</p>
    {stats_html}
    <div class="search-bar">
      <input id="rule-search" type="text" placeholder="Search rules by title..." aria-label="Search rules">
    </div>
    {pills_html}
    <h2 style="margin-bottom:16px;">Categories</h2>
    {cat_cards_html}
    <h2 style="margin-bottom:16px;">Rules{' (showing first 200)' if len(all_entries) > 200 else ''}</h2>
    {rule_cards_html}
  </div>
  {_HIGHLIGHT_JS}
  {search_js}
</body>
</html>"""
