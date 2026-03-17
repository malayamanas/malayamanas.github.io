#!/usr/bin/env python3
"""
FortiSIEM Advanced Search SQL Training Site Builder
Converts docs/*.md -> site/*.html with shared navigation and syntax highlighting.

Usage:
    python3 scripts/build.py

Requirements:
    pip3 install markdown
"""

import re
import shutil
from pathlib import Path

import markdown
from markdown.extensions.tables import TableExtension
from markdown.extensions.fenced_code import FencedCodeExtension

# ── Configuration ──────────────────────────────────────────────────────────────

DOCS_DIR   = Path(__file__).parent.parent / "docs"
SITE_DIR   = Path(__file__).parent.parent / "site"
ASSETS_SRC = DOCS_DIR / "assets"
ASSETS_DST = SITE_DIR / "assets"

PAGES = [
    ("00-introduction.md",  "index.html",         "Introduction"),
    ("01-beginner.md",      "beginner.html",       "Beginner"),
    ("02-intermediate.md",  "intermediate.html",   "Intermediate"),
    ("03-advanced.md",      "advanced.html",       "Advanced"),
    ("04-soc-workflow.md",  "soc-workflow.html",   "SOC Workflow"),
    ("05-reference.md",     "reference.html",      "Reference"),
]

HIGHLIGHT_JS = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0"

# ── Navigation ─────────────────────────────────────────────────────────────────

def build_nav(active_html: str) -> str:
    links = []
    for _, html_name, label in PAGES:
        active = ' class="active"' if html_name == active_html else ""
        links.append(f'<a href="{html_name}"{active}>{label}</a>')
    return (
        "<nav>\n"
        '  <a class="nav-brand" href="index.html">FortiSIEM&#8202;|&#8202;Advanced Search SQL</a>\n'
        + "\n".join(f"  {l}" for l in links)
        + "\n  <button id=\"theme-toggle\" aria-label=\"Toggle dark mode\">&#9790;</button>"
        + "\n</nav>"
    )

# ── Callout post-processing ─────────────────────────────────────────────────────
# Converts blockquotes that start with [NOTE], [WARN], [LAB], [SOC], [TIP]

CALLOUT_MAP = {
    "[NOTE]": ("callout-note",  "Note"),
    "[WARN]": ("callout-warn",  "Warning"),
    "[LAB]":  ("callout-lab",   "Lab Exercise"),
    "[SOC]":  ("callout-soc",   "SOC Tip"),
    "[TIP]":  ("callout-tip",   "Tip"),
}

def process_callouts(html: str) -> str:
    for tag, (css_class, label) in CALLOUT_MAP.items():
        pattern = (
            r'<blockquote>\s*<p>'
            + re.escape(tag)
            + r'\s*(.*?)</p>\s*</blockquote>'
        )
        replacement = (
            f'<div class="callout {css_class}">'
            f'<strong>{label}</strong>\\1</div>'
        )
        html = re.sub(pattern, replacement, html)
    return html

# ── HTML template ──────────────────────────────────────────────────────────────

def render_page(title: str, nav: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — FortiSIEM Advanced Search SQL</title>
  <link rel="stylesheet" href="assets/style.css">
  <link rel="stylesheet" href="{HIGHLIGHT_JS}/styles/atom-one-dark.min.css">
  <script>(function(){{var t=localStorage.getItem('theme');if(t==='dark'||t==='light')document.documentElement.setAttribute('data-theme',t);}})()</script>
</head>
<body>
{nav}
<div class="page-wrapper">
{body}
</div>
<footer>
  FortiSIEM Advanced Search SQL Training &mdash; FortiSIEM 7.4.x &mdash;
  Built with <a href="https://python-markdown.github.io/">Python-Markdown</a>
</footer>
<script src="{HIGHLIGHT_JS}/highlight.min.js"></script>
<script>
  document.querySelectorAll('pre code').forEach(el => {{
    hljs.highlightElement(el);
  }});
  (function() {{
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    function applyTheme(t) {{
      document.documentElement.setAttribute('data-theme', t);
      localStorage.setItem('theme', t);
      btn.textContent = t === 'dark' ? '☀' : '☾';
    }}
    var saved = localStorage.getItem('theme');
    if (saved !== 'dark' && saved !== 'light') saved = 'light';
    applyTheme(saved);
    btn.addEventListener('click', function() {{
      applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    }});
  }})();
</script>
</body>
</html>"""

# ── Build ──────────────────────────────────────────────────────────────────────

def extract_title(md_source: str) -> str:
    for line in md_source.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return "FortiSIEM Advanced Search SQL"

def convert_md(md_source: str) -> str:
    return markdown.markdown(
        md_source,
        extensions=[
            TableExtension(),
            FencedCodeExtension(),
            "toc",
            "attr_list",
        ],
    )

def build():
    SITE_DIR.mkdir(parents=True, exist_ok=True)

    # Copy assets
    if ASSETS_SRC.exists():
        shutil.copytree(ASSETS_SRC, ASSETS_DST, dirs_exist_ok=True)
        print(f"  Copied assets -> {ASSETS_DST}")

    for md_name, html_name, _label in PAGES:
        md_path = DOCS_DIR / md_name
        if not md_path.exists():
            print(f"  SKIP {md_name} (not found)")
            continue

        md_source = md_path.read_text(encoding="utf-8")
        title     = extract_title(md_source)
        body      = convert_md(md_source)
        body      = process_callouts(body)
        nav       = build_nav(html_name)
        page      = render_page(title, nav, body)

        out_path  = SITE_DIR / html_name
        out_path.write_text(page, encoding="utf-8")
        print(f"  Built {md_name} -> {out_path.relative_to(SITE_DIR.parent)}")

    print("\nDone. Open site/index.html in a browser.")

if __name__ == "__main__":
    build()
