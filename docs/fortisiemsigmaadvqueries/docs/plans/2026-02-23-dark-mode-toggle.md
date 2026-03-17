# Dark Mode Toggle Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a light/dark mode toggle button to the training site nav bar, persisted via `localStorage`, with no flash on reload.

**Architecture:** CSS custom properties under `:root` (light defaults) + `[data-theme="dark"]` override block. JS in `<head>` (no-flash init) and `<body>` (toggle handler). `build.py` injects button and both script blocks at build time.

**Tech Stack:** CSS custom properties, vanilla JS, localStorage, Python f-string templates in `build.py`

---

### Task 1: Refactor `docs/assets/style.css` — CSS custom properties

**Files:**
- Modify: `docs/assets/style.css`

No automated tests for CSS. Verification is visual (Task 3).

---

**Step 1: Replace the entire `docs/assets/style.css` with the refactored version**

Replace the file contents with:

```css
/* =============================================
   FortiSIEM Advanced Search SQL Training Site
   ============================================= */

/* ---- Light mode (default) custom properties ---- */
:root {
  --bg:              #f8f9fa;
  --text:            #1a1a2e;
  --strong:          #0d1b2a;
  --link:            #e94560;
  --link-hover:      #c73652;

  --nav-bg:          #0d1b2a;
  --nav-brand:       #e94560;
  --nav-brand-bdr:   #1e3a5f;
  --nav-link:        #a8c0d6;
  --nav-hover-bg:    #1e3a5f;
  --nav-hover-text:  #ffffff;

  --h1-text:         #0d1b2a;
  --h1-border:       #e94560;
  --h2-text:         #0d1b2a;
  --h2-border:       #dee2e6;
  --h3-text:         #1e3a5f;
  --h4-text:         #1e3a5f;
  --subtitle:        #6c757d;

  --table-head-bg:   #0d1b2a;
  --table-head-text: #ffffff;
  --table-border:    #dee2e6;
  --table-even:      #f0f4f8;
  --table-hover:     #e8eef4;

  --code-bg:         #1e3a5f12;
  --code-text:       #c73652;
  --pre-bg:          #0d1b2a;
  --pre-text:        #cdd6f4;

  --note-bg:         #eff6ff;  --note-bdr:  #3b82f6;  --note-strong:  #1d4ed8;
  --warn-bg:         #fffbeb;  --warn-bdr:  #f59e0b;  --warn-strong:  #b45309;
  --lab-bg:          #f0fdf4;  --lab-bdr:   #10b981;  --lab-strong:   #047857;
  --soc-bg:          #fff1f3;  --soc-bdr:   #e94560;  --soc-strong:   #c73652;
  --tip-bg:          #f5f3ff;  --tip-bdr:   #8b5cf6;  --tip-strong:   #6d28d9;

  --badge-beg-bg:    #d1fae5;  --badge-beg-text:  #065f46;
  --badge-int-bg:    #dbeafe;  --badge-int-text:  #1e40af;
  --badge-adv-bg:    #fce7f3;  --badge-adv-text:  #9d174d;
  --badge-all-bg:    #f3e8ff;  --badge-all-text:  #5b21b6;

  --footer-border:   #dee2e6;
  --footer-text:     #6c757d;

  --toggle-bg:       transparent;
  --toggle-border:   #1e3a5f;
  --toggle-text:     #a8c0d6;
  --toggle-hover-bg: #1e3a5f;
}

/* ---- Dark mode overrides ---- */
[data-theme="dark"] {
  --bg:              #0d1117;
  --text:            #e6edf3;
  --strong:          #e6edf3;
  --link:            #ff7b72;
  --link-hover:      #ffa198;

  --nav-bg:          #010409;
  --nav-brand:       #e94560;
  --nav-brand-bdr:   #21262d;
  --nav-link:        #8b949e;
  --nav-hover-bg:    #161b22;
  --nav-hover-text:  #e6edf3;

  --h1-text:         #e6edf3;
  --h1-border:       #e94560;
  --h2-text:         #e6edf3;
  --h2-border:       #21262d;
  --h3-text:         #79c0ff;
  --h4-text:         #79c0ff;
  --subtitle:        #8b949e;

  --table-head-bg:   #161b22;
  --table-head-text: #e6edf3;
  --table-border:    #21262d;
  --table-even:      #0d1117;
  --table-hover:     #161b22;

  --code-bg:         #30363d;
  --code-text:       #ff7b72;
  --pre-bg:          #0d1117;
  --pre-text:        #e6edf3;

  --note-bg:         #051d2c;  --note-bdr:  #3b82f6;  --note-strong:  #60a5fa;
  --warn-bg:         #2d1b00;  --warn-bdr:  #f59e0b;  --warn-strong:  #fbbf24;
  --lab-bg:          #0a2d1f;  --lab-bdr:   #10b981;  --lab-strong:   #34d399;
  --soc-bg:          #2d0a10;  --soc-bdr:   #e94560;  --soc-strong:   #f87171;
  --tip-bg:          #1a0a2d;  --tip-bdr:   #8b5cf6;  --tip-strong:   #a78bfa;

  --badge-beg-bg:    #0a2d1f;  --badge-beg-text:  #34d399;
  --badge-int-bg:    #051d2c;  --badge-int-text:  #60a5fa;
  --badge-adv-bg:    #2d0a1a;  --badge-adv-text:  #f9a8d4;
  --badge-all-bg:    #1a0a2d;  --badge-all-text:  #c084fc;

  --footer-border:   #21262d;
  --footer-text:     #8b949e;

  --toggle-bg:       transparent;
  --toggle-border:   #30363d;
  --toggle-text:     #8b949e;
  --toggle-hover-bg: #161b22;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 16px;
  line-height: 1.7;
  color: var(--text);
  background: var(--bg);
}

/* ---- Navigation ---- */
nav {
  background: var(--nav-bg);
  padding: 0 2rem;
  display: flex;
  align-items: center;
  gap: 0;
  flex-wrap: wrap;
  box-shadow: 0 2px 8px rgba(0,0,0,0.3);
}

nav .nav-brand {
  color: var(--nav-brand);
  font-weight: 700;
  font-size: 1rem;
  padding: 1rem 1.5rem 1rem 0;
  text-decoration: none;
  white-space: nowrap;
  border-right: 1px solid var(--nav-brand-bdr);
  margin-right: 0.5rem;
}

nav a {
  color: var(--nav-link);
  text-decoration: none;
  padding: 1rem 0.85rem;
  font-size: 0.88rem;
  transition: color 0.2s, background 0.2s;
  white-space: nowrap;
}

nav a:hover, nav a.active {
  color: var(--nav-hover-text);
  background: var(--nav-hover-bg);
}

#theme-toggle {
  margin-left: auto;
  background: var(--toggle-bg);
  border: 1px solid var(--toggle-border);
  color: var(--toggle-text);
  border-radius: 6px;
  padding: 0.3rem 0.65rem;
  font-size: 1rem;
  cursor: pointer;
  transition: background 0.2s, color 0.2s;
  line-height: 1;
}

#theme-toggle:hover {
  background: var(--toggle-hover-bg);
  color: var(--nav-hover-text);
}

/* ---- Page layout ---- */
.page-wrapper {
  max-width: 960px;
  margin: 0 auto;
  padding: 2.5rem 2rem 4rem;
}

/* ---- Headings ---- */
h1 { font-size: 2rem; color: var(--h1-text); margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 3px solid var(--h1-border); }
h2 { font-size: 1.5rem; color: var(--h2-text); margin: 2.5rem 0 0.75rem; padding-bottom: 0.3rem; border-bottom: 1px solid var(--h2-border); }
h3 { font-size: 1.2rem; color: var(--h3-text); margin: 2rem 0 0.5rem; }
h4 { font-size: 1rem; color: var(--h4-text); margin: 1.5rem 0 0.4rem; text-transform: uppercase; letter-spacing: 0.05em; }

.module-subtitle {
  color: var(--subtitle);
  font-size: 1.1rem;
  margin-bottom: 2rem;
}

/* ---- Body text ---- */
p { margin-bottom: 1rem; }
ul, ol { margin: 0.5rem 0 1rem 1.5rem; }
li { margin-bottom: 0.3rem; }
strong { color: var(--strong); }
a { color: var(--link); }
a:hover { color: var(--link-hover); }

/* ---- Tables ---- */
table {
  width: 100%;
  border-collapse: collapse;
  margin: 1.5rem 0;
  font-size: 0.9rem;
}
th {
  background: var(--table-head-bg);
  color: var(--table-head-text);
  padding: 0.65rem 1rem;
  text-align: left;
  font-weight: 600;
}
td {
  padding: 0.6rem 1rem;
  border-bottom: 1px solid var(--table-border);
  vertical-align: top;
}
tr:nth-child(even) td { background: var(--table-even); }
tr:hover td { background: var(--table-hover); }

/* ---- Code ---- */
code {
  font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", Consolas, monospace;
  font-size: 0.88em;
  background: var(--code-bg);
  color: var(--code-text);
  padding: 0.15em 0.4em;
  border-radius: 4px;
}

pre {
  background: var(--pre-bg);
  border-radius: 8px;
  padding: 1.25rem 1.5rem;
  overflow-x: auto;
  margin: 1.2rem 0;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

pre code {
  background: none;
  color: var(--pre-text);
  padding: 0;
  font-size: 0.88rem;
  line-height: 1.6;
}

/* ---- Callout boxes ---- */
.callout {
  border-left: 4px solid;
  padding: 1rem 1.25rem;
  margin: 1.5rem 0;
  border-radius: 0 6px 6px 0;
}

.callout-note   { border-color: var(--note-bdr); background: var(--note-bg); }
.callout-warn   { border-color: var(--warn-bdr); background: var(--warn-bg); }
.callout-lab    { border-color: var(--lab-bdr);  background: var(--lab-bg);  }
.callout-soc    { border-color: var(--soc-bdr);  background: var(--soc-bg);  }
.callout-tip    { border-color: var(--tip-bdr);  background: var(--tip-bg);  }

.callout strong { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.06em; }
.callout-note   strong { color: var(--note-strong); }
.callout-warn   strong { color: var(--warn-strong); }
.callout-lab    strong { color: var(--lab-strong);  }
.callout-soc    strong { color: var(--soc-strong);  }
.callout-tip    strong { color: var(--tip-strong);  }

/* ---- Skill level badge ---- */
.level-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 1rem;
}
.level-beginner     { background: var(--badge-beg-bg); color: var(--badge-beg-text); }
.level-intermediate { background: var(--badge-int-bg); color: var(--badge-int-text); }
.level-advanced     { background: var(--badge-adv-bg); color: var(--badge-adv-text); }
.level-all          { background: var(--badge-all-bg); color: var(--badge-all-text); }

/* ---- Footer ---- */
footer {
  text-align: center;
  padding: 2rem;
  color: var(--footer-text);
  font-size: 0.85rem;
  border-top: 1px solid var(--footer-border);
  margin-top: 4rem;
}
```

**Step 2: Verify the file saved correctly**

Open `docs/assets/style.css` and confirm:
- `:root` block at the top with `--bg`, `--text`, `--nav-bg`, etc.
- `[data-theme="dark"]` block immediately after `:root`
- All property declarations use `var(--...)` — no bare hex values remain except inside the variable blocks

**Step 3: Commit**

```bash
git add docs/assets/style.css
git commit -m "refactor: extract all CSS colours to custom properties, add dark mode vars"
```

---

### Task 2: Modify `scripts/build.py` — toggle button + JS blocks

**Files:**
- Modify: `scripts/build.py`

---

**Step 1: Add the toggle button to `build_nav()`**

Current `build_nav()` (lines 41–51) returns a string ending with `"\n</nav>"`. Add the button before the closing tag.

Find:
```python
        + "\n</nav>"
    )
```

Replace with:
```python
        + "\n  <button id=\"theme-toggle\" aria-label=\"Toggle dark mode\">&#9790;</button>"
        + "\n</nav>"
    )
```

The entity `&#9790;` is the crescent moon ☾ (default light-mode icon). The JS handler will swap it to &#9728; (☀) in dark mode.

**Step 2: Add no-flash `<script>` to `<head>` in `render_page()`**

Current `<head>` ends with (lines 87–88):
```python
  <link rel="stylesheet" href="assets/style.css">
  <link rel="stylesheet" href="{HIGHLIGHT_JS}/styles/atom-one-dark.min.css">
</head>
```

Replace with:
```python
  <link rel="stylesheet" href="assets/style.css">
  <link rel="stylesheet" href="{HIGHLIGHT_JS}/styles/atom-one-dark.min.css">
  <script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t);}})()</script>
</head>
```

Note the doubled braces `{{` and `}}` because this is inside a Python f-string.

**Step 3: Add toggle handler JS to bottom of `<body>` in `render_page()`**

Current `<body>` ends with (lines 99–105):
```python
<script src="{HIGHLIGHT_JS}/highlight.min.js"></script>
<script>
  document.querySelectorAll('pre code').forEach(el => {{
    hljs.highlightElement(el);
  }});
</script>
</body>
```

Replace with:
```python
<script src="{HIGHLIGHT_JS}/highlight.min.js"></script>
<script>
  document.querySelectorAll('pre code').forEach(el => {{
    hljs.highlightElement(el);
  }});
  (function() {{
    var btn = document.getElementById('theme-toggle');
    function applyTheme(t) {{
      document.documentElement.setAttribute('data-theme', t);
      localStorage.setItem('theme', t);
      btn.textContent = t === 'dark' ? '\u2600' : '\u263e';
    }}
    var saved = localStorage.getItem('theme') || 'light';
    applyTheme(saved);
    btn.addEventListener('click', function() {{
      applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    }});
  }})();
</script>
</body>
```

Unicode escapes: `\u2600` = ☀ (sun, shown in dark mode), `\u263e` = ☾ (crescent, shown in light mode).

**Step 4: Verify the edited `build.py` looks correct**

Read `scripts/build.py` and confirm:
- `build_nav()` ends with the `<button id="theme-toggle">` line before `</nav>`
- `render_page()` `<head>` has the inline no-flash script after the stylesheet links
- `render_page()` `<body>` has the `applyTheme` IIFE after the highlight.js init block
- All `{` and `}` inside JS code are doubled (`{{` / `}}`) for f-string escaping

**Step 5: Commit**

```bash
git add scripts/build.py
git commit -m "feat: inject dark mode toggle button and JS into build template"
```

---

### Task 3: Rebuild and verify

**Files:**
- Run: `python3 scripts/build.py`
- Check: `site/*.html` (6 files rebuilt)

---

**Step 1: Run the build**

```bash
python3 scripts/build.py
```

Expected output:
```
  Copied assets -> .../site/assets
  Built 00-introduction.md -> site/index.html
  Built 01-beginner.md -> site/beginner.html
  Built 02-intermediate.md -> site/intermediate.html
  Built 03-advanced.md -> site/advanced.html
  Built 04-soc-workflow.md -> site/soc-workflow.html
  Built 05-reference.md -> site/reference.html

Done. Open site/index.html in a browser.
```

If any Python error appears, debug before proceeding.

**Step 2: Spot-check the generated HTML**

Open `site/index.html` in a text editor and confirm all three injected pieces are present:

1. In `<head>` — the no-flash script (search for `localStorage.getItem`):
   ```html
   <script>(function(){var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t);})()</script>
   ```

2. In `<nav>` — the toggle button (search for `theme-toggle`):
   ```html
   <button id="theme-toggle" aria-label="Toggle dark mode">☾</button>
   ```

3. At the bottom of `<body>` — the `applyTheme` function (search for `applyTheme`):
   ```html
   function applyTheme(t) {
   ```

**Step 3: Open `site/index.html` in a browser and manually verify**

Checklist:
- [ ] Toggle button (☾) visible at the right end of the nav bar
- [ ] Clicking toggles the page to dark mode (all backgrounds, text, callouts flip)
- [ ] Button icon changes to ☀ in dark mode
- [ ] Reloading the page in dark mode — no flash of light mode before dark kicks in
- [ ] Navigating to `beginner.html` while in dark mode — arrives in dark mode
- [ ] Clicking ☀ returns to light mode; icon returns to ☾
- [ ] highlight.js syntax highlighting is readable in both modes

**Step 4: Commit**

```bash
git add site/
git commit -m "build: regenerate all 6 HTML pages with dark mode toggle"
```

---

## Summary of all commits in this feature

1. `refactor: extract all CSS colours to custom properties, add dark mode vars`
2. `feat: inject dark mode toggle button and JS into build template`
3. `build: regenerate all 6 HTML pages with dark mode toggle`
