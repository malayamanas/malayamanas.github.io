# Design: Dark Mode Toggle

**Date:** 2026-02-23
**Status:** Approved

## Summary

Add a light/dark mode toggle button to the training site nav bar. Preference persists via `localStorage`. Implemented using CSS custom properties + `data-theme` attribute on `<html>`.

## Approach

**Option A — CSS custom properties + `data-theme` attribute** (selected)

All colour values refactored to CSS variables under `:root` (light defaults). A `[data-theme="dark"]` override block provides dark colours. JS toggles the attribute and persists to `localStorage`. A no-flash initialiser script in `<head>` applies the saved theme before first paint.

## Changes Required

### 1. `docs/assets/style.css`
- Extract all hardcoded hex colour values into CSS custom properties under `:root`
- Add `[data-theme="dark"]` block with dark colour overrides for:
  - Page background, body text
  - Nav background, nav link colours
  - Headings
  - Tables (header, row backgrounds, hover)
  - Inline `code` background and colour
  - `pre` block background
  - All 5 callout box backgrounds (note, warn, lab, soc, tip)
  - Level badge backgrounds
  - Footer border and text
  - Link colours

### 2. `scripts/build.py` — `render_page()` function
- Add `<button id="theme-toggle">` to the right end of the nav bar
- Add no-flash `<script>` block in `<head>` (reads localStorage, sets data-theme before paint)
- Add toggle handler JS at bottom of `<body>` (after highlight.js init):
  - `applyTheme(t)` sets data-theme, saves to localStorage, updates button icon
  - Button shows ☾ in light mode, ☀ in dark mode
  - Initialises from localStorage on load
  - Click handler toggles between light/dark

### 3. Rebuild
- Run `python3 scripts/build.py` to regenerate all 6 HTML pages

## Files NOT Changed
- All 6 `docs/*.md` content files — unchanged
- No new files created

## Success Criteria
- Toggle button visible in nav on all 6 pages
- Clicking toggles light ↔ dark on all content
- Preference survives page reload and navigation between pages
- No flash of wrong theme on page load
- highlight.js syntax highlighting remains readable in both modes
