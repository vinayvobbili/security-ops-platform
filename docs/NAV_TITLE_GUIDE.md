# Top Bar Title Integration Guide

Any page can display a large animated gradient title inside the fixed top navigation.

## How to Use
1. Include the shared `top_bar.html` early in your template body.
2. Set these Jinja variables before including it:
   - `page_title`: HTML (icons + text). Use `aria-hidden="true"` on purely decorative emoji/icons.
   - `page_title_class`: Usually `dashboard-title` for gradient style (defined globally in `common.css`).
   - `page_title_aria`: Plain descriptive string for screen readers (falls back to "Page title" if omitted).
   - Optionally add `nav-title-large` to `<body>` class to expand nav height for large titles.

Example:
```jinja2
<body class="nav-title-large">
{% set page_title = "<span class='title-icon left' aria-hidden='true'>📊</span><span>Security Operations Metrics</span><span class='title-icon right' aria-hidden='true'>🛡️</span>" %}
{% set page_title_class = 'dashboard-title' %}
{% set page_title_aria = 'Security Operations Metrics dashboard' %}
{% include 'top_bar.html' %}
```

## Accessibility Notes
- Provide a concise `page_title_aria` for assistive tech.
- Keep visible text inside a single `<span>` to avoid repetition in screen readers.
- Icons/emoji should have `aria-hidden="true"` unless they convey essential meaning.

## Styling
- Gradient, animation, sizing, and responsive behavior live in `web/static/css/common.css`.
- Do NOT redefine `.dashboard-title` or `.title-icon` in page-specific CSS.
- Use `nav-title-large` body class only when the title needs extra vertical space; omit for compact pages.

## Dark Mode
- The title automatically adapts via the dark-mode filter in `common.css`.

## Gotchas
- Avoid duplicating the title text (once visually, once for SR) — use `page_title_aria` instead.
- If the nav looks cramped on small screens, consider shorter text or omit one icon.

Happy theming!
