"""Shared helper to expose journalctl output for vendor sidecar services.

Each vendor blueprint calls `register_vendor_logs(...)` to mount two routes
on its own URL prefix:

  /<app_slug>/logs        → HTML viewer page (auto-refreshing tail)
  /<app_slug>/logs/data   → JSON {lines: [...]} fed from
                            `journalctl --user -u <service> -n 500 --no-pager`

Polling (not SSE) because Waitress buffers long-lived responses; a 2-second
poll of ~500 lines is well under any throughput we care about and survives
worker restarts cleanly.
"""

import subprocess
from flask import jsonify, render_template_string


_LOGS_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ title }} — Logs</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #0b0e14; color: #d8dee9; }
  .header { display: flex; align-items: center; gap: 16px; padding: 10px 16px;
            background: #11151c; border-bottom: 1px solid #1f2630; position: sticky;
            top: 0; z-index: 1; font-size: 13px; }
  .header strong { font-size: 14px; color: #eceff4; }
  .header .svc { color: #8fbcbb; }
  .header .spacer { flex: 1; }
  .header a { color: #88c0d0; text-decoration: none; }
  .header label { display: flex; gap: 6px; align-items: center; cursor: pointer; }
  #log { padding: 12px 16px; font-size: 12.5px; line-height: 1.55;
         white-space: pre-wrap; word-break: break-word; }
  .line { display: block; }
  .lvl-INFO     { color: #a3be8c; }
  .lvl-DEBUG    { color: #5e6b7a; }
  .lvl-WARNING  { color: #ebcb8b; }
  .lvl-ERROR    { color: #bf616a; }
  .lvl-CRITICAL { color: #bf616a; font-weight: 600; }
  #status { color: #5e6b7a; font-size: 12px; }
</style>
</head>
<body>
<div class="header">
  <strong>{{ title }} — logs</strong>
  <span class="svc">{{ service }}</span>
  <span class="spacer"></span>
  <span id="status">connecting…</span>
  <label><input id="follow" type="checkbox" checked> follow</label>
  <a href="{{ back_href }}">← back</a>
</div>
<pre id="log"></pre>
<script>
  const logEl = document.getElementById('log');
  const statusEl = document.getElementById('status');
  const followEl = document.getElementById('follow');
  const dataUrl = "{{ data_url }}";
  let lastSig = "";

  function classify(line) {
    if (/\\bCRITICAL\\b/.test(line)) return 'lvl-CRITICAL';
    if (/\\bERROR\\b/.test(line))    return 'lvl-ERROR';
    if (/\\bWARNING\\b/.test(line))  return 'lvl-WARNING';
    if (/\\bDEBUG\\b/.test(line))    return 'lvl-DEBUG';
    if (/\\bINFO\\b/.test(line))     return 'lvl-INFO';
    return '';
  }

  async function poll() {
    try {
      const r = await fetch(dataUrl, {cache: 'no-store'});
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      const sig = data.lines.length + ':' + (data.lines[data.lines.length-1] || '');
      if (sig !== lastSig) {
        logEl.replaceChildren();
        for (const ln of data.lines) {
          const span = document.createElement('span');
          span.className = 'line ' + classify(ln);
          span.textContent = ln + '\\n';
          logEl.appendChild(span);
        }
        lastSig = sig;
        if (followEl.checked) window.scrollTo(0, document.body.scrollHeight);
      }
      statusEl.textContent = 'live · ' + data.lines.length + ' lines · ' +
        new Date().toLocaleTimeString();
    } catch (e) {
      statusEl.textContent = 'error: ' + e.message;
    }
  }

  poll();
  setInterval(poll, 2000);
</script>
</body>
</html>"""


def _journalctl_lines(service: str, n: int = 500) -> list[str]:
    try:
        out = subprocess.run(
            ["journalctl", "--user", "-u", service,
             "-n", str(n), "--no-pager",
             "--output=short-iso", "--no-hostname"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return [f"[journalctl unavailable: {exc}]"]
    if out.returncode != 0:
        return [f"[journalctl exit {out.returncode}]", out.stderr.strip() or "(no stderr)"]
    return out.stdout.splitlines()


def register_vendor_logs(blueprint, app_slug: str, service_name: str, title: str) -> None:
    """Mount /<app_slug>/logs and /<app_slug>/logs/data on the blueprint."""

    page_endpoint = f"{app_slug.replace('-', '_')}_logs"
    data_endpoint = f"{app_slug.replace('-', '_')}_logs_data"

    @blueprint.route(f"/{app_slug}/logs", endpoint=page_endpoint)
    def _logs_page():
        return render_template_string(
            _LOGS_HTML,
            title=title,
            service=service_name,
            back_href=f"/{app_slug}",
            data_url=f"/{app_slug}/logs/data",
        )

    @blueprint.route(f"/{app_slug}/logs/data", endpoint=data_endpoint)
    def _logs_data():
        return jsonify({"service": service_name, "lines": _journalctl_lines(service_name)})
