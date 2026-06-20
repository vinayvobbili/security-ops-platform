"""Shared "Verify at source" deep-link builders for Sleuth IOC tools.

Each enrichment tool can append a clickable link to the vendor's own UI for the
exact indicator it just reported, so an analyst can click through and confirm
Sleuth's results at the source. This generalizes the CrowdStrike IOC-pivot
pattern (a Falcon Advanced Event Search deep link) to the rest of the IOC tools.

The link target is the REAL (refanged) indicator riding in a URL the analyst
clicks; it is emitted as a markdown link, which:
  - the Webex defang passes leave clickable (link targets are masked), and
  - the synthesis model preserves verbatim (SYNTH_SYSTEM_PROMPT instructs it to
    keep any "Verify at source" / deep link intact when it re-renders the answer).

Every builder returns None when it cannot construct a sensible link (unknown
indicator kind, vendor with no public lookup page) — never a broken URL. Callers
use append_verify() so a None is simply a no-op. All links are https.
"""
import re
from urllib.parse import quote

_LINE = "🔗 Verify at source: [{label}]({url})"


def _refang(value: str) -> str:
    """Undo common defanging so the indicator works as a real URL component."""
    s = (value or "").strip()
    s = s.replace("[dot]", ".").replace("(dot)", ".").replace("{dot}", ".")
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[:]", ":").replace("[at]", "@").replace("(at)", "@")
    s = re.sub(r"h\s*[xX]{2}\s*p", "http", s)        # hxxp / hXXp -> http
    s = re.sub(r"\[(.)\]", r"\1", s)                 # any remaining [x] -> x
    return s.strip()


def _q(value: str) -> str:
    return quote(_refang(value), safe="")


def _line(label: str, url: str):
    return _LINE.format(label=label, url=url) if url else None


def append_verify(text: str, line) -> str:
    """Append a verify-at-source line to a tool's output block; no-op if None."""
    if not line:
        return text
    return f"{text}\n\n{line}"


def virustotal_line(indicator: str, kind: str):
    """kind: 'ip' | 'domain' | 'url' | 'hash'."""
    base = "https://www.virustotal.com/gui"
    paths = {"ip": "ip-address", "domain": "domain", "hash": "file"}
    if kind in paths:
        return _line("Open in VirusTotal", f"{base}/{paths[kind]}/{_q(indicator)}")
    if kind == "url":
        # VT's per-URL page needs an opaque id; the search page resolves any URL.
        return _line("Open in VirusTotal", f"{base}/search/{_q(indicator)}")
    return None


def abuseipdb_line(ip: str):
    return _line("Open in AbuseIPDB", f"https://www.abuseipdb.com/check/{_q(ip)}")


def shodan_line(indicator: str, kind: str):
    """kind: 'ip' | 'domain'."""
    if kind == "ip":
        return _line("Open in Shodan", f"https://www.shodan.io/host/{_q(indicator)}")
    if kind == "domain":
        return _line("Open in Shodan", f"https://www.shodan.io/domain/{_q(indicator)}")
    return None


def urlscan_line(indicator: str):
    """Link to URLScan's search page for the indicator (all scans, not one report)."""
    return _line("Search on URLScan.io", f"https://urlscan.io/search/#{_q(indicator)}")


def threatfox_line(indicator: str):
    """abuse.ch ThreatFox IOC browse search."""
    return _line(
        "Open in abuse.ch ThreatFox",
        f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{_q(indicator)}",
    )


def recorded_future_line(entity_id: str):
    """Intelligence Card for a Recorded Future entity. entity_id is RF's OWN entity
    id from the API (e.g. 'ip:8.8.8.8', 'idn:evil.com', 'hash:...') — guaranteed
    valid, so we link to it rather than guessing a portal URL. None if absent."""
    if not entity_id:
        return None
    return _line(
        "Open in Recorded Future",
        f"https://app.recordedfuture.com/live/sc/entity/{quote(entity_id.strip(), safe='')}",
    )


def qradar_line(aql: str):
    """Deep link to QRadar Log Activity pre-filled with the EXACT AQL a search ran
    (surfaced as result['aql']), so the analyst lands on identical results — no
    copy-paste. None if there is no AQL or no console URL can be built."""
    if not aql:
        return None
    try:
        from src.components.tipper_analyzer.formatters import _get_qradar_console_link
        link = _get_qradar_console_link(aql)
    except Exception:
        return None
    if not link:
        return None
    url, text = link
    return _line(text, url)


def attach_verify(result: dict, line) -> dict:
    """MCP-side counterpart to append_verify (which appends to a string output):
    ride a verify-at-source line in a dict tool result's 'verify_at_source' field.

    The MCP server tools return structured dicts, so there is no output string to
    append to. The full markdown line is carried in the dict instead; the answer
    composer's ensure_verify_links() recovers it from the serialized tool output
    (it matches the ASCII 'Verify at source:' marker, so it survives even if JSON
    serialization unicode-escapes the 🔗). No-op if line is None or result is not
    a dict."""
    if line and isinstance(result, dict):
        result["verify_at_source"] = line
    return result
