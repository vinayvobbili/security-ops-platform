"""Post-processors for Webex-bound bot responses.

- convert_markdown_tables: Webex doesn't render GFM tables, so fold them into
  bold headers + bullet lists.
- linkify_xsoar_tickets: turn bare ticket/incident references into clickable
  XSOAR case links.
- defang_urls: neutralize bare clickable http(s)/ftp URLs (IOC click-risk).
- defang: defang a single known indicator value (domain/IP/URL) a tool echoes.
- defang_ips: defang every bare IPv4 so Webex can't auto-link it.
- eastern_timestamps: rewrite UTC/ISO timestamps to Eastern at send time.

The linkify/defang/timestamp passes protect existing markdown links and inline
code spans so we never re-link, defang, or rewrite an intentional deep-link
target. They run at send time (after the model/synthesizer composes the answer),
so they hold regardless of which tool or LLM produced the text.
"""

import re
from datetime import datetime
from zoneinfo import ZoneInfo

# --- shared masking so we never touch existing links / code spans ----------

_MD_LINK_RE = re.compile(r'\[[^\]]*\]\([^)]*\)')
_CODE_SPAN_RE = re.compile(r'`[^`]+`')
_PLACEHOLDER_RE = re.compile('\x00(\\d+)\x00')


def _protect_and_transform(text, transform):
    """Mask markdown links + inline code, apply transform to the rest, restore.

    Keeps intentional deep links (e.g. [X#123](.../caseinfoid/123)) and code
    spans untouched while linkify/defang operate only on plain prose.
    """
    placeholders = []

    def _mask(m):
        placeholders.append(m.group(0))
        return f'\x00{len(placeholders) - 1}\x00'

    masked = _CODE_SPAN_RE.sub(_mask, text)
    masked = _MD_LINK_RE.sub(_mask, masked)
    masked = transform(masked)
    return _PLACEHOLDER_RE.sub(lambda m: placeholders[int(m.group(1))], masked)


# --- XSOAR ticket linkification --------------------------------------------

# "ticket 1224966", "incident #1224966", "case 1224966", "X#1224966",
# "#1224966". 6-8 digits keeps it to plausible case IDs.
_TICKET_RE = re.compile(
    r'(?P<kw>(?:\b(?:ticket|incident|case)\s+#?)|X#|(?<![\w/])#)(?P<id>\d{6,8})\b',
    re.IGNORECASE,
)


def linkify_xsoar_tickets(text: str, ui_base: str) -> str:
    """Turn bare XSOAR ticket/incident references into clickable case links."""
    if not text or not ui_base:
        return text
    base = ui_base.rstrip('/')

    def _do(s):
        return _TICKET_RE.sub(
            lambda m: f"{m.group('kw')}[{m.group('id')}]({base}/Custom/caseinfoid/{m.group('id')})",
            s,
        )

    return _protect_and_transform(text, _do)


# --- IOC URL defang ---------------------------------------------------------

_BARE_URL_RE = re.compile(r'\b(https?|ftp)://[^\s<>()\[\]"\']+', re.IGNORECASE)


def defang_urls(text: str) -> str:
    """Defang bare clickable URLs (hxxp://evil[.]com) so they can't be clicked.

    Only touches raw http(s)/ftp URLs in prose; markdown link targets and code
    spans (which carry our intentional deep links) are left clickable.
    Scheme-less IOC domains are handled by the model (it knows which domain is
    the suspect indicator vs. an internal AD/infra domain).
    """
    if not text:
        return text

    def _do(s):
        def _repl(m):
            scheme = m.group(1)
            rest = m.group(0)[len(scheme):]  # "://..."
            defanged_scheme = scheme.lower().replace('http', 'hxxp').replace('ftp', 'fxp')
            return defanged_scheme + rest.replace('.', '[.]')

        return _BARE_URL_RE.sub(_repl, s)

    return _protect_and_transform(text, _do)


def defang(indicator: str) -> str:
    """Defang a single KNOWN indicator (domain / IP / URL) for safe display.

    Companion to defang_urls: that pass scans prose for scheme-bearing URLs and
    deliberately leaves scheme-less domains to the model. This is for a value a
    tool already knows is the suspect IOC — including a bare domain/IP — so any
    indicator-emitting tool (CrowdStrike, VirusTotal, urlscan, AbuseIPDB, …) can
    neutralize the indicator it echoes back, regardless of the model.

    Idempotent: already-defanged input is returned unchanged so it never becomes
    evil[[.]]com.
    """
    if not indicator:
        return indicator
    s = str(indicator).strip()
    if '[.]' in s or 'hxxp' in s.lower() or 'fxp://' in s.lower():
        return s  # already defanged
    s = (s.replace('https://', 'hxxps://')
          .replace('http://', 'hxxp://')
          .replace('ftp://', 'fxp://'))
    return s.replace('.', '[.]')


# --- bare IPv4 defang (stop Webex auto-linking dotted quads) ----------------

_BARE_IPV4_RE = re.compile(
    r'(?<![\w.])'
    r'(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?![\w.])'
)


def defang_ips(text: str) -> str:
    """Defang every bare IPv4 address so Webex can't turn it into a link.

    Webex hyperlinks any dotted quad, including internal host IPs, and analysts
    asked for non-clickable IPs in replies. Markdown link targets and code spans
    are protected by _protect_and_transform, so IPs inside intentional deep links
    stay intact; IPs already inside a defanged URL carry '[.]' and won't match.
    """
    if not text:
        return text

    def _do(s):
        return _BARE_IPV4_RE.sub(lambda m: m.group(0).replace('.', '[.]'), s)

    return _protect_and_transform(text, _do)


# --- UTC -> Eastern timestamp normalization --------------------------------

_ET = ZoneInfo("America/New_York")
_UTC = ZoneInfo("UTC")

# 2026-06-18 17:20:02 UTC | 2026-06-18T17:20:02Z | 2026-06-18T17:20:02+00:00
_UTC_TS_RE = re.compile(
    r'(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})'
    r'[ T](?P<h>\d{2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?(?:\.\d+)?'
    r'\s*(?:Z|UTC|\+00:?00)\b',
    re.IGNORECASE,
)


def eastern_timestamps(text: str) -> str:
    """Rewrite UTC/ISO timestamps in prose to Eastern: MM/DD/YYYY H:MM AM/PM EDT.

    Send-time safety net: tools format their own timestamps in ET, but the synthesis
    final-answer synthesizer can re-render from raw UTC values, so we normalize
    here to guarantee analysts always see Eastern regardless of the source.
    """
    if not text:
        return text

    def _conv(m):
        try:
            dt = datetime(int(m['y']), int(m['mo']), int(m['d']),
                          int(m['h']), int(m['mi']), int(m['s'] or 0),
                          tzinfo=_UTC).astimezone(_ET)
        except ValueError:
            return m.group(0)
        hour = str(int(dt.strftime('%I')))
        return dt.strftime(f'%m/%d/%Y {hour}:%M %p %Z')

    def _do(s):
        return _UTC_TS_RE.sub(_conv, s)

    return _protect_and_transform(text, _do)


def convert_markdown_tables(text: str) -> str:
    """Convert markdown tables in text to bold-header + bullet-list format.

    Handles standard GFM tables like:
        | Role | Analysts |
        |------|----------|
        | Monitoring | Alice, Bob |

    Converts to:
        **Role — Analysts**
        - Monitoring — Alice, Bob
    """
    if not text or '|' not in text:
        return text

    lines = text.split('\n')
    result = []
    i = 0

    while i < len(lines):
        # Check if this line looks like a table row: starts/ends with |
        if _is_table_row(lines[i]):
            # Collect the full table block
            table_start = i
            table_lines = []
            while i < len(lines) and _is_table_row(lines[i]):
                table_lines.append(lines[i])
                i += 1

            # Need at least a header + separator + 1 data row (3 lines)
            # or header + 1 data row (2 lines, no separator)
            if len(table_lines) >= 2:
                converted = _convert_table(table_lines)
                result.append(converted)
            else:
                # Not a real table, keep as-is
                for line in table_lines:
                    result.append(line)
        else:
            result.append(lines[i])
            i += 1

    return '\n'.join(result)


def _is_table_row(line: str) -> bool:
    """Check if a line looks like a markdown table row."""
    stripped = line.strip()
    return stripped.startswith('|') and stripped.endswith('|') and len(stripped) > 2


def _is_separator_row(line: str) -> bool:
    """Check if a line is a table separator (|---|---|)."""
    stripped = line.strip().strip('|')
    # Separator cells contain only dashes, colons, and spaces
    return bool(re.match(r'^[\s\-:|]+$', stripped))


def _parse_row(line: str) -> list[str]:
    """Parse a table row into cell values."""
    stripped = line.strip()
    # Remove leading/trailing pipes and split
    if stripped.startswith('|'):
        stripped = stripped[1:]
    if stripped.endswith('|'):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split('|')]


def _convert_table(table_lines: list[str]) -> str:
    """Convert a collected markdown table into Webex-friendly format."""
    # Identify header and data rows (skip separator)
    rows = []
    header = None
    for line in table_lines:
        if _is_separator_row(line):
            continue
        cells = _parse_row(line)
        if header is None:
            header = cells
        else:
            rows.append(cells)

    if not header:
        return '\n'.join(table_lines)

    parts = []

    if rows:
        # Multi-row table: bold header, then bullet list for each row
        # Use " — " (em-dash) to join columns within each line
        parts.append(f"**{' — '.join(header)}**")
        for row in rows:
            # Pad row to header length if needed
            while len(row) < len(header):
                row.append('')
            parts.append(f"- {' — '.join(row)}")
    else:
        # Header-only table (unlikely but handle it)
        parts.append(f"**{' — '.join(header)}**")

    return '\n'.join(parts)
