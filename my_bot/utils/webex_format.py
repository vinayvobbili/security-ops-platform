"""Post-processor to convert markdown tables into Webex-compatible formatting.

Webex doesn't render GFM markdown tables (| col | col |), so we convert them
to bold headers with bullet lists, which Webex renders nicely.
"""

import re


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
