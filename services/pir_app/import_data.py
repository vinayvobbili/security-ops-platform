"""
import_data.py  –  One-time import of the XLSX collection matrix into SQLite.
Uses only Python stdlib (zipfile + xml.etree.ElementTree).

Usage:
    python import_data.py
    python import_data.py path/to/other_file.xlsx
"""

import re
import sys
import zipfile
import xml.etree.ElementTree as ET

import db

XLSX_PATH = 'the company_CTI_Collection_Requirements_Matrix_Consolidated.xlsx'
NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'

# Column letter → (source_name, category)  for source columns E–AE
# Column letter → source name (self-contained mapping, matches original XLSX layout)
COL_TO_SOURCE = {
    'E':  'RecordedFuture',
    'F':  'Intel471',
    'G':  'Dataminr',
    'H':  'FlashPoint',
    'I':  'RecordedFuture (Insikt)',
    'J':  'Dataminr (FINTEL)',
    'K':  'Intel471 (FINTEL)',
    'L':  'FlashPoint (FINTEL)',
    'M':  'CrowdStrike (CAO)',
    'N':  'FS-ISAC',
    'O':  'NCFTA',
    'P':  'CISA KEV',
    'Q':  'BlueVoyant',
    'R':  'SIEM',
    'S':  'VulnDB',
    'T':  'EDR',
    'U':  'Email Gateway',
    'V':  'Firewall (PAs)',
    'W':  'Akamai',
    'X':  'Proxy',
    'Y':  'Cloud Logs',
    'Z':  'Endpoint Logs',
    'AA': 'FS-ISAC Sharing',
    'AB': 'Peer Intel / Closed Groups',
    'AC': 'Vendor Briefings',
    'AD': 'Law Enforcement',
    'AE': 'Employee Reports',
}

DATA_START_ROW = 12   # 1-based row index where actual data begins


# ---------------------------------------------------------------------------
# XLSX helpers (pure stdlib)
# ---------------------------------------------------------------------------

def _col_index(letters: str) -> int:
    """Convert column letters (A, B, … AA, AB …) to 0-based index."""
    result = 0
    for ch in letters.upper():
        result = result * 26 + (ord(ch) - ord('A') + 1)
    return result - 1


def _load_shared_strings(zf: zipfile.ZipFile):
    try:
        with zf.open('xl/sharedStrings.xml') as f:
            tree = ET.parse(f)
        strings = []
        for si in tree.findall(f'.//{{{NS}}}si'):
            parts = [t.text or '' for t in si.findall(f'.//{{{NS}}}t')]
            strings.append(''.join(parts))
        return strings
    except KeyError:
        return []


def _cell_value(cell, shared_strings):
    t = cell.get('t')
    v = cell.find(f'{{{NS}}}v')
    if v is None or v.text is None:
        return None
    if t == 's':
        idx = int(v.text)
        return shared_strings[idx] if idx < len(shared_strings) else None
    return v.text


def read_sheet(zf: zipfile.ZipFile, shared_strings, sheet_path='xl/worksheets/sheet1.xml'):
    with zf.open(sheet_path) as f:
        tree = ET.parse(f)
    rows_out = {}   # row_number (1-based) -> {col_letter: value}
    for row_el in tree.findall(f'.//{{{NS}}}row'):
        r_num = int(row_el.get('r'))
        row_data = {}
        for cell in row_el.findall(f'{{{NS}}}c'):
            ref = cell.get('r')
            col_letters = ''.join(ch for ch in ref if ch.isalpha())
            val = _cell_value(cell, shared_strings)
            if val is not None:
                row_data[col_letters] = val
        if row_data:
            rows_out[r_num] = row_data
    return rows_out


# ---------------------------------------------------------------------------
# Requirement ID extraction
# ---------------------------------------------------------------------------

_PIR_RE = re.compile(r'(PIR-\d+)',          re.IGNORECASE)
_EEI_RE = re.compile(r'(EEI-[\d.]+)',       re.IGNORECASE)
_SIR_RE = re.compile(r'(SIR-[\d.]+)',       re.IGNORECASE)


def _extract_id(text: str, pattern: re.Pattern):
    m = pattern.search(text)
    return m.group(1).upper() if m else None


# ---------------------------------------------------------------------------
# Main import logic
# ---------------------------------------------------------------------------

def import_xlsx(xlsx_path=XLSX_PATH):
    db.init_db()

    print(f"[import] Reading {xlsx_path} …")
    with zipfile.ZipFile(xlsx_path) as zf:
        shared = _load_shared_strings(zf)
        rows   = read_sheet(zf, shared)

    print(f"[import] Loaded {len(rows)} non-empty rows from spreadsheet")

    requirements_inserted = 0
    coverage_inserted     = 0

    current_pir_id  = None
    current_eei_id  = None

    # Track already-seen req_ids so we can deduplicate (merged cells repeat)
    seen_req_ids = set()

    for row_num in sorted(rows.keys()):
        if row_num < DATA_START_ROW:
            continue

        row = rows[row_num]

        # Determine what level this row is
        pir_text = row.get('A')
        eei_text = row.get('B')
        sir_text = row.get('C')

        req_id   = None
        req_type = None
        req_text = None
        parent_id = None

        if pir_text and _extract_id(pir_text, _PIR_RE):
            req_id   = _extract_id(pir_text, _PIR_RE)
            req_type = 'PIR'
            req_text = pir_text.strip()
            current_pir_id = req_id
            current_eei_id = None   # reset when new PIR starts

        elif eei_text and _extract_id(eei_text, _EEI_RE):
            req_id   = _extract_id(eei_text, _EEI_RE)
            req_type = 'EEI'
            req_text = eei_text.strip()
            parent_id = current_pir_id
            current_eei_id = req_id

        elif sir_text and _extract_id(sir_text, _SIR_RE):
            req_id   = _extract_id(sir_text, _SIR_RE)
            req_type = 'SIR'
            req_text = sir_text.strip()
            parent_id = current_eei_id or current_pir_id

        if not req_id:
            continue

        if req_id in seen_req_ids:
            continue
        seen_req_ids.add(req_id)

        # Metadata fields
        priority  = row.get('D')
        frequency = row.get('AF')
        owner     = row.get('AG')
        status    = row.get('AH', 'Active')
        notes     = row.get('AI')

        # Insert requirement
        with db.get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO requirements
                   (req_id, req_type, req_text, parent_id,
                    priority, collection_frequency, primary_owner,
                    status, notes)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (req_id, req_type, req_text, parent_id,
                 priority, frequency, owner, status or 'Active', notes)
            )
        requirements_inserted += 1

        # Source coverage (columns E–AE)
        for col_letter, source_name in COL_TO_SOURCE.items():
            val = row.get(col_letter)
            if val:
                with db.get_connection() as conn:
                    conn.execute(
                        """INSERT OR REPLACE INTO source_coverage
                           (req_id, source_name, source_category, coverage_value)
                           VALUES (?,?,?,?)""",
                        (req_id, source_name, '', val)
                    )
                coverage_inserted += 1

    print(f"[import] Done.  Requirements: {requirements_inserted}  "
          f"Coverage cells: {coverage_inserted}")


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else XLSX_PATH
    import_xlsx(path)
