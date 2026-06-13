"""Static analysis of email attachments — safe, no execution.

Given raw attachment bytes, computes hashes, identifies the true file type
(content-based, not extension), measures entropy, and scans for the high-signal
tells an analyst looks for: Office macros, PDF active content, embedded URLs,
double extensions. Nothing is executed, opened, or rendered — bytes are only
read and pattern-matched.

Pairs with ``services.wildfire`` (hash-verdict lookup / detonation) and
``services.virustotal`` (hash reputation) for the dynamic/reputation layer.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

try:
    import magic  # python-magic — available in the venv
    _HAS_MAGIC = True
except Exception:  # pragma: no cover
    _HAS_MAGIC = False

_URL_RE = re.compile(rb"https?://[^\s<>\"'\)\]\x00]{4,300}", re.IGNORECASE)

# PDF active-content markers worth flagging.
_PDF_MARKERS = {
    b"/JavaScript": "JavaScript",
    b"/JS": "JS",
    b"/OpenAction": "auto-run OpenAction",
    b"/AA": "additional actions",
    b"/Launch": "Launch action",
    b"/EmbeddedFile": "embedded file",
}

_RISKY_EXTS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".jar", ".bat", ".cmd",
    ".ps1", ".hta", ".lnk", ".iso", ".img", ".html", ".htm", ".docm", ".xlsm",
    ".pptm", ".zip", ".rar", ".7z", ".gz", ".ace", ".msi", ".wsf",
}
# Extensions that should never carry executable payloads — a double-extension or
# magic mismatch here is a strong lure tell.
_BENIGN_LOOKING = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".gif"}


def _entropy(data: bytes) -> float:
    """Shannon entropy (bits/byte). >7.2 suggests packing/encryption."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 2)


def _detect_macros(data: bytes, filename: str) -> List[str]:
    """Heuristic Office-macro detection without oletools.

    OLE (.doc/.xls/.ppt): magic D0CF11E0 + a 'VBA'/'vbaProject' stream marker.
    OOXML (.docm/.xlsm): a zip (PK) containing 'vbaProject.bin'.
    """
    flags: List[str] = []
    if data[:4] == b"\xd0\xcf\x11\xe0":  # OLE compound document
        if b"VBA" in data or b"vbaProject" in data or b"Macros" in data:
            flags.append("Contains VBA macros (OLE)")
    if data[:2] == b"PK":  # zip-based OOXML
        if b"vbaProject.bin" in data:
            flags.append("Contains VBA macros (OOXML vbaProject.bin)")
        if b"externalLink" in data:
            flags.append("Contains external links/references")
    # Auto-exec macro names are a strong tell if present in the byte stream.
    for marker in (b"Auto_Open", b"AutoOpen", b"Document_Open", b"Workbook_Open"):
        if marker in data:
            flags.append(f"Auto-exec macro hook: {marker.decode()}")
            break
    return flags


def _detect_pdf_active(data: bytes) -> List[str]:
    if data[:5] != b"%PDF-":
        return []
    return [label for marker, label in _PDF_MARKERS.items() if marker in data]


def analyze_attachment(file_bytes: bytes, filename: str, content_type: str = "") -> Dict[str, Any]:
    """Static analysis of one attachment. Never executes the file."""
    name = filename or "(unnamed)"
    ext = os.path.splitext(name)[1].lower()
    size = len(file_bytes)

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    md5 = hashlib.md5(file_bytes).hexdigest()

    true_type = ""
    if _HAS_MAGIC and file_bytes:
        try:
            true_type = magic.from_buffer(file_bytes[:8192])
        except Exception:
            true_type = ""

    urls = []
    for m in _URL_RE.findall(file_bytes[:200_000]):
        u = m.decode("latin-1", "replace").rstrip(".,;)\"'>")
        if u not in urls:
            urls.append(u)

    flags: List[str] = []
    flags += _detect_macros(file_bytes, name)
    flags += _detect_pdf_active(file_bytes)

    ent = _entropy(file_bytes[:1_000_000])
    if ent >= 7.2 and ext not in {".zip", ".rar", ".7z", ".gz", ".png", ".jpg", ".gif", ".pdf"}:
        flags.append(f"High entropy ({ent}) — possibly packed/encrypted")

    # Double extension, e.g. invoice.pdf.exe
    base = name[:-len(ext)] if ext else name
    if os.path.splitext(base)[1].lower() in _BENIGN_LOOKING and ext in _RISKY_EXTS:
        flags.append(f"Double extension: looks like {os.path.splitext(base)[1]} but is {ext}")

    # Magic vs extension mismatch (benign-looking ext, executable content).
    tl = true_type.lower()
    if ext in _BENIGN_LOOKING and ("executable" in tl or "pe32" in tl or "ms-dos" in tl):
        flags.append(f"Type mismatch: extension {ext} but content is {true_type}")

    risky = ext in _RISKY_EXTS

    return {
        "filename": name,
        "extension": ext,
        "content_type": content_type,
        "size": size,
        "sha256": sha256,
        "md5": md5,
        "true_type": true_type,
        "entropy": ent,
        "embedded_urls": urls[:30],
        "static_flags": flags,
        "risky_extension": risky,
    }
