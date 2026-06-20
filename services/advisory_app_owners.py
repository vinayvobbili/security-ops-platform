"""Map a cs-advisory to the *owners* of the applications it actually affects.

The chain is:

    advisory --(CVE / package)--> Veracode SCA exposure --(app name)-->
    EAI application inventory --> business owners (LOB, CIO, Officer)

Veracode tells us *which* applications carry the vulnerable component but only by
Veracode profile name; it has no owner data. The EAI inventory (``V_APP_INFO``,
cached locally by :mod:`services.cgr`) carries the line-of-business, criticality,
internet-facing flag, CIO and accountable Officer — but is keyed by EAI code, not
by name. So the join is **by name**: each Veracode app name is normalized and
matched against the EAI short/long names.

This is heuristic — Veracode profile names don't always equal the EAI registered
name — so every match carries a confidence and unmatched apps are reported
honestly rather than silently dropped. Vuln management uses this to route an
advisory straight to the people who own the exposed apps instead of hunting
through two portals.

``app_owners(adv)`` never raises; on any failure it returns a result dict with an
``error`` and ``exposed=False`` so the capability tile degrades gracefully.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# How many owner rows to surface in the tile / evidence before truncating.
_MAX_APPS = 25


# --------------------------------------------------------------------------- #
# Name normalization + matching
# --------------------------------------------------------------------------- #
_STOP = {
    "app", "application", "applications", "system", "systems", "service",
    "services", "platform", "the", "and", "of", "for", "the company", "ml",
    "prod", "production", "portal", "tool", "web", "api",
}


def _norm(name: Optional[str]) -> str:
    """Lowercase, drop punctuation, collapse whitespace — for exact comparison."""
    if not name:
        return ""
    s = re.sub(r"[^a-z0-9]+", " ", str(name).lower())
    return re.sub(r"\s+", " ", s).strip()


def _tokens(name: Optional[str]) -> frozenset:
    """Distinctive lowercase tokens of a name (stop-words removed)."""
    return frozenset(t for t in _norm(name).split() if t and t not in _STOP)


class _EaiNameIndex:
    """Lookup of EAI records by normalized short/long name + token sets."""

    def __init__(self, eai_map: Dict[str, dict]):
        self._by_id: Dict[str, dict] = {}
        self._exact: Dict[str, dict] = {}
        self._token_recs: List[Tuple[frozenset, dict]] = []
        for rec in eai_map.values():
            eid = str(rec.get("eai_id") or "").strip()
            if eid:
                self._by_id.setdefault(eid, rec)
            for field in ("app_name", "app_long"):
                n = _norm(rec.get(field))
                if n:
                    self._exact.setdefault(n, rec)
            toks = _tokens(rec.get("app_name")) or _tokens(rec.get("app_long"))
            if toks:
                self._token_recs.append((toks, rec))

    def match(self, name: str) -> Tuple[Optional[dict], str, float]:
        """Return ``(eai_rec | None, via, confidence)`` for a Veracode app name."""
        # Veracode profile names are typically "<EAI code>_<app name>" — the
        # leading numeric prefix IS the EAI code, so try that first for an exact,
        # highest-confidence join before falling back to name matching.
        m = re.match(r"\s*(\d{2,})[\s_\-:]", str(name or ""))
        if m:
            rec = self._by_id.get(m.group(1))
            if rec is not None:
                return rec, "EAI code", 0.99
        n = _norm(name)
        if not n:
            return None, "", 0.0
        rec = self._exact.get(n)
        if rec is not None:
            return rec, "exact name", 0.95
        # Token-overlap fallback: best Jaccard over distinctive tokens.
        q = _tokens(name)
        if not q:
            return None, "", 0.0
        best: Optional[dict] = None
        best_score = 0.0
        for toks, rec in self._token_recs:
            inter = len(q & toks)
            if not inter:
                continue
            score = inter / len(q | toks)
            if score > best_score:
                best_score, best = score, rec
        # Require a solid overlap to claim a fuzzy match.
        if best is not None and best_score >= 0.5:
            return best, "name tokens", round(0.45 + best_score * 0.4, 2)
        return None, "", 0.0


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def _veracode_app_names(adv: dict) -> List[str]:
    """Affected-application names per Veracode SCA for this advisory (deduped)."""
    from services.github_advisories import enrich_veracode

    vc = enrich_veracode(adv)
    if not isinstance(vc, dict):
        return []
    names: List[str] = []
    seen = set()
    for axis in ("cves", "packages"):
        for _key, rows in (vc.get(axis) or {}).items():
            for row in rows or []:
                nm = (row.get("application") or "").strip()
                if nm and nm.lower() not in seen:
                    seen.add(nm.lower())
                    names.append(nm)
    return names


def _split_urls(raw: Optional[str]) -> List[str]:
    """Production URLs from the EAI free-text field (comma/semicolon/space split)."""
    if not raw:
        return []
    parts = re.split(r"[\s,;|]+", str(raw).strip())
    out: List[str] = []
    seen = set()
    for p in parts:
        u = p.strip().strip(".,")
        if u and "." in u and u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out[:10]


def _owner_label(rec: dict) -> str:
    """Compact ownership line for an EAI record."""
    bits = []
    officer = (rec.get("officer") or "").strip()
    cio = (rec.get("cio") or "").strip()
    lob = (rec.get("lob") or "").strip()
    if officer:
        bits.append(f"Officer: {officer}")
    if cio:
        bits.append(f"CIO: {cio}")
    if lob:
        bits.append(f"LOB: {lob}")
    return " · ".join(bits) if bits else "owner not recorded in EAI"


def app_owners(adv: dict) -> Dict[str, Any]:
    """Resolve the business owners of the apps this advisory affects.

    Returns a capability-result dict:
    ``{summary_text, exposed, app_count, matched:[...], unmatched:[...],
    owners:[...], error?}``. ``exposed`` is True when at least one affected app
    resolved to an EAI owner — i.e. there's a real person/LOB to route to.
    """
    result: Dict[str, Any] = {
        "exposed": False,
        "app_count": 0,
        "matched": [],
        "unmatched": [],
        "owners": [],
    }
    try:
        names = _veracode_app_names(adv)
    except Exception as e:  # noqa: BLE001
        logger.warning("app_owners: Veracode exposure failed: %s", e)
        result["error"] = f"Veracode exposure lookup failed: {e}"
        result["summary_text"] = "Couldn't determine affected applications (Veracode unavailable)."
        return result

    result["app_count"] = len(names)
    if not names:
        result["summary_text"] = (
            "No applications in the Veracode portfolio carry this advisory's "
            "component (findings-only — not proof of absence), so there are no "
            "app owners to route to yet."
        )
        return result

    try:
        from services.cgr import load_eai_map

        eai_map = load_eai_map()
    except Exception as e:  # noqa: BLE001
        logger.warning("app_owners: EAI inventory unavailable: %s", e)
        result["error"] = f"EAI inventory unavailable: {e}"
        result["unmatched"] = names[:_MAX_APPS]
        result["summary_text"] = (
            f"{len(names)} affected application(s) found, but the EAI owner "
            "inventory is unavailable — can't resolve owners right now."
        )
        return result

    if not eai_map:
        result["unmatched"] = names[:_MAX_APPS]
        result["summary_text"] = (
            f"{len(names)} affected application(s) found, but the EAI inventory "
            "cache is empty — can't resolve owners (refresh the EAI snapshot)."
        )
        return result

    index = _EaiNameIndex(eai_map)
    owner_seen: set = set()
    for nm in names:
        rec, via, conf = index.match(nm)
        if rec is None:
            result["unmatched"].append(nm)
            continue
        entry = {
            "app": nm,
            "eai_id": str(rec.get("eai_id") or "").strip(),
            "eai_name": (rec.get("app_name") or rec.get("app_long") or "").strip(),
            "lob": (rec.get("lob") or "").strip(),
            "criticality": (rec.get("crit_metal") or rec.get("critical_ind") or "").strip(),
            "internet_facing": str(rec.get("internet_facing") or "").strip().lower() == "yes",
            "prod_urls": _split_urls(rec.get("prod_urls")),
            "cio": (rec.get("cio") or "").strip(),
            "officer": (rec.get("officer") or "").strip(),
            "via": via,
            "confidence": conf,
            "owner_label": _owner_label(rec),
        }
        result["matched"].append(entry)
        for who in (entry["officer"], entry["cio"]):
            if who and who.lower() not in owner_seen:
                owner_seen.add(who.lower())
                result["owners"].append(who)

    result["matched"].sort(key=lambda e: (not e["internet_facing"], -e["confidence"]))
    result["matched"] = result["matched"][:_MAX_APPS]
    result["unmatched"] = result["unmatched"][:_MAX_APPS]
    n_matched = len(result["matched"])
    result["exposed"] = n_matched > 0

    ext = sum(1 for e in result["matched"] if e["internet_facing"])
    parts: List[str] = []
    if n_matched:
        parts.append(
            f"{n_matched} affected application(s) mapped to EAI owners"
            + (f" — {ext} internet-facing" if ext else "")
            + "."
        )
        if result["owners"]:
            who = ", ".join(result["owners"][:6])
            more = len(result["owners"]) - 6
            parts.append(f"Owners to route to: {who}" + (f" (+{more} more)" if more > 0 else "") + ".")
    if result["unmatched"]:
        parts.append(
            f"{len(result['unmatched'])} affected app(s) couldn't be matched to an "
            "EAI record by name — verify manually."
        )
    result["summary_text"] = " ".join(parts) or (
        f"{len(names)} affected app(s) found but none matched an EAI owner record."
    )
    return result


def attack_surface(adv: dict) -> Dict[str, Any]:
    """ASM lens: which affected apps are *internet-facing*, and their external URLs.

    Reuses the Veracode→EAI join from :func:`app_owners` and distills it to the
    attack-surface-management view — the externally-reachable footprint tied to
    this advisory, so ASM can confirm whether the vulnerable software sits on the
    perimeter. ``exposed`` is True when at least one affected app is
    internet-facing per EAI.
    """
    base = app_owners(adv)
    matched = base.get("matched") or []
    external = [e for e in matched if e.get("internet_facing")]
    urls: List[str] = []
    seen = set()
    for e in external:
        for u in e.get("prod_urls") or []:
            if u.lower() not in seen:
                seen.add(u.lower())
                urls.append(u)

    result: Dict[str, Any] = {
        "exposed": bool(external),
        "external_app_count": len(external),
        "matched_app_count": len(matched),
        "external_apps": external,
        "urls": urls[:25],
        "owners": base.get("owners", []),
    }
    if base.get("error"):
        result["error"] = base["error"]

    if external:
        names = ", ".join(e["app"] for e in external[:6])
        more = len(external) - 6
        bits = [
            f"🌐 {len(external)} affected application(s) are internet-facing per EAI: "
            f"{names}" + (f" (+{more} more)" if more > 0 else "") + "."
        ]
        if urls:
            shown = ", ".join(urls[:6])
            umore = len(urls) - 6
            bits.append(f"External endpoints: {shown}" + (f" (+{umore} more)" if umore > 0 else "") + ".")
        bits.append("Confirm perimeter reachability (Shodan/Censys/runZero) and prioritize.")
        result["summary_text"] = " ".join(bits)
    elif matched:
        result["summary_text"] = (
            f"None of the {len(matched)} affected application(s) are flagged "
            "internet-facing in EAI — no known external attack surface for this advisory."
        )
    else:
        result["summary_text"] = (
            base.get("summary_text")
            or "No affected applications resolved, so no external attack surface to assess."
        )
    return result
