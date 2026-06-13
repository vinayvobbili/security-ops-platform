"""Brand-keyword watchlist onboarding.

Historically the daily monitor only scanned the primary domain (``acme.com``)
for lookalikes. A brand-protection program, however, tracks impersonation
domains across *every* brand keyword in the portfolio (subsidiaries, regional
JVs, product brands), not just the flagship.

This module ingests a watchlist export (``Typosquat Domains_watch_list.xlsx``)
into the monitoring config so those domains are risk-enriched, CT-monitored and
surfaced on the dashboard for centralized visibility — and derives the distinct
brand keywords used to widen the daily Certificate Transparency impersonation
sweep.

The watchlist itself is data (lives in ``config.json`` under ``rf_watchlist``);
this module just keeps that data in sync with the latest export.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .config import CONFIG_FILE

logger = logging.getLogger(__name__)

# Canonical brand-protection scope — the brands the program actively monitors
# for impersonation (per the monthly Domain Monitoring & Brand Protection
# report). Each is swept in crt.sh regardless of whether it happens to appear in
# a given (partial) watchlist export, so coverage never silently narrows to
# whatever brands a single export contained. Kept explicit (not inferred from
# data) so a noisy export can't turn an unrelated token into a monitored brand.
# (Example portfolio — replace with your own brand stems.)
KNOWN_BRAND_STEMS: List[str] = [
    "acme",
    "acmebank",
    "acmehealth",
    "acmevision",
    "acmelegal",
    "acmevida",
    "acmepet",
    "acmebridge",
    # international JVs / subsidiaries
    "acmeasia",
    "acmeglobal",
    "acmeinsurance",
    "acmegroup",
]


# crt.sh substring search is literal: a search for "acmehealth" will NOT
# match "acme-health.com". So each multi-word brand is swept under every
# realistic spelling an impersonator might register — concatenated, hyphenated
# and (rarely, in subdomains) dotted. Single-token brands need no variants.
BRAND_SEARCH_VARIANTS: Dict[str, List[str]] = {
    "acme":          ["acme"],
    "acmebank":      ["acmebank", "acme-bank"],
    "acmehealth":    ["acmehealth", "acme-health"],
    "acmevision":    ["acmevision", "acme-vision"],
    "acmelegal":     ["acmelegal", "acme-legal"],
    "acmevida":      ["acmevida", "acme-vida"],
    "acmepet":       ["acmepet", "acme-pet"],
    "acmebridge":    ["acmebridge", "acme-bridge"],
    "acmeasia":      ["acmeasia", "acme-asia"],
    "acmeglobal":    ["acmeglobal", "acme-global"],
    "acmeinsurance": ["acmeinsurance", "acme-insurance"],
    "acmegroup":     ["acmegroup", "acme-group"],
}


# Canonical registrable root domain per brand — the legitimate domain the
# lookalike engine permutes to generate candidates. Seeded into ``monitored_domains`` so the
# staggered scan covers every brand. Analysts can correct any of these from the
# Manage Monitoring panel (e.g. if a brand's primary domain differs); seeding
# only ADDS missing roots and never removes an analyst's entry.
BRAND_ROOTS: Dict[str, str] = {
    "acme":       "acme.com",
    "acmebank":   "acmebank.com",
    "acmehealth": "acmehealth.com",
    "acmevision": "acmevision.com",
    "acmelegal":  "acmelegal.com",
    "acmevida":   "acmevida.cl",
    "acmepet":    "acmepet.com",
    "acmebridge": "acmebridge.com",
}


def brand_search_terms(keyword: str) -> List[str]:
    """Return the crt.sh search variants to sweep for a brand keyword.

    Falls back to the keyword itself for any brand without an explicit variant
    map, so a newly added brand still gets at least a literal sweep.
    """
    return BRAND_SEARCH_VARIANTS.get(keyword, [keyword])


# Flattened (hyphen-stripped variant -> canonical brand stem), longest variant
# first so a multi-word brand wins over a shorter stem it contains
# (e.g. 'acmeasia' must beat the 'acme' inside it).
_VARIANT_TO_BRAND: List[tuple] = sorted(
    ((v.replace("-", ""), stem)
     for stem, variants in BRAND_SEARCH_VARIANTS.items()
     for v in variants),
    key=lambda kv: len(kv[0]),
    reverse=True,
)


def brand_for_domain(domain: str) -> str | None:
    """Best-effort brand attribution for a watchlist / impersonation domain.

    Matches the domain (hyphens stripped) against the known brand search
    variants, longest first, and returns the canonical brand stem title-cased —
    the same shape lookalike attribution uses (``parent.split('.')[0].title()``)
    so the monthly By-Brand rollup groups RF and lookalike findings consistently.
    Returns None when no known brand keyword is present.
    """
    if not domain:
        return None
    hay = domain.lower().replace("-", "")
    for needle, stem in _VARIANT_TO_BRAND:
        if needle in hay:
            return stem.title()
    return None


def _normalize_domain(raw: str) -> str:
    """Normalize a watchlist cell to a bare registrable domain.

    Strips the Recorded Future ``idn:`` id-prefix, surrounding whitespace, a
    URL scheme/path if one slipped in, a leading ``*.`` wildcard and a trailing
    dot, then lowercases.
    """
    d = (raw or "").strip().lower()
    if not d:
        return ""
    if d.startswith("idn:"):
        d = d[4:]
    # Drop scheme/path if a full URL was pasted into the sheet
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    if d.startswith("*."):
        d = d[2:]
    return d.strip().strip(".")


def _sld(domain: str) -> str:
    """Second-level label of a domain, e.g. ``acmegulf`` from ``acmegulf.com``."""
    parts = domain.split(".")
    return parts[0] if parts else domain


def parse_watchlist_xlsx(xlsx_path: str | Path) -> List[str]:
    """Read the RF watchlist export and return a sorted, de-duplicated domain list.

    The export has an ``Id`` column (``idn:<domain>``) and a ``Domains Watchlist``
    column. We prefer the latter but fall back to any column whose normalized
    cells look like domains, so a re-exported sheet with renamed headers still works.
    """
    import pandas as pd

    xlsx_path = Path(xlsx_path)
    if not xlsx_path.exists():
        raise FileNotFoundError(f"RF watchlist not found: {xlsx_path}")

    xl = pd.ExcelFile(xlsx_path)
    domains: set[str] = set()
    for sheet in xl.sheet_names:
        df = xl.parse(sheet)
        # Prefer an explicitly named domains column, else scan every column
        cols = list(df.columns)
        domain_cols = [c for c in cols if "domain" in str(c).lower()]
        scan_cols = domain_cols or cols
        for col in scan_cols:
            for cell in df[col].dropna().astype(str):
                norm = _normalize_domain(cell)
                # Cheap sanity gate: must look like a domain (a dot, no spaces)
                if norm and "." in norm and " " not in norm:
                    domains.add(norm)

    return sorted(domains)


def derive_brand_keywords(domains: List[str]) -> List[str]:
    """Return the brand keywords to sweep in crt.sh.

    Always covers the full canonical brand-protection scope (``KNOWN_BRAND_STEMS``)
    so a partial RF export can never silently shrink coverage, and additionally
    logs which of those brands the current export actually contains (purely
    informational — every canonical brand is swept either way).
    """
    slds = {_sld(d) for d in domains}
    present = [stem for stem in KNOWN_BRAND_STEMS if any(stem in sld for sld in slds)]
    logger.info(f"Brand keywords present in this export: {', '.join(present) or '(none)'}")
    return list(KNOWN_BRAND_STEMS)


def import_watchlist(xlsx_path: str | Path, config_file: Path | None = None) -> Dict[str, Any]:
    """Onboard the RF watchlist export into ``config.json``.

    Writes ``rf_watchlist`` (every watchlist domain) and ``brand_keywords``
    (derived brand stems) without disturbing the rest of the config. Returns a
    summary dict for logging / CLI output.
    """
    config_file = Path(config_file) if config_file else CONFIG_FILE

    domains = parse_watchlist_xlsx(xlsx_path)
    keywords = derive_brand_keywords(domains)

    config: Dict[str, Any] = {}
    if config_file.exists():
        try:
            with open(config_file) as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Could not read existing config {config_file}: {e}")
            raise

    config["rf_watchlist"] = domains
    config["brand_keywords"] = keywords

    # Seed brand root domains into monitored_domains (union — never remove an
    # analyst's curated entry) so the staggered scan covers every brand.
    monitored = list(config.get("monitored_domains", []))
    seeded_roots = []
    for root in BRAND_ROOTS.values():
        if root not in monitored:
            monitored.append(root)
            seeded_roots.append(root)
    config["monitored_domains"] = sorted(monitored)

    config.setdefault("_comments", {})
    config["_comments"]["rf_watchlist"] = (
        "Recorded Future watchlist export (all brand keywords). RF-enriched and "
        "CT-monitored daily for centralized visibility; not run through the lookalike engine."
    )
    config["_comments"]["brand_keywords"] = (
        "Brand stems derived from rf_watchlist; each widens the daily crt.sh "
        "impersonation sweep beyond the primary monitored domains."
    )

    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)

    summary = {
        "domains_imported": len(domains),
        "brand_keywords": keywords,
        "monitored_domains": config["monitored_domains"],
        "brand_roots_seeded": seeded_roots,
        "config_file": str(config_file),
    }
    logger.info(
        f"Imported {len(domains)} RF watchlist domains, "
        f"brand keywords: {', '.join(keywords) or '(none)'}"
    )
    return summary


def load_rf_watchlist(config_file: Path | None = None) -> List[str]:
    """Load the onboarded RF watchlist domains from config."""
    config_file = Path(config_file) if config_file else CONFIG_FILE
    if config_file.exists():
        try:
            with open(config_file) as f:
                return json.load(f).get("rf_watchlist", [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading rf_watchlist: {e}")
    return []


def load_brand_keywords(config_file: Path | None = None) -> List[str]:
    """Load the derived brand keywords from config."""
    config_file = Path(config_file) if config_file else CONFIG_FILE
    if config_file.exists():
        try:
            with open(config_file) as f:
                return json.load(f).get("brand_keywords", [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading brand_keywords: {e}")
    return []


def monitor_rf_watchlist() -> Dict[str, Any]:
    """RF-enrich and reputation-check the onboarded RF watchlist for the daily run.

    Deliberately lightweight: the 165+ watchlist domains are *not* run through
    the lookalike engine or per-domain crt.sh (that would blow the 30-minute job budget).
    Instead they get a batched Recorded Future enrichment plus bulk abuse.ch /
    AbuseIPDB reputation checks, which together give each domain a risk score and
    a malicious/benign signal for centralized visibility on the dashboard.

    New-certificate discovery across these brands is handled separately and
    cheaply by the brand-keyword CT sweep (see ``load_brand_keywords``).
    """
    domains = load_rf_watchlist()
    if not domains:
        return {"success": True, "domains": [], "total": 0, "high_risk_count": 0}

    # Wrap as the dict shape enrich_with_recorded_future expects.
    records: List[Dict[str, Any]] = [
        {"domain": d, "registered": True} for d in domains
    ]

    try:
        from services.domain_lookalike import enrich_with_recorded_future
        enrich_with_recorded_future(records)
    except Exception as e:  # enrichment is best-effort
        logger.warning(f"RF watchlist enrichment failed: {e}")

    # Bulk reputation — one call each, cheap relative to per-domain crt.sh.
    malicious: set[str] = set()
    try:
        from services.abusech import bulk_check_domains as abusech_bulk_check
        ac = abusech_bulk_check(domains)
        if ac.get("success"):
            malicious.update(d.get("domain") for d in ac.get("malicious_domains", []))
    except Exception as e:
        logger.warning(f"RF watchlist abuse.ch check failed: {e}")

    try:
        from services.abuseipdb import bulk_check_domains as abuseipdb_bulk_check, AbuseIPDBClient
        if AbuseIPDBClient().is_configured():
            ab = abuseipdb_bulk_check(domains)
            if ab.get("success"):
                malicious.update(
                    d.get("domain") for d in ab.get("domains_with_malicious_ips", [])
                )
    except Exception as e:
        logger.warning(f"RF watchlist AbuseIPDB check failed: {e}")

    high_risk = 0
    for rec in records:
        if rec.get("domain") in malicious:
            rec["reputation_malicious"] = True
        score = rec.get("rf_risk_score")
        if isinstance(score, (int, float)) and score >= 65:
            high_risk += 1

    records.sort(key=lambda r: (r.get("rf_risk_score") or 0), reverse=True)

    return {
        "success": True,
        "domains": records,
        "total": len(records),
        "high_risk_count": high_risk,
    }


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if len(sys.argv) < 2:
        print("Usage: python -m src.components.domain_monitoring.rf_watchlist <watchlist.xlsx>")
        sys.exit(1)
    result = import_watchlist(sys.argv[1])
    print(json.dumps(result, indent=2))
