"""LLM weaponization triage for suspicious domains.

Turns "a lookalike exists" into "is this actually a live phishing kit?". For a
domain we gather hard signals — is the page live, does it have a login/password
form, does it clone the brand, is it mail-capable (MX/SPF/DMARC → BEC/credential
harvest) or just a parked typo — and hand them to GPT-4.1 for a structured
risk-tier verdict. Read-only: it fetches the suspect page and calls the LLM, but
takes no action. The verdict is what lets analysts confirm instead of investigate
cold, and doubles as evidence for a takedown request.
"""

import logging
import re
from typing import Any, Dict, List, Optional

import requests
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_FETCH_TIMEOUT = 6
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
_PASSWORD_INPUT_RE = re.compile(r"""<input[^>]+type=["']?password""", re.I)
_FORM_RE = re.compile(r"<form\b", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_PAGE_TEXT_BUDGET = 2500  # chars of visible text handed to the LLM


class WeaponizationVerdict(BaseModel):
    """The LLM's read on whether a suspicious domain is a live, weaponized threat."""

    risk_tier: str = Field(description="Severity tier. 'P1' = live, weaponized "
        "(working credential-harvest/login clone of the brand, act now); 'P2' = "
        "strong impersonation but not yet confirmed harvesting (mail-capable clone, "
        "stood-up phishing infra); 'P3' = suspicious lookalike, not yet weaponized "
        "(registered, parked or placeholder); 'P4' = benign / defensive / unrelated.")
    is_active_phishing: bool = Field(description="True only if the live page is an "
        "actual working phishing kit (collects credentials/PII), not merely a lookalike.")
    has_login_form: bool = Field(description="True if the page presents a login / "
        "credential-entry form.")
    brand_clone: bool = Field(description="True if the page visually/structurally "
        "impersonates the targeted brand (logo, copy, layout).")
    targets_credentials: bool = Field(description="True if the intent appears to be "
        "harvesting credentials, payment, or PII.")
    confidence: str = Field(description="'high', 'medium', or 'low' confidence in this verdict.")
    rationale: str = Field(description="2-3 terse sentences citing the concrete signals "
        "that drove the tier — for an analyst and as takedown evidence.")
    recommended_action: str = Field(description="One terse SOC next step, e.g. "
        "'Raise takedown + block at proxy/EDR', 'Monitor — parked', 'Close as benign'.")


_SYSTEM = (
    "You are a senior SOC analyst triaging suspected brand-impersonation domains for a "
    "large insurer. You are given hard signals collected from a suspect domain (live "
    "page state, presence of a login/password form, brand keywords in the page, "
    "redirect behavior, parked-page detection, and mail capability via MX/SPF/DMARC). "
    "Judge how WEAPONIZED the domain is right now, not merely whether it looks similar. "
    "Calibration: a working credential-harvest/login clone is P1; stood-up impersonation "
    "infrastructure that is mail-capable or a clone but not yet confirmed harvesting is "
    "P2; a registered/parked/placeholder lookalike is P3; clearly benign, defensive, or "
    "unrelated is P4. Do not over-escalate parked or for-sale domains. Be decisive and "
    "concrete; your rationale will be attached to a takedown request."
)


def _strip_text(html: str) -> str:
    """Crude visible-text extraction for the LLM (no bs4 dependency)."""
    html = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    text = _TAG_RE.sub(" ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:_PAGE_TEXT_BUDGET]


def _fetch_page(domain: str) -> Dict[str, Any]:
    """Fetch the suspect page directly (https then http) and extract page signals.

    Public-internet fetch — no corp proxy. Best-effort: an unreachable domain is a
    signal in itself (registered but not stood up).
    """
    sig: Dict[str, Any] = {
        "reachable": False, "status_code": None, "final_url": None,
        "redirected_offsite": False, "has_form": False, "has_password_input": False,
        "title": None, "content_length": 0, "error": None,
    }
    page_text = ""
    headers = {"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(url, timeout=_FETCH_TIMEOUT, allow_redirects=True,
                                headers=headers, verify=False)
        except requests.RequestException as e:
            sig["error"] = f"{type(e).__name__}"
            continue
        body = resp.text or ""
        sig["reachable"] = True
        sig["status_code"] = resp.status_code
        sig["final_url"] = resp.url
        sig["content_length"] = len(body)
        sig["has_form"] = bool(_FORM_RE.search(body))
        sig["has_password_input"] = bool(_PASSWORD_INPUT_RE.search(body))
        try:
            final_host = (resp.url.split("://", 1)[-1].split("/", 1)[0]).lower()
            sig["redirected_offsite"] = domain not in final_host
        except Exception:
            pass
        m = _TITLE_RE.search(body)
        if m:
            sig["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160]
        page_text = _strip_text(body)
        sig["error"] = None
        break
    return sig, page_text


def _dns_mail_signals(domain: str) -> Dict[str, Any]:
    """MX / SPF / DMARC presence — a domain set up to send mail is a BEC / phishing
    delivery risk, not just a parked lookalike. Best-effort; dnspython optional."""
    out = {"has_mx": False, "mx_hosts": [], "has_spf": False, "has_dmarc": False, "error": None}
    try:
        import dns.resolver
    except Exception:
        out["error"] = "dnspython_unavailable"
        return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 4.0
    try:
        answers = resolver.resolve(domain, "MX")
        out["has_mx"] = True
        out["mx_hosts"] = [str(r.exchange).rstrip(".") for r in answers][:5]
    except Exception:
        pass
    try:
        for r in resolver.resolve(domain, "TXT"):
            txt = b"".join(r.strings).decode("utf-8", "ignore") if hasattr(r, "strings") else str(r)
            if "v=spf1" in txt.lower():
                out["has_spf"] = True
    except Exception:
        pass
    try:
        for r in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = b"".join(r.strings).decode("utf-8", "ignore") if hasattr(r, "strings") else str(r)
            if "v=dmarc1" in txt.lower():
                out["has_dmarc"] = True
    except Exception:
        pass
    return out


def gather_signals(domain: str, brand: Optional[str] = None) -> Dict[str, Any]:
    """Collect hard signals about a domain (page + DNS + parked detection)."""
    domain = (domain or "").strip().lower()
    page_sig, page_text = _fetch_page(domain)
    dns_sig = _dns_mail_signals(domain)

    parked = None
    try:
        from services.domain_lookalike import check_if_parked_content
        parked = check_if_parked_content(domain)
    except Exception as e:
        logger.debug(f"parked check failed for {domain}: {e}")

    brand_in_page = None
    if brand and page_text:
        brand_in_page = brand.lower().replace(" ", "") in page_text.lower().replace(" ", "")

    return {
        "domain": domain,
        "brand": brand,
        "page": page_sig,
        "dns": dns_sig,
        "parked": parked,
        "brand_in_page": brand_in_page,
        "page_text_excerpt": page_text,
    }


def _facts_prompt(signals: Dict[str, Any]) -> str:
    p, d = signals["page"], signals["dns"]
    lines = [
        f"Domain: {signals['domain']}",
        f"Targeted brand: {signals.get('brand') or 'unknown'}",
        f"Page reachable: {p['reachable']} (HTTP {p['status_code']})",
        f"Final URL after redirects: {p['final_url']}",
        f"Redirected off the domain: {p['redirected_offsite']}",
        f"Has a form: {p['has_form']}; has a password field: {p['has_password_input']}",
        f"Page title: {p['title']!r}",
        f"Brand name appears in page text: {signals.get('brand_in_page')}",
        f"Parked/for-sale page detected: {signals.get('parked')}",
        f"Mail-capable (MX): {d['has_mx']} {d['mx_hosts']}; SPF: {d['has_spf']}; DMARC: {d['has_dmarc']}",
    ]
    if signals.get("page_text_excerpt"):
        lines.append(f"\nVisible page text (truncated):\n{signals['page_text_excerpt']}")
    return "\n".join(lines)


def score_domain(domain: str, brand: Optional[str] = None) -> Dict[str, Any]:
    """Gather signals and produce a structured weaponization verdict.

    Returns ``{signals, verdict, llm_error}``. ``verdict`` is None (with
    ``llm_error`` set) when the LLM is unreachable — the signals are still useful.
    """
    domain = (domain or "").strip().lower()
    signals = gather_signals(domain, brand=brand)
    try:
        from my_bot.utils.llm_factory import create_llm, structured_output
        chain = structured_output(create_llm(temperature=0),
                                  WeaponizationVerdict)
        verdict_obj = chain.invoke([
            SystemMessage(content=_SYSTEM),
            HumanMessage(content=_facts_prompt(signals)),
        ])
        verdict = verdict_obj.model_dump()
        return {"domain": domain, "signals": signals, "verdict": verdict, "llm_error": None}
    except Exception as e:
        logger.error(f"Weaponization LLM failed for {domain}: {type(e).__name__}: {e}")
        return {"domain": domain, "signals": signals, "verdict": None,
                "llm_error": f"{type(e).__name__}: {e}"}


def score_and_record(domain: str, brand: Optional[str] = None) -> Dict[str, Any]:
    """Score a domain and persist the verdict to the findings ledger."""
    result = score_domain(domain, brand=brand)
    verdict = result.get("verdict") or {}
    try:
        from .findings_ledger import set_weaponization
        set_weaponization(
            domain,
            tier=verdict.get("risk_tier"),
            is_active=bool(verdict.get("is_active_phishing")),
            verdict_blob=result,
        )
    except Exception as e:
        logger.error(f"Could not persist weaponization for {domain}: {e}")
    return result


def backfill_untriaged(llm_limit: int = 40, budget_s: int = 900,
                       dry_run: bool = False) -> Dict[str, Any]:
    """One-shot triage of findings that were never weaponization-scored.

    The dormant majority (no resolving A record) can't be live phishing, so they
    get a cheap heuristic P4 with no LLM call. Only the domains that actually
    resolve are worth the LLM's time, and those are scored up to ``llm_limit``
    within ``budget_s``; the rest stay untriaged for the next daily auto-triage
    pass to pick up.

    Returns ``{total, heuristic_tiered, llm_scored, llm_deferred, dry_run}``.
    """
    import json
    import time

    from .findings_ledger import set_weaponization, untriaged_findings

    rows = untriaged_findings()
    if not rows:
        return {"total": 0, "heuristic_tiered": 0, "llm_scored": 0,
                "llm_deferred": 0, "dry_run": dry_run}

    def _resolves(r: Dict[str, Any]) -> bool:
        v = (r.get("ip_addresses") or "").strip()
        return bool(v) and v != "[]"

    live = [r for r in rows if _resolves(r)]
    dormant = [r for r in rows if not _resolves(r)]

    heuristic = {
        "verdict": {
            "risk_tier": "P4",
            "is_active_phishing": False,
            "confidence": "low",
            "rationale": "Heuristic backfill: no resolving A record at scan time, "
                         "treated as dormant. Re-scored automatically if it goes live.",
        },
        "heuristic": True,
    }

    heuristic_tiered = llm_scored = 0
    if not dry_run:
        for r in dormant:
            try:
                set_weaponization(r["domain"], tier="P4", is_active=False,
                                  verdict_blob=heuristic)
                heuristic_tiered += 1
            except Exception as e:
                logger.warning(f"Backfill heuristic tier failed for {r['domain']}: {e}")
    else:
        heuristic_tiered = len(dormant)

    deadline = time.monotonic() + budget_s
    to_score = live[:llm_limit]
    if not dry_run:
        for r in to_score:
            if time.monotonic() > deadline:
                logger.warning(f"Backfill hit {budget_s}s budget after {llm_scored} LLM scores")
                break
            try:
                score_and_record(r["domain"], brand=r.get("brand"))
                llm_scored += 1
            except Exception as e:
                logger.warning(f"Backfill LLM score failed for {r['domain']}: {e}")
    else:
        llm_scored = len(to_score)

    deferred = len(live) - llm_scored
    logger.info(
        f"backfill_untriaged: {len(rows)} untriaged → {heuristic_tiered} heuristic P4, "
        f"{llm_scored} LLM-scored, {deferred} live deferred (dry_run={dry_run})"
    )
    return {"total": len(rows), "heuristic_tiered": heuristic_tiered,
            "llm_scored": llm_scored, "llm_deferred": deferred, "dry_run": dry_run}


def evidence_summary(verdict_blob: Dict[str, Any]) -> str:
    """Render a stored weaponization result into a plain-text evidence block for a
    takedown request / Webex notification. Safe on partial/None blobs."""
    if not verdict_blob:
        return ""
    v = verdict_blob.get("verdict") or {}
    s = verdict_blob.get("signals") or {}
    p, d = s.get("page") or {}, s.get("dns") or {}
    lines: List[str] = []
    if v:
        lines.append(f"Assessment: {v.get('risk_tier')} — "
                     f"{'ACTIVE PHISHING' if v.get('is_active_phishing') else 'not confirmed active'} "
                     f"(confidence {v.get('confidence')})")
        if v.get("rationale"):
            lines.append(f"Rationale: {v['rationale']}")
    facts = []
    if p.get("reachable"):
        facts.append(f"live page (HTTP {p.get('status_code')})")
    if p.get("has_password_input"):
        facts.append("password/login form present")
    elif p.get("has_form"):
        facts.append("input form present")
    if s.get("brand_in_page"):
        facts.append("brand name on page")
    if p.get("title"):
        facts.append(f"title {p['title']!r}")
    if d.get("has_mx"):
        facts.append("mail-capable (MX present)")
    if s.get("parked"):
        facts.append("parked-page markers")
    if facts:
        lines.append("Signals: " + "; ".join(facts))
    return "\n".join(lines)
