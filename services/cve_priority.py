"""
Composite CVE-priority scoring, lifted from the war-room remediation playbook.

Turns the signals we already collect about a CVE — CVSS base score + vector,
EPSS exploitation probability, CISA KEV membership, and whether we actually run
the affected thing — into a single remediation tier with an SLA and a plain-text
rationale. The tier model is fixed by the playbook (see ``composite_priority``).

Entry points:
    pre_auth_from_cvss_vector(vector) -> bool   (pure)
    is_kev(cve_id)                    -> bool   (network/cache — the only impure fn)
    composite_priority(...)           -> dict   (pure)

Only ``is_kev`` touches the network or disk; everything else is a pure function
of its arguments so the tier model is trivially unit-testable.

The KEV check reuses the catalog fetch+parse that already backs the advisory
poller (``services.github_advisories._fetch_cisa_kev`` / ``CISA_KEV_URL``) — we
do NOT add a second KEV fetcher. This module only adds the membership-set + cache
layer that the per-CVE lookup needs (the poller consumes the whole catalog, we
need O(1) "is this one CVE in it?").
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Cache the KEV catalog as a flat CVE-ID set under the shared threat_intel dir,
# alongside services/nvd.py's nvd_cve_cache. Daily TTL — KEV grows slowly and a
# day-stale set never under-prioritizes by more than one poll cycle.
CACHE_PATH = (
    Path(__file__).resolve().parent.parent
    / "data" / "threat_intel" / "cisa_kev_set.json"
)
CACHE_TTL_SECONDS = 24 * 3600  # daily

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Process-local memo so repeated is_kev() calls in one run don't re-read disk.
_KEV_SET: Optional[set[str]] = None
_KEV_SET_LOADED_AT: float = 0.0


# ---------------------------------------------------------------------------
# pre_auth  (pure)
# ---------------------------------------------------------------------------
def pre_auth_from_cvss_vector(vector: str) -> bool:
    """True iff the CVSS v3 vector is exploitable pre-authentication.

    Per the playbook: pre-auth == no privileges required AND no user interaction,
    i.e. the vector contains both ``PR:N`` and ``UI:N``. Returns False for an
    empty/None/garbage vector (we can't claim pre-auth without evidence).
    """
    if not vector:
        return False
    parts = {p.strip().upper() for p in str(vector).split("/")}
    return "PR:N" in parts and "UI:N" in parts


# ---------------------------------------------------------------------------
# KEV  (impure — cached catalog membership)
# ---------------------------------------------------------------------------
def _load_cached_set() -> Optional[set[str]]:
    if not CACHE_PATH.exists():
        return None
    try:
        data = json.loads(CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        logger.warning("Corrupt KEV cache, re-fetching: %s", CACHE_PATH)
        return None
    if time.time() - data.get("fetched_at", 0) > CACHE_TTL_SECONDS:
        return None
    return {c.upper() for c in data.get("cve_ids", [])}


def _save_cached_set(cve_ids: set[str]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"fetched_at": time.time(), "cve_ids": sorted(cve_ids)}
    CACHE_PATH.write_text(json.dumps(payload))


def _fetch_kev_set() -> set[str]:
    """Build the KEV CVE-ID set by reusing the advisory poller's catalog fetch.

    We import the existing fetcher rather than re-implementing the HTTP call /
    JSON shape, so there is exactly one place that knows the KEV feed URL and
    record layout.
    """
    from services.github_advisories import _fetch_cisa_kev
    records = _fetch_cisa_kev()
    return {r["cve_id"].upper() for r in records if r.get("cve_id")}


def _get_kev_set(force_refresh: bool = False) -> set[str]:
    global _KEV_SET, _KEV_SET_LOADED_AT
    if (
        not force_refresh
        and _KEV_SET is not None
        and time.time() - _KEV_SET_LOADED_AT <= CACHE_TTL_SECONDS
    ):
        return _KEV_SET

    if not force_refresh:
        cached = _load_cached_set()
        if cached is not None:
            _KEV_SET, _KEV_SET_LOADED_AT = cached, time.time()
            return cached

    try:
        kev = _fetch_kev_set()
    except Exception as e:  # network/parse failure — fall back to whatever we have
        logger.warning("CISA KEV refresh failed: %s", e)
        if _KEV_SET is not None:
            return _KEV_SET
        stale = _load_cached_set()
        return stale if stale is not None else set()

    _save_cached_set(kev)
    _KEV_SET, _KEV_SET_LOADED_AT = kev, time.time()
    return kev


def is_kev(cve_id: str) -> bool:
    """Whether ``cve_id`` is on CISA's Known Exploited Vulnerabilities catalog.

    Backed by a daily-TTL cached set of the catalog (the only network/disk touch
    in this module). On a fetch failure with no cache available, returns False
    (absence of evidence — the composite scorer still tiers on CVSS/EPSS).
    """
    if not cve_id or not CVE_RE.match(cve_id):
        return False
    return cve_id.upper() in _get_kev_set()


# ---------------------------------------------------------------------------
# Composite tier  (pure)
# ---------------------------------------------------------------------------
# Reachability ceiling — the war-room policy (2026-06-03) that "reachability is
# a key factor in the final score." Evidence that the fleet cannot actually reach
# a CVE *caps* how urgent it can be, even when CVSS/EPSS/pre-auth would push it
# higher. A CVSS 9.8 in a base-image package with no confirmed code path is not a
# 72h emergency. KEV / exploited signals are NOT exempt from the cap (war-room
# decision: reachability "caps every tier") — they raise the floor of urgency,
# reachability sets the ceiling.
#
# Reachability has TWO axes (Aaron's "accessible from the internet, directly or a
# simple chain" needs both):
#   * code-path reachability — is the vulnerable code actually present/exercisable
#     here? (present-confirmed/present-conditional = reachable; pending-image =
#     base-image OS pkg, code path unconfirmed; unknown = no presence signal).
#   * internet exposure — is the carrying app internet-facing? (the
#     application-inventory internet-facing flag; True/False, or None when we have
#     no inventory linkage for the CVE).
_TIER_SLA = {1: 3, 2: 30, 3: 90, 4: 180}

# Code-path-only ceiling, used when the EAI internet-facing flag is unknown.
_REACH_CEILING = {
    "present-confirmed": 1,    # in our apps, no limiting preconditions -> no cap
    "present-conditional": 2,  # present but config/arch/version-gated -> max P2
    "pending-image": 3,        # base-image OS pkg, code path unconfirmed -> max P3
    "unknown": 3,              # no presence signal at all -> max P3
}
# Labels that count as "really in our environment" for the P3 presence clause AND
# as code-path-reachable for the 2-axis ceiling. pending-image / unknown presence
# is NOT enough to earn P3 on its own — such a CVE falls through to P4 unless an
# exploitation signal (KEV/EPSS/pre-auth) fires.
_REACH_PRESENT = {"present-confirmed", "present-conditional"}

# Higher bar, used ONLY by the MUST-ACT force (not the ceiling). To pin a CVE to
# P1 above the analysts on reachability grounds we demand *confirmed* code-path
# presence — purely application-layer, scanner-visible in the app — not the
# "present-conditional" mixed/base+app case where the path is config/arch-gated.
# The softer _REACH_PRESENT still lets present-conditional reach P1 via the normal
# tier + debate path; it just can't be *forced* there by the deterministic gate.
_REACH_CONFIRMED = {"present-confirmed"}


# ---------------------------------------------------------------------------
# MUST-ACT override  (pure, deterministic)
# ---------------------------------------------------------------------------
# The war-room (war-room lead, 2026-06) "if it has THESE factors, we WILL act on it,
# regardless of the analysts' reasoning." A small set of deterministic gates that
# force P1 *above* everything else — the LLM debate, the raw tier, AND the
# reachability ceiling. The point is to remove these from human/LLM judgment
# entirely: they are non-negotiable. Each gate is built only from signals we
# already compute, so it costs nothing extra.
#
# Factor set (user-selected, all four pin to P1):
#   1. KEV + internet-facing          — actively exploited and externally reachable
#   2. KEV + pre-auth                 — actively exploited and no auth needed
#   3. internet-facing + pre-auth + confirmed-reachable — external,
#                                        unauthenticated, present-confirmed code
#                                        path (high-confidence; even without KEV)
#   4. CVSS >= 9.8 + internet-facing  — critical severity on an external app
_MUST_ACT_CVSS = 9.8


def must_act(
    *,
    kev: bool,
    internet_facing: Optional[bool],
    pre_auth: bool,
    cvss_score: Optional[float],
    reachable: bool,
) -> Optional[str]:
    """Return the name of the MUST-ACT rule that fires, else ``None``.

    A non-None result means "force P1 regardless of any other reasoning."
    ``internet_facing`` is the EAI flag (True/False/None); a gate that needs it
    only fires on an explicit True (an unknown exposure never forces action).
    ``reachable`` is the *high-confidence* code-path axis: only present-confirmed
    (purely application-layer) counts. present-conditional / pending-image is not
    confident enough to force P1 — it reaches P1 only via the normal tier+debate.
    """
    cvss = cvss_score if cvss_score is not None else 0.0
    if kev and internet_facing:
        return "KEV + internet-facing"
    if kev and pre_auth:
        return "KEV + pre-auth"
    if internet_facing and pre_auth and reachable:
        return "internet-facing + pre-auth + reachable"
    if cvss >= _MUST_ACT_CVSS and internet_facing:
        return f"CVSS >= {_MUST_ACT_CVSS} + internet-facing"
    return None


def _reach_ceiling(reachability: Optional[str], internet_facing: Optional[bool]) -> Optional[int]:
    """Most-urgent tier (1=P1 .. 4=P4) a CVE may reach, from the 2-axis matrix:

                       reachable-code   pending/unknown-code
        internet-facing      P1                 P3
        internal-only        P2                 P4

    When the EAI internet-facing flag is unknown (``None``) we fall back to the
    code-path-only ceiling (``_REACH_CEILING``). Returns ``None`` only when no
    policy applies (flag unknown AND reachability not in our label set), i.e. the
    legacy no-reachability call — no cap.
    """
    if internet_facing is None:
        return _REACH_CEILING.get(reachability)
    code_reachable = reachability in _REACH_PRESENT
    if internet_facing:
        return 1 if code_reachable else 3
    return 2 if code_reachable else 4


def composite_priority(
    *,
    cvss_score: Optional[float],
    epss: Optional[float],
    kev: bool,
    pre_auth: bool,
    in_environment: bool,
    is_rce: bool = False,
    is_dos: bool = False,
    reachability: Optional[str] = None,
    internet_facing: Optional[bool] = None,
) -> dict:
    """Compute the remediation tier from the playbook's fixed model.

    Raw tiers (first match wins, highest urgency first):
        P1 / 72h  : KEV OR (cvss>=9.0 AND epss>=0.5) OR (pre_auth AND is_rce)
        P2 / 30d  : (cvss>=7.0 AND epss>=0.3) OR (pre_auth AND is_dos)
        P3 / 90d  : cvss>=4.0 AND reachable-in-environment
        P4 / 180d : otherwise

    ``reachability`` (code-path label) and ``internet_facing`` (EAI flag, or None)
    then apply the war-room reachability policy on top of the raw tier:
      * the P3 presence clause requires confirmed/conditional code-path presence —
        a base-image (pending-image) or no-signal (unknown) CVE can't reach P3 on
        presence alone, so it falls to P4;
      * the 2-axis ceiling (see ``_reach_ceiling``) caps the final tier so a CVE
        we can't confirm is internet-reachable can never out-rank that ceiling
        (e.g. a KEV that's only pending-image -> P3; an internal-only KEV -> P2).
    Passing both as None disables the policy (legacy/pure callers).

    Finally, the MUST-ACT gate (see ``must_act``) can force P1 above everything —
    the raw tier, the cap, and the LLM debate — when a non-negotiable factor set
    fires (KEV+internet-facing, KEV+pre-auth, internet-facing+pre-auth+reachable,
    CVSS>=9.8+internet-facing).

    Returns ``{"tier": "P1".."P4", "sla_days": int, "why": str, "must_act":
    Optional[str]}``. ``why`` names the clause that fired, plus any reachability
    cap and any MUST-ACT override applied; ``must_act`` is the rule name when the
    override fired, else None. All keyword-only so call sites read clearly.
    """
    cvss = cvss_score if cvss_score is not None else 0.0
    ep = epss if epss is not None else 0.0

    # The P3 "present in environment" clause needs evidence the component is
    # actually reachable here — Veracode-confirmed (with or without limiting
    # preconditions). pending-image / unknown presence does not qualify.
    present = in_environment and (
        reachability is None or reachability in _REACH_PRESENT
    )

    # --- raw tier (highest urgency first) ---
    if kev:
        raw = {"tier": "P1", "sla_days": 3, "why": "on CISA KEV (known exploited)"}
    elif cvss >= 9.0 and ep >= 0.5:
        raw = {"tier": "P1", "sla_days": 3,
               "why": f"critical + likely exploited (cvss {cvss} >= 9.0, epss {ep} >= 0.5)"}
    elif pre_auth and is_rce:
        raw = {"tier": "P1", "sla_days": 3, "why": "pre-auth remote code execution"}
    elif cvss >= 7.0 and ep >= 0.3:
        raw = {"tier": "P2", "sla_days": 30,
               "why": f"high + elevated exploitation (cvss {cvss} >= 7.0, epss {ep} >= 0.3)"}
    elif pre_auth and is_dos:
        raw = {"tier": "P2", "sla_days": 30, "why": "pre-auth denial of service"}
    elif cvss >= 4.0 and present:
        raw = {"tier": "P3", "sla_days": 90,
               "why": f"present + reachable in environment (cvss {cvss} >= 4.0)"}
    else:
        raw = {"tier": "P4", "sla_days": 180, "why": "no urgency signal met"}

    # --- 2-axis reachability ceiling cap (code-path x internet exposure) ---
    ceiling = _reach_ceiling(reachability, internet_facing)
    if ceiling is not None and int(raw["tier"][1]) < ceiling:
        exposure = (
            "internet-facing" if internet_facing
            else "internal-only" if internet_facing is False
            else "exposure-unknown"
        )
        result = {
            "tier": f"P{ceiling}",
            "sla_days": _TIER_SLA[ceiling],
            "why": f"{raw['why']}; capped to P{ceiling} "
                   f"(reachability: {reachability}, {exposure})",
            "must_act": None,
        }
    else:
        result = {**raw, "must_act": None}

    # --- MUST-ACT override (non-negotiable; trumps the cap and the debate) ---
    rule = must_act(
        kev=kev, internet_facing=internet_facing, pre_auth=pre_auth,
        cvss_score=cvss_score, reachable=(reachability in _REACH_CONFIRMED),
    )
    if rule and int(result["tier"][1]) > 1:
        return {
            "tier": "P1",
            "sla_days": _TIER_SLA[1],
            "why": f"{result['why']}; MUST-ACT: {rule} -> forced P1",
            "must_act": rule,
        }
    if rule:
        result["must_act"] = rule
    return result
