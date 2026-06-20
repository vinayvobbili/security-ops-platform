"""Power BI cross-dataset router.

Given a natural-language question and the workspace's full dataset catalog
(~90+ datasets), pick the single dataset that best answers it. This removes the
"pick a dataset first" gate from the Explorer: the user just asks, the router
chooses, and the normal NL->DAX flow runs against the chosen dataset.

Routing is one cheap LLM classification over a compact catalog (dataset names +
short topic hints). If the LLM is unavailable or returns garbage, a deterministic
keyword-overlap fallback always returns a best guess, so the router never dead-ends.
"""

import json
import logging
import re
import time

logger = logging.getLogger(__name__)

# ── Curated topic hints ──
# Keys are lowercase substrings matched against dataset names. Values are one-line
# topic descriptions that give the router strong signal for the common SOC/IT
# datasets. Datasets with no match fall back to just their (humanized) name.
_TOPIC_HINTS: dict[str, str] = {
    "os currency": "Operating-system support lifecycle: current / extended / expired OS counts per device, country, region.",
    "client_health": "Security-tool coverage audit: which hosts are missing required agents (Tanium, CrowdStrike, etc.), current-month snapshot.",
    "crowdstrike": "CrowdStrike Falcon sensor coverage & health: installed vs missing (NO CS), exemptions, agent health, by asset class / region.",
    "workstation patching": "Workstation patch compliance: compliant vs not-compliant, per patch month, by country / OS.",
    "server os patching": "Server OS patch compliance: patched vs unpatched servers, compliance rate, per region / country / month.",
    "ssl vulnerability": "SSL/TLS certificate issues: expired, self-signed, expiring-soon certs, by priority / region / country.",
    "dns infoblox": "DNS configuration compliance: approved InfoBlox DNS vs non-compliant, per asset.",
    "tanium": "Tanium endpoint-management coverage & health: installed vs missing (NO TANIUM), exemptions, by asset class / region.",
    "database inventory": "Database & application inventory: EAI application details, CMDB database details.",
    "macos_compliance": "macOS patch compliance: patched-within-30-days vs not, by macOS version / country.",
}

# Catalog cache: (catalog_list, timestamp). One workspace, so a single slot.
_catalog_cache: tuple[list[dict], float] | None = None
_CATALOG_TTL = 1800  # 30 min — dataset roster changes rarely


def _humanize(name: str) -> str:
    return (name or "").replace("_", " ").strip()


def _topic_hint(name: str) -> str:
    nl = (name or "").lower()
    for key, hint in _TOPIC_HINTS.items():
        if key in nl:
            return hint
    return ""


def build_catalog(pbi_client, force: bool = False) -> list[dict]:
    """Return [{id, name, hint}] for every dataset in the workspace (cached)."""
    global _catalog_cache
    now = time.time()
    if not force and _catalog_cache and (now - _catalog_cache[1]) < _CATALOG_TTL:
        return _catalog_cache[0]
    catalog: list[dict] = []
    try:
        for ds in pbi_client.list_datasets():
            ds_id = ds.get("id")
            name = ds.get("name") or ""
            if not ds_id or not name:
                continue
            catalog.append({"id": ds_id, "name": name, "hint": _topic_hint(name)})
    except Exception as exc:
        logger.warning("Power BI catalog build failed: %s", exc)
        if _catalog_cache:
            return _catalog_cache[0]
        return []
    _catalog_cache = (catalog, now)
    return catalog


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "and", "for", "are", "how", "many", "what", "which", "with", "from",
    "show", "list", "count", "have", "has", "our", "all", "per", "this", "that",
    "give", "get", "much", "does", "did", "was", "were", "into", "out", "not",
    "any", "can", "you", "tell", "about", "across", "over", "vs", "versus",
}


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall((text or "").lower()) if len(t) > 2 and t not in _STOP]


def _keyword_route(question: str, catalog: list[dict]) -> dict:
    """Deterministic fallback: score each dataset by token overlap with name + hint."""
    q_tokens = set(_tokens(question))
    best = None
    best_score = 0
    scored: list[tuple[int, dict]] = []
    for ds in catalog:
        hay = set(_tokens(ds["name"])) | set(_tokens(ds.get("hint", "")))
        score = len(q_tokens & hay)
        scored.append((score, ds))
        if score > best_score:
            best_score = score
            best = ds
    if not best:
        best = catalog[0] if catalog else {"id": "", "name": ""}
    scored.sort(key=lambda s: s[0], reverse=True)
    alts = [s[1] for s in scored[1:3] if s[0] > 0]
    return {
        "dataset_id": best["id"],
        "dataset_name": best["name"],
        "confidence": "high" if best_score >= 2 else ("medium" if best_score == 1 else "low"),
        "reason": "Matched on dataset name/topic keywords." if best_score else "No strong match — defaulting to the closest dataset.",
        "alternatives": [{"id": a["id"], "name": a["name"]} for a in alts],
        "method": "keyword",
    }


_ROUTER_PROMPT = """\
You are a dataset router for a Power BI analytics assistant. Choose the SINGLE dataset \
that best answers the user's question.

DATASETS:
{catalog}
{context}
User question: "{question}"

Respond with ONLY this JSON on one line, nothing else:
{{"pick": <dataset number>, "confidence": "high|medium|low", "reason": "<one short sentence>", "alternatives": [<number>, <number>]}}
/no_think"""


def route_question(question: str, catalog: list[dict], llm,
                   history: list[dict] | None = None) -> dict:
    """Pick the best dataset for a question. Returns a result dict.

    Result: {dataset_id, dataset_name, confidence, reason, alternatives:[{id,name}], method}.
    Falls back to keyword routing on any LLM failure.
    """
    if not catalog:
        return {"dataset_id": "", "dataset_name": "", "confidence": "low",
                "reason": "No datasets available.", "alternatives": [], "method": "none"}

    lines = []
    for i, ds in enumerate(catalog, 1):
        label = _humanize(ds["name"])
        hint = ds.get("hint", "")
        lines.append(f"{i}. {label}" + (f" — {hint}" if hint else ""))
    catalog_text = "\n".join(lines)

    # A little conversation context helps follow-ups like "what about tanium?"
    context = ""
    if history:
        recent_users = [h.get("text", "") for h in history if (h.get("role") == "user")][-2:]
        recent_users = [t for t in recent_users if t]
        if recent_users:
            context = "\nRecent questions (context): " + " | ".join(recent_users) + "\n"

    if llm is not None:
        prompt = _ROUTER_PROMPT.format(catalog=catalog_text, context=context, question=question[:500])
        try:
            resp = llm.invoke(prompt)
            text = (getattr(resp, "content", None) or "").strip()
            start, end = text.find("{"), text.rfind("}")
            if start >= 0 and end > start:
                parsed = json.loads(text[start:end + 1])
                pick = int(parsed.get("pick", 0))
                if 1 <= pick <= len(catalog):
                    chosen = catalog[pick - 1]
                    alts = []
                    for a in (parsed.get("alternatives") or [])[:2]:
                        try:
                            ai = int(a)
                        except (TypeError, ValueError):
                            continue
                        if 1 <= ai <= len(catalog) and ai != pick:
                            alts.append({"id": catalog[ai - 1]["id"], "name": catalog[ai - 1]["name"]})
                    conf = str(parsed.get("confidence", "medium")).lower()
                    if conf not in ("high", "medium", "low"):
                        conf = "medium"
                    return {
                        "dataset_id": chosen["id"],
                        "dataset_name": chosen["name"],
                        "confidence": conf,
                        "reason": str(parsed.get("reason", "")).strip()[:240] or "Best topical match for the question.",
                        "alternatives": alts,
                        "method": "llm",
                    }
            logger.info("Router LLM returned unparseable pick: %r — falling back to keywords", text[:200])
        except Exception as exc:
            logger.warning("Router LLM failed (%s) — falling back to keywords", exc)

    return _keyword_route(question, catalog)
