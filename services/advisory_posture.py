"""Fleet-posture enrichment for security advisories — Power BI.

Given an advisory, route it to the most relevant *fleet posture* dataset in the
Power BI workspace (patch compliance, OS currency, endpoint tool coverage, …),
run one NL->DAX query for the current numbers, and return a grounded one-paragraph
posture statement the assessor would otherwise have to chase by hand.

This reuses:
  - services.powerbi_router  — pick the dataset (restricted to curated posture sets)
  - powerbi_chat_handler     — schema build / prune / DAX extract / result format
  - the LLM                  — DAX generation + posture summary

It is opt-in (an on-demand capability), so the many package-compromise advisories
where fleet posture is irrelevant never trigger a query. Never raises — degrades
to an {error, summary_text} dict.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

_MAX_SUMMARY_ROWS = 30


def _posture_question(adv: dict[str, Any]) -> str:
    """Build the routing/DAX question from the advisory's facts."""
    sid = adv.get("source_id") or ""
    cve = adv.get("cve_id") or ""
    title = (adv.get("title") or adv.get("summary") or "").strip()
    pkgs = adv.get("packages") or []
    eco = adv.get("ecosystem") or ""
    bits = [f"advisory {sid}"]
    if cve:
        bits.append(cve)
    if title:
        bits.append(title[:200])
    if pkgs:
        bits.append("affected: " + ", ".join(str(p) for p in pkgs[:5]))
    if eco:
        bits.append(f"ecosystem {eco}")
    desc = "; ".join(bits)
    return (
        "What is our current fleet posture relevant to this security advisory? "
        f"Advisory — {desc}. "
        "Report the single most relevant current coverage / compliance number "
        "for our environment (e.g. patch compliance %, hosts missing the agent, "
        "expired-OS count). Keep it to a small summary."
    )


_DAX_PROMPT = """\
Translate the question into ONE DAX EVALUATE query that returns a SMALL current-state \
summary (a few rows at most) — a compliance %, a coverage count, or a missing/affected \
count. Respond with ONLY a ```dax code block, no prose.

Use table and column names EXACTLY as in SCHEMA. Start with EVALUATE. Always aggregate \
(COUNTROWS / SUM / DIVIDE) and filter to the current snapshot where the schema/hints \
indicate one. Do not return per-row detail tables.

SCHEMA:
{schema}
{hints}
Question: {question}"""


def _gen_dax(llm, schema: str, hints: str, question: str) -> str | None:
    from langchain_core.messages import HumanMessage
    from src.components.web.powerbi_chat_handler import _extract_dax
    prompt = _DAX_PROMPT.format(schema=schema, hints=hints or "", question=question)
    resp = llm.invoke([HumanMessage(content=prompt)])
    return _extract_dax((getattr(resp, "content", None) or ""))


_SUMMARY_PROMPT = """\
You are a SOC analyst. Given a security advisory and a live query result from our fleet \
posture data, write a CRISP 2-3 sentence statement of our current posture relevant to \
this advisory. Lead with the number. State the dataset it came from. Do NOT invent \
figures — use only the result. If the result looks empty or off-topic, say the posture \
data did not yield a clear relevant number.

Advisory: {advisory}
Posture dataset: {dataset}
Question asked: {question}
Query result:
{result}"""


def _summarize(llm, adv: dict[str, Any], dataset: str, question: str, result_text: str) -> str:
    from langchain_core.messages import HumanMessage
    adv_line = f"{adv.get('source_id')} ({adv.get('cve_id') or 'no CVE'}) — {(adv.get('title') or adv.get('summary') or '')[:160]}"
    prompt = _SUMMARY_PROMPT.format(
        advisory=adv_line, dataset=dataset, question=question, result=result_text[:2500],
    )
    resp = llm.invoke([HumanMessage(content=prompt)])
    return (getattr(resp, "content", None) or "").strip()[:900]


def fleet_posture(adv: dict[str, Any]) -> dict[str, Any]:
    """Route an advisory to the best fleet-posture dataset and report the current
    number. Returns ``{summary_text, dataset, dataset_id, confidence, dax, row_count,
    rows, error?}``. Never raises."""
    try:
        from services.powerbi import PowerBIClient
    except Exception as e:  # noqa: BLE001
        return {"error": f"Power BI client unavailable: {e}",
                "summary_text": "Power BI is not available in this environment."}

    try:
        client = PowerBIClient()
    except Exception as e:  # noqa: BLE001
        return {"error": str(e),
                "summary_text": "Power BI is not configured — cannot pull fleet posture."}

    from services.powerbi_router import build_catalog, route_question
    from src.components.web.powerbi_chat_handler import (
        _build_compact_schema, _prune_schema, _get_table_hints, _format_results_as_text,
        _suggest_schema_match,
    )
    from my_bot.utils.llm_factory import create_llm

    # Restrict routing to the curated fleet-posture datasets (those with a topic
    # hint). Package advisories with no posture-relevant dataset get a clean miss.
    catalog = build_catalog(client)
    posture_catalog = [d for d in catalog if d.get("hint")]
    if not posture_catalog:
        return {"error": "no posture datasets",
                "summary_text": "No fleet-posture datasets are available in the Power BI workspace."}

    llm = create_llm(max_tokens=1024, timeout=120)
    question = _posture_question(adv)

    route = route_question(question, posture_catalog, llm)
    ds_id, ds_name = route.get("dataset_id"), route.get("dataset_name")
    confidence = route.get("confidence", "medium")
    if not ds_id:
        return {"error": "routing failed",
                "summary_text": "Could not match this advisory to a fleet-posture dataset."}

    # Schema (compact, LLM-sized) then prune to the relevant tables.
    schema = _build_compact_schema(client, ds_id)
    if not schema:
        return {"error": "schema unavailable", "dataset": ds_name, "dataset_id": ds_id,
                "summary_text": f"Routed to the {ds_name} dataset, but its schema could not be read."}
    pruned, _, _ = _prune_schema(schema, question, None, dataset_name=ds_name)
    hints = _get_table_hints(ds_name)

    dax = _gen_dax(llm, pruned, hints, question)
    if not dax:
        return {"error": "no DAX generated", "dataset": ds_name, "dataset_id": ds_id,
                "confidence": confidence,
                "summary_text": f"Routed to the {ds_name} dataset, but no query could be formed."}

    result = client.execute_dax(ds_id, dax)
    # One retry on a name/syntax error, using the schema-match hint.
    if result.get("error"):
        hint = _suggest_schema_match(result["error"], pruned)
        retry_q = question + (f"\nSchema hint: {hint}" if hint else "") + \
            f"\nThe previous query failed: {result['error'][:300]}. Fix only the names/syntax."
        dax2 = _gen_dax(llm, pruned, hints, retry_q)
        if dax2:
            dax = dax2
            result = client.execute_dax(ds_id, dax)

    if result.get("error"):
        return {"error": result["error"], "dataset": ds_name, "dataset_id": ds_id,
                "confidence": confidence, "dax": dax,
                "summary_text": f"Routed to the {ds_name} dataset, but the posture query failed."}

    result_text = _format_results_as_text(result, max_rows=_MAX_SUMMARY_ROWS)
    summary = _summarize(llm, adv, ds_name, question, result_text)
    prefix = f"🛰️ Fleet posture (Power BI · {ds_name}): "
    summary_text = (prefix + summary) if summary else (
        prefix + "query ran but produced no clear posture number.")

    return {
        "summary_text": summary_text,
        "dataset": ds_name,
        "dataset_id": ds_id,
        "confidence": confidence,
        "dax": dax,
        "row_count": result.get("row_count", 0),
        "rows": result.get("rows", [])[:_MAX_SUMMARY_ROWS],
        "columns": result.get("columns", []),
    }
