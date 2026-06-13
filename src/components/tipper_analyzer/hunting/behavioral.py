"""Behavioral (TTP) threat hunting — LLM-authored hunt queries across SIEMs.

This is the *threat hunting* counterpart to the IOC sweep in this package. Where
the IOC adapters (qradar / crowdstrike / abnormal / xsiam) match *known
indicators*, this module asks the local LLM to author *behavioral hunt queries*
from the tipper narrative — hunting the adversary's techniques (TTPs), not just
their indicators — then validates and executes them against the SIEM(s).

Platforms (all auto-run; pick via the ``platforms`` arg):
  - "logscale" : CrowdStrike Falcon LogScale (Humio QL / CQL)
  - "xql"      : Palo Alto Cortex XSIAM (XQL)

Each platform plugs into one shared loop via a small ``_PlatformSpec`` (authoring
prompt, validator, executor, repair). The CQL and XQL stages differ only in DSL.

Flow per hunt:  generate (LLM)  ->  validate (allow-list + bounding)  ->
                execute (SIEM)  ->  on validation/compile error, LLM-repair and
                retry (capped) -> record outcome on the BehavioralHunt.

Design choices:
  - LLM is the in-house FailoverChatModel (m1 -> s1), same as the rest of
    tipper_analyzer — tipper narratives never leave our infrastructure.
  - Queries are auto-run, but ONLY after passing validation: every query must
    filter on an allowed source (CQL #event_simpleName / XQL dataset) and be
    result-bounded. Anything that doesn't validate (after repair) is recorded as
    `skipped_validation` and never executed.
  - Execution is read-only and the executors cap rows, so a bad query that slips
    past validation is still bounded in blast radius.
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from ..models import BehavioralHunt, BehavioralHuntResult, DEFAULT_THREAT_HUNT_HOURS

logger = logging.getLogger(__name__)

# ── CrowdStrike LogScale (CQL) ────────────────────────────────────────────────
# Vetted CrowdStrike LogScale event_simpleName values the LLM may hunt on.
# Authoritative allow-list — queries referencing anything outside this set are
# rejected at validation time (catches hallucinated/invalid event names).
VALID_LOGSCALE_EVENTS = {
    "ProcessRollup2",
    "SyntheticProcessRollup2",
    "NetworkConnectIP4",
    "NetworkConnectIP6",
    "DnsRequest",
    "ImageHash",
    "UserLogon",
    "UserIdentity",
    "CreateRemoteThreadDetectInfo",
    "CommandHistory",
    "ServiceStartType",
    "DriverLoad",
    "ScheduledTaskRegistered",
    "WmiBindEventConsumerToFilter",
    "RegKeySecurityDecrease",
    "RawAccessRead",
    "IntegrityLevel",
    "UdpConnectionReceived",
    "CreateSocket",
    "AsepValueUpdate",
    "ProcessInjection",
}

# ── Cortex XSIAM (XQL) ────────────────────────────────────────────────────────
# Datasets the LLM may query. xdr_data is the canonical EDR/telemetry dataset;
# anything else is rejected at validation time.
VALID_XSIAM_DATASETS = {"xdr_data"}

_MAX_HUNTS = 3              # how many behavioral hunts to author per platform
_MAX_QUERY_CHARS = 4000
_MAX_HOSTS = 10            # cap hostnames stored per hunt
# Total query generations attempted per hunt (1 initial + LLM repairs). On a
# validation reject or a compile error we feed the error back to the LLM and
# regenerate; after this many attempts we gracefully degrade.
_MAX_QUERY_ATTEMPTS = 2

# Hard wall-clock budget for a whole behavioral run (all platforms + repairs).
# The de_scheduler runs tipper analysis hourly and launches this in a detached
# daemon thread; this ceiling guarantees a hunt self-terminates well under that
# cadence so a slow run can't bleed into — or stack against — the next hour.
# Hunts that don't fit are recorded as `skipped_deadline` (query still shown).
_HUNT_DEADLINE_SECONDS = 1800   # 30 min — leaves a full 30-min buffer each hour

# Fields we try, in order, to pull a hostname out of a result row, per platform.
_LOGSCALE_HOST_FIELDS = ("ComputerName", "aip", "aid", "event_platform")
_XQL_HOST_FIELDS = ("agent_hostname", "agent_id", "actor_effective_username")

_LOGSCALE_GUIDE = """\
CrowdStrike LogScale (Humio QL) — minimal syntax:
- Every query MUST start by filtering an event type: #event_simpleName=ProcessRollup2
- Pipe stages with |. Regex match: FieldName=/pattern/i  (i = case-insensitive)
- Combine with: and / or / not, parentheses for grouping.
- ALWAYS bound output with a final | head(100) (or | tail(100)).
- Code block language tag is logscale.
Common fields: ImageFileName, ParentBaseFileName, CommandLine, ComputerName,
UserName, RemoteAddressIP4, DomainName, TargetFileName, RegObjectName, aid.
"""

_XQL_GUIDE = """\
Palo Alto Cortex XSIAM — XQL (Cortex Query Language) — minimal syntax:
- Every query MUST start from the dataset: dataset = xdr_data
- Scope to ONE event class next: | filter event_type = ENUM.PROCESS
  (valid: ENUM.PROCESS, ENUM.NETWORK, ENUM.FILE, ENUM.REGISTRY, ENUM.LOAD_IMAGE)
- Pipe stages with |. String contains: field contains "x". Regex: field ~= "(?i)pat".
- Combine with: and / or / not, parentheses for grouping.
- ALWAYS bound output with a final | limit 100.
- Aggregate (optional) with: | comp count() as cnt by <field>
- Code block language tag is xql.
Verified fields, by event_type:
  PROCESS:    action_process_image_name, action_process_image_command_line,
              actor_process_image_name, actor_process_command_line, actor_process_image_path,
              causality_actor_process_image_name, causality_actor_process_command_line
  NETWORK:    action_remote_ip, action_remote_port, dns_query_name
  FILE:       action_file_name, action_file_path
  REGISTRY:   action_registry_key_name, action_registry_value_name
  LOAD_IMAGE: action_module_path, action_module_md5
  common:     agent_hostname, event_type, event_sub_type
"""


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json(content):
    """Parse the first complete JSON value out of an LLM response.

    Tolerant of the common failure modes: code fences, leading/trailing prose,
    and a valid JSON value followed by extra data (chatter or a second block) —
    plain ``json.loads`` raises "Extra data" on the latter, so we fall back to
    ``raw_decode`` scanning from the first ``[``/``{``. Returns the value or None.

    NB: we deliberately do NOT use ``strip_json_fence`` here — it slices first-{
    to last-}, which drops the ``[ ]`` of a JSON *array* and would collapse a
    list of hunts down to its first object. We strip fences array-safely instead.
    """
    if isinstance(content, list):  # some models return content blocks
        content = " ".join(str(c) for c in content)
    text = str(content).strip()
    if not text:
        return None
    m = _FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    # Fall back: decode from the first bracket. The "Extra data" failure mode is
    # a model emitting several top-level objects back-to-back (newline-separated)
    # instead of one array — so keep decoding consecutive values and collect them.
    start = min(
        (i for i in (text.find("["), text.find("{")) if i != -1),
        default=-1,
    )
    if start == -1:
        return None
    decoder = json.JSONDecoder()
    values = []
    idx = start
    n = len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n,":
            idx += 1
        if idx >= n:
            break
        try:
            value, end = decoder.raw_decode(text, idx)
        except Exception:
            break
        values.append(value)
        idx = end
    if not values:
        logger.warning("[behavioral] JSON extraction found no decodable value")
        return None
    if len(values) == 1:
        return values[0]
    # Multiple top-level values: flatten any arrays into one list of objects.
    flat = []
    for v in values:
        flat.extend(v if isinstance(v, list) else [v])
    return flat


# ── Prompts ───────────────────────────────────────────────────────────────────

def _build_hunt_prompt(spec, title: str, narrative: str, max_hunts: int) -> str:
    """Build the LLM prompt for authoring behavioral hunts for one platform."""
    narrative = (narrative or "").strip()
    if len(narrative) > 8000:
        narrative = narrative[:8000] + " …[truncated]"
    return (
        "You are a senior threat hunter authoring BEHAVIORAL hunt queries for "
        f"{spec.dialect}. You are given a threat intel tipper. Derive the "
        "adversary's TECHNIQUES (TTPs) and write hunts that look for the "
        "BEHAVIOR — process lineage, command-line patterns, persistence, lateral "
        "movement, injection — NOT just the literal indicators (IPs/hashes/domains "
        "are already swept separately).\n\n"
        f"Author at most {max_hunts} distinct, high-value hunts.\n\n"
        "HARD RULES for every query:\n"
        f"  1. {spec.start_rule}\n"
        f"  2. {spec.bound_rule}\n"
        "  3. Must be behavioral (patterns/lineage), not a lookup of a single IOC.\n"
        "  4. No comments, no markdown fences inside the query string.\n\n"
        f"{spec.guide}\n"
        "Return STRICT JSON ONLY — an array of objects with exactly these keys:\n"
        '  [{"title": str, "hypothesis": str, "attack_technique": str, "query": str}]\n'
        'attack_technique is an ATT&CK id like "T1059.001" or "" if unknown.\n'
        "No prose outside the JSON.\n\n"
        f"TIPPER TITLE: {title}\n\n"
        f"TIPPER NARRATIVE:\n{narrative}\n"
    )


def _build_repair_prompt(spec, title: str, hypothesis: str, bad_query: str, error: str) -> str:
    """Prompt the LLM to fix a query that failed validation or compilation."""
    return (
        f"A {spec.dialect} hunt query you wrote is INVALID. Fix it.\n\n"
        f"Hunt: {title}\n"
        f"Hypothesis: {hypothesis}\n\n"
        f"FAILING QUERY:\n{bad_query}\n\n"
        f"ERROR:\n{error}\n\n"
        "Rewrite the query so it compiles and runs. Keep the SAME hunting intent.\n"
        "HARD RULES:\n"
        f"  1. {spec.start_rule}\n"
        f"  2. {spec.bound_rule}\n"
        "  3. Keep it behavioral (patterns/lineage), not a single-IOC lookup.\n\n"
        f"{spec.guide}\n"
        'Return STRICT JSON ONLY: {"query": "<the corrected query>"}\n'
        "No prose outside the JSON."
    )


def generate_behavioral_hunts(title: str, narrative: str, llm, max_hunts: int = _MAX_HUNTS,
                              platform: str = "logscale") -> list:
    """Ask the LLM to author behavioral hunts for one platform. Returns raw dicts.

    Never raises — returns [] on any failure (parse, LLM, empty).
    """
    spec = _PLATFORMS.get(platform) or _PLATFORMS["logscale"]
    prompt = _build_hunt_prompt(spec, title, narrative, max_hunts)
    try:
        resp = llm.invoke(prompt)
        content = getattr(resp, "content", resp)
    except Exception as exc:
        logger.warning(f"[behavioral] LLM generation failed ({platform}): {exc}")
        return []
    parsed = _extract_json(content)
    if parsed is None:
        logger.warning(f"[behavioral] LLM generation produced no parseable JSON ({platform})")
        return []

    if isinstance(parsed, dict):
        # tolerate {"hunts": [...]} or a single object
        parsed = parsed.get("hunts") or parsed.get("queries") or [parsed]
    if not isinstance(parsed, list):
        return []

    hunts = []
    for item in parsed[:max_hunts]:
        if not isinstance(item, dict):
            continue
        query = (item.get("query") or "").strip()
        if not query:
            continue
        hunts.append({
            "title": (item.get("title") or "Untitled hunt").strip(),
            "hypothesis": (item.get("hypothesis") or "").strip(),
            "attack_technique": (item.get("attack_technique") or "").strip(),
            "query": query,
        })
    return hunts


# ── Validation ──────────────────────────────────────────────────────────────

def _basic_query_checks(query: str):
    """Shared pre-checks. Returns (False, reason) on failure, else None."""
    if not query or not query.strip():
        return False, "empty query"
    if len(query) > _MAX_QUERY_CHARS:
        return False, f"query too long ({len(query)} chars)"
    low = query.lower()
    if low.startswith(("i cannot", "i can't", "sorry", "as an ai")):
        return False, "LLM returned prose, not a query"
    return None


def validate_logscale_query(query: str):
    """Validate an LLM-authored CrowdStrike LogScale query before execution.

    Returns (ok: bool, reason: str). Reason is "" when ok.
    Enforces: non-empty, sane length, filters on an allowed #event_simpleName,
    references only allowed event types, and is output-bounded.
    """
    basic = _basic_query_checks(query)
    if basic:
        return basic

    events = re.findall(r"#event_simpleName\s*=\s*\"?/?([A-Za-z0-9]+)", query)
    if not events:
        return False, "no #event_simpleName filter"
    bad = sorted({e for e in events if e not in VALID_LOGSCALE_EVENTS})
    if bad:
        return False, f"disallowed event type(s): {', '.join(bad)}"

    # Must be output-bounded (head/tail/limit) so an LLM query can't pull unbounded rows
    if not re.search(r"\b(head|tail)\s*\(", query) and not re.search(r"\blimit\s*=", query):
        return False, "not output-bounded (needs head()/tail()/limit)"

    return True, ""


def validate_xql_query(query: str):
    """Validate an LLM-authored Cortex XSIAM XQL query before execution.

    Returns (ok: bool, reason: str). Reason is "" when ok.
    Enforces: non-empty, sane length, sources an allowed dataset, and is bounded
    with ``| limit N``. (XQL has no clean event-name allow-list like CQL's
    #event_simpleName, so the dataset allow-list + the compile-error repair loop
    are the guard rails here.)
    """
    basic = _basic_query_checks(query)
    if basic:
        return basic

    m = re.search(r"dataset\s*=\s*([A-Za-z0-9_\-]+)", query)
    if not m:
        return False, "no 'dataset = ...' source clause"
    ds = m.group(1)
    if ds not in VALID_XSIAM_DATASETS:
        return False, f"disallowed dataset: {ds}"

    if not re.search(r"\|\s*limit\s+\d+", query, re.IGNORECASE):
        return False, "not output-bounded (needs | limit N)"

    return True, ""


def _repair_query(spec, title: str, hypothesis: str, bad_query: str, error: str, llm):
    """Ask the LLM to repair a failing query. Returns the new query string or None."""
    try:
        resp = llm.invoke(_build_repair_prompt(spec, title, hypothesis, bad_query, error))
        content = getattr(resp, "content", resp)
    except Exception as exc:
        logger.warning(f"[behavioral] repair failed for '{title}': {exc}")
        return None
    parsed = _extract_json(content)
    new_query = (parsed.get("query") if isinstance(parsed, dict) else None) or ""
    new_query = new_query.strip()
    return new_query or None


# ── Execution (per platform) ──────────────────────────────────────────────────
# Executors return a normalized dict:
#   {"events": list, "count": int|None, "error": str|None,
#    "access_denied": bool, "not_configured": bool}
# access_denied / not_configured short-circuit the platform (not repairable);
# a plain "error" is treated as a compile error and triggers the repair loop.

def _build_logscale_client():
    from services.crowdstrike import CrowdStrikeClient
    return CrowdStrikeClient()


def _execute_logscale(client, query: str, hours: int, timeout: float) -> dict:
    start = f"{max(1, hours // 24)}d"
    # run_logscale_query already returns {events, count, error, access_denied, not_configured}
    return client.run_logscale_query(query, start=start, end="now", limit=100,
                                     timeout=int(max(5, timeout)))


def _build_xsiam_client():
    from services.xsiam import XsiamClient
    client = XsiamClient()
    if not client.is_configured():
        return None  # run_behavioral_hunt records this as not-configured
    return client


_XQL_AUTH_HINTS = ("auth", "forbidden", "unauthorized", "permission", "credential",
                   "401", "403", "not configured")


def _execute_xql(client, query: str, hours: int, timeout: float) -> dict:
    """Submit an XQL query, poll, and normalize the result.

    XSIAM is async (start -> poll), unlike LogScale's synchronous call. Auth /
    permission failures are flagged not_configured (no repair); other submit /
    compile errors come back as a plain `error` so the repair loop can fix them.
    Polling is bounded by `timeout` (the run's remaining time budget).
    """
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    from_ms = now_ms - hours * 3600 * 1000

    def _err(msg):
        text = str(msg or "query failed")
        if any(h in text.lower() for h in _XQL_AUTH_HINTS):
            return {"events": [], "count": 0, "error": text, "not_configured": True}
        return {"events": [], "count": 0, "error": text}

    sub = client.start_xql_query(query, time_from_ms=from_ms, time_to_ms=now_ms)
    if not isinstance(sub, dict) or "error" in sub:
        return _err(sub.get("error") if isinstance(sub, dict) else "submit failed")
    query_id = sub.get("reply")
    if not query_id:
        return _err("no query_id returned")

    res = client.get_query_results(query_id, poll=True, max_wait=max(10.0, float(timeout)))
    if not isinstance(res, dict) or "error" in res:
        return _err(res.get("error") if isinstance(res, dict) else "results failed")

    results = (res.get("reply") or {}).get("results") or {}
    stream_id = results.get("stream_id")
    if stream_id:
        stream = client.get_query_results_stream(stream_id)
        if isinstance(stream, dict) and "error" in stream:
            return _err(stream["error"])
        rows = (stream or {}).get("data") or []
    else:
        rows = results.get("data") or []
    return {"events": rows, "count": len(rows), "error": None}


def _extract_hostnames(events: list, host_fields) -> list:
    """Pull up to _MAX_HOSTS distinct hostnames from result rows."""
    hosts = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        for f in host_fields:
            v = ev.get(f)
            if v and v not in hosts:
                hosts.append(v)
                break
        if len(hosts) >= _MAX_HOSTS:
            break
    return hosts


# ── Platform registry ─────────────────────────────────────────────────────────

@dataclass
class _PlatformSpec:
    query_type: str                 # tag stored on each BehavioralHunt
    name: str                       # display name
    dialect: str                    # prose name for prompts
    guide: str                      # syntax cheat-sheet injected into prompts
    start_rule: str                 # HARD RULE 1 text
    bound_rule: str                 # HARD RULE 2 text
    validate: Callable[[str], tuple]
    execute: Callable               # (client, query, hours, timeout) -> normalized dict
    build_client: Callable          # () -> client | None
    host_fields: tuple
    query_timeout: float            # per-query ceiling (s), clamped to remaining budget


_PLATFORMS = {
    "logscale": _PlatformSpec(
        query_type="logscale",
        name="CrowdStrike LogScale",
        dialect="CrowdStrike Falcon LogScale (Humio QL)",
        guide=_LOGSCALE_GUIDE,
        start_rule=(
            "Must start with a #event_simpleName filter using ONLY these event "
            "types: " + ", ".join(sorted(VALID_LOGSCALE_EVENTS))
        ),
        bound_rule="Must end with a bounding stage: | head(100)",
        validate=validate_logscale_query,
        execute=_execute_logscale,
        build_client=_build_logscale_client,
        host_fields=_LOGSCALE_HOST_FIELDS,
        query_timeout=60.0,
    ),
    "xql": _PlatformSpec(
        query_type="xql",
        name="XSIAM XQL",
        dialect="Palo Alto Cortex XSIAM XQL",
        guide=_XQL_GUIDE,
        start_rule=(
            "Must start with 'dataset = xdr_data' and scope with "
            "'| filter event_type = ENUM.<CLASS>' "
            "(PROCESS / NETWORK / FILE / REGISTRY / LOAD_IMAGE)"
        ),
        bound_rule="Must end with a bounding stage: | limit 100",
        validate=validate_xql_query,
        execute=_execute_xql,
        build_client=_build_xsiam_client,
        host_fields=_XQL_HOST_FIELDS,
        query_timeout=150.0,
    ),
}

# Default platforms for an auto-run (both SIEMs).
DEFAULT_HUNT_PLATFORMS = ["logscale", "xql"]


def run_behavioral_hunt(
    tipper_id: str,
    tipper_title: str,
    narrative: str,
    hours: int = DEFAULT_THREAT_HUNT_HOURS,
    llm=None,
    platforms: Optional[list] = None,
    clients: Optional[dict] = None,
    max_hunts: int = _MAX_HUNTS,
    max_runtime_seconds: float = _HUNT_DEADLINE_SECONDS,
) -> BehavioralHuntResult:
    """Generate, validate, and execute behavioral hunts for a tipper.

    Args:
        tipper_id / tipper_title: for result tracking
        narrative: the tipper writeup the LLM reasons over (full description)
        hours: SIEM lookback window
        llm: a chat model; defaults to the tipper_analyzer FailoverChatModel
        platforms: which SIEM dialects to hunt (default both: logscale + xql)
        clients: optional {platform: client} overrides (mainly for tests)
        max_hunts: cap on authored hunts PER platform
        max_runtime_seconds: hard wall-clock budget for the whole run. The hourly
            scheduler launches this in a daemon thread; the deadline guarantees a
            slow run self-terminates well under the hourly cadence so it can't
            bleed into / stack against the next hour. Hunts that don't fit are
            recorded as `skipped_deadline` (their query is still surfaced).

    Never raises — failures land in the result's errors/hunt statuses.
    """
    if platforms is None:
        platforms = list(DEFAULT_HUNT_PLATFORMS)
    platforms = [p for p in platforms if p in _PLATFORMS] or ["logscale"]
    clients = clients or {}

    deadline = time.monotonic() + max(60.0, float(max_runtime_seconds))
    _remaining = lambda: deadline - time.monotonic()

    result = BehavioralHuntResult(
        tipper_id=str(tipper_id),
        tipper_title=tipper_title,
        hunt_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        search_hours=hours,
        platform=" + ".join(_PLATFORMS[p].name for p in platforms),
    )

    # LLM (in-house FailoverChatModel)
    if llm is None:
        try:
            from ..llm_init import get_llm_with_temperature
            llm = get_llm_with_temperature(0.3)
        except Exception as exc:
            result.errors.append(f"LLM unavailable: {exc}")
            return result
    result.llm_model = getattr(llm, "model_name", getattr(llm, "model", "")) or ""

    any_authored = False
    for ptype in platforms:
        spec = _PLATFORMS[ptype]

        if _remaining() <= 0:
            result.errors.append(f"Time budget exhausted — skipped {spec.name} hunts")
            logger.warning(f"[behavioral] deadline reached before {ptype}; skipping")
            continue

        authored = generate_behavioral_hunts(
            tipper_title, narrative, llm, max_hunts=max_hunts, platform=ptype
        )
        result.queries_generated += len(authored)
        if not authored:
            continue
        any_authored = True

        # Resolve the platform's client once (lazily).
        client = clients.get(ptype)
        if client is None:
            try:
                client = spec.build_client()
            except Exception as exc:
                client = None
                result.errors.append(f"{spec.name} client unavailable: {exc}")
        if client is None:
            result.errors.append(f"{spec.name} not configured")
        access_blocked = client is None

        for h in authored:
            hunt = BehavioralHunt(
                title=h["title"],
                hypothesis=h["hypothesis"],
                attack_technique=h["attack_technique"],
                query=h["query"],
                query_type=spec.query_type,
            )

            # Out of time budget — surface the query for manual use, don't run it.
            if _remaining() <= 0:
                hunt.status = "skipped_deadline"
                hunt.detail = "skipped: run-level time budget exhausted"
                logger.warning(f"[behavioral] deadline reached; skipping '{hunt.title}' ({ptype})")
                result.hunts.append(hunt)
                continue

            # Attempt loop: validate -> execute. On a validation reject or a
            # compile error, feed the error back to the LLM, regenerate, and
            # retry — up to _MAX_QUERY_ATTEMPTS total, then gracefully degrade.
            for attempt in range(1, _MAX_QUERY_ATTEMPTS + 1):
                hunt.attempts = attempt
                ok, reason = spec.validate(hunt.query)
                if not ok:
                    if attempt < _MAX_QUERY_ATTEMPTS:
                        fixed = _repair_query(spec, hunt.title, hunt.hypothesis,
                                              hunt.query, f"validation failed: {reason}", llm)
                        if fixed:
                            logger.info(f"[behavioral] '{hunt.title}' ({ptype}): repairing after validation ({reason})")
                            hunt.query = fixed
                            continue
                    hunt.status = "skipped_validation"
                    hunt.detail = reason
                    logger.info(f"[behavioral] skip '{hunt.title}' ({ptype}): {reason}")
                    break

                if client is None or access_blocked:
                    hunt.status = "error"
                    hunt.detail = f"{spec.name} not available"
                    break

                # Bound this query's wait to the smaller of its platform ceiling
                # and the run's remaining budget, so no single query overruns.
                q_timeout = min(spec.query_timeout, max(5.0, _remaining()))
                try:
                    res = spec.execute(client, hunt.query, hours, q_timeout)
                except Exception as exc:
                    res = {"error": f"execution error: {exc}"}

                # Access problems are not repairable — short-circuit this platform.
                if res.get("access_denied") or res.get("not_configured"):
                    access_blocked = True
                    hunt.status = "error"
                    hunt.detail = res.get("error", f"{spec.name} access denied")
                    result.errors.append(f"{spec.name}: {hunt.detail}")
                    break

                err = res.get("error")
                if err:
                    if attempt < _MAX_QUERY_ATTEMPTS:
                        fixed = _repair_query(spec, hunt.title, hunt.hypothesis,
                                              hunt.query, str(err)[:500], llm)
                        if fixed:
                            logger.info(f"[behavioral] '{hunt.title}' ({ptype}): repairing after compile error")
                            hunt.query = fixed
                            continue
                    hunt.status = "error"
                    hunt.detail = str(err)[:300]
                    break

                # Success
                events = res.get("events") or []
                count = res.get("count")
                hit_count = count if isinstance(count, int) else len(events)
                result.queries_executed += 1
                hunt.hit_count = hit_count
                hunt.hostnames = _extract_hostnames(events, spec.host_fields)
                hunt.status = "executed" if hit_count > 0 else "no_hits"
                logger.info(f"[behavioral] '{hunt.title}' ({ptype}): {hit_count} hit(s) (attempt {attempt})")
                break

            result.hunts.append(hunt)

    if not any_authored:
        result.errors.append("LLM authored no behavioral hunts")

    result.total_hits = sum(h.hit_count for h in result.hunts)
    logger.info(
        f"[behavioral] tipper #{tipper_id}: {result.queries_generated} authored, "
        f"{result.queries_executed} executed, {result.total_hits} total hit(s) "
        f"across {result.platform}"
    )
    return result
