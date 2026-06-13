"""Detection-as-Code pipeline — Sigma → XSIAM, run like CI/CD.

Paste a Sigma rule (the vendor-neutral detection-as-code standard) and this
service runs it through the same gates a real detection-content CI/CD pipeline
would, then packages it as a GitLab merge request for the detection repo:

  1. Lint & schema-validate the Sigma rule (deterministic).
  2. Compile it to an XSIAM XQL correlation query (GPT-4.1, with a
     deterministic best-effort floor if the model is unavailable).
  3. Dry-run that XQL against the live XSIAM tenant — read-only, bounded
     window — to prove it parses and to surface a hit count (real CI gate).
  4. Detection-engineering review (the LLM gateway): quality, false-positive risk,
     ATT&CK mapping, overlap with rules already in the catalog, improvements.
  5. Package the GitLab artifacts: the rule file, the compiled XQL, a
     `.gitlab-ci.yml`, and an MR description.

The pipeline runs in a background worker; the page polls and watches the stages
light up. Everything to here is local + read-only. The one write path — opening
the merge request via the GitLab API — is an explicit, human-gated action and is
disabled outright on the dev instance (it always targets the prod detection
repo). Every run + deploy is logged with an audit trail.

The generic, vendor-neutral pieces — Sigma/XQL linting, drafting from plain
English, catalog overlap, and the senior-engineer review — are delegated to the
``detflow`` OSS package (extracted from this very workbench) so the two don't
drift; the XSIAM-specific compile, the live-tenant dry-run, and the GitLab
packaging stay here. The LLM tier is injected via :func:`_detflow_model` so
detflow runs on the LLM gateway (GPT-4.1 + m1 fallback), not its own env config.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import detflow  # OSS detection-engineering copilot — the generic lint/draft/overlap/review core

logger = logging.getLogger(__name__)

_DB = Path(__file__).resolve().parent.parent / "data" / "detection_pipeline.db"
_RULES_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "rules_cache"

# Two bounded the LLM gateway calls + a tenant round-trip per run; keep concurrency low.
_MAX_CONCURRENT = 2
_slots = threading.BoundedSemaphore(_MAX_CONCURRENT)

# Bound each LLM stage well under any HTTP ceiling; fall to the floor on timeout.
_LLM_TIMEOUT = 120.0

# Dry-run is read-only and bounded: last N hours, short poll, small sample.
# The window is deliberately tight — the gate exists to prove the XQL parses on
# the tenant and surface a rough hit count, not to backfill history; a wider
# window just scans more rows and burns more Cortex compute for no extra signal.
_DRYRUN_WINDOW_HOURS = 4
_DRYRUN_MAX_WAIT = 75.0
_DRYRUN_SAMPLE = 3
# Dedupe identical dry-runs: a successful run of the same XQL over the same
# window is cached this long so re-submitting the same rule doesn't re-bill the
# tenant. Compile/parse errors are NOT cached (they fail fast and are cheap).
_DRYRUN_CACHE_TTL_HOURS = 6

_MAX_RULE_CHARS = 60_000

# Pipeline stages, in order. (key, label)
_STAGES = [
    ("lint", "🔍 Lint &amp; schema validation"),
    ("compile", "🧬 Compile Sigma → XSIAM XQL"),
    ("test", "🧪 Dry-run on XSIAM (read-only)"),
    ("review", "🧠 Detection-engineering review"),
    ("package", "📦 Package GitLab merge request"),
]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Persistence ───────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    _DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dac_jobs (
                id            TEXT PRIMARY KEY,
                created_at    TEXT NOT NULL,
                completed_at  TEXT,
                actor         TEXT,
                title         TEXT,
                rule_source   TEXT,
                status        TEXT NOT NULL,   -- queued | running | done | error
                phase         TEXT,
                verdict       TEXT,            -- pass | warn | fail
                stages_json   TEXT,
                compiled_json TEXT,
                review_json   TEXT,
                artifacts_json TEXT,
                error         TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dac_jobs_created ON dac_jobs(created_at DESC)")
        # migration: source-of-truth lane (sigma | xql) — added 2026-06-05
        try:
            conn.execute("ALTER TABLE dac_jobs ADD COLUMN source_type TEXT DEFAULT 'sigma'")
        except sqlite3.OperationalError:
            pass  # column already present
        # migration: opt-in live XSIAM dry-run — added 2026-06-12. Default 0 so an
        # ordinary run lints/compiles/reviews without ever touching the tenant.
        try:
            conn.execute("ALTER TABLE dac_jobs ADD COLUMN run_dry_run INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already present
        # Dedupe cache for identical successful dry-runs (see _DRYRUN_CACHE_TTL_HOURS).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dac_dryrun_cache (
                xql_hash      TEXT PRIMARY KEY,
                created_at    TEXT NOT NULL,
                created_epoch INTEGER NOT NULL,
                result_json   TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dac_deploys (
                id          TEXT PRIMARY KEY,
                job_id      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                actor       TEXT,
                target      TEXT,
                status      TEXT,    -- opened | dev_blocked | not_configured | error
                detail      TEXT,
                mr_url      TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dac_deploys_job ON dac_deploys(job_id, created_at)")
        conn.commit()


def _reconcile_orphans() -> None:
    """A restart leaves no worker driving in-flight jobs — mark them interrupted
    so the shared history never shows a zombie 'running' pipeline."""
    try:
        with _connect() as conn:
            conn.execute(
                "UPDATE dac_jobs SET status='error', phase='Interrupted', "
                "error='Interrupted by a server restart — re-run the pipeline.', "
                "completed_at=? WHERE status IN ('queued','running')",
                (_now(),),
            )
            conn.commit()
    except Exception:
        logger.exception("[dac] orphan reconcile failed")


_init_db()
_reconcile_orphans()


def _update(job_id: str, **cols) -> None:
    if not cols:
        return
    sets = ", ".join(f"{k} = ?" for k in cols)
    vals = list(cols.values()) + [job_id]
    try:
        with _connect() as conn:
            conn.execute(f"UPDATE dac_jobs SET {sets} WHERE id = ?", vals)
            conn.commit()
    except Exception:
        logger.exception("[dac] failed to update job %s", job_id)


def _j(v):
    if not v:
        return None
    try:
        return json.loads(v)
    except Exception:
        return None


def list_deploys(job_id: str) -> List[Dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT * FROM dac_deploys WHERE job_id = ? ORDER BY created_at DESC",
                (job_id,),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        logger.exception("[dac] list_deploys failed")
        return []


def _row_to_job(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "actor": row["actor"],
        "title": row["title"],
        "rule_source": row["rule_source"],
        "source_type": (row["source_type"] if "source_type" in row.keys() else "sigma") or "sigma",
        "run_dry_run": bool(row["run_dry_run"]) if "run_dry_run" in row.keys() else False,
        "status": row["status"],
        "phase": row["phase"],
        "verdict": row["verdict"],
        "stages": _j(row["stages_json"]) or [],
        "compiled": _j(row["compiled_json"]),
        "review": _j(row["review_json"]),
        "artifacts": _j(row["artifacts_json"]),
        "error": row["error"],
    }


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    try:
        with _connect() as conn:
            row = conn.execute("SELECT * FROM dac_jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        job = _row_to_job(row)
        job["deploys"] = list_deploys(job_id)
        return job
    except Exception:
        logger.exception("[dac] get_job failed")
        return None


def list_recent(limit: int = 25) -> List[Dict[str, Any]]:
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, actor, title, status, phase, verdict "
                "FROM dac_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    except Exception:
        logger.exception("[dac] list_recent failed")
        return []
    return [{
        "id": r["id"], "created_at": r["created_at"], "actor": r["actor"],
        "title": r["title"] or "Untitled rule", "status": r["status"],
        "phase": r["phase"], "verdict": r["verdict"],
    } for r in rows]


# ── Orchestration ───────────────────────────────────────────────────────────────

def submit(rule_source: str, title: str = "", actor: str = "anonymous",
           source_type: str = "sigma", run_dry_run: bool = False) -> str:
    """Create a pipeline job and kick off the background worker. Returns job_id.

    source_type "sigma" (default) lints + compiles a Sigma rule; "xql" takes a
    Cortex XSIAM XQL query directly and skips Sigma (the direct-XQL lane).

    run_dry_run gates the one tenant-touching stage: when False (the default) the
    pipeline lints, compiles, reviews and packages entirely offline — the live
    XSIAM dry-run is skipped so no Cortex compute is spent. The caller sets it
    True only when the engineer explicitly asks to validate on the live tenant.
    """
    source_type = "xql" if str(source_type).lower() == "xql" else "sigma"
    job_id = uuid.uuid4().hex[:16]
    rule_source = (rule_source or "").strip()[:_MAX_RULE_CHARS]
    title = (title or "").strip() or _derive_title(rule_source, source_type)

    stages = [{"key": k, "label": lbl, "status": "pending", "summary": "", "details": []}
              for k, lbl in _STAGES]

    with _connect() as conn:
        conn.execute(
            "INSERT INTO dac_jobs (id, created_at, actor, title, rule_source, source_type, run_dry_run, status, phase, stages_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 'Queued', ?)",
            (job_id, _now(), actor, title, rule_source, source_type, 1 if run_dry_run else 0,
             json.dumps(stages)),
        )
        conn.commit()

    logger.info("[DAC] user=%s action=submit job=%s title=%s", actor, job_id, title[:80])
    t = threading.Thread(target=_run_job, args=(job_id,), name=f"dac-{job_id}", daemon=True)
    t.start()
    return job_id


def _derive_title(rule_source: str, source_type: str = "sigma") -> str:
    if source_type == "xql":
        # No title field in raw XQL — derive from the dataset, else first line.
        ds = _xql_dataset(rule_source)
        if ds:
            return f"XQL detection on {ds}"
        for line in rule_source.splitlines():
            if line.strip():
                return line.strip()[:140]
        return "Untitled XQL detection"
    # Prefer the Sigma `title:` field, else first non-empty line.
    m = re.search(r"^\s*title\s*:\s*(.+)$", rule_source, re.MULTILINE)
    if m:
        return m.group(1).strip().strip("'\"")[:140]
    for line in rule_source.splitlines():
        if line.strip():
            return line.strip()[:140]
    return "Untitled rule"


class _Stages:
    """Mutable in-worker view of the pipeline stages, persisted after each change
    so the polling UI watches stages light up live."""

    def __init__(self, job_id: str):
        self.job_id = job_id
        self.items = [{"key": k, "label": lbl, "status": "pending", "summary": "", "details": []}
                      for k, lbl in _STAGES]

    def _idx(self, key: str) -> int:
        return next(i for i, s in enumerate(self.items) if s["key"] == key)

    def set(self, key: str, *, status: Optional[str] = None, summary: Optional[str] = None,
            details: Optional[List[str]] = None, phase: Optional[str] = None) -> None:
        s = self.items[self._idx(key)]
        if status is not None:
            s["status"] = status
        if summary is not None:
            s["summary"] = summary
        if details is not None:
            s["details"] = details
        _update(self.job_id, stages_json=json.dumps(self.items),
                phase=phase or s["label"])


def _run_job(job_id: str) -> None:
    acquired = False
    st = _Stages(job_id)
    try:
        job = get_job(job_id)
        if not job:
            return
        rule_source = job["rule_source"] or ""
        source_type = job.get("source_type") or "sigma"

        _update(job_id, status="queued", phase="Waiting for a pipeline runner")
        _slots.acquire()
        acquired = True
        _update(job_id, status="running")

        if source_type == "xql":
            # ── Direct-XQL lane: Sigma skipped ─────────────────────────
            # Stage 1: validate the XQL instead of linting Sigma.
            st.set("lint", status="running", phase="Validating the XQL")
            xql_clean, lint = _lint_xql(rule_source)
            st.set("lint", status=lint["status"], summary=lint["summary"],
                   details=[f"{f['level'].upper()}: {f['msg']}" for f in lint["findings"]])
            if lint["status"] == "fail":
                _finish(job_id, st, "fail")
                return
            # Synthetic Sigma-shaped record so downstream stages stay uniform.
            parsed = {"title": job["title"], "description": "", "level": "medium",
                      "logsource": {}, "detection": {}, "tags": []}
            # Stage 2: no compile — the XQL IS the artifact.
            st.set("compile", status="running", phase="Using the provided XQL")
            compiled = {"xql": xql_clean, "dataset": _xql_dataset(xql_clean),
                        "confidence": "provided", "assumptions": [], "field_mappings": [],
                        "notes": "Authored directly in XQL — Sigma compile skipped.",
                        "llm_authored": False}
            _update(job_id, compiled_json=json.dumps(compiled))
            st.set("compile", status="pass",
                   summary=f"XQL provided directly · dataset {compiled['dataset'] or 'n/a'} · Sigma skipped",
                   details=[])
        else:
            # ── Sigma lane (default) ───────────────────────────────────
            # Stage 1: lint
            st.set("lint", status="running", phase="Linting the Sigma rule")
            parsed, lint = _lint_sigma(rule_source)
            lint_details = [f"{f['level'].upper()}: {f['msg']}" for f in lint["findings"]]
            st.set("lint", status=lint["status"], summary=lint["summary"], details=lint_details)
            if lint["status"] == "fail":
                # Unparseable / missing required fields — the pipeline gate fails here.
                _finish(job_id, st, "fail")
                return

            # Stage 2: compile
            st.set("compile", status="running", phase="Compiling to XSIAM XQL")
            compiled = _compile(parsed, rule_source)
            _update(job_id, compiled_json=json.dumps(compiled))
            c_details = []
            if compiled.get("assumptions"):
                c_details += [f"assumption: {a}" for a in compiled["assumptions"][:6]]
            if compiled.get("notes"):
                c_details.append(compiled["notes"])
            comp_status = "pass" if compiled.get("xql") else "fail"
            if comp_status == "pass" and (compiled.get("confidence") or "").lower() == "low":
                comp_status = "warn"
            st.set("compile", status=comp_status,
                   summary=("Compiled" if compiled.get("xql") else "Could not compile")
                   + (f" · {'🤖 LLM' if compiled.get('llm_authored') else 'floor'}"
                      f" · confidence {compiled.get('confidence', 'n/a')}"),
                   details=c_details)
            if not compiled.get("xql"):
                _finish(job_id, st, "fail")
                return

        # ── Stage 3: dry-run on XSIAM (opt-in — the only tenant-touching stage) ──
        if job.get("run_dry_run"):
            st.set("test", status="running", phase="Dry-running on XSIAM (read-only)")
            dry = _dry_run(compiled["xql"])
        else:
            dry = {"status": "skip",
                   "summary": "Live tenant dry-run not requested — skipped (no Cortex compute spent).",
                   "details": ["Tick “Validate on the live tenant” before running to dry-run the "
                               "XQL against XSIAM and get a hit count."],
                   "ran": False}
            st.set("test", status="skip", summary=dry["summary"], details=dry["details"])
        compiled["dry_run"] = dry
        _update(job_id, compiled_json=json.dumps(compiled))

        # ── Stage 4: review ───────────────────────────────────────────
        st.set("review", status="running", phase="Reviewing the detection")
        overlaps = _catalog_overlap(parsed)
        review = _review(parsed, rule_source, compiled, dry, overlaps, source_type=source_type)
        review["catalog_overlap"] = overlaps
        _update(job_id, review_json=json.dumps(review))
        rev_status = _review_status(review, overlaps)
        rv_details = []
        if overlaps:
            rv_details.append(f"{len(overlaps)} similar rule(s) already in the catalog")
        if review.get("improvements"):
            rv_details += [f"improve: {i}" for i in review["improvements"][:5]]
        st.set("review", status=rev_status,
               summary=(f"Quality {review.get('quality_score', '—')}/100 · "
                        f"FP risk {review.get('false_positive_risk', 'n/a')} · "
                        f"recommends {review.get('verdict_recommendation', 'n/a')}"),
               details=rv_details)

        # ── Stage 5: package ──────────────────────────────────────────
        st.set("package", status="running", phase="Packaging the merge request")
        artifacts = _package(job_id, job["title"], rule_source, parsed, compiled, review, dry, overlaps,
                             source_type=source_type)
        _update(job_id, artifacts_json=json.dumps(artifacts))
        st.set("package", status="pass",
               summary=f"{len(artifacts['files'])} file(s) · branch {artifacts['branch']}",
               details=[f"{p}" for p in artifacts["files"].keys()])

        verdict = _overall_verdict(st.items)
        _finish(job_id, st, verdict)
        logger.info("[DAC] job=%s done verdict=%s compiled=%s dryrun=%s",
                    job_id, verdict, bool(compiled.get("xql")), dry["status"])
    except Exception as e:
        logger.exception("[dac] job %s failed", job_id)
        _update(job_id, status="error", phase="Failed",
                error=f"{type(e).__name__}: {e}", completed_at=_now())
    finally:
        if acquired:
            _slots.release()


def _finish(job_id: str, st: "_Stages", verdict: str) -> None:
    _update(job_id, status="done", phase="Pipeline complete", verdict=verdict,
            stages_json=json.dumps(st.items), completed_at=_now())


def _overall_verdict(stages: List[dict]) -> str:
    statuses = {s["key"]: s["status"] for s in stages}
    if any(v == "fail" for v in statuses.values()):
        return "fail"
    if any(v == "warn" for v in statuses.values()):
        return "warn"
    return "pass"


# ── Stage 1: lint ───────────────────────────────────────────────────────────────

def _lint_sigma(text: str):
    """Parse + schema-check a Sigma rule. Returns (parsed_or_None, lint_dict).

    Delegates the schema checks to ``detflow.lint_sigma`` (the same rules,
    maintained once in the OSS package) and adapts its ``LintReport`` to the
    ``{status, summary, findings:[{level, msg}]}`` shape the worker/template use.
    Returns the parsed mapping only when the rule has no hard error (``ok``).
    """
    rep = detflow.lint_sigma(text or "")
    lint = _lint_to_dict(rep)
    parsed: Optional[dict] = None
    if rep.ok:
        try:
            import yaml
            loaded = yaml.safe_load(text)
            parsed = loaded if isinstance(loaded, dict) else None
        except Exception:
            parsed = None
    return parsed, lint


def _lint_to_dict(rep) -> dict:
    """Adapt a detflow ``LintReport`` to the worker's lint dict (``msg`` key)."""
    return {"status": rep.status, "summary": rep.summary,
            "findings": [{"level": f.level, "msg": f.message} for f in rep.findings]}


# ── Stage 2: compile to XQL ───────────────────────────────────────────────────────

# Rough Sigma logsource -> XSIAM dataset hints. The LLM refines these; the floor
# uses them so it always emits a runnable skeleton.
_DATASET_HINTS = {
    ("windows", "process_creation"): "xdr_data",
    ("windows", "security"): "xdr_data",
    ("windows", "sysmon"): "xdr_data",
    ("windows", "powershell"): "xdr_data",
    ("windows", "network_connection"): "xdr_data",
    ("linux", "process_creation"): "xdr_data",
    ("linux", "auditd"): "xdr_data",
    ("macos", "process_creation"): "xdr_data",
}

_MOD_OPS = {
    "contains": "contains",
    "startswith": "contains",
    "endswith": "contains",
    "re": "~=",
}


def _guess_dataset(logsource: dict) -> str:
    product = (logsource.get("product") or "").lower()
    cat = (logsource.get("category") or logsource.get("service") or "").lower()
    return _DATASET_HINTS.get((product, cat)) or "xdr_data"


def _floor_compile(parsed: dict) -> dict:
    """Deterministic best-effort Sigma->XQL — always a runnable skeleton, refined
    by the LLM when available. Field names are approximate by design."""
    logsource = parsed.get("logsource") or {}
    dataset = _guess_dataset(logsource if isinstance(logsource, dict) else {})
    det = parsed.get("detection") or {}
    conds: List[str] = []
    for key, block in det.items():
        if key == "condition" or not isinstance(block, dict):
            continue
        for field, val in block.items():
            base, _, mod = field.partition("|")
            op = _MOD_OPS.get(mod, "=")
            if isinstance(val, list):
                vals = ", ".join(f'"{str(v)}"' for v in val[:20])
                conds.append(f'{base} in ({vals})')
            else:
                conds.append(f'{base} {op} "{val}"')
        break  # floor only renders the first selection block
    where = " and ".join(conds) if conds else "true"
    xql = f"dataset = {dataset}\n| filter {where}\n| limit 100"
    return {
        "xql": xql,
        "dataset": dataset,
        "confidence": "low",
        "assumptions": ["Deterministic skeleton — XQL field names are approximate "
                        "and should be confirmed against the tenant schema."],
        "field_mappings": [],
        "notes": "Floor compile (LLM unavailable).",
        "llm_authored": False,
    }


def _xql_dataset(xql: str) -> str:
    """Pull the dataset name out of an XQL query (`dataset = <name> | …`)."""
    m = re.search(r"\bdataset\s*=\s*([A-Za-z_][\w.]*)", xql or "")
    return m.group(1) if m else ""


def _lint_xql(xql: str):
    """Validate a directly-authored XQL query (the direct-XQL lane's stage 1).

    Returns (cleaned_xql, lint_dict). Delegates the structural checks to
    ``detflow.lint_xql`` and adapts the result; the live dry-run (stage 3) is the
    real correctness gate. The cleaned text is just the stripped input.
    """
    text = (xql or "").strip()
    return text, _lint_to_dict(detflow.lint_xql(text))


def draft_xql_from_text(description: str) -> dict:
    """Draft a Cortex XSIAM XQL query directly from a plain-English description
    (the direct-XQL lane's front door — no Sigma in between).
    Returns {"xql": "...", "notes": [...]} or {"error": "..."}.
    """
    res = _draft(description, "cortex-xql", "dac-draftxql",
                 "The model did not return a usable XQL query — try rephrasing.",
                 "write the XQL directly")
    if "rule" in res:
        return {"xql": res["rule"], "notes": res["notes"]}
    return res


def draft_sigma_from_text(description: str) -> dict:
    """Draft a Sigma rule from a plain-English description of the behavior.

    This is the optional front door: an analyst describes what to detect and
    the LLM gateway drafts a Sigma rule, which then drops into the same pipeline. The
    draft is a STARTING POINT — lint/compile/review still validate it.
    Returns {"sigma": "<yaml>", "notes": [...]} or {"error": "..."}.
    """
    res = _draft(description, "sigma", "dac-draft",
                 "The model did not return a usable Sigma rule — try rephrasing.",
                 "write the rule directly")
    if "rule" in res:
        return {"sigma": res["rule"], "notes": res["notes"]}
    return res


def _draft(description: str, fmt: str, thread_prefix: str,
           unusable_msg: str, fallback_hint: str) -> dict:
    """Draft a detection via ``detflow.draft`` on the LLM tier, under the same
    bounded-timeout guard the worker uses elsewhere. Returns ``{"rule", "notes"}``
    on success or ``{"error": ...}``."""
    description = (description or "").strip()
    if not description:
        return {"error": "Describe the behavior you want to detect."}
    description = description[:4000]
    try:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix=thread_prefix) as ex:
            res = ex.submit(
                lambda: detflow.draft(description, fmt, model=_detflow_model())
            ).result(timeout=_LLM_TIMEOUT)
    except _FTimeout:
        return {"error": f"Drafting timed out after {_LLM_TIMEOUT:.0f}s — try again or {fallback_hint}."}
    except Exception as e:
        logger.warning("[dac] %s drafting failed: %s", fmt, e)
        return {"error": f"Could not draft: {type(e).__name__}"}
    if not res.ok:
        return {"error": res.error or unusable_msg}
    notes = list(res.notes) or ["Drafted from plain text — review and edit before running the pipeline."]
    return {"rule": res.rule, "notes": notes}


def _compile(parsed: dict, rule_source: str) -> dict:
    floor = _floor_compile(parsed)
    try:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="dac-compile") as ex:
            out = ex.submit(_llm_compile, parsed, rule_source).result(timeout=_LLM_TIMEOUT)
        if out and out.get("xql"):
            out["llm_authored"] = True
            return out
    except _FTimeout:
        logger.warning("[dac] compile LLM exceeded %.0fs — using floor", _LLM_TIMEOUT)
    except Exception as e:
        logger.warning("[dac] compile LLM unavailable, using floor: %s", e)
    return floor


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL)
    if fence:
        t = fence.group(1).strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    snippet = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", t[start:end + 1])
    try:
        data = json.loads(snippet)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _llm():
    """GPT-4.1 (non-tool drafting tier) with m1-GLM fallback; thinking off so
    the GLM fallback never leaks reasoning tokens into the JSON."""
    from my_bot.utils.llm_factory import create_llm
    return create_llm(temperature=0.15,
                            extra_body={"chat_template_kwargs": {"enable_thinking": False}})


def _detflow_model():
    """Wrap the LLM gateway chat model as a detflow ``DetectionModel`` so detflow's
    drafting/review run on the same GPT-4.1 (+ m1 fallback) tier the rest of the
    workbench uses. detflow never reads ``DETFLOW_LLM_*`` here — we always inject
    this so it can't silently fall back to an unconfigured environment model."""
    return detflow.LangChainModel(_llm(), name="llm")


def _llm_invoke_json(prompt: str, attempts: int = 2) -> Optional[dict]:
    llm = _llm()
    for i in range(attempts):
        try:
            result = llm.invoke(prompt)
        except Exception as e:
            logger.warning("[dac] LLM invoke failed (attempt %d): %s", i + 1, e)
            continue
        data = _extract_json(getattr(result, "content", None) or "")
        if data:
            return data
    return None


def _llm_compile(parsed: dict, rule_source: str) -> Optional[dict]:
    prompt = (
        "You are a senior detection engineer translating a Sigma rule into a Cortex "
        "XSIAM XQL correlation query. Produce a query that faithfully reproduces the "
        "Sigma detection logic on XSIAM data.\n\n"
        "XQL STRUCTURE (mandatory — this is XQL, NOT SQL):\n"
        "  Every query MUST start with `dataset = <name>` and chain stages with pipes:\n"
        "    `| filter <predicate>`  `| fields <a, b, c>`  `| limit <n>`\n"
        "  NEVER use SQL keywords (no from / where / select). Use `filter`, not `where`.\n"
        "  Worked example:\n"
        "    dataset = xdr_data\n"
        "    | filter event_type = ENUM.PROCESS and action_process_image_name contains \"powershell\"\n"
        "    | fields agent_hostname, action_process_image_command_line, actor_effective_username\n"
        "    | limit 100\n\n"
        "Rules:\n"
        "- Pick the most appropriate XSIAM dataset (e.g. xdr_data for endpoint/process "
        "telemetry) for the Sigma logsource.\n"
        "- Map Sigma fields to the closest XSIAM/XDR field names; if unsure, choose the "
        "best canonical XDR field and record it as an assumption.\n"
        "- Use ONLY valid XQL operators. XQL has NO startswith/endswith. Translate:\n"
        "    exact -> `field = \"v\"` ; not-equal -> `field != \"v\"`\n"
        "    Sigma |contains -> `field contains \"v\"`\n"
        "    Sigma |startswith -> regex `field ~= \"^v\"` ; |endswith -> regex `field ~= \"v$\"`\n"
        "    Sigma |re -> `field ~= \"<regex>\"` ; a list of values -> `field in (\"a\", \"b\")`\n"
        "  Combine selections with `and`/`or`/`not` per the Sigma `condition` "
        "(honor 'all of', '1 of'); group with parentheses.\n"
        "- Escape backslashes for regex; remember XQL regex is unanchored unless you add ^ or $.\n"
        "- End the query with a sensible `| fields` projection and a `| limit`.\n"
        "- Do NOT invent specific hostnames, users, or values not in the rule.\n\n"
        "SIGMA RULE:\n```yaml\n" + rule_source[:_MAX_RULE_CHARS] + "\n```\n\n"
        "Respond with ONLY a single JSON object — no markdown fences, no prose — with EXACTLY these keys:\n"
        '  "xql": string — the full XQL query (use \\n for newlines between stages)\n'
        '  "dataset": string — the XSIAM dataset the query reads from\n'
        '  "field_mappings": array of {"sigma_field": string, "xql_field": string}\n'
        '  "assumptions": array of strings — any field/schema assumptions you made\n'
        '  "confidence": "high" | "medium" | "low" — how confident the translation is exact\n'
        '  "notes": string — one line on anything a reviewer should double-check\n'
    )
    data = _llm_invoke_json(prompt)
    if not data or not str(data.get("xql") or "").strip():
        return None
    fms = []
    for m in (data.get("field_mappings") or []):
        if isinstance(m, dict) and (m.get("sigma_field") or m.get("xql_field")):
            fms.append({"sigma_field": str(m.get("sigma_field") or "").strip(),
                        "xql_field": str(m.get("xql_field") or "").strip()})
    return {
        "xql": str(data["xql"]).strip(),
        "dataset": str(data.get("dataset") or "").strip(),
        "field_mappings": fms,
        "assumptions": [str(a).strip() for a in (data.get("assumptions") or []) if str(a).strip()],
        "confidence": str(data.get("confidence") or "medium").strip().lower(),
        "notes": str(data.get("notes") or "").strip(),
    }


# ── Stage 3: dry-run on XSIAM (read-only) ─────────────────────────────────────────

def _dryrun_cache_key(xql: str) -> str:
    """Stable key for a dry-run: normalized XQL + the window it would scan."""
    norm = " ".join((xql or "").split())
    return hashlib.sha256(f"{_DRYRUN_WINDOW_HOURS}h\n{norm}".encode()).hexdigest()


def _dryrun_cache_get(key: str) -> Optional[dict]:
    """A cached PASS result for this exact query/window, if still fresh."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT created_epoch, result_json FROM dac_dryrun_cache WHERE xql_hash = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        if (time.time() - (row["created_epoch"] or 0)) > _DRYRUN_CACHE_TTL_HOURS * 3600:
            return None
        return _j(row["result_json"])
    except Exception:
        logger.exception("[dac] dry-run cache read failed")
        return None


def _dryrun_cache_put(key: str, result: dict) -> None:
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dac_dryrun_cache (xql_hash, created_at, created_epoch, result_json) "
                "VALUES (?, ?, ?, ?)",
                (key, _now(), int(time.time()), json.dumps(result)),
            )
            conn.commit()
    except Exception:
        logger.exception("[dac] dry-run cache write failed")


def _dry_run(xql: str) -> dict:
    """Run the compiled XQL against the live tenant over a bounded recent window,
    read-only. Proves the query parses and reports a hit count. Never raises.

    A query that fails to parse on the tenant is a WARN (our compile may be
    imperfect), not a hard FAIL — the rule itself can still be sound.

    Identical successful runs are served from a short-lived cache so re-submitting
    the same rule doesn't re-bill the tenant; only PASS results are cached (parse
    errors fail fast and are cheap to repeat)."""
    try:
        from services.xsiam import XsiamClient
        client = XsiamClient()
    except Exception as e:
        return {"status": "skip", "summary": "XSIAM client unavailable.",
                "details": [str(e)], "ran": False}
    if not client.is_configured():
        return {"status": "skip", "summary": "XSIAM tenant not configured — dry-run skipped.",
                "details": ["Set XSIAM_PROD_API_* to enable the live dry-run gate."], "ran": False}

    cache_key = _dryrun_cache_key(xql)
    cached = _dryrun_cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        out["cached"] = True
        summary = out.get("summary") or ""
        if not summary.startswith("♻️"):
            out["summary"] = "♻️ cached · " + summary
        return out

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    from_ms = now_ms - _DRYRUN_WINDOW_HOURS * 3600 * 1000
    try:
        start = client.start_xql_query(xql, time_from_ms=from_ms, time_to_ms=now_ms)
        if "error" in start:
            return {"status": "warn", "summary": f"Query did not run on the tenant: {start['error']}",
                    "details": ["The XQL compile likely needs a field/schema correction."],
                    "ran": True, "parses": False}
        query_id = start.get("reply")
        if not query_id:
            return {"status": "warn", "summary": "Tenant did not return a query id.",
                    "details": [str(start)[:300]], "ran": True, "parses": False}
        res = client.get_query_results(str(query_id), poll=True, poll_interval=4.0,
                                       max_wait=_DRYRUN_MAX_WAIT)
        if "error" in res:
            return {"status": "warn", "summary": f"Dry-run did not complete: {res['error']}",
                    "details": [], "ran": True, "parses": True}
        reply = res.get("reply") or {}
        results = reply.get("results") or {}
        rows = results.get("data") or []
        n = reply.get("number_of_results")
        if n is None:
            n = len(rows)
        cols = sorted(rows[0].keys())[:12] if rows else []
        details = []
        if cols:
            details.append("columns: " + ", ".join(cols))
        for row in rows[:_DRYRUN_SAMPLE]:
            flat = "; ".join(f"{k}={str(v)[:60]}" for k, v in list(row.items())[:5])
            details.append("• " + flat)
        summary = (f"✅ Valid XQL — {n:,} event(s) matched in the last "
                   f"{_DRYRUN_WINDOW_HOURS}h.") if n else \
                  (f"✅ Valid XQL — 0 events in the last {_DRYRUN_WINDOW_HOURS}h "
                   "(syntactically sound; may simply be quiet).")
        result = {"status": "pass", "summary": summary, "details": details,
                  "ran": True, "parses": True, "hit_count": int(n)}
        _dryrun_cache_put(cache_key, result)
        return result
    except Exception as e:
        logger.warning("[dac] dry-run errored: %s", e)
        return {"status": "warn", "summary": f"Dry-run error: {type(e).__name__}: {e}",
                "details": [], "ran": True, "parses": False}


# ── Stage 4: review ───────────────────────────────────────────────────────────────

def _sigma_techniques(parsed: dict) -> List[str]:
    """ATT&CK technique IDs from a parsed Sigma rule's tags (via detflow)."""
    return detflow.techniques_from_sigma(parsed or {})


_RULES_CACHE: Optional[List[dict]] = None


def _load_rules_cache() -> List[dict]:
    """The existing-rule inventory used for catalog-overlap, in detflow's loose
    ``{name, source, techniques}`` catalog shape (detflow tokenizes names itself)."""
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    rules: List[dict] = []
    for fn in ("crowdstrike_rules.json", "qradar_rules.json", "tanium_rules.json"):
        try:
            with open(_RULES_CACHE_DIR / fn, "r", encoding="utf-8") as f:
                data = json.load(f)
            for r in data.get("rules", []):
                rules.append({
                    "source": r.get("platform", fn.split("_")[0]),
                    "name": r.get("name", ""),
                    "techniques": [str(t).upper() for t in (r.get("mitre_techniques") or [])],
                })
        except Exception:
            continue
    _RULES_CACHE = rules
    return rules


def _catalog_overlap(parsed: dict, techniques: Optional[List[str]] = None) -> List[dict]:
    """Surface existing catalog rules that share an ATT&CK technique or a strong
    title-token overlap with this detection (via ``detflow.find_overlaps``),
    adapted to the worker/template ``{platform, name, why, score}`` shape."""
    overlaps = detflow.find_overlaps(parsed or {}, _load_rules_cache(), techniques=techniques)
    return [{"platform": o.source, "name": o.name, "why": o.reason, "score": o.score}
            for o in overlaps]


def _review(parsed: dict, rule_source: str, compiled: dict, dry: dict, overlaps: List[dict],
            source_type: str = "sigma") -> dict:
    """Senior-engineer review via ``detflow.review`` on the LLM tier, with the
    compiled XQL + live dry-run folded in as context and the catalog passed so
    detflow flags duplicate coverage. Returns the worker's review dict; falls to
    a deterministic floor on timeout / model failure (detflow never raises, but
    we still guard the call with the same bounded timeout used elsewhere)."""
    floor = {
        "quality_score": None, "severity": parsed.get("level") or "medium",
        "false_positive_risk": "unknown", "fp_rationale": "",
        "mitre_techniques": _sigma_techniques(parsed), "coverage_gaps": [],
        "strengths": [], "improvements": [], "verdict_recommendation": "revise",
        "summary": "Automated review unavailable — manual review recommended.",
        "llm_authored": False,
    }
    try:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="dac-review") as ex:
            rr = ex.submit(_detflow_review, parsed, rule_source, compiled, dry,
                           source_type).result(timeout=_LLM_TIMEOUT)
        if rr is not None and rr.llm_authored:
            return _review_to_dict(rr, parsed)
    except _FTimeout:
        logger.warning("[dac] review LLM exceeded %.0fs — using floor", _LLM_TIMEOUT)
    except Exception as e:
        logger.warning("[dac] review LLM unavailable, using floor: %s", e)
    return floor


def _detflow_review(parsed: dict, rule_source: str, compiled: dict, dry: dict,
                    source_type: str):
    """Call ``detflow.review`` with the workbench's extra context (compiled XQL +
    live dry-run result) and rule catalog."""
    dry_line = dry.get("summary", "not run")
    xql = (compiled.get("xql") or "")[:4000]
    if source_type == "xql":
        rule, fmt = xql, "cortex-xql"
        extra = f"LIVE DRY-RUN RESULT: {dry_line}"
    else:
        rule, fmt = rule_source, "sigma"
        extra = f"COMPILED XSIAM XQL:\n```\n{xql}\n```\n\nLIVE DRY-RUN RESULT: {dry_line}"
    return detflow.review(
        rule, fmt,
        catalog=_load_rules_cache(),
        techniques=_sigma_techniques(parsed) or None,
        extra_context=extra,
        model=_detflow_model(),
    )


def _review_to_dict(rr, parsed: dict) -> dict:
    """Adapt a detflow ``ReviewResult`` to the worker/template review dict."""
    return {
        "quality_score": rr.quality_score,
        "severity": rr.severity.value,
        "false_positive_risk": rr.false_positive_risk,
        "fp_rationale": rr.fp_rationale,
        "mitre_techniques": rr.mitre_techniques or _sigma_techniques(parsed),
        "coverage_gaps": rr.coverage_gaps,
        "strengths": rr.strengths,
        "improvements": rr.improvements,
        "verdict_recommendation": rr.verdict,
        "summary": rr.summary,
        "llm_authored": rr.llm_authored,
    }


def _review_status(review: dict, overlaps: List[dict]) -> str:
    rec = (review.get("verdict_recommendation") or "").lower()
    fp = (review.get("false_positive_risk") or "").lower()
    if rec == "reject":
        return "fail"
    if rec == "revise" or fp == "high" or overlaps:
        return "warn"
    return "pass"


# ── Stage 5: package the GitLab MR ────────────────────────────────────────────────

def _slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (title or "rule").lower()).strip("-")
    return (s or "rule")[:60]


_GITLAB_CI = """\
# Detection-as-Code pipeline — generated by the Detection-as-Code workbench.
# Set XSIAM_API_KEY / XSIAM_API_KEY_ID / XSIAM_BASE_URL as masked CI/CD variables.
stages: [lint, test, deploy]

sigma-lint:
  stage: lint
  image: python:3.11-slim
  script:
    - pip install sigma-cli
    - sigma check detections/

xql-dry-run:
  stage: test
  image: python:3.11-slim
  script:
    - pip install requests
    - python ci/xsiam_dry_run.py detections/compiled/
  rules:
    - if: '$CI_MERGE_REQUEST_IID'

deploy-xsiam:
  stage: deploy
  image: python:3.11-slim
  script:
    - pip install requests
    - python ci/xsiam_deploy.py detections/compiled/ --apply
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
  when: manual
"""

# The self-contained CI scripts shipped into the detection-content repo so the
# runner can lint/dry-run/deploy. Source of truth lives in this repo's ci/ dir;
# every MR carries them (create-or-update is idempotent) so the deploy path is
# real the moment a runner is registered.
_CI_DIR = Path(__file__).resolve().parent.parent / "ci"
_CI_SCRIPTS = ("_xsiam_api.py", "xsiam_dry_run.py", "xsiam_deploy.py")


def _ci_files() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name in _CI_SCRIPTS:
        try:
            out[f"ci/{name}"] = (_CI_DIR / name).read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("[dac] CI script %s unreadable, omitting from MR: %s", name, e)
    return out


def _package(job_id, title, rule_source, parsed, compiled, review, dry, overlaps,
             source_type="sigma") -> dict:
    slug = _slug(parsed.get("title") or title)
    branch = f"detection/{slug}-{job_id[:6]}"
    rule_path = f"detections/{slug}.yml"
    xql_path = f"detections/compiled/{slug}.xql"
    manifest_path = f"detections/compiled/{slug}.json"
    is_xql = source_type == "xql"

    techniques = review.get("mitre_techniques") or _sigma_techniques(parsed)

    xql_header = (
        f"// {'Authored directly in XQL' if is_xql else f'Compiled from {rule_path}'} "
        f"by the Detection-as-Code workbench.\n"
        f"// Dataset: {compiled.get('dataset', 'n/a')} | confidence: {compiled.get('confidence', 'n/a')}\n"
        f"// Review: quality {review.get('quality_score', '—')}/100, "
        f"FP risk {review.get('false_positive_risk', 'n/a')}.\n\n"
    )
    # Deploy manifest — the contract the CI deploy script reads to create the
    # XSIAM correlation rule (no Sigma re-parsing needed at deploy time).
    manifest = {
        "name": parsed.get("title") or title,
        "description": parsed.get("description") or "",
        "severity": review.get("severity") or parsed.get("level") or "medium",
        "xql": compiled.get("xql") or "",
        "dataset": compiled.get("dataset"),
        "mitre_techniques": techniques,
        "mitre_tactics": [],
        "search_window": "24_HOURS",
        "enabled": True,
        "source_rule": (xql_path if is_xql else rule_path),
    }
    files = {
        xql_path: xql_header + (compiled.get("xql") or "") + "\n",
        manifest_path: json.dumps(manifest, indent=2) + "\n",
        ".gitlab-ci.yml": _GITLAB_CI,
    }
    # The Sigma lane ships the .yml as the source of truth; the direct-XQL lane
    # has no Sigma to ship (the .xql is the source).
    if not is_xql:
        files[rule_path] = rule_source.rstrip() + "\n"
    files.update(_ci_files())
    overlap_md = ""
    if overlaps:
        overlap_md = ("\n**Related existing rules** (review for overlap):\n"
                      + "\n".join(f"- `[{o['platform']}]` {o['name']} — {o['why']}" for o in overlaps[:6]) + "\n")
    mr_title = f"Detection: {parsed.get('title') or title}"
    mr_description = (
        f"## 🛡️ {parsed.get('title') or title}\n\n"
        f"{parsed.get('description') or '_No description provided._'}\n\n"
        f"**Severity:** {review.get('severity', parsed.get('level', 'n/a'))}  ·  "
        f"**Quality:** {review.get('quality_score', '—')}/100  ·  "
        f"**FP risk:** {review.get('false_positive_risk', 'n/a')}  ·  "
        f"**Reviewer recommends:** {review.get('verdict_recommendation', 'n/a')}\n\n"
        f"**ATT&CK:** {', '.join(techniques) if techniques else 'none mapped'}\n\n"
        f"### Pipeline result\n"
        + (f"- **Source:** authored directly in XQL (Sigma skipped)\n"
           f"- **Validate:** XQL on `{compiled.get('dataset', 'n/a')}`\n"
           if is_xql else
           f"- **Lint:** schema-valid Sigma\n"
           f"- **Compile → XQL:** `{compiled.get('dataset', 'n/a')}` "
           f"({'LLM-authored' if compiled.get('llm_authored') else 'floor'}, "
           f"confidence {compiled.get('confidence', 'n/a')})\n") +
        f"- **Dry-run:** {dry.get('summary', 'not run')}\n"
        f"- **Review:** {review.get('summary', 'n/a')}\n"
        f"{overlap_md}\n"
        f"### Compiled XQL\n```\n{(compiled.get('xql') or '')[:2000]}\n```\n\n"
        f"_Generated by the Detection-as-Code workbench. Review, then merge to let CI deploy to XSIAM._\n"
    )
    return {
        "branch": branch,
        "files": files,
        "mr_title": mr_title,
        "mr_description": mr_description,
        "commit_message": f"Add detection: {parsed.get('title') or title}",
    }


# ── Deploy (human-gated; disabled on the dev instance) ────────────────────────────

def _record_deploy(job_id, actor, target, status, detail="", mr_url="") -> dict:
    rec = {"id": uuid.uuid4().hex[:16], "job_id": job_id, "created_at": _now(),
           "actor": actor, "target": target, "status": status,
           "detail": (detail or "")[:500], "mr_url": mr_url or ""}
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO dac_deploys (id, job_id, created_at, actor, target, status, detail, mr_url) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rec["id"], job_id, rec["created_at"], actor, target, status, rec["detail"], rec["mr_url"]),
            )
            conn.commit()
    except Exception:
        logger.exception("[dac] failed to record deploy")
    return rec


def open_merge_request(job_id: str, actor: str) -> dict:
    """Approve-and-open the GitLab MR for a finished pipeline. Disabled in dev."""
    from my_config import get_config
    cfg = get_config()
    job = get_job(job_id)
    if not job or not job.get("artifacts"):
        return {"ok": False, "error": "Pipeline not found or not ready."}
    arts = job["artifacts"]
    target = f"{arts.get('branch')} → detection repo"

    if not cfg.is_production:
        rec = _record_deploy(job_id, actor, target, "dev_blocked",
                             f"Disabled on the {cfg.environment} instance.")
        logger.info("[DAC] job=%s MR open blocked (dev) by %s", job_id, actor)
        return {"ok": False, "error": "deploy_disabled_in_dev",
                "warning": f"Opening merge requests is disabled on the {cfg.environment} instance "
                           "(it always targets the prod detection repo). The artifacts are ready to copy.",
                "deploy": rec}

    try:
        from services.gitlab_client import GitLabClient
        client = GitLabClient()
        if not client.is_configured():
            rec = _record_deploy(job_id, actor, target, "not_configured", client.config_hint())
            return {"ok": False, "error": "gitlab_not_configured",
                    "warning": "GitLab is not configured yet. " + client.config_hint(),
                    "deploy": rec}
        res = client.open_merge_request(
            branch=arts["branch"], files=arts["files"],
            title=arts["mr_title"], description=arts["mr_description"],
            commit_message=arts["commit_message"],
        )
        if res.get("error"):
            rec = _record_deploy(job_id, actor, target, "error", res["error"])
            return {"ok": False, "error": res["error"], "deploy": rec}
        rec = _record_deploy(job_id, actor, target, "opened",
                             f"MR !{res.get('mr_iid', '')}", res.get("mr_url", ""))
        logger.info("[DAC] job=%s MR opened by %s url=%s", job_id, actor, res.get("mr_url"))
        return {"ok": True, "mr_url": res.get("mr_url"), "deploy": rec}
    except Exception as e:
        logger.exception("[dac] MR open failed")
        rec = _record_deploy(job_id, actor, target, "error", f"{type(e).__name__}: {e}")
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "deploy": rec}
