"""Local-LLM benchmarks page — renders results from docs/benchmarks/."""

import json
from pathlib import Path

from flask import Blueprint, abort, render_template

from src.utils.logging_utils import log_web_activity

bench_local_bp = Blueprint("bench_local", __name__)

_BENCH_DIR = Path(__file__).resolve().parents[2] / "docs" / "benchmarks"


def _load_runs() -> list[dict]:
    index_path = _BENCH_DIR / "index.json"
    if not index_path.exists():
        return []
    try:
        index = json.loads(index_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    runs = list(index.get("runs", []))
    runs.sort(key=lambda r: r.get("date", ""), reverse=True)

    for run in runs:
        result_rel = run.get("result_file")
        if not result_rel:
            run["_detail"] = None
            continue
        result_path = _BENCH_DIR / result_rel
        if not result_path.exists():
            run["_detail"] = None
            continue
        try:
            run["_detail"] = json.loads(result_path.read_text())
        except (OSError, json.JSONDecodeError):
            run["_detail"] = None
    return runs


@bench_local_bp.route("/bench-local")
@log_web_activity
def display_bench_local():
    """Render local-LLM benchmark results."""
    return render_template("bench_local.html", runs=_load_runs())
