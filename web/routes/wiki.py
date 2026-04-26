"""Wiki Knowledge Base routes — viewer, search, graph, and compile API."""

import logging
import threading

from flask import Blueprint, jsonify, render_template, request

from src.utils.logging_utils import log_web_activity
from src.components.web.edit_auth import check_edit_password, notify_edit_async

logger = logging.getLogger(__name__)

wiki_bp = Blueprint("wiki", __name__)

# Module-level compile status (updated by background thread)
_compile_status: dict = {"running": False, "last_result": None}


def _run_compile(full: bool = False):
    _compile_status["running"] = True
    try:
        from src.components.web import wiki_handler as h
        if full:
            _compile_status["last_result"] = h.compile_full()
        else:
            _compile_status["last_result"] = h.compile_incremental()
    except Exception as exc:
        logger.error("Background wiki compile failed: %s", exc, exc_info=True)
        _compile_status["last_result"] = {"error": str(exc)}
    finally:
        _compile_status["running"] = False


@wiki_bp.route("/wiki")
@log_web_activity
def wiki_index():
    from src.components.web import wiki_handler as h
    articles = h.list_articles()
    stats = h.get_stats()
    all_tags = h.get_all_tags()
    return render_template("wiki.html", articles=articles, stats=stats,
                           all_tags=all_tags)


@wiki_bp.route("/wiki/<slug>")
@log_web_activity
def wiki_article(slug):
    from src.components.web import wiki_handler as h
    content = h.read_article(slug)
    if content is None:
        articles = h.list_articles()
        stats = h.get_stats()
        all_tags = h.get_all_tags()
        return render_template("wiki.html", articles=articles, stats=stats,
                               all_tags=all_tags,
                               error=f"Article '{slug}' not found"), 404
    meta = h.get_article_meta(slug) or {}
    backlinks = h.get_backlinks(slug)
    articles = h.list_articles()
    stats = h.get_stats()
    all_tags = h.get_all_tags()
    return render_template("wiki.html", articles=articles, stats=stats,
                           all_tags=all_tags,
                           current_slug=slug, current_content=content,
                           article_meta=meta, backlinks=backlinks)


@wiki_bp.route("/api/wiki/search")
@log_web_activity
def wiki_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"results": []})
    from src.components.web import wiki_handler as h
    results = h.search_articles(q)
    return jsonify({"results": results})


@wiki_bp.route("/api/wiki/graph")
@log_web_activity
def wiki_graph():
    from src.components.web import wiki_handler as h
    return jsonify(h.get_graph_data())


@wiki_bp.route("/api/wiki/compile", methods=["POST"])
@log_web_activity
def wiki_compile():
    if not check_edit_password(request, "wiki"):
        return jsonify({"success": False, "error": "Invalid password"}), 403
    if _compile_status["running"]:
        return jsonify({"success": False, "error": "A compile is already in progress"}), 409
    data = request.get_json() or {}
    full = data.get("full", False)
    threading.Thread(target=_run_compile, args=(full,), daemon=True).start()
    mode = "full rebuild" if full else "incremental"
    notify_edit_async("Wiki", f"Triggered {mode} compile")
    return jsonify({"success": True, "message": f"Wiki {mode} compile started"})


@wiki_bp.route("/api/wiki/status")
def wiki_status():
    from src.components.web import wiki_handler as h
    stats = h.get_stats()
    return jsonify({
        "running": _compile_status["running"],
        "last_result": _compile_status["last_result"],
        "stats": stats,
    })
