"""OE Detection Scanner — orchestration pipeline.

Exposes run_scan() as the primary callable for the scheduler.
No argparse, no main() — just the orchestration logic.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime
from pathlib import Path

import httpx

from src.components.oe_detection.base_rule import BaseRule
from src.components.oe_detection.mcp_client import MCPClient
from src.components.oe_detection.models import RiskScore, Signal
from src.components.oe_detection.scoring import ScoringEngine
from src.components.oe_detection.dispatcher import AlertCoordinator

from src.components.oe_detection.rules.network_endpoint import (
    SharedIPNonCorpVPN,
    IdleActiveCycling,
    UnauthorizedRemoteTools,
)
from src.components.oe_detection.rules.identity import (
    AuthCadenceShift,
    SaaSEngagementDrop,
)
from src.components.oe_detection.rules.behavioral import (
    MeetingAvoidance,
    ResponseDegradation,
    OutputVelocityFloor,
)
from src.components.oe_detection.rules.compliance import (
    FINRAOBAInconsistency,
    DataExfiltrationPattern,
    BenefitsEnrollmentAnomaly,
)

logger = logging.getLogger("oe_detector")

ALL_RULES: list[type[BaseRule]] = [
    SharedIPNonCorpVPN,
    IdleActiveCycling,
    UnauthorizedRemoteTools,
    AuthCadenceShift,
    SaaSEngagementDrop,
    MeetingAvoidance,
    ResponseDegradation,
    OutputVelocityFloor,
    FINRAOBAInconsistency,
    DataExfiltrationPattern,
    BenefitsEnrollmentAnomaly,
]


def _init_mcp_clients(config: dict) -> dict[str, MCPClient]:
    clients = {}
    for name, cfg in config.get("mcp_servers", {}).items():
        try:
            client = MCPClient(
                server_url=cfg["url"],
                server_name=cfg.get("name", name),
                timeout=cfg.get("timeout_seconds", 30),
            )
            clients[name] = client
            logger.info(f"MCP client initialized: {name} -> {cfg['url']}")
        except Exception as e:
            logger.warning(f"Failed to init MCP client {name}: {e}")
    return clients


def _init_rules(config: dict, mcp_clients: dict[str, MCPClient]) -> list[BaseRule]:
    rules = []
    for rule_cls in ALL_RULES:
        try:
            rule = rule_cls(config, mcp_clients)
            if rule.enabled:
                rules.append(rule)
                logger.info(f"Rule loaded: {rule.rule_id} (weight={rule.weight})")
            else:
                logger.info(f"Rule disabled: {rule.rule_id}")
        except Exception as e:
            logger.error(f"Failed to init rule {rule_cls.__name__}: {e}")
    return rules


_POC_ROSTER = Path(__file__).resolve().parents[3] / "data" / "oe_detection" / "poc_employees.json"


def _load_poc_roster() -> list[dict]:
    """Load POC employee list from gitignored JSON file."""
    if not _POC_ROSTER.exists():
        logger.warning(f"POC roster not found: {_POC_ROSTER}")
        return []
    with open(_POC_ROSTER) as f:
        employees = json.load(f)
    logger.info(f"Loaded {len(employees)} employees from POC roster")
    return employees


def _get_employee_list(mcp_clients: dict[str, MCPClient]) -> list[dict]:
    # Try MCP HRIS server first
    hris = mcp_clients.get("hris")
    if hris:
        result = hris.call_tool("get_active_employees", {})
        if result and "employees" in result:
            logger.info(f"Got {len(result['employees'])} employees from HRIS MCP")
            return result["employees"]

    # Try MCP Identity server
    identity = mcp_clients.get("identity")
    if identity:
        result = identity.call_tool("get_active_users", {})
        if result and "users" in result:
            logger.info(f"Got {len(result['users'])} employees from Identity MCP")
            return result["users"]

    # Fallback: gitignored POC roster (pending SNOW Table API RITM)
    return _load_poc_roster()


def run_scan(config: dict, dry_run: bool = False, employee_id: str | None = None) -> list[RiskScore]:
    """Run the full OE detection pipeline.

    Args:
        config: Loaded OE detection config dict (from settings.yaml)
        dry_run: If True, calculate scores but don't dispatch alerts
        employee_id: If set, scan only this employee

    Returns:
        List of RiskScore objects for all scanned employees
    """
    scan_id = str(uuid.uuid4())[:8]
    scan_start = datetime.utcnow()

    logger.info(f"OE scan {scan_id} starting (dry_run={dry_run})")

    mcp_clients = _init_mcp_clients(config)
    rules = _init_rules(config, mcp_clients)
    scoring_engine = ScoringEngine(config)
    alert_coordinator = AlertCoordinator(config, scoring_engine)

    logger.info(f"Initialized: {len(mcp_clients)} MCP clients, {len(rules)} detection rules")

    if employee_id:
        employees = [{"id": employee_id, "name": employee_id}]
    else:
        employees = _get_employee_list(mcp_clients)

    if not employees:
        logger.warning("No employees to scan — MCP servers may not be running yet")
        # Save empty scan record
        _save_scan_results(scan_id, scan_start, [], dry_run)
        return []

    batch_size = config.get("scheduler", {}).get("batch_size", 50)
    batch_delay = config.get("scheduler", {}).get("batch_delay", 5)

    all_scores = []
    total = len(employees)

    logger.info(f"Starting scan for {total} employees with {len(rules)} rules")

    for i, emp in enumerate(employees):
        emp_id = emp.get("id", emp.get("employee_id", "unknown"))
        emp_name = emp.get("name", emp.get("display_name", emp_id))

        all_signals: list[Signal] = []

        for rule in rules:
            try:
                signals = rule.evaluate(emp_id)
                all_signals.extend(signals)
            except Exception as e:
                logger.error(f"Rule {rule.rule_id} failed for {emp_id}: {e}", exc_info=True)

        score = scoring_engine.calculate(emp_id, emp_name, all_signals)
        all_scores.append(score)

        if not dry_run:
            alert_coordinator.process_score(score)
        else:
            if score.normalized_score > 0:
                logger.info(
                    f"[DRY RUN] Would alert for {emp_name}: "
                    f"{score.normalized_score:.1f} ({score.risk_level.value})"
                )

        if (i + 1) % batch_size == 0 and i + 1 < total:
            logger.info(f"Batch complete ({i + 1}/{total}). Pausing {batch_delay}s...")
            time.sleep(batch_delay)

    scan_duration = (datetime.utcnow() - scan_start).total_seconds()

    level_counts = {}
    for s in all_scores:
        level_counts[s.risk_level.value] = level_counts.get(s.risk_level.value, 0) + 1

    logger.info(
        f"Scan {scan_id} complete in {scan_duration:.1f}s | "
        f"{total} employees | Results: {json.dumps(level_counts)}"
    )

    # Persist results to DB
    _save_scan_results(scan_id, scan_start, all_scores, dry_run)

    # Cleanup MCP clients
    for client in mcp_clients.values():
        try:
            client.close()
        except Exception:
            pass

    return all_scores


def _save_scan_results(scan_id: str, scan_start: datetime, scores: list[RiskScore], dry_run: bool) -> None:
    """Persist scan results to the OE detection database."""
    try:
        from services.oe_detection_db import save_scan_result
        save_scan_result(scan_id, scan_start, scores, dry_run)
        logger.info(f"Scan {scan_id} results saved to database ({len(scores)} scores)")
    except Exception as e:
        logger.error(f"Failed to save scan results: {e}", exc_info=True)


def send_heartbeat() -> None:
    """Send a weekly heartbeat to Webex confirming OE detection is alive."""
    from src.components.oe_detection.config.loader import load_oe_config

    config = load_oe_config()
    webex_cfg = config.get("alerts", {}).get("webex", {})
    bot_token = webex_cfg.get("bot_token", "")
    room_id = webex_cfg.get("room_id", "")

    if not bot_token or not room_id:
        logger.warning("OE heartbeat skipped — no Webex bot_token or room_id configured")
        return

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Gather stats from DB
    try:
        from services.oe_detection_db import get_summary_stats, get_scan_history
        stats = get_summary_stats()
        scans = get_scan_history(limit=5)
    except Exception:
        stats = {}
        scans = []

    total = stats.get("total_scanned", 0)
    dist = stats.get("risk_distribution", {})
    last_scan = stats.get("last_scan", "never")

    # POC roster info
    roster = _load_poc_roster()
    roster_names = ", ".join(e.get("name", e.get("id", "?")) for e in roster) if roster else "none loaded"

    # Enabled rules count
    enabled_rules = sum(
        1 for r in config.get("rules", {}).values()
        if isinstance(r, dict) and r.get("enabled", False)
    )

    # Build risk distribution line
    dist_parts = []
    for level in ["critical", "high", "medium", "low"]:
        count = dist.get(level, 0)
        if count:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[level]
            dist_parts.append(f"{emoji} {level.upper()}: {count}")
    dist_line = " | ".join(dist_parts) if dist_parts else "No scores yet"

    # Recent scans summary
    scan_lines = []
    for s in scans[:3]:
        dry = " (dry run)" if s.get("dry_run") else ""
        scan_lines.append(f"  - `{s['scan_id']}` — {s['started_at']} — {s['employee_count']} employees{dry}")
    scan_text = "\n".join(scan_lines) if scan_lines else "  No scans yet"

    message = (
        f"💓 **OE Detection — Weekly Heartbeat**\n\n"
        f"🕐 {timestamp}\n\n"
        f"**Status:** ✅ Running (scan every 6h)\n"
        f"**Rules:** {enabled_rules} enabled / {len(ALL_RULES)} total\n"
        f"**POC Roster:** {len(roster)} employees — {roster_names}\n"
        f"**Last Scan:** {last_scan or 'never'}\n"
        f"**Employees Scored:** {total}\n"
        f"**Risk Distribution:** {dist_line}\n\n"
        f"**Recent Scans:**\n{scan_text}\n\n"
        f"---\n"
        f"_Employee source: {'POC roster' if roster else 'none'} "
        f"(pending SNOW Table API RITM for dynamic list)_"
    )

    try:
        resp = httpx.post(
            "https://webexapis.com/v1/messages",
            headers={
                "Authorization": f"Bearer {bot_token}",
                "Content-Type": "application/json",
            },
            json={"roomId": room_id, "markdown": message},
            timeout=15,
        )
        resp.raise_for_status()
        logger.info("OE Detection heartbeat sent to Webex")
    except Exception as e:
        logger.error(f"OE heartbeat Webex send failed: {e}")
