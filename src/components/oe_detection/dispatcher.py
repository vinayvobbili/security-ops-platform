"""Alert Dispatcher.

Routes OE risk alerts to:
- Webex Teams (SOC room)
- Email (CISO / compliance escalation)
- SIEM (Splunk HEC / Sentinel / QRadar)
- Local LLM (Qwen 32B via Ollama for analyst narratives)
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from src.components.oe_detection.models import Alert, RiskScore, RiskLevel
from src.components.oe_detection.scoring import ScoringEngine

logger = logging.getLogger("oe_detector")


def _resolve_env(value: str) -> str:
    """Resolve ${ENV_VAR} references in config values."""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        env_key = value[2:-1]
        return os.environ.get(env_key, "")
    return value


class WebexDispatcher:
    """Send alert cards to Webex Teams SOC room."""

    def __init__(self, config: dict):
        cfg = config.get("alerts", {}).get("webex", {})
        self.enabled = cfg.get("enabled", False)
        self.webhook_url = _resolve_env(cfg.get("webhook_url", ""))
        self.room_id = _resolve_env(cfg.get("room_id", ""))
        self.bot_token = _resolve_env(cfg.get("bot_token", ""))
        self.min_level = cfg.get("min_level", "high")

    def dispatch(self, score: RiskScore) -> bool:
        if not self.enabled or not self.bot_token:
            return False

        level_emoji = {
            "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"
        }
        emoji = level_emoji.get(score.risk_level.value, "⚪")

        signal_lines = []
        for s in score.signals:
            signal_lines.append(f"  - **{s.rule_id}** (+{s.weight}): {s.description}")
        signals_text = "\n".join(signal_lines) if signal_lines else "  No signals"

        message = (
            f"{emoji} **OE Detection Alert -- {score.risk_level.value.upper()}**\n\n"
            f"**Employee:** {score.employee_name} (`{score.employee_id}`)\n"
            f"**Score:** {score.normalized_score:.1f}/100\n"
            f"**Domains:** {', '.join(sorted(score.domains_hit))} "
            f"({score.domain_count} domains, x{score.correlation_multiplier:.2f})\n"
            f"**Signals ({score.signal_count}):**\n{signals_text}\n\n"
            f"**Time:** {score.calculated_at.strftime('%Y-%m-%d %H:%M UTC')}\n"
        )

        if score.narrative:
            message += f"\n**Analyst Summary:**\n{score.narrative}\n"

        message += "\n---\n_Human review required. No automated action taken._"

        try:
            resp = httpx.post(
                "https://webexapis.com/v1/messages",
                headers={
                    "Authorization": f"Bearer {self.bot_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "roomId": self.room_id,
                    "markdown": message,
                },
                timeout=15,
            )
            resp.raise_for_status()
            logger.info(f"Webex alert sent for {score.employee_id}")
            return True
        except Exception as e:
            logger.error(f"Webex dispatch failed: {e}")
            return False


class EmailDispatcher:
    """Send HTML email alerts for high/critical scores."""

    def __init__(self, config: dict):
        cfg = config.get("alerts", {}).get("email", {})
        self.enabled = cfg.get("enabled", False)
        self.smtp_host = cfg.get("smtp_host", "")
        self.smtp_port = cfg.get("smtp_port", 587)
        self.from_addr = cfg.get("from_addr", "")
        self.recipients = cfg.get("recipients", {})

    def dispatch(self, score: RiskScore) -> bool:
        if not self.enabled or not self.smtp_host:
            return False

        recipients = self.recipients.get(score.risk_level.value, [])
        if not recipients:
            return False

        subject = (
            f"[OE Detection] {score.risk_level.value.upper()} -- "
            f"{score.employee_name} (Score: {score.normalized_score:.0f})"
        )

        signal_rows = ""
        for s in score.signals:
            signal_rows += (
                f"<tr>"
                f"<td style='padding:6px;border:1px solid #ddd;'><b>{s.rule_id}</b></td>"
                f"<td style='padding:6px;border:1px solid #ddd;'>{s.domain.value}</td>"
                f"<td style='padding:6px;border:1px solid #ddd;'>+{s.weight}</td>"
                f"<td style='padding:6px;border:1px solid #ddd;'>{s.description}</td>"
                f"</tr>"
            )

        level_colors = {
            "low": "#4CAF50", "medium": "#FF9800",
            "high": "#F44336", "critical": "#B71C1C",
        }
        color = level_colors.get(score.risk_level.value, "#666")

        html = f"""
        <html><body style="font-family:Arial,sans-serif;color:#333;">
        <div style="background:{color};color:white;padding:16px;border-radius:8px 8px 0 0;">
            <h2 style="margin:0;">OE Detection Alert -- {score.risk_level.value.upper()}</h2>
        </div>
        <div style="border:1px solid #ddd;padding:20px;border-radius:0 0 8px 8px;">
            <table style="width:100%;margin-bottom:16px;">
                <tr><td><b>Employee:</b></td><td>{score.employee_name} ({score.employee_id})</td></tr>
                <tr><td><b>Score:</b></td><td>{score.normalized_score:.1f} / 100</td></tr>
                <tr><td><b>Domains:</b></td><td>{', '.join(sorted(score.domains_hit))} ({score.domain_count})</td></tr>
                <tr><td><b>Correlation Multiplier:</b></td><td>x{score.correlation_multiplier:.2f}</td></tr>
                <tr><td><b>Time:</b></td><td>{score.calculated_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
            </table>
            <h3>Detection Signals ({score.signal_count})</h3>
            <table style="width:100%;border-collapse:collapse;">
                <tr style="background:#f5f5f5;">
                    <th style="padding:8px;border:1px solid #ddd;text-align:left;">Rule</th>
                    <th style="padding:8px;border:1px solid #ddd;text-align:left;">Domain</th>
                    <th style="padding:8px;border:1px solid #ddd;text-align:left;">Weight</th>
                    <th style="padding:8px;border:1px solid #ddd;text-align:left;">Description</th>
                </tr>
                {signal_rows}
            </table>
            {"<h3>Analyst Narrative</h3><p>" + score.narrative + "</p>" if score.narrative else ""}
            <hr style="margin:20px 0;">
            <p style="color:#999;font-size:12px;">
                This is an automated detection alert. <b>Human review is required</b>
                before any action is taken. No employee should be contacted or disciplined
                based solely on this alert. Escalate per the Insider Risk SOP.
            </p>
        </div>
        </body></html>
        """

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(recipients)
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.send_message(msg)

            logger.info(f"Email alert sent for {score.employee_id} to {recipients}")
            return True
        except Exception as e:
            logger.error(f"Email dispatch failed: {e}")
            return False


class SIEMDispatcher:
    """Push events to SIEM via webhook (Splunk HEC, Sentinel, etc.)."""

    def __init__(self, config: dict):
        cfg = config.get("alerts", {}).get("siem", {})
        self.enabled = cfg.get("enabled", False)
        self.webhook_url = _resolve_env(cfg.get("webhook_url", ""))
        self.auth_token = _resolve_env(cfg.get("auth_token", ""))
        self.source_type = cfg.get("source_type", "oe_detection")
        self.min_level = cfg.get("min_level", "low")

    def dispatch(self, score: RiskScore) -> bool:
        if not self.enabled or not self.webhook_url:
            return False

        event = {
            "time": int(score.calculated_at.timestamp()),
            "sourcetype": self.source_type,
            "event": {
                "action": "oe_risk_score",
                "employee_id": score.employee_id,
                "employee_name": score.employee_name,
                "score": round(score.normalized_score, 2),
                "risk_level": score.risk_level.value,
                "signal_count": score.signal_count,
                "domain_count": score.domain_count,
                "domains": list(score.domains_hit),
                "correlation_multiplier": score.correlation_multiplier,
                "signals": [
                    {
                        "rule_id": s.rule_id,
                        "domain": s.domain.value,
                        "weight": s.weight,
                        "description": s.description,
                        "source": s.source_tool,
                    }
                    for s in score.signals
                ],
            },
        }

        try:
            headers = {"Content-Type": "application/json"}
            if self.auth_token:
                headers["Authorization"] = f"Splunk {self.auth_token}"

            resp = httpx.post(
                self.webhook_url,
                json=event,
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            logger.info(f"SIEM event sent for {score.employee_id}")
            return True
        except Exception as e:
            logger.error(f"SIEM dispatch failed: {e}")
            return False


class LLMNarrativeGenerator:
    """Generate human-readable analyst narratives using local Qwen model."""

    def __init__(self, config: dict):
        cfg = config.get("alerts", {}).get("llm_narrative", {})
        self.enabled = cfg.get("enabled", False)
        self.m1_analysis_base_url = cfg.get("m1_analysis_base_url", "http://localhost:8000/v1")
        self.model = cfg.get("model", "default")
        self.min_level = cfg.get("min_level", "medium")

    def generate(self, score: RiskScore) -> str:
        if not self.enabled:
            return ""

        signal_details = "\n".join(
            f"- {s.rule_id} ({s.domain.value}, +{s.weight}): {s.description}"
            for s in score.signals
        )

        prompt = f"""You are a SOC insider risk analyst. Analyze the following overemployment \
detection signals for an employee and write a concise investigation summary \
(3-5 sentences). Focus on which signals correlate, what the likely scenario is, \
recommended next steps, and any caveats about false positives.

Employee: {score.employee_name} ({score.employee_id})
Risk Score: {score.normalized_score:.1f}/100 ({score.risk_level.value.upper()})
Domains: {', '.join(sorted(score.domains_hit))} ({score.domain_count} domains)
Correlation Multiplier: x{score.correlation_multiplier:.2f}

Detection Signals:
{signal_details}

Write the analyst summary now. Be specific and actionable."""

        try:
            resp = httpx.post(
                f"{self.m1_analysis_base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 300,
                },
                timeout=120,
            )
            resp.raise_for_status()
            narrative = resp.json()["choices"][0]["message"]["content"].strip()
            logger.info(f"LLM narrative generated for {score.employee_id}")
            return narrative
        except Exception as e:
            logger.error(f"LLM narrative generation failed: {e}")
            return ""


class AlertCoordinator:
    """Coordinates alert dispatch across all configured channels."""

    def __init__(self, config: dict, scoring_engine: ScoringEngine):
        self.config = config
        self.scoring_engine = scoring_engine

        self.webex = WebexDispatcher(config)
        self.email = EmailDispatcher(config)
        self.siem = SIEMDispatcher(config)
        self.llm = LLMNarrativeGenerator(config)

    def process_score(self, score: RiskScore) -> Alert:
        dispatched_to = []

        if self.scoring_engine.should_alert(score, self.llm.min_level):
            narrative = self.llm.generate(score)
            score.narrative = narrative

        if self.scoring_engine.should_alert(score, self.siem.min_level):
            if self.siem.dispatch(score):
                dispatched_to.append("siem")

        if self.scoring_engine.should_alert(score, self.webex.min_level):
            if self.webex.dispatch(score):
                dispatched_to.append("webex")

        if score.risk_level.value in self.email.recipients:
            if self.email.dispatch(score):
                dispatched_to.append("email")

        alert = Alert(
            risk_score=score,
            dispatched_to=dispatched_to,
        )

        if dispatched_to:
            logger.info(
                f"Alert {alert.alert_id} dispatched for {score.employee_id} "
                f"({score.risk_level.value}) -> {', '.join(dispatched_to)}"
            )
        else:
            logger.debug(
                f"Score for {score.employee_id} ({score.risk_level.value}) "
                f"below all alert thresholds"
            )

        return alert
