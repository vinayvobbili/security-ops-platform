"""Abnormal Security IOC hunting functions."""

import logging
from datetime import datetime, timedelta, timezone

from ..models import ToolHuntResult

logger = logging.getLogger(__name__)


def hunt_abnormal(entities, hours: int) -> ToolHuntResult:
    """Hunt IOCs in Abnormal Security (email-focused).

    Args:
        entities: ExtractedEntities object from entity_extractor
        hours: Number of hours to search back

    Returns:
        ToolHuntResult with Abnormal Security findings
    """
    try:
        from services.abnormal_security import AbnormalSecurityClient
    except ImportError:
        return ToolHuntResult(
            tool_name="Abnormal",
            total_hits=0,
            errors=["Abnormal Security client not available"]
        )

    email_hits = []
    domain_hits = []
    errors = []

    try:
        client = AbnormalSecurityClient()
        if not client.is_configured():
            return ToolHuntResult(
                tool_name="Abnormal",
                total_hits=0,
                errors=["Abnormal Security API not configured"]
            )

        # Time range for search
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        # Hunt sender domains
        for domain in entities.domains[:10]:
            try:
                result = client.get_threats_by_timerange(
                    start_time=start_time,
                    end_time=end_time,
                    sender=f"*@{domain}",
                    page_size=50
                )
                threats = result.get("threats", [])
                if threats:
                    domain_hits.append({
                        'domain': domain,
                        'threat_count': len(threats),
                        'attack_types': list(set(t.get('attackType', 'Unknown') for t in threats[:5]))
                    })
                    logger.info(f"  [Abnormal] HIT: Domain {domain} - {len(threats)} threats")
            except Exception as e:
                logger.debug(f"Abnormal domain search error: {e}")

        # Hunt sender emails if extracted
        for email in getattr(entities, 'emails', [])[:10]:
            try:
                result = client.get_threats_by_timerange(
                    start_time=start_time,
                    end_time=end_time,
                    sender=email,
                    page_size=50
                )
                threats = result.get("threats", [])
                if threats:
                    email_hits.append({
                        'email': email,
                        'threat_count': len(threats),
                        'attack_types': list(set(t.get('attackType', 'Unknown') for t in threats[:5]))
                    })
                    logger.info(f"  [Abnormal] HIT: Email {email} - {len(threats)} threats")
            except Exception as e:
                logger.debug(f"Abnormal email search error: {e}")

    except Exception as e:
        errors.append(f"Abnormal connection error: {str(e)}")
        logger.error(f"Abnormal hunt error: {e}")

    total_hits = len(email_hits) + len(domain_hits)
    return ToolHuntResult(
        tool_name="Abnormal",
        total_hits=total_hits,
        domain_hits=domain_hits,
        email_hits=email_hits,
        errors=errors[:3]
    )
