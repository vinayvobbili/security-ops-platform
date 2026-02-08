"""Health Check Handler for Web Dashboard."""

import logging
import os
from datetime import datetime
from typing import Dict, Any

import pytz

logger = logging.getLogger(__name__)


def get_server_health(
    eastern: pytz.tzinfo.BaseTzInfo,
    server_start_time: datetime,
    team_name: str,
    web_server_port: int,
    request_environ: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Lightweight health probe endpoint for load balancers / monitoring.

    Args:
        eastern: Pytz timezone object for US/Eastern
        server_start_time: When the server started
        team_name: Name of the team (e.g., 'SecOps')
        web_server_port: Web server port
        request_environ: Optional request environment dict

    Returns:
        Dictionary with health status information
    """
    logger.debug("Performing health check")

    try:
        current_time = datetime.now(eastern)
        timestamp = current_time.strftime('%Y-%m-%d %H:%M:%S %Z')

        # Calculate uptime
        uptime_delta = current_time - server_start_time
        uptime_seconds = int(uptime_delta.total_seconds())
        uptime_hours = uptime_seconds // 3600
        uptime_minutes = (uptime_seconds % 3600) // 60
        uptime_str = f"{uptime_hours}h {uptime_minutes}m"

        try:
            if request_environ:
                server_software = request_environ.get('SERVER_SOFTWARE', 'unknown')
                server_name = request_environ.get('SERVER_NAME', 'unknown')
                server_port = request_environ.get('SERVER_PORT', web_server_port)
                server_type = _detect_server_type(server_software)

                server_info = {
                    'server_type': server_type,
                    'server_software': server_software,
                    'host': server_name,
                    'port': int(server_port) if server_port else web_server_port,
                    'start_time': server_start_time.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'uptime': uptime_str,
                    'uptime_seconds': uptime_seconds
                }
            else:
                server_info = {
                    'server_type': 'unknown',
                    'server_software': 'unknown',
                    'host': 'unknown',
                    'port': web_server_port,
                    'start_time': server_start_time.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'uptime': uptime_str,
                    'uptime_seconds': uptime_seconds,
                    'pid': os.getpid()
                }
        except Exception as exc:
            logger.warning(f"Could not get live server info, using fallback: {exc}", exc_info=True)
            server_info = {
                'server_type': 'unknown',
                'server_software': 'unknown',
                'host': 'unknown',
                'port': web_server_port,
                'start_time': server_start_time.strftime('%Y-%m-%d %H:%M:%S %Z'),
                'uptime': uptime_str,
                'uptime_seconds': uptime_seconds
            }

        return {
            "status": "ok",
            "timestamp": timestamp,
            "team": team_name,
            "service": "ir_web_server",
            "server": server_info
        }

    except Exception as exc:
        logger.error(f"Health check failed: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": str(exc)
        }


def _detect_server_type(server_software: str) -> str:
    """Detect server type from SERVER_SOFTWARE string."""
    server_software_lower = (server_software or '').lower()
    if 'waitress' in server_software_lower:
        return 'waitress'
    if 'gunicorn' in server_software_lower:
        return 'gunicorn'
    if 'uwsgi' in server_software_lower:
        return 'uwsgi'
    if 'werkzeug' in server_software_lower:
        return 'flask-dev'
    return 'unknown'
