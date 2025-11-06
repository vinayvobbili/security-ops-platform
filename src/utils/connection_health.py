"""
Connection Health Monitoring (Keepalive-Focused)

Tracks and logs keepalive ping health metrics for Webex bots.
Monitors connection stability through periodic keepalive pings and logs failures.
Triggers reactive reconnections on connection issues (no proactive restarts).

Usage:
    from src.utils.connection_health import ConnectionHealthMonitor

    monitor = ConnectionHealthMonitor(bot_name="MoneyBall")
    monitor.record_request_success(duration=1.2)  # Record successful keepalive ping
    monitor.record_request_timeout(duration=60.0)  # Record ping timeout
    monitor.log_summary()  # Log concise keepalive health summary
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)


class ConnectionHealthMonitor:
    """
    Monitor keepalive ping health metrics for a Webex bot.

    Tracks periodic keepalive pings to monitor connection stability.
    Logs concise summaries and triggers reactive reconnections on failures.
    Does NOT perform proactive/scheduled restarts.
    """

    def __init__(self, bot_name: str, window_size: int = 100):
        """
        Initialize connection health monitor

        Args:
            bot_name: Name of the bot being monitored
            window_size: Number of recent requests to track (default: 100)
        """
        self.bot_name = bot_name
        self.window_size = window_size

        # Thread-safe lock for metrics
        self._lock = Lock()

        # Metrics
        self.start_time = datetime.now()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.timeout_requests = 0
        self.connection_error_requests = 0
        self.reconnection_count = 0

        # Rolling window for recent requests
        self.recent_requests = deque(maxlen=window_size)

        # Response time tracking
        self.total_response_time = 0.0
        self.min_response_time = float('inf')
        self.max_response_time = 0.0

        # Error tracking
        self.error_types = {}

        # Last successful request timestamp
        self.last_successful_request = None
        self.last_request_time = None

    def record_request_success(self, duration: float):
        """Record a successful API request"""
        with self._lock:
            self.total_requests += 1
            self.successful_requests += 1
            self.last_successful_request = datetime.now()
            self.last_request_time = datetime.now()

            # Update response time metrics
            self.total_response_time += duration
            self.min_response_time = min(self.min_response_time, duration)
            self.max_response_time = max(self.max_response_time, duration)

            # Add to rolling window
            self.recent_requests.append({
                'timestamp': datetime.now(),
                'success': True,
                'duration': duration
            })

    def record_request_timeout(self, duration: float):
        """Record a request timeout"""
        with self._lock:
            self.total_requests += 1
            self.failed_requests += 1
            self.timeout_requests += 1
            self.last_request_time = datetime.now()

            # Add to rolling window
            self.recent_requests.append({
                'timestamp': datetime.now(),
                'success': False,
                'error_type': 'timeout',
                'duration': duration
            })

    def record_connection_error(self, error: Exception):
        """Record a connection error"""
        with self._lock:
            self.total_requests += 1
            self.failed_requests += 1
            self.connection_error_requests += 1
            self.last_request_time = datetime.now()

            # Track error type
            error_type = type(error).__name__
            self.error_types[error_type] = self.error_types.get(error_type, 0) + 1

            # Add to rolling window
            self.recent_requests.append({
                'timestamp': datetime.now(),
                'success': False,
                'error_type': error_type,
                'error_message': str(error)
            })

    def record_reconnection(self, reason: str = ""):
        """Record a bot reconnection event"""
        with self._lock:
            self.reconnection_count += 1
            logger.info(f"🔄 [{self.bot_name}] Reconnection #{self.reconnection_count}: {reason}")

    def get_success_rate(self) -> float:
        """Calculate overall success rate"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

    def get_recent_success_rate(self) -> float:
        """Calculate success rate for recent requests"""
        if not self.recent_requests:
            return 0.0

        successful = sum(1 for req in self.recent_requests if req.get('success', False))
        return (successful / len(self.recent_requests)) * 100

    def get_average_response_time(self) -> float:
        """Calculate average response time"""
        if self.successful_requests == 0:
            return 0.0
        return self.total_response_time / self.successful_requests

    def get_time_since_last_success(self) -> Optional[float]:
        """Get seconds since last successful request"""
        if not self.last_successful_request:
            return None
        return (datetime.now() - self.last_successful_request).total_seconds()

    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics as a dictionary"""
        with self._lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            time_since_last = self.get_time_since_last_success()

            return {
                'bot_name': self.bot_name,
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime))),
                'total_requests': self.total_requests,
                'successful_requests': self.successful_requests,
                'failed_requests': self.failed_requests,
                'timeout_requests': self.timeout_requests,
                'connection_error_requests': self.connection_error_requests,
                'reconnection_count': self.reconnection_count,
                'success_rate': self.get_success_rate(),
                'recent_success_rate': self.get_recent_success_rate(),
                'avg_response_time': self.get_average_response_time(),
                'min_response_time': self.min_response_time if self.min_response_time != float('inf') else 0,
                'max_response_time': self.max_response_time,
                'time_since_last_success': time_since_last,
                'error_types': dict(self.error_types),
                'recent_requests_count': len(self.recent_requests)
            }

    def log_summary(self):
        """Log a summary of connection health metrics (keepalive-focused)"""
        metrics = self.get_metrics()

        logger.info(f"📊 [{self.bot_name}] Keepalive Health: Uptime {metrics['uptime_formatted']} | "
                   f"Pings: {metrics['successful_requests']}/{metrics['total_requests']} "
                   f"({metrics['success_rate']:.1f}% success)")

        # Only log detailed stats if there are issues
        if metrics['failed_requests'] > 0:
            logger.info(f"  ⚠️  Failures: {metrics['failed_requests']} "
                       f"(Timeouts: {metrics['timeout_requests']}, Errors: {metrics['connection_error_requests']})")
            if metrics['error_types']:
                logger.info(f"  Error Types: {metrics['error_types']}")

        # Log reconnections only if they occurred
        if metrics['reconnection_count'] > 0:
            logger.info(f"  🔄 Reconnections: {metrics['reconnection_count']}")

        # Log response time for successful pings
        if metrics['successful_requests'] > 0:
            logger.debug(f"  Ping Response Time: avg={metrics['avg_response_time']:.2f}s | "
                        f"min={metrics['min_response_time']:.2f}s | max={metrics['max_response_time']:.2f}s")

        # Warn if last success was too long ago
        if metrics['time_since_last_success'] is not None and metrics['time_since_last_success'] > 120:
            logger.warning(f"  ⚠️  Last successful ping: {metrics['time_since_last_success']:.0f}s ago")

    def log_periodic_summary(self, interval_seconds: int = 300):
        """
        Check if it's time to log a periodic summary

        Args:
            interval_seconds: How often to log (default: 5 minutes)

        Returns:
            True if summary was logged, False otherwise
        """
        if not hasattr(self, '_last_summary_time'):
            self._last_summary_time = datetime.now()
            return False

        elapsed = (datetime.now() - self._last_summary_time).total_seconds()
        if elapsed >= interval_seconds:
            self.log_summary()
            self._last_summary_time = datetime.now()
            return True

        return False

    def is_healthy(self,
                   min_success_rate: float = 80.0,
                   max_time_since_success: float = 600.0) -> bool:
        """
        Check if the connection is healthy

        Args:
            min_success_rate: Minimum acceptable success rate (%)
            max_time_since_success: Maximum acceptable time since last success (seconds)

        Returns:
            True if healthy, False otherwise
        """
        metrics = self.get_metrics()

        # Check overall success rate
        if metrics['total_requests'] >= 10:  # Only check after some requests
            if metrics['success_rate'] < min_success_rate:
                logger.warning(f"⚠️ [{self.bot_name}] Low success rate: {metrics['success_rate']:.1f}%")
                return False

        # Check time since last success
        if metrics['time_since_last_success'] is not None:
            if metrics['time_since_last_success'] > max_time_since_success:
                logger.warning(f"⚠️ [{self.bot_name}] No successful request in {metrics['time_since_last_success']:.0f}s")
                return False

        return True


# Global monitor instance (optional - can be used for singleton pattern)
_global_monitors = {}


def get_monitor(bot_name: str) -> ConnectionHealthMonitor:
    """
    Get or create a connection health monitor for a bot

    Args:
        bot_name: Name of the bot

    Returns:
        ConnectionHealthMonitor instance
    """
    if bot_name not in _global_monitors:
        _global_monitors[bot_name] = ConnectionHealthMonitor(bot_name)
    return _global_monitors[bot_name]
