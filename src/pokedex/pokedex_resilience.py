# Pokedex-Specific Resilience Module
"""
Enhanced resilience specifically for Pokedex bot dealing with ZScaler proxy issues
during macbook sleep/wake cycles.

This extends the base bot_resilience with Pokedex-specific features:
- Sleep/wake cycle detection
- ZScaler-specific connection monitoring
- Adaptive reconnection strategies
- Enhanced logging for connection issues
"""

import time
import threading
import logging
import subprocess
from datetime import datetime
from typing import Callable, Optional, Any

from src.utils.bot_resilience import ResilientBot

logger = logging.getLogger(__name__)


class PokedexResilientBot(ResilientBot):
    """
    Pokedex-specific resilient bot runner with enhanced ZScaler handling
    """

    def __init__(self,
                 bot_factory: Callable[[], Any],
                 initialization_func: Optional[Callable[..., bool]] = None,
                 bot_name: Optional[str] = None,
                 **kwargs):
        """
        Initialize Pokedex-specific resilient bot runner
        """
        # Enhanced settings for ZScaler environment
        kwargs.setdefault('keepalive_interval', 45)  # More frequent pings
        kwargs.setdefault('websocket_ping_interval', 15)  # Aggressive WebSocket pings
        kwargs.setdefault('proxy_detection', True)
        kwargs.setdefault('initial_retry_delay', 10)  # Faster recovery
        kwargs.setdefault('max_retry_delay', 60)  # Lower max delay for ZScaler

        super().__init__(bot_factory, initialization_func, bot_name or "Pokedx", **kwargs)

        # Pokedex-specific state
        self.sleep_wake_monitor_thread = None
        self._system_sleep_detected = False
        self._last_activity_time = datetime.now()
        self._connection_stability_score = 100
        self._last_successful_connection = datetime.now()
        self._zscaler_detected = False

        # Enhanced ZScaler detection
        self._detect_zscaler_environment()

    def _detect_zscaler_environment(self):
        """Enhanced ZScaler detection with Pokedex-specific optimizations"""
        try:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            if "zscaler" in result.stdout.lower():
                self._zscaler_detected = True
                logger.info(f"🛡️ ZScaler detected for {self.bot_name} - enabling Pokedx-specific optimizations")

                # Even more aggressive settings for ZScaler
                self.keepalive_interval = 30  # Very frequent pings
                self.websocket_ping_interval = 10  # Aggressive WebSocket monitoring

                return True
        except Exception as e:
            logger.debug(f"ZScaler detection error: {e}")

        return False

    def _monitor_sleep_wake_cycles(self):
        """Monitor macOS sleep/wake cycles and trigger reconnections"""
        last_uptime = self._get_system_uptime()
        consecutive_sleep_events = 0

        while not self.shutdown_requested:
            try:
                time.sleep(30)  # Check every 30 seconds

                current_uptime = self._get_system_uptime()
                self._last_activity_time = datetime.now()

                # Detect sleep/wake by uptime changes
                if current_uptime < last_uptime or (last_uptime - current_uptime) > 60:
                    consecutive_sleep_events += 1
                    self._system_sleep_detected = True

                    logger.info(f"🌙 Sleep/wake detected for {self.bot_name} (event #{consecutive_sleep_events}) - uptime: {last_uptime}s → {current_uptime}s")

                    # For ZScaler, always reconnect after sleep
                    if self._zscaler_detected:
                        logger.info(f"🔄 ZScaler + sleep detected - triggering immediate reconnection for {self.bot_name}")
                        self._trigger_reconnection("ZScaler + system sleep/wake detected")
                        consecutive_sleep_events = 0

                    # Reduce connection stability
                    self._connection_stability_score = max(10, self._connection_stability_score - 30)

                elif current_uptime > last_uptime + 600:  # System stable for 10+ minutes
                    consecutive_sleep_events = 0
                    self._system_sleep_detected = False
                    self._connection_stability_score = min(100, self._connection_stability_score + 10)

                last_uptime = current_uptime

            except Exception as e:
                logger.debug(f"Sleep/wake monitor error: {e}")
                time.sleep(60)

    def _get_system_uptime(self):
        """Get macOS system uptime in seconds"""
        try:
            result = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True)
            if result.returncode == 0:
                import re
                match = re.search(r'sec = (\d+)', result.stdout)
                if match:
                    boot_time = int(match.group(1))
                    current_time = int(datetime.now().timestamp())
                    return current_time - boot_time
        except Exception:
            pass
        return 0

    def _enhanced_keepalive_ping(self):
        """Pokedx-specific keepalive with adaptive timing"""
        wait = 30 if self._zscaler_detected else 60

        while not self.shutdown_requested:
            try:
                if self.bot_instance and hasattr(self.bot_instance, 'teams'):
                    # Test connection health
                    self.bot_instance.teams.people.me()
                    self.last_successful_ping = datetime.now()
                    self._last_successful_connection = datetime.now()
                    self.consecutive_failures = 0

                    # Adaptive timing based on stability and sleep state
                    if self._system_sleep_detected:
                        wait = 10  # Very frequent after sleep
                    elif self._connection_stability_score < 50:
                        wait = 15  # Frequent when unstable
                    elif self._zscaler_detected:
                        wait = 20  # More frequent for ZScaler
                    else:
                        wait = self.keepalive_interval

                    # Improve stability on success
                    self._connection_stability_score = min(100, self._connection_stability_score + 3)

                    logger.debug(f"Pokedx keepalive successful (stability: {self._connection_stability_score}, wait: {wait}s)")

                time.sleep(wait)

            except (ConnectionResetError, ConnectionAbortedError, OSError) as conn_error:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    self._connection_stability_score = max(0, self._connection_stability_score - 15)

                    logger.warning(f"Pokedx keepalive failed with connection error (failure #{self.consecutive_failures}, stability: {self._connection_stability_score}): {conn_error}")

                    # For ZScaler, be more aggressive about reconnection
                    if self._zscaler_detected:
                        logger.warning(f"ZScaler connection error for {self.bot_name} - triggering immediate reconnection")
                        self._trigger_reconnection(f"ZScaler connection error: {type(conn_error).__name__}")
                        break
                    elif self.consecutive_failures >= 2:
                        self._trigger_reconnection(f"Multiple connection errors: {type(conn_error).__name__}")
                        break

            except Exception as e:
                if not self.shutdown_requested:
                    self.consecutive_failures += 1
                    self._connection_stability_score = max(0, self._connection_stability_score - 10)

                    if self._is_proxy_related_error(e) or self._zscaler_detected:
                        logger.warning(f"Pokedx proxy-related error (stability: {self._connection_stability_score}): {e}")
                        self._trigger_reconnection("Proxy connection issue")
                        break

                    wait = min(wait * 1.5, 120)
                    time.sleep(wait)

    def run(self):
        """
        Enhanced run method with Pokedx-specific monitoring
        """
        try:
            # Kill competing processes (inherited)
            killed_count = self._kill_competing_processes()
            if killed_count > 0:
                logger.info(f"🧹 Cleaned up {killed_count} competing Pokedx process(es)")

            # Start enhanced keepalive monitoring
            self.keepalive_thread = threading.Thread(target=self._enhanced_keepalive_ping, daemon=True)
            self.keepalive_thread.start()
            logger.info(f"💓 Enhanced Pokedx keepalive monitoring started")

            # Start WebSocket monitoring (inherited)
            self.websocket_monitor_thread = threading.Thread(target=self._websocket_monitor, daemon=True)
            self.websocket_monitor_thread.start()
            logger.info(f"🔌 WebSocket monitoring started for {self.bot_name}")

            # Start sleep/wake monitoring
            if self._zscaler_detected:
                self.sleep_wake_monitor_thread = threading.Thread(target=self._monitor_sleep_wake_cycles, daemon=True)
                self.sleep_wake_monitor_thread.start()
                logger.info(f"🌙 Sleep/wake monitoring started for {self.bot_name}")

            # Run with reconnection logic
            self.run_with_reconnection()

        except Exception as e:
            logger.error(f"Fatal error in {self.bot_name}: {e}", exc_info=True)
            self._graceful_shutdown()
            raise


def run_with_pokedx_resilience(bot_factory, initialization_func=None):
    """
    Convenience function to run a bot with Pokedx-specific resilience
    """
    resilient_runner = PokedexResilientBot(
        bot_factory=bot_factory,
        initialization_func=initialization_func,
        bot_name="Pokedx"
    )
    resilient_runner.run()