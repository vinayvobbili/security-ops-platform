#!/usr/bin/env python3
"""
MacBook Sleep/Wake Monitor for Pokedex Bot

This script monitors macOS system events to detect when the MacBook goes to sleep
and immediately restarts the Pokedex bot to prevent ZScaler from killing connections.

Uses multiple detection methods:
1. System log monitoring for sleep/wake events
2. Power management state changes
3. Network interface state monitoring
4. Proactive connection refresh
"""

import subprocess
import time
import logging
import signal
import sys
from datetime import datetime, timedelta
from pathlib import Path
import threading
import os
import requests

PROJECT_DIR = Path(__file__).parent.parent.parent
LOG_FILE = PROJECT_DIR / "logs" / "macbook_sleep_monitor.log"
LOCK_FILE = "/tmp/pokedex_macbook_sleep_monitor.lock"

# Ensure logs directory exists
LOG_FILE.parent.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class MacBookSleepMonitor:
    def __init__(self):
        self.running = True
        self.last_restart_time = datetime.min
        self.restart_cooldown = timedelta(minutes=2)  # Minimum 2 minutes between restarts
        self.connection_test_url = "https://webexapis.com/v1/people/me"
        self.webex_token = self._get_webex_token()

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _get_webex_token(self):
        """Get WebEx token from config"""
        try:
            sys.path.append(str(PROJECT_DIR))
            from my_config import get_config
            config = get_config()
            return config.webex_bot_access_token_pokedex
        except Exception as e:
            logger.warning(f"Could not get WebEx token: {e}")
            return None

    def _signal_handler(self, sig, frame):
        logger.info(f"Received signal {sig}, shutting down...")
        self.running = False
        sys.exit(0)

    def _should_restart_bot(self):
        """Check if enough time has passed since last restart"""
        return datetime.now() - self.last_restart_time > self.restart_cooldown

    def _restart_pokedex_bot(self, reason):
        """Restart the Pokedex bot"""
        if not self._should_restart_bot():
            logger.info(f"Restart requested ({reason}) but cooldown active")
            return False

        logger.info(f"🔄 Restarting Pokedex bot: {reason}")
        self.last_restart_time = datetime.now()

        try:
            # Use the existing restart script
            restart_script = PROJECT_DIR / "src" / "pokedex" / "restart_pokedex.sh"
            if restart_script.exists():
                result = subprocess.run(
                    [str(restart_script)],
                    cwd=restart_script.parent,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    logger.info("✅ Pokedex bot restarted successfully")
                    return True
                else:
                    logger.error(f"❌ Bot restart failed: {result.stderr}")
            else:
                logger.error(f"❌ Restart script not found: {restart_script}")

        except Exception as e:
            logger.error(f"❌ Error restarting bot: {e}")

        return False

    def _test_webex_connection(self):
        """Test WebEx API connectivity"""
        if not self.webex_token:
            return False

        try:
            response = requests.get(
                self.connection_test_url,
                headers={"Authorization": f"Bearer {self.webex_token}"},
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"WebEx connectivity test failed: {e}")
            return False

    def _monitor_system_log(self):
        """Monitor system log for sleep/wake events"""
        logger.info("📋 Starting system log monitoring...")

        try:
            # Use log stream to get real-time events
            process = subprocess.Popen([
                "log", "stream",
                "--predicate", 'subsystem == "com.apple.SleepWakeAgent" OR subsystem == "com.apple.powerd"',
                "--style", "syslog"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while self.running:
                line = process.stdout.readline()
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                # Look for sleep/wake indicators
                if any(keyword in line.lower() for keyword in [
                    'going to sleep', 'wake reason', 'system sleep',
                    'entering sleep', 'waking', 'sleep assertion'
                ]):
                    logger.info(f"🌙 Sleep/wake event detected: {line}")
                    self._restart_pokedex_bot("System sleep/wake event detected")

        except Exception as e:
            logger.error(f"System log monitoring failed: {e}")

    def _monitor_power_management(self):
        """Monitor power management events using pmset"""
        logger.info("⚡ Starting power management monitoring...")

        last_state = None

        while self.running:
            try:
                # Get current power management state
                result = subprocess.run([
                    "pmset", "-g", "ps"
                ], capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    current_state = result.stdout.strip()

                    # Detect significant state changes
                    if last_state and last_state != current_state:
                        # Check for power source changes (AC/Battery) which often indicate wake
                        if ("AC Power" in current_state and "Battery Power" in last_state) or \
                           ("Battery Power" in current_state and "AC Power" in last_state):
                            logger.info(f"⚡ Power source change detected")
                            self._restart_pokedex_bot("Power source change (likely wake event)")

                    last_state = current_state

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                logger.debug(f"Power management check failed: {e}")
                time.sleep(30)

    def _monitor_network_connectivity(self):
        """Monitor network connectivity and preemptively restart on long disconnections"""
        logger.info("🌐 Starting network connectivity monitoring...")

        consecutive_failures = 0
        last_success = datetime.now()

        while self.running:
            try:
                if self._test_webex_connection():
                    consecutive_failures = 0
                    last_success = datetime.now()
                else:
                    consecutive_failures += 1
                    time_since_success = datetime.now() - last_success

                    # If WebEx API has been unreachable for 3+ minutes, restart
                    if time_since_success > timedelta(minutes=3):
                        logger.warning(f"🚨 WebEx API unreachable for {time_since_success.total_seconds():.0f}s")
                        self._restart_pokedex_bot("Extended WebEx API connectivity loss")
                        consecutive_failures = 0  # Reset after restart attempt

                    elif consecutive_failures >= 6:  # 6 failures = 3 minutes
                        logger.warning(f"🚨 {consecutive_failures} consecutive connectivity failures")
                        self._restart_pokedex_bot("Multiple consecutive connectivity failures")
                        consecutive_failures = 0

                time.sleep(30)  # Check every 30 seconds

            except Exception as e:
                logger.debug(f"Network connectivity check failed: {e}")
                time.sleep(60)

    def _proactive_connection_refresh(self):
        """Proactively refresh connections every hour during active hours"""
        logger.info("🔄 Starting proactive connection refresh...")

        while self.running:
            try:
                # Sleep for 50-70 minutes (randomized to avoid patterns)
                import random
                refresh_interval = random.randint(3000, 4200)  # 50-70 minutes
                time.sleep(refresh_interval)

                if not self.running:
                    break

                # Only refresh during reasonable hours (6 AM - 11 PM)
                current_hour = datetime.now().hour
                if 6 <= current_hour <= 23:
                    logger.info("🔄 Proactive connection refresh")
                    self._restart_pokedex_bot("Proactive connection refresh")

            except Exception as e:
                logger.error(f"Proactive refresh failed: {e}")
                time.sleep(3600)  # Wait an hour on error

    def run(self):
        """Run all monitoring threads"""
        logger.info("🚀 Starting MacBook Sleep Monitor for Pokedx bot...")

        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_system_log, daemon=True),
            threading.Thread(target=self._monitor_power_management, daemon=True),
            threading.Thread(target=self._monitor_network_connectivity, daemon=True),
            threading.Thread(target=self._proactive_connection_refresh, daemon=True)
        ]

        for thread in threads:
            thread.start()
            time.sleep(1)  # Stagger thread starts

        logger.info("✅ All monitoring threads started")

        try:
            # Main loop - just keep the process alive
            while self.running:
                time.sleep(10)
        except KeyboardInterrupt:
            logger.info("🛑 Shutdown requested")
            self.running = False

        logger.info("🏁 MacBook Sleep Monitor shutting down")


def main():
    """Main entry point"""
    # Check if already running
    if os.path.exists(LOCK_FILE):
        print("MacBook Sleep Monitor already running")
        return

    # Create lock file
    with open(LOCK_FILE, 'w') as f:
        f.write(str(os.getpid()))

    try:
        monitor = MacBookSleepMonitor()
        monitor.run()
    finally:
        # Clean up lock file
        if os.path.exists(LOCK_FILE):
            os.unlink(LOCK_FILE)


if __name__ == "__main__":
    main()