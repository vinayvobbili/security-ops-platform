"""
ZScaler-aware resilience wrapper for WebEx bots experiencing connection issues.

This module provides ZScaler-aware resilience for bots running on machines with
newer ZScaler versions (4.5.x+) that cause WebSocket connection drops during 
Mac sleep/wake cycles. Can be easily extended to other bots as needed.

Currently used by: Pokedex
Future candidates: HAL (when ZScaler is upgraded on that machine)
"""
import logging
import subprocess
import threading
import time
import traceback
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ZScalerResilientBot:
    """
    ZScaler-aware resilience wrapper for WebEx bots.
    
    This addresses the issue where newer ZScaler versions (4.5.x+) cause WebSocket
    connection drops during Mac sleep/wake cycles. The wrapper automatically detects
    ZScaler and applies appropriate monitoring and recovery strategies.
    
    Usage:
        # For Pokedex (currently affected)
        resilient_runner = ZScalerResilientBot(..., bot_name="Pokedex")
        
        # For HAL (when ZScaler gets upgraded)
        resilient_runner = ZScalerResilientBot(..., bot_name="HAL9000")
    """
    
    def __init__(self, bot_factory, initialization_func, bot_name="WebexBot"):
        self.bot_factory = bot_factory
        self.initialization_func = initialization_func
        self.bot_name = bot_name
        self.bot = None
        self.is_running = False
        self.last_restart = None
        self.restart_count = 0
        
        # ZScaler-specific settings
        self.zscaler_detected = self._detect_zscaler()
        self.websocket_check_interval = 30 if self.zscaler_detected else 60
        self.max_restarts_per_hour = 10
        
        logger.info(f"🛡️ {bot_name} resilience initialized - ZScaler detected: {self.zscaler_detected}")
    
    def _detect_zscaler(self):
        """Detect if ZScaler 4.5.x is running (the problematic version)"""
        try:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
            if "zscaler" in result.stdout.lower():
                # Try to get ZScaler version
                try:
                    version_result = subprocess.run(
                        ["system_profiler", "SPApplicationsDataType"], 
                        capture_output=True, text=True, timeout=10
                    )
                    if "zscaler" in version_result.stdout.lower() and "4.5" in version_result.stdout:
                        logger.warning(f"🚨 ZScaler 4.5.x detected - enabling enhanced monitoring for {self.bot_name}")
                        return True
                except Exception:
                    pass
                
                logger.info(f"🛡️ ZScaler detected for {self.bot_name} - enabling monitoring")
                return True
        except Exception as e:
            logger.debug(f"Could not detect ZScaler: {e}")
        return False
    
    def _should_restart(self):
        """Check if we should restart based on rate limiting"""
        now = datetime.now()
        if self.last_restart:
            if now - self.last_restart < timedelta(hours=1):
                if self.restart_count >= self.max_restarts_per_hour:
                    logger.error(f"❌ {self.bot_name} restart rate limit exceeded - waiting 1 hour")
                    return False
            else:
                # Reset counter after an hour
                self.restart_count = 0
        return True
    
    def _websocket_health_check(self):
        """Monitor WebSocket health for ZScaler-specific issues"""
        while self.is_running:
            try:
                time.sleep(self.websocket_check_interval)
                
                if not self.is_running:
                    break
                
                if self.bot and hasattr(self.bot, 'teams'):
                    try:
                        # Simple API call to check connectivity
                        self.bot.teams.people.me()
                        logger.debug(f"✅ {self.bot_name} WebSocket health check passed")
                    except Exception as e:
                        logger.warning(f"⚠️ {self.bot_name} WebSocket health check failed: {e}")
                        if self.zscaler_detected and "connection" in str(e).lower():
                            logger.error(f"🔄 ZScaler connection issue detected for {self.bot_name} - triggering restart")
                            self._restart_bot()
                            
            except Exception as e:
                logger.error(f"Error in WebSocket health check: {e}")
    
    def _restart_bot(self):
        """Restart the bot with rate limiting"""
        if not self._should_restart():
            return
            
        try:
            logger.info(f"🔄 Restarting {self.bot_name}...")
            self.last_restart = datetime.now()
            self.restart_count += 1
            
            # Stop current bot
            if self.bot:
                try:
                    self.bot.stop()
                except Exception as e:
                    logger.warning(f"Error stopping {self.bot_name}: {e}")
            
            # Brief delay for cleanup
            time.sleep(5)
            
            # Reinitialize and start
            if self.initialization_func():
                self.bot = self.bot_factory()
                self.bot.run()
                logger.info(f"✅ {self.bot_name} restarted successfully")
            else:
                logger.error(f"❌ {self.bot_name} initialization failed during restart")
                
        except Exception as e:
            logger.error(f"❌ Error restarting {self.bot_name}: {e}")
            traceback.print_exc()
    
    def run(self):
        """Run the Pokedex bot with ZScaler-aware resilience"""
        logger.info(f"🚀 Starting {self.bot_name} with ZScaler resilience...")
        
        try:
            # Initialize bot components
            if not self.initialization_func():
                logger.error(f"❌ {self.bot_name} initialization failed")
                return
            
            # Create bot instance
            self.bot = self.bot_factory()
            self.is_running = True
            
            # Start WebSocket health monitoring if ZScaler detected
            if self.zscaler_detected:
                health_thread = threading.Thread(
                    target=self._websocket_health_check, 
                    daemon=True, 
                    name=f"{self.bot_name}_health_monitor"
                )
                health_thread.start()
                logger.info(f"🩺 {self.bot_name} health monitoring started")
            
            # Run the bot
            logger.info(f"▶️ {self.bot_name} starting main loop...")
            self.bot.run()
            
        except KeyboardInterrupt:
            logger.info(f"⏹️ {self.bot_name} stopped by user")
        except Exception as e:
            logger.error(f"❌ {self.bot_name} crashed: {e}")
            traceback.print_exc()
        finally:
            self.is_running = False
            logger.info(f"🛑 {self.bot_name} shutdown complete")


# Bot-specific configuration - bots can choose if they need ZScaler resilience
ZSCALER_AFFECTED_BOTS = {
    "Pokedex": {
        "description": "Currently affected by ZScaler 4.5.0.198",
        "needs_resilience": True
    },
    "HAL9000": {
        "description": "Will need resilience when ZScaler gets upgraded",
        "needs_resilience": False  # Set to True when HAL's ZScaler is upgraded
    }
}


def should_use_zscaler_resilience(bot_name):
    """
    Check if a bot should use ZScaler resilience based on configuration.
    
    Args:
        bot_name: Name of the bot
        
    Returns:
        bool: True if bot should use ZScaler resilience
    """
    config = ZSCALER_AFFECTED_BOTS.get(bot_name, {})
    return config.get("needs_resilience", False)


# Convenience alias for any bot that needs ZScaler resilience
ZScalerAwareBot = ZScalerResilientBot