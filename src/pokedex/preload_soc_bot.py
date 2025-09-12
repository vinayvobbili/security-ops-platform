#!/usr/bin/env python3
"""
SOC Bot Preloader Service
Loads all bot components into memory and keeps them warm for instant responses.
"""

import os
import sys
import time
import signal
import logging
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from my_bot.core.my_model import initialize_model_and_agent
from my_bot.core.state_manager import get_state_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/soc_bot_preloader.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SOC_Bot_Preloader')

class SOCBotPreloader:
    """Preloader service for SOC Bot components"""
    
    def __init__(self):
        self.running = True
        self.initialized = False
        self.start_time = datetime.now()
        
        # Handle shutdown signals gracefully
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def initialize_components(self):
        """Initialize all SOC bot components"""
        logger.info("🚀 Starting SOC Bot component initialization...")
        
        try:
            # Initialize the model and agent
            success = initialize_model_and_agent()
            
            if success:
                # Verify components are loaded
                state_manager = get_state_manager()
                if state_manager and state_manager.is_initialized:
                    health = state_manager.health_check()
                    logger.info(f"✅ All components initialized successfully: {health}")
                    
                    # Log memory usage and initialization time
                    init_duration = (datetime.now() - self.start_time).total_seconds()
                    logger.info(f"⏱️  Initialization completed in {init_duration:.1f} seconds")
                    
                    self.initialized = True
                    return True
                else:
                    logger.error("❌ State manager not properly initialized")
                    return False
            else:
                logger.error("❌ Model and agent initialization failed")
                return False
                
        except Exception as e:
            logger.error(f"❌ Initialization failed with exception: {e}", exc_info=True)
            return False
    
    def health_check(self):
        """Perform periodic health checks"""
        try:
            state_manager = get_state_manager()
            if state_manager and state_manager.is_initialized:
                health = state_manager.health_check()
                logger.debug(f"Health check: {health}")
                return True
            else:
                logger.warning("⚠️  Health check failed - state manager not initialized")
                return False
        except Exception as e:
            logger.error(f"❌ Health check error: {e}")
            return False
    
    def run(self):
        """Main service loop"""
        logger.info("🤖 SOC Bot Preloader Service starting...")
        
        # Initialize components
        if not self.initialize_components():
            logger.error("❌ Failed to initialize components. Exiting.")
            return 1
        
        logger.info("✅ SOC Bot is now HOT and ready for instant responses!")
        logger.info("📊 Service Status:")
        logger.info(f"   • Start Time: {self.start_time}")
        logger.info(f"   • Process ID: {os.getpid()}")
        logger.info(f"   • Log File: /tmp/soc_bot_preloader.log")
        
        # Keep service alive and perform periodic health checks
        health_check_interval = 300  # 5 minutes
        last_health_check = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Periodic health check
                if current_time - last_health_check >= health_check_interval:
                    if self.health_check():
                        uptime = datetime.now() - self.start_time
                        logger.info(f"💚 SOC Bot healthy - Uptime: {uptime}")
                    else:
                        logger.warning("⚠️  SOC Bot health check failed")
                    last_health_check = current_time
                
                # Sleep for 1 minute between loops
                time.sleep(60)
                
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt, shutting down...")
                break
            except Exception as e:
                logger.error(f"❌ Service loop error: {e}", exc_info=True)
                time.sleep(10)  # Wait a bit before retrying
        
        # Cleanup
        logger.info("🛑 SOC Bot Preloader Service shutting down...")
        uptime = datetime.now() - self.start_time
        logger.info(f"Final uptime: {uptime}")
        return 0


def main():
    """Main entry point for the preloader service"""
    preloader = SOCBotPreloader()
    return preloader.run()


if __name__ == "__main__":
    sys.exit(main())