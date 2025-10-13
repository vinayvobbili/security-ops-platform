"""
Webex Device Management Utilities

Provides utilities for managing Webex device registrations, including
cleanup of stale registrations that can cause connection issues.
"""

import logging
import requests

logger = logging.getLogger(__name__)


def cleanup_stale_devices(access_token: str, verbose: bool = True) -> bool:
    """
    Clean up all existing Webex device registrations for a bot.

    This is useful when a bot has stale device registrations that cause
    WebSocket connection failures (HTTP 404 errors). Clearing all devices
    allows the bot to create a fresh registration on startup.

    Args:
        access_token: Webex bot access token
        verbose: If True, log detailed cleanup progress

    Returns:
        bool: True if cleanup succeeded (or no devices to clean), False on error

    Example:
        from src.utils.webex_device_manager import cleanup_stale_devices

        cleanup_stale_devices(bot_access_token)
        # Bot can now start with a clean slate
    """
    try:
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Get current devices
        if verbose:
            logger.info("🧹 Checking for stale Webex device registrations...")

        response = requests.get(
            'https://wdm-a.wbx2.com/wdm/api/v1/devices',
            headers=headers,
            verify=False  # Corporate proxy (ZScaler) compatibility
        )

        if response.status_code != 200:
            logger.warning(f"Failed to retrieve device registrations: {response.status_code}")
            return False

        devices = response.json().get('devices', [])

        if not devices:
            if verbose:
                logger.info("✅ No stale device registrations found")
            return True

        if verbose:
            logger.info(f"📋 Found {len(devices)} device registration(s) to clean up")

        deleted_count = 0
        failed_count = 0

        for device in devices:
            device_url = device.get('url')
            device_name = device.get('name', 'Unknown')

            if device_url:
                del_response = requests.delete(
                    device_url,
                    headers=headers,
                    verify=False
                )

                if del_response.status_code in [200, 204]:
                    deleted_count += 1
                    if verbose:
                        logger.debug(f"   Deleted device: {device_name}")
                else:
                    failed_count += 1
                    logger.warning(f"   Failed to delete device: {device_name} ({del_response.status_code})")
            else:
                failed_count += 1

        if verbose:
            if deleted_count > 0:
                logger.info(f"✅ Cleaned up {deleted_count} stale device registration(s)")
            if failed_count > 0:
                logger.warning(f"⚠️  Failed to delete {failed_count} device(s)")

        return failed_count == 0

    except Exception as e:
        logger.error(f"Error cleaning up device registrations: {e}")
        return False


def cleanup_devices_on_startup(access_token: str, bot_name: str = "Bot") -> None:
    """
    Clean up stale device registrations during bot startup.

    This is a convenience wrapper around cleanup_stale_devices() designed
    to be called during bot initialization. It includes appropriate logging
    for startup context.

    Args:
        access_token: Webex bot access token
        bot_name: Name of the bot for logging purposes

    Example:
        def create_my_bot():
            # Clean up old devices before creating bot
            cleanup_devices_on_startup(config.bot_token, "MyBot")

            # Now create the bot with a clean slate
            return WebexBot(...)
    """
    logger.info(f"🧹 [{bot_name}] Cleaning up stale device registrations...")

    success = cleanup_stale_devices(access_token, verbose=True)

    if success:
        logger.info(f"✅ [{bot_name}] Device cleanup complete - ready for fresh registration")
    else:
        logger.warning(f"⚠️  [{bot_name}] Device cleanup encountered issues, continuing anyway...")
