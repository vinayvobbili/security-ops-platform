"""Deferred RTR actions — persistent queue for offline hosts.

When an analyst requests an RTR action on an offline host, the request is
written to a JSON file. The scheduler calls process_pending() every 15 minutes
to check if hosts have come online and execute the deferred actions.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

QUEUE_FILE = Path(__file__).parent.parent / "data" / "transient" / "deferred_rtr.json"


def _load_queue() -> list[dict]:
    if not QUEUE_FILE.exists():
        return []
    try:
        with open(QUEUE_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read deferred RTR queue: {e}")
        return []


def _save_queue(queue: list[dict]):
    try:
        QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(QUEUE_FILE, "w") as f:
            json.dump(queue, f, indent=2)
    except OSError as e:
        logger.error(f"Failed to save deferred RTR queue: {e}")


def add_entry(hostname: str, ticket_number: str, rtr_action: str, room_id: str,
              file_path: str = None, requester: str = None):
    """Add a pending RTR action to the queue."""
    queue = _load_queue()

    # Don't duplicate same host + action + ticket
    for entry in queue:
        if (entry["hostname"] == hostname
                and entry["rtr_action"] == rtr_action
                and entry["ticket_number"] == ticket_number):
            logger.info(f"Deferred RTR entry already exists for {hostname}/{rtr_action}/X#{ticket_number}")
            return

    entry = {
        "hostname": hostname,
        "ticket_number": ticket_number,
        "rtr_action": rtr_action,
        "room_id": room_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if file_path:
        entry["file_path"] = file_path
    if requester:
        entry["requester"] = requester

    queue.append(entry)
    _save_queue(queue)
    logger.info(f"Added deferred RTR entry: {rtr_action} on {hostname} for X#{ticket_number}")


def process_pending(webex_api):
    """Check each pending entry — if host is online, execute and remove from queue."""
    from my_config import get_config
    from services.crowdstrike import CrowdStrikeClient
    from services.crowdstrike_rtr import download_rtr_file
    from services.xsoar import TicketHandler, XsoarEnvironment
    from my_bot.tools.crowdstrike_tools import collect_browser_history, get_and_clear_generated_file_path
    from src.utils.xsoar_helpers import build_incident_url

    queue = _load_queue()
    if not queue:
        return

    config = get_config()
    cs = CrowdStrikeClient()
    prod_incident_handler = TicketHandler(XsoarEnvironment.PROD)
    completed = []

    for i, entry in enumerate(queue):
        hostname = entry["hostname"]
        ticket_number = entry["ticket_number"]
        rtr_action = entry["rtr_action"]
        file_path = entry.get("file_path")
        requester = entry.get("requester", "unknown")

        # Check online status
        try:
            if cs.get_device_online_state(hostname) != "online":
                continue
        except Exception as e:
            logger.warning(f"Deferred RTR: online check failed for {hostname}: {e}")
            continue

        # Host is online — execute
        logger.info(f"Host {hostname} is online, executing deferred {rtr_action}")
        ticket_url = build_incident_url(ticket_number)
        notify_msg = None

        try:
            if rtr_action == "fetch_browser_history":
                device_id = cs.get_device_id(hostname)
                platform = None
                if device_id:
                    details = cs.get_device_details(device_id)
                    platform = details.get("platform_name")

                result_message = collect_browser_history.func(hostname, platform=platform)
                generated_file = get_and_clear_generated_file_path()

                if generated_file and os.path.exists(generated_file):
                    try:
                        prod_incident_handler.upload_file_to_attachment(
                            ticket_number, generated_file,
                            comment=f"Browser history collected from {hostname}"
                        )
                    except Exception as e:
                        logger.error(f"Deferred RTR: upload failed for X#{ticket_number}: {e}")

                    notify_msg = (
                        f"Hello, <@personEmail:{requester}>! "
                        f"🌐 Browser history collected from **{hostname}** (host came back online) "
                        f"and attached to [X#{ticket_number}]({ticket_url})"
                    )
                else:
                    notify_msg = (
                        f"Hello, <@personEmail:{requester}>! "
                        + (result_message or f"Browser history collected from **{hostname}** (no file generated).")
                    )

            elif rtr_action == "fetch_file_pull":
                basename = os.path.basename(file_path.replace("\\", "/"))
                local_path = f"/tmp/rtr_file_pull_{hostname}_{basename}"
                result = download_rtr_file(hostname, file_path, local_path)

                if result.get("success"):
                    actual_path = result.get("local_path", local_path)
                    try:
                        prod_incident_handler.upload_file_to_attachment(
                            ticket_number, actual_path,
                            comment=f"File pulled from {hostname}: {file_path}"
                        )
                    except Exception as e:
                        logger.error(f"Deferred RTR: upload failed for X#{ticket_number}: {e}")
                    try:
                        os.remove(actual_path)
                    except OSError:
                        pass

                    notify_msg = (
                        f"Hello, <@personEmail:{requester}>! "
                        f"📁 **{basename}** pulled from **{hostname}** (host came back online) "
                        f"and attached to [X#{ticket_number}]({ticket_url})"
                    )
                else:
                    notify_msg = (
                        f"Hello, <@personEmail:{requester}>! "
                        f"⚠️ File pull failed for **{hostname}** after it came online: {result.get('error', 'Unknown error')}"
                    )
            else:
                logger.error(f"Unknown deferred RTR action: {rtr_action}")

        except Exception as e:
            logger.error(f"Deferred RTR execution failed for {hostname}: {e}")
            notify_msg = (
                f"Hello, <@personEmail:{requester}>! "
                f"⚠️ Deferred RTR action `{rtr_action}` failed for **{hostname}**: `{e}`"
            )

        # Notify Host Announcements room
        if notify_msg:
            try:
                webex_api.messages.create(
                    roomId=config.webex_room_id_host_announcements,
                    markdown=notify_msg
                )
            except Exception as e:
                logger.error(f"Failed to notify Host Announcements for {hostname}: {e}")

        completed.append(i)

    # Remove completed/expired entries
    if completed:
        queue = [e for idx, e in enumerate(queue) if idx not in completed]
        _save_queue(queue)
        logger.info(f"Deferred RTR: removed {len(completed)} completed entries, {len(queue)} remaining")
