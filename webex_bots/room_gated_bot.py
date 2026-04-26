"""WebexBot subclass that restricts commands to an allowlist of room IDs.

Rejects anything not in `allowed_room_ids` — including 1-1 chats — with a
short message back to the user. Bot-to-bot messages are still allowed
through unconditionally so peer-ping and inter-bot calls keep working.
"""
import logging

from webex_bot.webex_bot import WebexBot

log = logging.getLogger(__name__)


class RoomGatedWebexBot(WebexBot):
    REJECTION_MESSAGE = "run only in auth rooms"

    def __init__(self, *args, allowed_room_ids=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_room_ids = {r for r in (allowed_room_ids or []) if r}

    def process_raw_command(self, raw_message, teams_message, user_email, activity, is_card_callback_command=False):
        room_id = getattr(teams_message, "roomId", None)
        actor_type = activity.get("actor", {}).get("type")

        if actor_type == "PERSON" and self.allowed_room_ids and room_id not in self.allowed_room_ids:
            log.info(f"Rejecting command from {user_email} in room {room_id} — not in allowlist")
            try:
                self.teams.messages.create(roomId=room_id, markdown=self.REJECTION_MESSAGE)
            except Exception as e:
                log.warning(f"Failed to send rejection message to {room_id}: {e}")
            return

        return super().process_raw_command(
            raw_message, teams_message, user_email, activity,
            is_card_callback_command=is_card_callback_command,
        )
