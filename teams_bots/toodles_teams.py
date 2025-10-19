#!/usr/bin/env python3
"""
Teams Bot Framework Bot for Toodles with WebSocket Streaming
Provides same functionality as Webex Toodles bot via Bot Framework Streaming
Uses persistent WebSocket connection similar to Webex bot architecture

ARCHITECTURE COMPARISON:
======================
Webex Bot (toodles.py):
  - Bot opens WebSocket TO Webex service
  - Persistent bidirectional connection
  - No public endpoint needed
  - Works behind firewalls/NAT

Teams Bot (THIS FILE - toodles_teams.py):
  - Bot opens WebSocket TO Bot Framework service
  - Persistent bidirectional connection
  - No public endpoint needed (same as Webex!)
  - Works behind firewalls/NAT

Teams Webhook Bot (toodles_teams_webhooks.py):
  - Teams sends HTTP POSTs TO your bot
  - Request/response model
  - Requires public endpoint
  - Traditional webhook architecture

AZURE BOT SERVICE CONFIGURATION:
================================
To use streaming mode, you need to:
1. Register bot in Azure Bot Service
2. Enable "Streaming Endpoint" in Azure portal
3. Set TEAMS_TOODLES_APP_ID and TEAMS_TOODLES_APP_PASSWORD in .secrets
4. Run this script - it will connect OUT to Microsoft's service

Bot connects OUT to Microsoft service (not inbound webhooks)
"""
import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent if '__file__' in globals() else Path.cwd().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Bot Framework imports
from botbuilder.core import (
    ActivityHandler,
    TurnContext,
    MessageFactory,
    ConversationState,
    MemoryStorage,
    UserState,
    BotFrameworkAdapter,
    BotFrameworkAdapterSettings
)
from botbuilder.schema import Activity
from aiohttp import web, ClientSession, WSMsgType

try:
    from my_config import get_config
except ImportError:
    # Fallback config function if my_config doesn't exist
    def get_config():
        return {}
from webex_bots.toodles import (
    GetApprovedTestingCard, GetCurrentApprovedTestingEntries, AddApprovedTestingEntry,
    RemoveApprovedTestingEntry, Who, Rotation, ContainmentStatusCS, Review,
    GetNewXTicketForm, CreateXSOARTicket, IOC, IOCHunt, URLs, ThreatHunt,
    CreateThreatHunt, CreateAZDOWorkItem, GetAllOptions, ImportTicket,
    CreateTuningRequest, GetSearchXSOARCard, FetchXSOARTickets,
    GetCompanyHolidays, GetBotHealth, Hi
)

CONFIG = get_config()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Microsoft Teams Toodles Bot Configuration from Azure Bot Service
# Get these values from your Azure engineer and set them in .secrets.age file
# These are loaded through my_config.py from encrypted secrets
TEAMS_TOODLES_APP_ID = CONFIG.teams_toodles_app_id or ''  # Application (client) ID from Azure
TEAMS_TOODLES_APP_PASSWORD = CONFIG.teams_toodles_app_password or ''  # Client secret Value from Azure
TEAMS_TOODLES_TENANT_ID = CONFIG.teams_toodles_tenant_id or ''  # Directory (tenant) ID from Azure (optional)

# Bot Framework Streaming Settings
SETTINGS = BotFrameworkAdapterSettings(
    app_id=TEAMS_TOODLES_APP_ID,
    app_password=TEAMS_TOODLES_APP_PASSWORD
)

# Create adapter for streaming
ADAPTER = BotFrameworkAdapter(SETTINGS)

# Create conversation state
MEMORY = MemoryStorage()
CONVERSATION_STATE = ConversationState(MEMORY)
USER_STATE = UserState(MEMORY)

# Bot Framework Streaming WebSocket URL
# This is where we connect TO (similar to Webex WebSocket)
BOT_FRAMEWORK_STREAMING_URL = "wss://streaming.botframework.com/.bot/"

# Teams command mapping - same commands as Webex Toodles
TEAMS_COMMANDS = {
    'approved-testing-card': GetApprovedTestingCard(),
    'approved-testing-entries': GetCurrentApprovedTestingEntries(),
    'add-approved-testing': AddApprovedTestingEntry(),
    'remove-approved-testing': RemoveApprovedTestingEntry(),
    'who': Who(),
    'rotation': Rotation(),
    'containment-status': ContainmentStatusCS(),
    'review': Review(),
    'new-ticket-form': GetNewXTicketForm(),
    'create-ticket': CreateXSOARTicket(),
    'ioc': IOC(),
    'ioc-hunt': IOCHunt(),
    'urls': URLs(),
    'threat-hunt': ThreatHunt(),
    'create-threat-hunt': CreateThreatHunt(),
    'create-azdo': CreateAZDOWorkItem(),
    'options': GetAllOptions(),
    'import-ticket': ImportTicket(),
    'tuning-request': CreateTuningRequest(),
    'search-xsoar': GetSearchXSOARCard(),
    'fetch-tickets': FetchXSOARTickets(),
    'holidays': GetCompanyHolidays(),
    'health': GetBotHealth(),
    'hi': Hi(),
    'help': None  # Special case for help
}


def parse_command(message_text: str) -> Tuple[str, str]:
    """Parse Teams message to extract command and arguments"""
    text = message_text.strip()

    # Remove bot mention if present
    if text.startswith('<at>') and '</at>' in text:
        # Teams mentions format: <at>BotName</at> command
        text = text.split('</at>', 1)[1].strip()

    # Split command and args
    parts = text.split(' ', 1)
    command = parts[0].lower().strip()
    args = parts[1] if len(parts) > 1 else ''

    return command, args


def create_webex_activity_adapter(turn_context: TurnContext) -> Dict[str, Any]:
    """Create Webex-compatible activity object from Teams TurnContext"""
    return {
        'verb': 'post',
        'actor': {
            'type': 'PERSON',
            'displayName': turn_context.activity.from_property.name or 'Unknown'
        }
    }


def get_help_message() -> str:
    """Generate help message listing all available commands"""
    return """**Available Toodles Commands:**

**Security & Threat Hunting:**
• `ioc <indicator>` - Look up IOC information
• `ioc-hunt <indicator>` - Hunt for IOC across systems
• `threat-hunt <query>` - Search threat intelligence
• `create-threat-hunt` - Create new threat hunt
• `containment-status` - Check CrowdStrike containment status

**Tickets & Work Items:**
• `create-ticket` - Create XSOAR ticket
• `import-ticket <id>` - Import existing ticket
• `fetch-tickets` - Get recent XSOAR tickets
• `search-xsoar` - Search XSOAR tickets
• `create-azdo` - Create Azure DevOps work item
• `tuning-request` - Create tuning request

**Operations:**
• `who` - Who's on call
• `rotation` - Current rotation schedule
• `holidays` - Company holidays
• `approved-testing-entries` - Current approved testing
• `add-approved-testing` - Add testing entry
• `review <item>` - Review items
• `urls <url>` - URL analysis

**Bot Management:**
• `health` - Bot health status
• `options` - Available options
• `help` - This help message

Use commands like: `@toodles ioc 1.2.3.4` or `threat-hunt malware`
"""


async def on_turn_error(context: TurnContext, error: Exception) -> None:
    """
    Handle turn errors.

    Args:
        context: Turn context for the current conversation
        error: Exception that occurred during turn processing
    """
    logger.error(f"Turn error: {error}", exc_info=True)
    await context.send_activity(MessageFactory.text("Sorry, I encountered an error."))


class TeamsBot(ActivityHandler):
    """
    Teams Bot using Bot Framework - similar architecture to WebexBot with real-time connections
    Handles persistent socket connections like Webex bots with threads=True
    """

    def __init__(self, conversation_state: ConversationState, user_state: UserState):
        self.conversation_state = conversation_state
        self.user_state = user_state

    async def on_message_activity(self, turn_context: TurnContext) -> None:
        """
        Handle incoming messages - equivalent to Webex process_incoming_message.
        Real-time processing similar to Webex socket handling.

        Args:
            turn_context: Context for the current conversation turn
        """
        try:
            message_text = turn_context.activity.text.strip()
            user_name = turn_context.activity.from_property.name or 'Unknown'
            logger.info(f"Received message from {user_name}: {message_text[:50]}...")
            logger.debug(f"Full message: {message_text}")

            # Parse command like Webex bot
            command, args = parse_command(message_text)
            logger.debug(f"Parsed command: '{command}', args: '{args}'")

            if command == 'help' or command == '?':
                logger.info(f"Sending help message to {user_name}")
                response_text = get_help_message()
                await turn_context.send_activity(MessageFactory.text(response_text))
                return

            # Execute Toodles command using same business logic
            if command in TEAMS_COMMANDS:
                logger.debug(f"Found command '{command}' in TEAMS_COMMANDS")
                cmd_instance = TEAMS_COMMANDS[command]
                if cmd_instance:
                    logger.info(f"Executing command '{command}' for {user_name}")
                    # Create Webex-compatible adapters
                    webex_message = self.create_webex_message_adapter(turn_context)
                    webex_activity = create_webex_activity_adapter(turn_context)

                    try:
                        # Execute the same command as Webex bot
                        logger.debug(f"Calling execute() on {cmd_instance.__class__.__name__}")
                        result = cmd_instance.execute(webex_message, None, webex_activity)

                        if isinstance(result, str):
                            response_text = result
                            logger.debug(f"Command returned string result: {len(result)} chars")
                        else:
                            response_text = f"Command '{command}' executed successfully"
                            logger.warning(f"Command returned non-string result: {type(result)}")

                        await turn_context.send_activity(MessageFactory.text(response_text))
                        logger.info(f"Command '{command}' completed successfully")

                    except Exception as cmd_error:
                        logger.error(f"Command '{command}' execution failed: {cmd_error}", exc_info=True)
                        error_msg = f"Error executing command '{command}': {str(cmd_error)}"
                        await turn_context.send_activity(MessageFactory.text(error_msg))
                else:
                    logger.warning(f"Command '{command}' found but has no implementation")
                    await turn_context.send_activity(
                        MessageFactory.text(f"Command '{command}' is not implemented yet")
                    )
            else:
                logger.warning(f"Unknown command '{command}' from {user_name}")
                await turn_context.send_activity(
                    MessageFactory.text(f"Unknown command '{command}'. Type 'help' for available commands.")
                )

        except Exception as e:
            logger.error(f"Message processing failed: {e}", exc_info=True)
            await turn_context.send_activity(
                MessageFactory.text("Sorry, I encountered an error processing your request.")
            )
        finally:
            # Save state changes
            logger.debug("Saving conversation and user state")
            await self.conversation_state.save_changes(turn_context)
            await self.user_state.save_changes(turn_context)

    def create_webex_message_adapter(self, turn_context: TurnContext) -> Any:
        """
        Create Webex-compatible message object from Teams TurnContext.

        Args:
            turn_context: Teams turn context to convert

        Returns:
            Adapter object compatible with Webex bot command interface
        """

        class WebexMessageAdapter:
            """Adapter to make Teams messages compatible with Webex command interface."""

            def __init__(self, activity: Activity):
                self.text = activity.text
                self.personEmail = activity.from_property.id
                self.roomId = activity.conversation.id
                self.id = activity.id

        return WebexMessageAdapter(turn_context.activity)


# Create bot instance - similar to WebexBot initialization
BOT = TeamsBot(CONVERSATION_STATE, USER_STATE)


class StreamingConnectionManager:
    """
    Manages persistent WebSocket connection to Bot Framework service
    Similar to how Webex bot maintains WebSocket connection
    """

    def __init__(self, app_id: str, app_password: str, bot_instance: TeamsBot):
        self.app_id = app_id
        self.app_password = app_password
        self.bot_instance = bot_instance
        self.ws = None
        self.session = None
        self.running = False
        self.reconnect_delay = 5
        self.max_reconnect_delay = 300

    async def get_streaming_token(self) -> str:
        """
        Get authentication token for streaming connection using OAuth2.

        Returns:
            Access token string for Bot Framework authentication
        """
        logger.debug(f"Requesting OAuth2 token for app_id: {self.app_id[:8]}...")

        # Microsoft identity platform OAuth2 endpoint
        token_url = f"https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"

        # Request body for client credentials flow
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.app_id,
            'client_secret': self.app_password,
            'scope': 'https://api.botframework.com/.default'
        }

        try:
            async with ClientSession() as session:
                async with session.post(token_url, data=data) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Token request failed: {response.status} - {error_text}")
                        raise Exception(f"Failed to get token: {response.status}")

                    result = await response.json()
                    token = result.get('access_token')

                    if not token:
                        raise Exception("No access_token in response")

                    logger.debug("Successfully obtained OAuth2 token")
                    return token

        except Exception as e:
            logger.error(f"Error getting streaming token: {e}")
            raise

    async def connect(self) -> None:
        """
        Open WebSocket connection to Bot Framework service.
        Similar to Webex bot opening WebSocket to Webex service.
        """
        logger.info("🔌 Opening WebSocket connection to Bot Framework streaming service...")

        try:
            # Get auth token
            logger.debug("Requesting OAuth2 token...")
            token = await self.get_streaming_token()
            logger.debug(f"Got token: {token[:20]}...")

            # Create WebSocket session
            logger.debug("Creating WebSocket client session")
            self.session = ClientSession()
            headers = {
                'Authorization': f'Bearer {token}',
                'User-Agent': 'Toodles-Teams-Bot/1.0'
            }

            # Connect to Bot Framework streaming endpoint
            streaming_url = f"{BOT_FRAMEWORK_STREAMING_URL}{self.app_id}"
            logger.info(f"Connecting to: {streaming_url}")
            logger.debug(f"Headers: User-Agent={headers['User-Agent']}, Auth token length={len(token)}")

            self.ws = await self.session.ws_connect(
                streaming_url,
                headers=headers,
                heartbeat=30  # Send ping every 30s to keep connection alive
            )

            logger.info("✅ WebSocket connection established! (Like Webex bot)")
            logger.debug(f"WebSocket state: {self.ws.closed}")
            self.running = True
            self.reconnect_delay = 5  # Reset delay on successful connect

            # Start listening for messages
            await self.listen()

        except Exception as e:
            logger.error(f"❌ WebSocket connection failed: {e}", exc_info=True)
            await self.cleanup()
            raise

    async def listen(self) -> None:
        """
        Listen for messages on WebSocket connection.
        Similar to Webex bot's message listening loop.
        """
        logger.info("👂 Listening for Teams messages via WebSocket...")

        try:
            async for msg in self.ws:
                logger.debug(f"Received WebSocket message type: {msg.type}")

                if msg.type == WSMsgType.TEXT:
                    # Received activity from Bot Framework
                    logger.debug("Processing TEXT message from Bot Framework")
                    await self.process_activity(msg.json())

                elif msg.type == WSMsgType.BINARY:
                    logger.debug("Received BINARY message (ignored)")

                elif msg.type == WSMsgType.PING:
                    logger.debug("Received PING, sending PONG")
                    await self.ws.pong()

                elif msg.type == WSMsgType.PONG:
                    logger.debug("Received PONG (heartbeat alive)")

                elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                    logger.warning(f"WebSocket closed by server: {msg.type}")
                    break

                elif msg.type == WSMsgType.ERROR:
                    error = self.ws.exception()
                    logger.error(f"WebSocket error: {error}")
                    break

        except Exception as e:
            logger.error(f"Error in WebSocket listen loop: {e}", exc_info=True)
        finally:
            logger.info("WebSocket listen loop ended")
            self.running = False
            await self.cleanup()

    async def process_activity(self, activity_data: dict) -> None:
        """
        Process incoming activity from WebSocket.

        Args:
            activity_data: Dictionary containing activity data from Bot Framework
        """
        try:
            logger.debug(f"Processing activity type: {activity_data.get('type', 'unknown')}")

            # Create Activity object from dict - Activity has from_dict or can be initialized with kwargs
            # Bot Framework SDK expects an Activity object, create it from the dict data
            activity = Activity(**activity_data) if isinstance(activity_data, dict) else activity_data

            # Create turn context and process with bot
            async def bot_callback(turn_context: TurnContext) -> None:
                await self.bot_instance.on_turn(turn_context)

            # Process the activity - empty string for auth header in streaming mode
            # The connection is already authenticated via OAuth2 token in WebSocket headers
            auth_header = ""  # type: str
            await ADAPTER.process_activity(activity, auth_header, bot_callback)

        except Exception as e:
            logger.error(f"Error processing activity: {e}", exc_info=True)

    async def cleanup(self) -> None:
        """Clean up WebSocket and session."""
        logger.debug("Cleaning up WebSocket connection and session")
        if self.ws and not self.ws.closed:
            await self.ws.close()
        if self.session and not self.session.closed:
            await self.session.close()

    async def run_with_reconnect(self) -> None:
        """
        Run bot with automatic reconnection.
        Similar to resilient Webex bot that reconnects on disconnect.
        """
        logger.info("🚀 Starting Teams bot with WebSocket streaming (like Webex bot)")
        logger.debug(f"Initial reconnect delay: {self.reconnect_delay}s, max: {self.max_reconnect_delay}s")

        while True:
            try:
                logger.debug("Attempting to connect...")
                await self.connect()

                # If we get here, connection was closed normally
                if not self.running:
                    logger.info("Bot stopped normally (running=False)")
                    break
                else:
                    logger.warning("Connection ended but running=True, will reconnect")

            except Exception as e:
                logger.error(f"Connection error: {e}")

            # Reconnect with exponential backoff
            logger.info(f"⏳ Reconnecting in {self.reconnect_delay} seconds...")
            logger.debug(f"Sleeping {self.reconnect_delay}s before next connection attempt")
            await asyncio.sleep(self.reconnect_delay)

            # Exponential backoff up to max
            old_delay = self.reconnect_delay
            self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
            logger.debug(f"Reconnect delay increased: {old_delay}s -> {self.reconnect_delay}s")


async def health_check(_request: web.Request) -> web.Response:
    """
    Health check endpoint for monitoring.

    Args:
        _request: HTTP request (unused)

    Returns:
        JSON response with bot health status
    """
    logger.debug("Health check endpoint called")
    return web.json_response({
        'status': 'healthy',
        'bot': 'toodles-teams-streaming',
        'timestamp': str(datetime.now()),
        'connection_type': 'Bot Framework WebSocket Streaming (like Webex)'
    })


def main() -> None:
    """
    Main function - similar to Webex bot main() with resilient framework.
    Opens persistent WebSocket connection to Bot Framework service.
    Bot connects OUT (like Webex), not waiting for inbound webhooks.
    """
    logger.info("=" * 80)
    logger.info("🚀 Starting Toodles Teams Bot with WebSocket Streaming")
    logger.info("=" * 80)
    logger.info("📡 Connection Type: Outbound WebSocket (LIKE WEBEX BOT)")
    logger.info("🔌 Bot connects TO Microsoft Bot Framework service")
    logger.info("🔄 Automatic reconnection on disconnect")
    logger.info("=" * 80)

    # Validate required configuration
    if not TEAMS_TOODLES_APP_ID or not TEAMS_TOODLES_APP_PASSWORD:
        logger.error("=" * 80)
        logger.error("❌ ERROR: Microsoft Teams Toodles Bot credentials not configured!")
        logger.error("=" * 80)
        logger.error("Please set the following environment variables in your .secrets file:")
        logger.error("  TEAMS_TOODLES_APP_ID         - Application (client) ID from Azure")
        logger.error("  TEAMS_TOODLES_APP_PASSWORD   - Client secret Value from Azure")
        logger.error("  TEAMS_TOODLES_TENANT_ID      - Directory (tenant) ID from Azure (optional)")
        logger.error("=" * 80)
        logger.error("Contact your Azure engineer for these values if you don't have them.")
        logger.error("=" * 80)
        sys.exit(1)

    logger.debug(f"App ID configured: {TEAMS_TOODLES_APP_ID[:8]}... (length: {len(TEAMS_TOODLES_APP_ID)})")
    logger.debug(f"App Password configured: {'*' * 8}... (length: {len(TEAMS_TOODLES_APP_PASSWORD)})")
    logger.debug(f"Registered {len(TEAMS_COMMANDS)} commands")

    # Create streaming connection manager (like Webex bot WebSocket)
    logger.debug("Creating StreamingConnectionManager")
    streaming_manager = StreamingConnectionManager(
        app_id=TEAMS_TOODLES_APP_ID,
        app_password=TEAMS_TOODLES_APP_PASSWORD,
        bot_instance=BOT
    )

    # Run the bot with WebSocket streaming (like Webex)
    try:
        logger.debug("Starting asyncio event loop")
        asyncio.run(streaming_manager.run_with_reconnect())
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user (KeyboardInterrupt)")
    except Exception as e:
        logger.error(f"❌ Bot crashed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
