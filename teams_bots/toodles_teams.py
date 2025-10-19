#!/usr/bin/env python3
"""
Teams Bot Framework Bot for Toodles
Provides same functionality as Webex Toodles bot via Teams Bot Framework with websockets
Real-time socket connection similar to Webex bot architecture
"""
import logging
import sys
from datetime import datetime
from pathlib import Path

from aiohttp import web
from aiohttp.web import Request, Response, json_response

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
    UserState
)
from botbuilder.schema import Activity
from botbuilder.core.bot_framework_adapter import BotFrameworkAdapter, BotFrameworkAdapterSettings

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

# Bot Framework Settings
SETTINGS = BotFrameworkAdapterSettings(
    app_id=TEAMS_TOODLES_APP_ID,
    app_password=TEAMS_TOODLES_APP_PASSWORD
)

# Create adapter - this handles the websocket connections like Webex
ADAPTER = BotFrameworkAdapter(SETTINGS)

# Create conversation state
MEMORY = MemoryStorage()
CONVERSATION_STATE = ConversationState(MEMORY)
USER_STATE = UserState(MEMORY)

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


def parse_command(message_text):
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


def create_webex_activity_adapter(turn_context: TurnContext):
    """Create Webex-compatible activity object from Teams TurnContext"""
    return {
        'verb': 'post',
        'actor': {
            'type': 'PERSON',
            'displayName': turn_context.activity.from_property.name or 'Unknown'
        }
    }


def get_help_message():
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


async def on_turn_error(context: TurnContext, error: Exception):
    """Handle turn errors"""
    logger.error(f"Turn error: {error}")
    await context.send_activity(MessageFactory.text("Sorry, I encountered an error."))


class TeamsBot(ActivityHandler):
    """
    Teams Bot using Bot Framework - similar architecture to WebexBot with real-time connections
    Handles persistent socket connections like Webex bots with threads=True
    """

    def __init__(self, conversation_state: ConversationState, user_state: UserState):
        self.conversation_state = conversation_state
        self.user_state = user_state

    async def on_message_activity(self, turn_context: TurnContext):
        """
        Handle incoming messages - equivalent to Webex process_incoming_message
        Real-time processing similar to Webex socket handling
        """
        try:
            message_text = turn_context.activity.text.strip()
            logger.info(f"Processing Teams message: {message_text[:50]}...")

            # Parse command like Webex bot
            command, args = parse_command(message_text)

            if command == 'help' or command == '?':
                response_text = get_help_message()
                await turn_context.send_activity(MessageFactory.text(response_text))
                return

            # Execute Toodles command using same business logic
            if command in TEAMS_COMMANDS:
                cmd_instance = TEAMS_COMMANDS[command]
                if cmd_instance:
                    # Create Webex-compatible adapters
                    webex_message = self.create_webex_message_adapter(turn_context)
                    webex_activity = create_webex_activity_adapter(turn_context)

                    try:
                        # Execute the same command as Webex bot
                        result = cmd_instance.execute(webex_message, None, webex_activity)

                        if isinstance(result, str):
                            response_text = result
                        else:
                            response_text = f"Command '{command}' executed successfully"

                        await turn_context.send_activity(MessageFactory.text(response_text))

                    except Exception as cmd_error:
                        logger.error(f"Command execution failed: {cmd_error}")
                        error_msg = f"Error executing command '{command}': {str(cmd_error)}"
                        await turn_context.send_activity(MessageFactory.text(error_msg))
                else:
                    await turn_context.send_activity(
                        MessageFactory.text(f"Command '{command}' is not implemented yet")
                    )
            else:
                await turn_context.send_activity(
                    MessageFactory.text(f"Unknown command '{command}'. Type 'help' for available commands.")
                )

        except Exception as e:
            logger.error(f"Message processing failed: {e}")
            await turn_context.send_activity(
                MessageFactory.text("Sorry, I encountered an error processing your request.")
            )
        finally:
            # Save state changes
            await self.conversation_state.save_changes(turn_context)
            await self.user_state.save_changes(turn_context)

    def create_webex_message_adapter(self, turn_context: TurnContext):
        """Create Webex-compatible message object from Teams TurnContext"""

        class WebexMessageAdapter:
            def __init__(self, activity: Activity):
                self.text = activity.text
                self.personEmail = activity.from_property.id
                self.roomId = activity.conversation.id
                self.id = activity.id

        return WebexMessageAdapter(turn_context.activity)


# Create bot instance - similar to WebexBot initialization
BOT = TeamsBot(CONVERSATION_STATE, USER_STATE)


async def messages(req: Request) -> Response:
    """
    Main message handler - equivalent to Webex bot message processing
    Handles real-time bot framework messages via persistent connections
    """
    # Process the Bot Framework activity
    if "application/json" in req.headers["Content-Type"]:
        body = await req.json()
    else:
        return Response(status=415)

    activity = Activity().deserialize(body)
    auth_header = req.headers["Authorization"] if "Authorization" in req.headers else ""

    try:
        # Use Bot Framework adapter to process the activity
        # This maintains persistent connections like Webex bots
        response = await ADAPTER.process_activity(activity, auth_header, on_turn_error)
        if response:
            return json_response(data=response.body, status=response.status)
        return Response(status=201)
    except Exception as e:
        logger.error(f"Error processing activity: {e}")
        return Response(status=500)


async def health_check(_request: Request) -> Response:
    """Health check endpoint"""
    return json_response({
        'status': 'healthy',
        'bot': 'toodles-teams-websocket',
        'timestamp': str(datetime.now()),
        'connection_type': 'Bot Framework (websocket-like)'
    })


def create_app() -> web.Application:
    """Create aiohttp app with Bot Framework integration"""
    app = web.Application()

    # Add routes
    app.router.add_post("/api/messages", messages)  # Bot Framework standard endpoint
    app.router.add_get("/health", health_check)

    return app


async def init_func():
    """Initialize the bot - similar to Webex bot initialization"""
    logger.info("Initializing Teams Bot with Bot Framework (websocket connections)...")

    app = create_app()
    return app


def main():
    """
    Main function - similar to Webex bot main() with resilient framework
    Starts persistent Bot Framework connections
    """
    logger.info("Starting Toodles Teams Bot with Bot Framework...")
    logger.info("This provides websocket-like persistent connections similar to Webex bots")

    # Validate required configuration
    if not TEAMS_TOODLES_APP_ID or not TEAMS_TOODLES_APP_PASSWORD:
        logger.error("=" * 80)
        logger.error("ERROR: Microsoft Teams Toodles Bot credentials not configured!")
        logger.error("=" * 80)
        logger.error("Please set the following environment variables in your .secrets file:")
        logger.error("  TEAMS_TOODLES_APP_ID         - Application (client) ID from Azure")
        logger.error("  TEAMS_TOODLES_APP_PASSWORD   - Client secret Value from Azure")
        logger.error("  TEAMS_TOODLES_TENANT_ID      - Directory (tenant) ID from Azure (optional)")
        logger.error("=" * 80)
        logger.error("Contact your Azure engineer for these values if you don't have them.")
        logger.error("=" * 80)
        sys.exit(1)

    # Start the web server for Bot Framework
    web.run_app(init_func(), host="0.0.0.0", port=3978)


if __name__ == '__main__':
    main()
