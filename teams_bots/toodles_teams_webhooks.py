#!/usr/bin/env python3
"""
Teams Webhook Bot for Toodles (No Registration Required)
Provides same functionality as Webex Toodles bot via Teams outgoing webhooks
Use this version for immediate testing without Azure Bot Service registration
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from my_config import get_config
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

app = Flask(__name__)

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


class TeamsMessageAdapter:
    """Adapter to make Teams webhook messages compatible with Webex bot commands"""

    def __init__(self, teams_data, message_text):
        self.teams_data = teams_data
        self.text = message_text
        # Teams webhook format
        self.user_name = teams_data.get('from', {}).get('name', 'Unknown')
        self.user_id = teams_data.get('from', {}).get('id', '')
        self.channel_id = teams_data.get('channelData', {}).get('channel', {}).get('id', '')
        self.service_url = teams_data.get('serviceUrl', '')
        # Webex compatibility properties
        self.personEmail = self.user_id
        self.roomId = self.channel_id
        self.id = teams_data.get('id', '')


class TeamsActivityAdapter:
    """Adapter for Teams activity data to match Webex format"""

    def __init__(self, teams_data):
        self.teams_data = teams_data
        self.verb = 'post'  # Teams equivalent
        self.actor = {
            'type': 'PERSON',
            'displayName': teams_data.get('from', {}).get('name', 'Unknown')
        }


def parse_command(message_text):
    """Parse Teams message to extract command and arguments"""
    text = message_text.strip()

    # Remove bot mention if present (Teams format: @BotName or <at>BotName</at>)
    if text.startswith('@'):
        parts = text.split(' ', 1)
        text = parts[1] if len(parts) > 1 else ''
    elif text.startswith('<at>') and '</at>' in text:
        text = text.split('</at>', 1)[1].strip()

    # Split command and args
    parts = text.split(' ', 1)
    command = parts[0].lower().strip()
    args = parts[1] if len(parts) > 1 else ''

    return command, args


def get_help_message():
    """Generate help message listing all available commands"""
    return """**🤖 Toodles Teams Bot - Available Commands:**

**🔒 Security & Threat Hunting:**
• `ioc <indicator>` - Look up IOC information
• `ioc-hunt <indicator>` - Hunt for IOC across systems
• `threat-hunt <query>` - Search threat intelligence
• `create-threat-hunt` - Create new threat hunt
• `containment-status` - Check CrowdStrike containment status

**🎫 Tickets & Work Items:**
• `create-ticket` - Create XSOAR ticket
• `import-ticket <id>` - Import existing ticket
• `fetch-tickets` - Get recent XSOAR tickets
• `search-xsoar` - Search XSOAR tickets
• `create-azdo` - Create Azure DevOps work item
• `tuning-request` - Create tuning request

**👥 Operations:**
• `who` - Who's on call
• `rotation` - Current rotation schedule
• `holidays` - Company holidays
• `approved-testing-entries` - Current approved testing
• `add-approved-testing` - Add testing entry
• `review <item>` - Review items
• `urls <url>` - URL analysis

**⚙️ Bot Management:**
• `health` - Bot health status
• `options` - Available options
• `help` - This help message

**Usage Examples:**
• `@toodles ioc 1.2.3.4`
• `@toodles who`
• `@toodles threat-hunt malware`

*Same commands as your Webex Toodles bot!*"""


@app.route('/webhook', methods=['POST'])
def teams_webhook():
    """
    Handle incoming Teams outgoing webhook messages
    Teams Channel → Outgoing Webhook → This endpoint
    """
    try:
        # Get Teams webhook data
        data = request.get_json()
        logger.info(f"Received Teams webhook from: {data.get('from', {}).get('name', 'Unknown')}")

        # Extract message info
        message_text = data.get('text', '').strip()
        if not message_text:
            return jsonify({'status': 'ignored', 'reason': 'empty message'})

        # Parse command
        command, args = parse_command(message_text)
        logger.info(f"Processing command: '{command}' with args: '{args}'")

        # Handle help command
        if command in ['help', '?']:
            response_text = get_help_message()
            return jsonify({
                'type': 'message',
                'text': response_text
            })

        # Find and execute Toodles command
        if command in TEAMS_COMMANDS:
            cmd_instance = TEAMS_COMMANDS[command]
            if cmd_instance:
                # Create Webex-compatible adapters
                webex_message = TeamsMessageAdapter(data, message_text)
                webex_activity = TeamsActivityAdapter(data).__dict__

                try:
                    # Execute the same command logic as Webex Toodles
                    logger.info(f"Executing Toodles command: {command}")
                    result = cmd_instance.execute(webex_message, None, webex_activity)

                    # Format response
                    if isinstance(result, str):
                        response_text = result
                    else:
                        # Handle card responses or other formats
                        response_text = f"✅ Command '{command}' executed successfully"

                    logger.info(f"Command '{command}' completed successfully")
                    return jsonify({
                        'type': 'message',
                        'text': response_text
                    })

                except Exception as cmd_error:
                    logger.error(f"Command '{command}' execution failed: {cmd_error}", exc_info=True)
                    error_msg = f"❌ Error executing command '{command}': {str(cmd_error)}"
                    return jsonify({
                        'type': 'message',
                        'text': error_msg
                    })
            else:
                return jsonify({
                    'type': 'message',
                    'text': f"⚠️ Command '{command}' is not implemented yet"
                })
        else:
            # Unknown command - show helpful message
            return jsonify({
                'type': 'message',
                'text': f"❓ Unknown command '{command}'. Type `@toodles help` for available commands."
            })

    except Exception as e:
        logger.error(f"Webhook processing failed: {e}", exc_info=True)
        return jsonify({
            'type': 'message',
            'text': "❌ Sorry, I encountered an error processing your request."
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'bot': 'toodles-teams-webhook',
        'timestamp': str(datetime.now()),
        'connection_type': 'Teams Outgoing Webhook',
        'commands_available': len([k for k in TEAMS_COMMANDS.keys() if TEAMS_COMMANDS[k] is not None])
    })


@app.route('/', methods=['GET'])
def root():
    """Root endpoint with setup instructions"""
    return jsonify({
        'bot': 'Toodles Teams Webhook Bot',
        'status': 'running',
        'setup_instructions': {
            'step_1': 'Create Teams outgoing webhook in your channel',
            'step_2': f'Set webhook URL to: http://your-server:5000/webhook',
            'step_3': 'Set bot name to: toodles',
            'step_4': 'Test with: @toodles help'
        },
        'health_check': '/health',
        'webhook_endpoint': '/webhook'
    })


if __name__ == '__main__':
    logger.info("🚀 Starting Toodles Teams Webhook Bot...")
    logger.info("📡 This version uses Teams outgoing webhooks (no Azure registration required)")
    logger.info("🔧 Setup: Teams Channel → Apps → Outgoing Webhook")
    logger.info("🌐 Webhook URL: http://your-server:5000/webhook")
    logger.info("📋 Test command: @toodles help")

    # Run Flask server
    app.run(
        host='0.0.0.0',
        port=5001,
        debug=True,
        threaded=True  # Handle multiple webhook requests
    )
