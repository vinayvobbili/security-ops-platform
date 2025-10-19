# Microsoft Teams Toodles Bot

## Overview

The Teams Toodles bot provides the same functionality as the Webex Toodles bot but operates within Microsoft Teams using the Bot Framework. It provides real-time, websocket-like persistent connections similar to Webex bots.

## Configuration

### Required Environment Variables

Add these to your encrypted secrets file (`data/transient/.secrets`):

```bash
# Microsoft Teams Toodles Bot Configuration (from Azure Bot Service)
TEAMS_TOODLES_APP_ID=<Application (client) ID from Azure>
TEAMS_TOODLES_APP_PASSWORD=<Client secret Value from Azure>
TEAMS_TOODLES_TENANT_ID=<Directory (tenant) ID from Azure>  # Optional
```

**Required credentials (only 2):**

- `TEAMS_TOODLES_APP_ID` - Application (client) ID (REQUIRED)
- `TEAMS_TOODLES_APP_PASSWORD` - Client secret Value (REQUIRED)

**Optional:**

- `TEAMS_TOODLES_TENANT_ID` - Directory (tenant) ID (optional)

### Azure Credential Mapping

When the Azure engineer provides credentials, map them as follows:

| Azure Detail                   | Variable Name                | Description                                |
|--------------------------------|------------------------------|--------------------------------------------|
| **Application (client) ID**    | `TEAMS_TOODLES_APP_ID`       | Your bot's application ID                  |
| **Value** (from client secret) | `TEAMS_TOODLES_APP_PASSWORD` | The secret value (NOT the Secret ID)       |
| **Directory (tenant) ID**      | `TEAMS_TOODLES_TENANT_ID`    | Your Azure tenant ID (optional)            |
| Teams Display name             | N/A                          | Not needed in code (UI only)               |
| Secret ID                      | N/A                          | Not needed in code (portal reference only) |

**Important:** Use the **Value** field from the client secret, not the "Secret ID".

## Setup Instructions

### 1. Encrypt Secrets

After adding credentials to `data/transient/.secrets`:

```bash
python scripts/encrypt_secrets.py --plaintext data/transient/.secrets --output data/transient/.secrets.age --force
```

### 2. Start the Bot Server

```bash
.venv/bin/python teams_bots/toodles_teams.py
```

The bot will start on **port 3978** with the following endpoints:

- **Message endpoint**: `http://0.0.0.0:3978/api/messages`
- **Health endpoint**: `http://0.0.0.0:3978/health`

### 3. Verify Bot Health

```bash
curl http://localhost:3978/health
```

Expected response:

```json
{
  "status": "healthy",
  "bot": "toodles-teams-websocket",
  "timestamp": "2025-10-19 10:12:45.040565",
  "connection_type": "Bot Framework (websocket-like)"
}
```

## Testing with Microsoft Teams

### Step 1: Expose Bot to the Internet

Azure Bot Service needs to send messages to your bot via a public URL.

#### Option A: Using ngrok (Recommended for Testing)

```bash
ngrok http 3978
```

This provides a public URL like: `https://abc123.ngrok.io`

**Note**: Keep this terminal window open while testing. The URL changes each time you restart ngrok (unless using a paid account with reserved domains).

#### Option B: Deploy to Server with Public IP

Deploy the bot to a server with a public IP and configure DNS/firewall appropriately.

### Step 2: Configure Azure Bot Service

1. Go to **Azure Portal** > Your Bot Service
2. Navigate to **Configuration** > **Messaging endpoint**
3. Set the endpoint to: `https://your-public-url/api/messages`
    - Example: `https://abc123.ngrok.io/api/messages`
4. Click **Apply** to save the configuration

### Step 3: Add Microsoft Teams Channel

1. In Azure Portal > Your Bot Service
2. Go to **Channels** section
3. Click **Microsoft Teams** channel (if not already added)
4. Accept the Terms of Service
5. Click **Save**

### Step 4: Test in Microsoft Teams

1. In Azure Portal > Channels > Microsoft Teams
2. Click **"Open in Teams"** link
3. Microsoft Teams will open with a chat to your bot
4. Try these test commands:

```
@toodles help
@toodles health
@toodles who
@toodles rotation
@toodles holidays
```

## Available Commands

The Teams Toodles bot supports all the same commands as the Webex Toodles bot:

### Security & Threat Hunting

- `ioc <indicator>` - Look up IOC information
- `ioc-hunt <indicator>` - Hunt for IOC across systems
- `threat-hunt <query>` - Search threat intelligence
- `create-threat-hunt` - Create new threat hunt
- `containment-status` - Check CrowdStrike containment status

### Tickets & Work Items

- `create-ticket` - Create XSOAR ticket
- `import-ticket <id>` - Import existing ticket
- `fetch-tickets` - Get recent XSOAR tickets
- `search-xsoar` - Search XSOAR tickets
- `create-azdo` - Create Azure DevOps work item
- `tuning-request` - Create tuning request

### Operations

- `who` - Who's on call
- `rotation` - Current rotation schedule
- `holidays` - Company holidays
- `approved-testing-entries` - Current approved testing
- `add-approved-testing` - Add testing entry
- `review <item>` - Review items
- `urls <url>` - URL analysis

### Bot Management

- `health` - Bot health status
- `options` - Available options
- `help` - Show help message

## Architecture

### Bot Framework Integration

The Teams bot uses the Microsoft Bot Framework with:

- **BotFrameworkAdapter** - Handles persistent connections (websocket-like)
- **ConversationState** - Maintains conversation context
- **UserState** - Maintains user-specific state
- **ActivityHandler** - Processes incoming messages

### Webex Compatibility Layer

The bot includes adapter classes to make Webex command implementations work with Teams:

- `create_webex_message_adapter()` - Converts Teams messages to Webex format
- `create_webex_activity_adapter()` - Converts Teams activities to Webex format

This allows reusing all existing Webex command logic without modification.

## File Locations

- **Bot code**: `teams_bots/toodles_teams.py`
- **Configuration**: `my_config.py` (lines 131-133, 238-240)
- **Encrypted secrets**: `data/transient/.secrets.age`
- **Documentation**: `docs/TEAMS_TOODLES.md`

## Troubleshooting

### Bot won't start - Missing credentials

**Error:**

```
ERROR: Microsoft Teams Toodles Bot credentials not configured!
```

**Solution:**
Ensure `TEAMS_TOODLES_APP_ID` and `TEAMS_TOODLES_APP_PASSWORD` are set in `data/transient/.secrets` and the file is encrypted to `.secrets.age`.

### Azure can't reach the bot

**Symptoms:**

- Messages sent in Teams don't reach the bot
- Azure shows "Messaging endpoint validation failed"

**Solution:**

1. Verify the bot is running: `curl http://localhost:3978/health`
2. Verify ngrok is running and the URL is correct
3. Check Azure messaging endpoint matches your ngrok URL + `/api/messages`
4. Check ngrok logs for incoming requests

### Commands not working

**Symptoms:**

- Bot responds but commands don't work
- Error messages about missing integrations

**Solution:**
Ensure all required environment variables for the specific command are set:

- XSOAR credentials for ticket commands
- CrowdStrike credentials for containment status
- Azure DevOps credentials for work item creation
- etc.

## Production Deployment

For production deployment:

1. **Deploy to a stable server** (not ngrok)
2. **Use HTTPS** with a valid SSL certificate
3. **Configure firewall** to allow Azure Bot Service IPs
4. **Set up monitoring** for bot health endpoint
5. **Configure logging** to track bot usage and errors
6. **Use a process manager** (systemd, supervisor, etc.) to keep the bot running

Example systemd service:

```ini
[Unit]
Description = Teams Toodles Bot
After = network.target

[Service]
Type = simple
User = your-user
WorkingDirectory = /path/to/IR
ExecStart = /path/to/IR/.venv/bin/python teams_bots/toodles_teams.py
Restart = always
RestartSec = 10

[Install]
WantedBy = multi-user.target
```

## Security Notes

- Keep `.secrets` file encrypted at all times
- Never commit `.secrets` or `.secrets.age` to git
- Rotate credentials regularly
- Use least-privilege Azure service principal
- Monitor bot logs for suspicious activity
- Validate all user inputs before processing

## Support

For issues or questions:

1. Check this documentation
2. Review bot logs: stderr output from the Python process
3. Check Azure Portal > Bot Service > Channels > Test in Web Chat
4. Verify all credentials are correctly configured
