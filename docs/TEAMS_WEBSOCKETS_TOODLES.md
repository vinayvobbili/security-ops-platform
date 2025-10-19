# Microsoft Teams Toodles Bot (WebSocket Streaming)

> Uses persistent WebSocket connections like Webex. No public endpoint, no ngrok, no webhooks!

## Prerequisites

You need three values from Azure Bot Service (get from your Azure admin):

- `TEAMS_TOODLES_APP_ID` - Application (client) ID
- `TEAMS_TOODLES_APP_PASSWORD` - Client secret **Value** (not Secret ID)
- `TEAMS_TOODLES_TENANT_ID` - Directory (tenant) ID (optional)

## Setup Steps

### 1. Add Credentials to Secrets File

Edit `data/transient/.secrets` and add:

```bash
TEAMS_TOODLES_APP_ID=your-app-id-here
TEAMS_TOODLES_APP_PASSWORD=your-secret-value-here
TEAMS_TOODLES_TENANT_ID=your-tenant-id-here
```

### 2. Encrypt Secrets

```bash
python scripts/encrypt_secrets.py --plaintext data/transient/.secrets --output data/transient/.secrets.age --force
```

### 3. Configure Azure Bot Service

**In Azure Portal > Your Bot Service > Configuration:**

1. Check ✅ **"Use Streaming Endpoint"**
2. Clear ❌ the **messaging endpoint URL** field (leave it blank)
3. Click **Apply**

**Why?** The bot connects OUT to Microsoft (like Webex), so Azure doesn't need your bot's URL.

### 4. Add Teams Channel

**In Azure Portal > Your Bot Service > Channels:**

1. Add **Microsoft Teams** channel (if not already added)
2. Accept Terms of Service
3. Click **Save**

### 5. Start the Bot

```bash
.venv/bin/python teams_bots/toodles_teams.py
```

**Wait for this message:**

```
✅ WebSocket connection established! (Like Webex bot)
👂 Listening for Teams messages via WebSocket...
```

### 6. Test in Teams

1. **Azure Portal** > Your Bot Service > **Channels** > **Microsoft Teams** > Click **"Open in Teams"**
2. Send: `@toodles help`
3. Bot should respond with available commands

## Available Commands

Same commands as Webex Toodles bot. Key commands:

- `help` - Show all commands
- `who` - On-call person
- `rotation` - Current rotation
- `holidays` - Company holidays
- `create-ticket` - Create XSOAR ticket
- `containment-status` - Check CrowdStrike status
- `create-azdo` - Create Azure DevOps work item

Full command list: Run `@toodles help` in Teams

## How It Works

Bot connects OUT to Microsoft via WebSocket (like Webex):

```
Your Bot → WebSocket OUT → Microsoft Service ← Teams
```

- Connection: `wss://streaming.botframework.com/.bot/<app-id>`
- Auto-reconnects on disconnect
- Heartbeat every 30s to keep connection alive
- Same architecture as Webex bot

## Troubleshooting

### Connection Fails

**Error:** `❌ WebSocket connection failed`

**Check:**

1. Credentials correct in `.secrets.age`?
2. "Use Streaming Endpoint" enabled in Azure Portal?
3. Firewall allows outbound to `streaming.botframework.com:443`?
4. Bot exists in Azure Portal (not deleted/suspended)?

### Messages Not Reaching Bot

**Check:**

1. Teams channel added in Azure Portal?
2. Bot invited to the Teams chat?
3. Try `@toodles help` to test

### Commands Not Working

Ensure required service credentials are set in `.secrets`:

- XSOAR credentials for ticket commands
- CrowdStrike for containment status
- Azure DevOps for work items

## Production Deployment

**Key Benefits:**

- ✅ No public endpoint needed
- ✅ No SSL cert needed
- ✅ Works behind corporate firewalls
- ✅ Only needs outbound HTTPS (port 443)

**Firewall Requirements:**

- Allow outbound to `streaming.botframework.com:443`
- Allow outbound to `login.microsoftonline.com:443`

**Example systemd service:**

```ini
[Unit]
Description = Teams Toodles Bot
After = network.target

[Service]
Type = simple
WorkingDirectory = /path/to/IR
ExecStart = /path/to/IR/.venv/bin/python teams_bots/toodles_teams.py
Restart = always
RestartSec = 10

[Install]
WantedBy = multi-user.target
```

**Start service:**

```bash
sudo systemctl enable toodles-teams
sudo systemctl start toodles-teams
sudo journalctl -u toodles-teams -f  # View logs
```

## Security

- Keep `.secrets` encrypted
- Never commit `.secrets` or `.secrets.age` to git
- Rotate Azure credentials regularly
