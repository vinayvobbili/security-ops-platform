#!/bin/bash
# Setup Python-based log viewers with nginx landing page
# Run this script with: bash setup_log_viewers.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load environment variables from .env
if [ -f "$PROJECT_ROOT/.env" ]; then
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | grep -v '^$' | xargs)
fi

# Use LOG_VIEWER settings from .env or defaults
LOG_VIEWER_BASE_URL="${LOG_VIEWER_BASE_URL:-http://localhost}"
LOG_VIEWER_USERNAME="${LOG_VIEWER_USERNAME:-sirt}"
LOG_VIEWER_PASSWORD="${LOG_VIEWER_PASSWORD:-sirt}"
# Extract hostname from URL for nginx server_name
LOG_VIEWER_HOSTNAME=$(echo "$LOG_VIEWER_BASE_URL" | sed -E 's|https?://([^:/]+).*|\1|')

echo "================================================"
echo "Setting up Log Viewers with nginx Landing Page"
echo "================================================"
echo ""

# Install nginx if not present
if ! command -v nginx &> /dev/null; then
    echo "Installing nginx..."
    sudo apt-get update -qq
    sudo apt-get install -y nginx apache2-utils
    echo "  ✓ nginx installed"
else
    echo "  ✓ nginx already installed"
fi
echo ""

# Create htpasswd file for basic auth
echo "Setting up password protection..."
echo -n "$LOG_VIEWER_PASSWORD" | sudo htpasswd -i -c /home/vinay/pub/IR/.htpasswd "$LOG_VIEWER_USERNAME"
sudo chown vinay:vinay /home/vinay/pub/IR/.htpasswd
sudo chmod 644 /home/vinay/pub/IR/.htpasswd
echo "  ✓ Password configured (username: $LOG_VIEWER_USERNAME, password: $LOG_VIEWER_PASSWORD)"
echo ""

# Ensure home directory is accessible for nginx
echo "Configuring directory permissions..."
chmod 751 /home/vinay
echo "  ✓ Directory permissions set"
echo ""

# Generate nginx configuration from template
echo "Generating nginx configuration..."
cat > /tmp/ir-log-viewer.conf <<EOF
server {
    listen 8030;
    server_name $LOG_VIEWER_HOSTNAME;

    root /home/vinay/pub/IR/deployment;
    index log-viewer-index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
sudo mv /tmp/ir-log-viewer.conf /etc/nginx/sites-available/ir-log-viewer.conf
sudo ln -sf /etc/nginx/sites-available/ir-log-viewer.conf /etc/nginx/sites-enabled/ir-log-viewer.conf
sudo nginx -t
echo "  ✓ nginx configuration installed with server_name: $LOG_VIEWER_HOSTNAME"
echo ""

# Generate HTML landing page from environment variables
echo "Generating HTML landing page..."
cat > "$SCRIPT_DIR/log-viewer-index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IR Log Viewer</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 800px;
            width: 100%;
            padding: 40px;
        }

        h1 {
            color: #2d3748;
            margin-bottom: 10px;
            font-size: 2em;
        }

        .subtitle {
            color: #718096;
            margin-bottom: 30px;
            font-size: 1.1em;
        }

        .log-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }

        .log-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            padding: 24px;
            text-decoration: none;
            color: white;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .log-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 12px rgba(0, 0, 0, 0.2);
        }

        .log-card.featured {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .log-card h3 {
            font-size: 1.3em;
            margin-bottom: 8px;
        }

        .log-card p {
            opacity: 0.9;
            font-size: 0.9em;
        }

        .features {
            background: #f7fafc;
            border-radius: 12px;
            padding: 20px;
            margin-top: 30px;
        }

        .features h3 {
            color: #2d3748;
            margin-bottom: 12px;
        }

        .features ul {
            list-style: none;
            color: #4a5568;
        }

        .features li {
            padding: 8px 0;
            padding-left: 24px;
            position: relative;
        }

        .features li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #48bb78;
            font-weight: bold;
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            color: #a0aec0;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 IR Log Viewer</h1>
    <p class="subtitle">Real-time log monitoring for all IR services</p>

    <div class="log-grid">
        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8031" class="log-card featured" target="_blank">
            <h3>📊 All Services</h3>
            <p>Combined view of all IR services using journalctl</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8032" class="log-card" target="_blank">
            <h3>🎯 the notification service</h3>
            <p>the notification service bot logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8033" class="log-card" target="_blank">
            <h3>🤖 the case orchestrator</h3>
            <p>the case orchestrator bot logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8034" class="log-card" target="_blank">
            <h3>💰 MoneyBall</h3>
            <p>MoneyBall bot logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8035" class="log-card" target="_blank">
            <h3>🛡️ the orchestration service</h3>
            <p>the orchestration service bot logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8036" class="log-card" target="_blank">
            <h3>⚓ the alert triage service</h3>
            <p>the alert triage service bot logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8038" class="log-card" target="_blank">
            <h3>🤖 the threat-intel service</h3>
            <p>the threat-intel service bot logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8037" class="log-card" target="_blank">
            <h3>⏰ All Jobs</h3>
            <p>Scheduler logs</p>
        </a>

        <a href="LOG_VIEWER_BASE_URL_PLACEHOLDER:8039" class="log-card" target="_blank">
            <h3>🌐 Web Server</h3>
            <p>Web server logs</p>
        </a>
    </div>

    <div class="features">
        <h3>Features</h3>
        <ul>
            <li>Real-time log streaming</li>
            <li>Color-coded log levels (ERROR, WARNING, INFO)</li>
            <li>Full-text search across logs</li>
            <li>Filter by log level and timestamp</li>
            <li>No SSH access required</li>
        </ul>
    </div>

    <div class="footer">
        Security Operations Team
    </div>
</div>
</body>
</html>
HTMLEOF

# Replace placeholder with actual URL
sed -i "s|LOG_VIEWER_BASE_URL_PLACEHOLDER|$LOG_VIEWER_BASE_URL|g" "$SCRIPT_DIR/log-viewer-index.html"
echo "  ✓ HTML landing page generated"
echo ""

# Install Python log viewer systemd services
echo "Installing new log viewer systemd services..."
sudo cp "$SCRIPT_DIR/systemd"/ir-log-viewer-*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable all services
for service in all toodles msoar money-ball barnacles tars jobs jarvis; do
    sudo systemctl enable ir-log-viewer-${service}.service
done
echo "  ✓ Systemd services installed and enabled"
echo ""

# Make log viewer script executable
echo "Making log viewer script executable..."
chmod +x "$SCRIPT_DIR/log_viewer.py"
chmod +x "$SCRIPT_DIR/manage_log_viewers.sh"
echo "  ✓ Script permissions set"
echo ""

# Create symlink in ~/bin for easy management
echo "Creating management symlink..."
mkdir -p ~/bin
ln -sf /home/vinay/pub/IR/deployment/manage_log_viewers.sh ~/bin/start_log_service
echo "  ✓ Symlink created: ~/bin/start_log_service"
echo ""

# Start all log viewer services
echo "Starting log viewer services..."
for service in all toodles msoar money-ball barnacles tars jobs jarvis; do
    sudo systemctl start ir-log-viewer-${service}.service
done
sleep 2
echo "  ✓ All log viewer services started"
echo ""

# Restart nginx
echo "Restarting nginx..."
sudo systemctl restart nginx
echo "  ✓ nginx restarted"
echo ""

echo "================================================"
echo "✅ Log Viewers Setup Complete!"
echo "================================================"
echo ""
echo "Landing page:"
echo "  ${LOG_VIEWER_BASE_URL}:8030"
echo "  (Username: $LOG_VIEWER_USERNAME, Password: $LOG_VIEWER_PASSWORD)"
echo ""
echo "Direct access URLs:"
echo "  ${LOG_VIEWER_BASE_URL}:8031 - All Services (journalctl)"
echo "  ${LOG_VIEWER_BASE_URL}:8032 - the notification service"
echo "  ${LOG_VIEWER_BASE_URL}:8033 - the case orchestrator"
echo "  ${LOG_VIEWER_BASE_URL}:8034 - MoneyBall"
echo "  ${LOG_VIEWER_BASE_URL}:8035 - the orchestration service"
echo "  ${LOG_VIEWER_BASE_URL}:8036 - the alert triage service"
echo "  ${LOG_VIEWER_BASE_URL}:8038 - the threat-intel service"
echo "  ${LOG_VIEWER_BASE_URL}:8037 - All Jobs"
echo "  (Each protected with username: $LOG_VIEWER_USERNAME, password: $LOG_VIEWER_PASSWORD)"
echo ""
echo "Features:"
echo "  ✓ Full log streaming (like tail -f)"
echo "  ✓ Auto-scrolling with pause on manual scroll"
echo "  ✓ Color-coded log levels (ERROR, WARNING, INFO, DEBUG)"
echo "  ✓ Browser native search (Ctrl+F)"
echo "  ✓ Dark theme optimized for readability"
echo "  ✓ Real-time connection status"
echo "  ✓ Password protected"
echo "  ✓ No SSH access required"
echo ""
echo "Management:"
echo "  Simple commands (via ~/bin/start_log_service):"
echo "    start_log_service start    - Start all log viewers"
echo "    start_log_service stop     - Stop all log viewers"
echo "    start_log_service restart  - Restart all log viewers"
echo "    start_log_service status   - Check status of all log viewers"
echo ""
echo "  Direct systemctl commands:"
echo "    sudo systemctl status ir-log-viewer-*"
echo "    sudo systemctl status nginx"
echo "    sudo journalctl -u ir-log-viewer-* -f"
echo ""
echo "Testing locally (before firewall opens ports):"
echo "  ssh -L 8030:localhost:8030 -L 8031:localhost:8031 -L 8032:localhost:8032 -L 8033:localhost:8033 -L 8034:localhost:8034 -L 8035:localhost:8035 -L 8036:localhost:8036 -L 8037:localhost:8037 -L 8038:localhost:8038 lab-vm"
echo "  Then access: http://localhost:8030"
echo ""
