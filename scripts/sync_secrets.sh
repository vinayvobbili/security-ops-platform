#!/bin/bash
# Sync encrypted secrets to Ubuntu server via SCP
# Usage: ./scripts/sync_secrets.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SECRETS_FILE="$PROJECT_ROOT/data/transient/.secrets.age"
UBUNTU_HOST="vinay@metcirt-lab-12.internal.company.com"
UBUNTU_PATH="~/pub/IR/data/transient/.secrets.age"

echo "🔐 Syncing encrypted secrets to Ubuntu..."

# Check if .secrets.age exists
if [ ! -f "$SECRETS_FILE" ]; then
    echo "❌ No .secrets.age file found at $SECRETS_FILE"
    echo "   Create it first:"
    echo "   1. Edit data/transient/.secrets"
    echo "   2. Run: bash scripts/encrypt_secrets.sh"
    exit 1
fi

echo "📤 Copying $SECRETS_FILE → $UBUNTU_HOST:$UBUNTU_PATH"

# SCP the file
scp "$SECRETS_FILE" "$UBUNTU_HOST:$UBUNTU_PATH"

echo "✅ Secrets synced to Ubuntu!"
echo ""
echo "💡 Next steps on Ubuntu:"
echo "   cd ~/pub/IR"
echo "   python web/web_server.py  # Restart to pick up new secrets"
