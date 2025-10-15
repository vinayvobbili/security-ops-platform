#!/bin/bash
# Encrypt .secrets file to .secrets.age
# Usage: ./scripts/encrypt_secrets.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SECRETS_DIR="$PROJECT_ROOT/data/transient"
KEY_FILE="${AGE_KEY_FILE:-$HOME/.config/age/key.txt}"

echo "🔐 Encrypting secrets..."

# Check if .secrets exists
if [ ! -f "$SECRETS_DIR/.secrets" ]; then
    echo "❌ No .secrets file found at $SECRETS_DIR/.secrets"
    echo "   Create it first with your API keys and passwords"
    exit 1
fi

# Check if age key exists
if [ ! -f "$KEY_FILE" ]; then
    echo "❌ Age key not found at $KEY_FILE"
    echo "   Run: bash scripts/setup_age_encryption.sh"
    exit 1
fi

# Backup existing .secrets.age if it exists
if [ -f "$SECRETS_DIR/.secrets.age" ]; then
    cp "$SECRETS_DIR/.secrets.age" "$SECRETS_DIR/.secrets.age.backup"
    echo "✓ Backed up existing .secrets.age"
fi

# Extract public key and encrypt
PUBLIC_KEY=$(age-keygen -y "$KEY_FILE")
age -e -r "$PUBLIC_KEY" "$SECRETS_DIR/.secrets" > "$SECRETS_DIR/.secrets.age"

echo "✓ Encrypted $SECRETS_DIR/.secrets → .secrets.age"
echo ""
echo "📋 Next steps:"
echo "   1. Verify: python -c 'from my_config import get_config; print(get_config().ollama_llm_model)'"
echo "   2. Delete plaintext: rm $SECRETS_DIR/.secrets"
echo "   3. Commit encrypted: git add data/transient/.secrets.age && git commit -m 'Update secrets'"
echo ""
echo "💡 To edit secrets in the future:"
echo "   1. Decrypt: age -d -i $KEY_FILE $SECRETS_DIR/.secrets.age > $SECRETS_DIR/.secrets"
echo "   2. Edit: nano $SECRETS_DIR/.secrets"
echo "   3. Re-encrypt: $SCRIPT_DIR/encrypt_secrets.sh"
echo "   4. Delete plaintext: rm $SECRETS_DIR/.secrets"
