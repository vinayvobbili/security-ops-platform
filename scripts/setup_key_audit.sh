#!/bin/bash
#
# Setup audit logging for age encryption key
# This tracks all access attempts to the encryption key file
#

set -e

echo "=========================================="
echo "Age Key Audit Setup"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

KEY_FILE="$HOME/.config/age/key.txt"
AUDIT_RULE_NAME="age_key_access"

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo -e "${RED}✗ This script only works on Linux${NC}"
    exit 1
fi

# Check if key file exists
if [[ ! -f "$KEY_FILE" ]]; then
    echo -e "${RED}✗ Key file not found: $KEY_FILE${NC}"
    echo "Run setup_age_encryption.sh first"
    exit 1
fi

# Check if auditd is installed
if ! command -v auditctl &> /dev/null; then
    echo "auditd not found. Installing..."

    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Need sudo to install auditd${NC}"
        sudo apt update
        sudo apt install -y auditd audispd-plugins
        sudo systemctl enable auditd
        sudo systemctl start auditd
    else
        apt update
        apt install -y auditd audispd-plugins
        systemctl enable auditd
        systemctl start auditd
    fi

    echo -e "${GREEN}✓ auditd installed${NC}"
else
    echo -e "${GREEN}✓ auditd already installed${NC}"
fi

# Check if auditd is running
if ! systemctl is-active --quiet auditd; then
    echo "Starting auditd..."
    sudo systemctl start auditd
fi

# Remove existing rule if present
echo ""
echo "Checking for existing audit rules..."
if sudo auditctl -l | grep -q "$AUDIT_RULE_NAME"; then
    echo "Removing old rule..."
    sudo auditctl -D -k "$AUDIT_RULE_NAME" 2>/dev/null || true
fi

# Add audit rule for the key file
echo "Adding audit rule for: $KEY_FILE"
sudo auditctl -w "$KEY_FILE" -p rwxa -k "$AUDIT_RULE_NAME"

# Make the rule persistent across reboots
RULES_FILE="/etc/audit/rules.d/age-key.rules"
echo "Making rule persistent..."
echo "# Audit rule for age encryption key access" | sudo tee "$RULES_FILE" > /dev/null
echo "-w $KEY_FILE -p rwxa -k $AUDIT_RULE_NAME" | sudo tee -a "$RULES_FILE" > /dev/null

echo -e "${GREEN}✓ Audit rule added and persisted${NC}"

# Verify the rule
echo ""
echo "Current audit rules for key file:"
sudo auditctl -l | grep "$AUDIT_RULE_NAME" || echo "No rules found"

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "The following actions on the key file will be logged:"
echo "  r = read"
echo "  w = write"
echo "  x = execute"
echo "  a = attribute change"
echo ""
echo "To view access logs:"
echo "  sudo ausearch -k $AUDIT_RULE_NAME"
echo ""
echo "Or use the helper script:"
echo "  python scripts/check_key_access.py"
echo ""
echo -e "${YELLOW}Note: All access is logged, including legitimate access${NC}"
echo "by your application. Review logs for suspicious patterns."
echo ""
