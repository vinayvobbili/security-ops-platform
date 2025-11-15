#!/bin/bash
#
# Setup script for age encryption
# This script:
# 1. Installs age on Ubuntu (if not already installed)
# 2. Generates an encryption key
# 3. Secures the key with proper permissions
#

set -e  # Exit on error

echo "=========================================="
echo "Age Encryption Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo -e "${YELLOW}⚠️  Warning: This script is designed for Ubuntu/Linux${NC}"
    echo "For macOS, run: brew install age"
    exit 1
fi

# Check if age is installed
echo "Checking for age installation..."
if command -v age &> /dev/null; then
    AGE_VERSION=$(age --version 2>&1 | head -n1)
    echo -e "${GREEN}✓ age is already installed: $AGE_VERSION${NC}"
else
    echo "Installing age..."

    # Check if running as root/sudo
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}This script needs sudo privileges to install age.${NC}"
        sudo apt update
        sudo apt install -y age
    else
        apt update
        apt install -y age
    fi

    if command -v age &> /dev/null; then
        echo -e "${GREEN}✓ age installed successfully${NC}"
    else
        echo -e "${RED}✗ Failed to install age${NC}"
        exit 1
    fi
fi

# Set up key directory
KEY_DIR="$HOME/.config/age"
KEY_FILE="$KEY_DIR/key.txt"

echo ""
echo "Setting up encryption key..."

# Create key directory if it doesn't exist
if [[ ! -d "$KEY_DIR" ]]; then
    mkdir -p "$KEY_DIR"
    echo -e "${GREEN}✓ Created key directory: $KEY_DIR${NC}"
fi

# Generate key if it doesn't exist
if [[ -f "$KEY_FILE" ]]; then
    echo -e "${YELLOW}⚠️  Key already exists at $KEY_FILE${NC}"
    echo -n "Do you want to generate a new key? (y/N): "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Using existing key."
    else
        echo "Backing up existing key..."
        cp "$KEY_FILE" "$KEY_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        echo "Generating new key..."
        age-keygen -o "$KEY_FILE"
        echo -e "${GREEN}✓ New key generated${NC}"
    fi
else
    echo "Generating new key..."
    age-keygen -o "$KEY_FILE"
    echo -e "${GREEN}✓ Key generated at $KEY_FILE${NC}"
fi

# Secure the key file
chmod 600 "$KEY_FILE"
echo -e "${GREEN}✓ Key permissions set to 600 (owner read/write only)${NC}"

# Display public key
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Private key location: $KEY_FILE"
echo "Public key:"
age-keygen -y "$KEY_FILE"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Encrypt your .env file:"
echo "   python scripts/encrypt_env.py"
echo ""
echo "2. Verify the encryption works:"
echo "   python src/utils/env_encryption.py"
echo ""
echo "3. Update your application to use encrypted secrets"
echo ""
echo -e "${YELLOW}IMPORTANT: Back up your private key securely!${NC}"
echo "If you lose $KEY_FILE, you won't be able to decrypt your secrets."
echo ""
