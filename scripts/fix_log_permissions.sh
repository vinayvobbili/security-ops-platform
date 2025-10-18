#!/bin/bash
# Script to fix log directory permissions for IR bot

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

LOG_DIR="/home/vinay/pub/IR/data/transient/logs"
USER="${USER:-vinay}"

echo -e "${YELLOW}🔧 Fixing log directory permissions...${NC}"

# Check if directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo -e "${RED}❌ Directory does not exist: $LOG_DIR${NC}"
    exit 1
fi

# Display current ownership
echo -e "${YELLOW}📋 Current ownership:${NC}"
ls -ld "$LOG_DIR"
ls -la "$LOG_DIR"

# Fix ownership
echo -e "${YELLOW}🔨 Fixing ownership to $USER:$USER...${NC}"
sudo chown -R "$USER:$USER" "$LOG_DIR"

# Verify fix
echo -e "${GREEN}✅ New ownership:${NC}"
ls -ld "$LOG_DIR"
ls -la "$LOG_DIR"

echo -e "${GREEN}✅ Permissions fixed successfully!${NC}"
echo -e "${YELLOW}💡 You can now restart the the notification service bot${NC}"
