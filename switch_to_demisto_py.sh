#!/bin/bash
# Script to switch from custom XSOAR implementation to demisto-py SDK
# Usage: ./switch_to_demisto_py.sh [--rollback]

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}XSOAR Migration to demisto-py SDK${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if rollback flag is provided
if [ "$1" == "--rollback" ]; then
    echo -e "${YELLOW}Rolling back to original implementation...${NC}"

    if [ ! -f "services/xsoar.py.backup" ]; then
        echo -e "${RED}Error: Backup file not found!${NC}"
        echo "Cannot rollback without backup: services/xsoar.py.backup"
        exit 1
    fi

    echo "1. Restoring original xsoar.py from backup..."
    cp services/xsoar.py services/xsoar_demisto.py.save 2>/dev/null || true
    cp services/xsoar.py.backup services/xsoar.py

    echo -e "${GREEN}✅ Rollback complete!${NC}"
    echo "Original implementation restored."
    echo "demisto-py version saved as: services/xsoar_demisto.py.save"
    exit 0
fi

# Normal migration flow
echo "This script will:"
echo "  1. Verify backup exists"
echo "  2. Run tests to ensure new implementation works"
echo "  3. Replace services/xsoar.py with demisto-py version"
echo ""
echo -e "${YELLOW}⚠️  This will modify your codebase!${NC}"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Migration cancelled."
    exit 0
fi

# Step 1: Verify backup
echo ""
echo "Step 1: Verifying backup..."
if [ ! -f "services/xsoar.py.backup" ]; then
    echo -e "${RED}Error: Backup not found!${NC}"
    echo "Please create backup first: cp services/xsoar.py services/xsoar.py.backup"
    exit 1
fi
echo -e "${GREEN}✅ Backup verified${NC}"

# Step 2: Run tests
echo ""
echo "Step 2: Running migration tests..."
if ! .venv/bin/python test_xsoar_migration.py > /tmp/migration_test.log 2>&1; then
    echo -e "${RED}❌ Tests failed!${NC}"
    echo "Check logs: /tmp/migration_test.log"
    echo "Migration aborted."
    exit 1
fi

# Check if all tests passed
if grep -q "Total: 4/4 tests passed" /tmp/migration_test.log; then
    echo -e "${GREEN}✅ All tests passed (4/4)${NC}"
else
    echo -e "${RED}❌ Not all tests passed!${NC}"
    echo "Check logs: /tmp/migration_test.log"
    echo "Migration aborted."
    exit 1
fi

# Step 3: Switch implementation
echo ""
echo "Step 3: Switching to demisto-py implementation..."

# Keep another backup
cp services/xsoar.py services/xsoar_old_$(date +%Y%m%d_%H%M%S).py

# Replace with new implementation
cp services/xsoar_new.py services/xsoar.py

echo -e "${GREEN}✅ Migration complete!${NC}"
echo ""
echo "=========================================="
echo "Next Steps:"
echo "1. Restart your services"
echo "2. Monitor logs for any errors"
echo "3. Test critical workflows"
echo ""
echo "Rollback if needed:"
echo "  ./switch_to_demisto_py.sh --rollback"
echo ""
echo "Files:"
echo "  - Active:  services/xsoar.py (demisto-py version)"
echo "  - Backup:  services/xsoar.py.backup (original)"
echo "  - Old:     services/xsoar_old_*.py (timestamped)"
echo "=========================================="
