#!/bin/bash
# Weekly backup of non-git runtime data to lab-vm2
# Prevents data loss from accidental rm -rf or disk failures
#
# Usage: bash scripts/backup_to_lab_vm2.sh
# Cron:  0 2 * * 0 /home/vinay/security-ops-platform/scripts/backup_to_lab_vm2.sh >> /home/vinay/security-ops-platform/data/transient/logs/backup.log 2>&1

set -euo pipefail

REMOTE="lab-vm2"
REMOTE_DIR="/home/vinay/security-ops-platform-backup"
PROJECT="/home/vinay/security-ops-platform"
TIMESTAMP=$(date +%Y-%m-%d_%H%M)

echo "=== IR Backup to $REMOTE — $TIMESTAMP ==="

# Ensure remote directory structure exists
ssh "$REMOTE" "mkdir -p $REMOTE_DIR/data/{threat_intel,xsoar_timeline,epp_tagging,rules_cache,transient/{chroma_tipper_index,chroma_rules_catalog}} $REMOTE_DIR/{chroma_documents,systemd_services}"

# Backup critical config & credentials
rsync -az --info=progress2 \
    "$PROJECT/.env" \
    "$REMOTE:$REMOTE_DIR/"

# Backup databases (SQLite files — small, critical)
rsync -az --info=progress2 \
    "$PROJECT/data/threat_intel/" \
    "$REMOTE:$REMOTE_DIR/data/threat_intel/"

rsync -az --info=progress2 \
    "$PROJECT/data/xsoar_timeline/" \
    "$REMOTE:$REMOTE_DIR/data/xsoar_timeline/"

rsync -az --info=progress2 \
    "$PROJECT/data/epp_tagging/" \
    "$REMOTE:$REMOTE_DIR/data/epp_tagging/" 2>/dev/null || true

# Backup rules cache (JSON files)
rsync -az --info=progress2 \
    "$PROJECT/data/rules_cache/" \
    "$REMOTE:$REMOTE_DIR/data/rules_cache/"

# Backup vector stores / Chroma indexes
rsync -az --info=progress2 \
    "$PROJECT/data/transient/chroma_tipper_index/" \
    "$REMOTE:$REMOTE_DIR/data/transient/chroma_tipper_index/" 2>/dev/null || true

rsync -az --info=progress2 \
    "$PROJECT/data/transient/chroma_rules_catalog/" \
    "$REMOTE:$REMOTE_DIR/data/transient/chroma_rules_catalog/" 2>/dev/null || true

# Backup transient data (SecOps tickets, sessions, tokens)
rsync -az --info=progress2 --delete \
    --exclude='logs/' \
    --exclude='__pycache__/' \
    "$PROJECT/data/transient/" \
    "$REMOTE:$REMOTE_DIR/data/transient/"

# Backup Chroma documents DB
rsync -az --info=progress2 \
    "$PROJECT/chroma_documents/" \
    "$REMOTE:$REMOTE_DIR/chroma_documents/" 2>/dev/null || true

# Backup crontab
crontab -l > /tmp/ir_crontab_backup.txt 2>/dev/null
rsync -az /tmp/ir_crontab_backup.txt "$REMOTE:$REMOTE_DIR/crontab_backup.txt"
rm -f /tmp/ir_crontab_backup.txt

# Backup systemd service files
rsync -az --info=progress2 \
    "$HOME/.config/systemd/user/" \
    "$REMOTE:$REMOTE_DIR/systemd_services/"

echo "=== Backup complete: $(date) ==="
