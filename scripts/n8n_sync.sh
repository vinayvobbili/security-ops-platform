#!/bin/bash
#
# n8n Workflow Sync Script
# Syncs workflows between n8n instance and Git repository
#
# Usage:
#   ./n8n_sync.sh export    - Export all workflows from n8n to Git
#   ./n8n_sync.sh import    - Import all workflows from Git to n8n
#   ./n8n_sync.sh status    - Show sync status (what differs)
#   ./n8n_sync.sh backup    - Create timestamped backup of n8n workflows
#

set -e

# Configuration
N8N_URL="${N8N_URL:-http://localhost:8080}"
N8N_API_KEY="${N8N_API_KEY:-}"
WORKFLOW_DIR="${WORKFLOW_DIR:-/home/vinay/IR/n8n_workflows}"
BACKUP_DIR="${BACKUP_DIR:-/home/vinay/IR/n8n_workflows/.backups}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_api_key() {
    if [ -z "$N8N_API_KEY" ]; then
        log_error "N8N_API_KEY environment variable is not set"
        echo ""
        echo "To enable the n8n API:"
        echo "  1. Run: sudo systemctl stop n8n"
        echo "  2. Edit /etc/systemd/system/n8n.service"
        echo "  3. Add: Environment=\"N8N_PUBLIC_API_ENABLED=true\""
        echo "  4. Run: sudo systemctl daemon-reload && sudo systemctl start n8n"
        echo "  5. Open n8n UI -> Settings -> API -> Create API Key"
        echo "  6. Export: export N8N_API_KEY='your-key'"
        echo ""
        exit 1
    fi
}

check_n8n_health() {
    if ! curl -s --connect-timeout 5 "${N8N_URL}/healthz" > /dev/null 2>&1; then
        # Try alternate health endpoint
        if ! curl -s --connect-timeout 5 "${N8N_URL}/" > /dev/null 2>&1; then
            log_error "Cannot connect to n8n at ${N8N_URL}"
            exit 1
        fi
    fi
    log_success "Connected to n8n at ${N8N_URL}"
}

api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    local curl_args=(
        -s
        -X "$method"
        -H "X-N8N-API-KEY: ${N8N_API_KEY}"
        -H "Content-Type: application/json"
    )

    if [ -n "$data" ]; then
        curl_args+=(-d "$data")
    fi

    curl "${curl_args[@]}" "${N8N_URL}/api/v1${endpoint}"
}

# Export workflows from n8n to Git
export_workflows() {
    log_info "Exporting workflows from n8n to ${WORKFLOW_DIR}..."

    check_api_key
    check_n8n_health

    # Get all workflows
    local response
    response=$(api_call GET "/workflows")

    if echo "$response" | jq -e '.data' > /dev/null 2>&1; then
        local count
        count=$(echo "$response" | jq '.data | length')
        log_info "Found ${count} workflows in n8n"

        # Export each workflow
        echo "$response" | jq -c '.data[]' | while read -r workflow; do
            local id name filename
            id=$(echo "$workflow" | jq -r '.id')
            name=$(echo "$workflow" | jq -r '.name')

            # Get full workflow with nodes
            local full_workflow
            full_workflow=$(api_call GET "/workflows/${id}")

            # Create filename from workflow name (sanitize)
            filename=$(echo "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g' | sed 's/__*/_/g' | sed 's/^_//;s/_$//')
            filename="${filename}.json"

            # Save workflow
            echo "$full_workflow" | jq '.' > "${WORKFLOW_DIR}/${filename}"
            log_success "Exported: ${name} -> ${filename}"
        done

        log_success "Export complete!"
    else
        log_error "Failed to get workflows from n8n"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
        exit 1
    fi
}

# Import workflows from Git to n8n
import_workflows() {
    log_info "Importing workflows from ${WORKFLOW_DIR} to n8n..."

    check_api_key
    check_n8n_health

    # Get existing workflows to check for duplicates
    local existing
    existing=$(api_call GET "/workflows" | jq -r '.data[].name' 2>/dev/null || echo "")

    local imported=0
    local updated=0
    local failed=0

    for file in "${WORKFLOW_DIR}"/*.json; do
        [ -f "$file" ] || continue

        # Skip backup directory
        [[ "$file" == *".backups"* ]] && continue

        local workflow_name
        workflow_name=$(jq -r '.name' "$file" 2>/dev/null)

        if [ -z "$workflow_name" ] || [ "$workflow_name" == "null" ]; then
            log_warn "Skipping ${file} - invalid workflow JSON"
            ((failed++))
            continue
        fi

        # Check if workflow exists
        local existing_id
        existing_id=$(api_call GET "/workflows" | jq -r --arg name "$workflow_name" '.data[] | select(.name == $name) | .id' 2>/dev/null)

        if [ -n "$existing_id" ] && [ "$existing_id" != "null" ]; then
            # Update existing workflow - only keep allowed fields
            local workflow_data
            workflow_data=$(jq '{name, nodes, connections, settings, staticData}' "$file")

            local result
            result=$(api_call PUT "/workflows/${existing_id}" "$workflow_data")

            if echo "$result" | jq -e '.id' > /dev/null 2>&1; then
                log_success "Updated: ${workflow_name}"
                ((updated++))
            else
                log_error "Failed to update: ${workflow_name}"
                ((failed++))
            fi
        else
            # Create new workflow - only keep allowed fields
            local workflow_data
            workflow_data=$(jq '{name, nodes, connections, settings, staticData}' "$file")

            local result
            result=$(api_call POST "/workflows" "$workflow_data")

            if echo "$result" | jq -e '.id' > /dev/null 2>&1; then
                log_success "Imported: ${workflow_name}"
                ((imported++))
            else
                log_error "Failed to import: ${workflow_name}"
                echo "$result" | jq '.' 2>/dev/null || echo "$result"
                ((failed++))
            fi
        fi
    done

    echo ""
    log_info "Import Summary:"
    echo "  New imports: ${imported}"
    echo "  Updated:     ${updated}"
    echo "  Failed:      ${failed}"
}

# Show sync status
show_status() {
    log_info "Checking sync status..."

    check_api_key
    check_n8n_health

    # Get workflows from n8n
    local n8n_workflows
    n8n_workflows=$(api_call GET "/workflows" | jq -r '.data[].name' 2>/dev/null | sort)

    # Get workflows from Git
    local git_workflows
    git_workflows=$(for f in "${WORKFLOW_DIR}"/*.json; do
        [ -f "$f" ] && [[ "$f" != *".backups"* ]] && jq -r '.name' "$f" 2>/dev/null
    done | sort)

    echo ""
    echo "=== Workflows in n8n only (not in Git) ==="
    comm -23 <(echo "$n8n_workflows") <(echo "$git_workflows") | while read -r name; do
        [ -n "$name" ] && echo "  - $name"
    done

    echo ""
    echo "=== Workflows in Git only (not in n8n) ==="
    comm -13 <(echo "$n8n_workflows") <(echo "$git_workflows") | while read -r name; do
        [ -n "$name" ] && echo "  + $name"
    done

    echo ""
    echo "=== Workflows in both ==="
    comm -12 <(echo "$n8n_workflows") <(echo "$git_workflows") | wc -l | xargs -I {} echo "  {} workflows synced"
}

# Create backup
create_backup() {
    log_info "Creating backup..."

    check_api_key
    check_n8n_health

    mkdir -p "${BACKUP_DIR}"

    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="${BACKUP_DIR}/n8n_backup_${timestamp}.json"

    # Export all workflows to single backup file
    local response
    response=$(api_call GET "/workflows")

    if echo "$response" | jq -e '.data' > /dev/null 2>&1; then
        echo "$response" | jq '.' > "$backup_file"
        local count
        count=$(echo "$response" | jq '.data | length')
        log_success "Backed up ${count} workflows to ${backup_file}"

        # Keep only last 10 backups
        ls -t "${BACKUP_DIR}"/n8n_backup_*.json 2>/dev/null | tail -n +11 | xargs -r rm
        log_info "Cleaned old backups (keeping last 10)"
    else
        log_error "Failed to create backup"
        exit 1
    fi
}

# Main
case "${1:-}" in
    export)
        export_workflows
        ;;
    import)
        import_workflows
        ;;
    status)
        show_status
        ;;
    backup)
        create_backup
        ;;
    *)
        echo "n8n Workflow Sync Script"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  export    Export all workflows from n8n to Git directory"
        echo "  import    Import all workflows from Git to n8n"
        echo "  status    Show what differs between n8n and Git"
        echo "  backup    Create timestamped backup of all n8n workflows"
        echo ""
        echo "Environment variables:"
        echo "  N8N_URL        n8n instance URL (default: http://localhost:8080)"
        echo "  N8N_API_KEY    n8n API key (required)"
        echo "  WORKFLOW_DIR   Workflow directory (default: /home/vinay/IR/n8n_workflows)"
        echo ""
        echo "Example:"
        echo "  export N8N_API_KEY='your-api-key'"
        echo "  $0 export"
        echo ""
        exit 1
        ;;
esac
