#!/bin/bash
# Simple log viewer service management script
#
# Setup: ln -sf /home/vinay/pub/IR/deployment/manage_log_viewers.sh ~/bin/start_log_service
# Usage: start_log_service [start|stop|restart|status]
#        start_log_service (no args) - stops all existing services and starts them

set -e

# List of log viewer services (excluding jarvais - not used on VM)
SERVICES="all toodles msoar money-ball barnacles jobs"

ACTION="${1:-restart}"

case "$ACTION" in
    start)
        echo "Starting log viewer services..."
        for service in $SERVICES; do
            sudo systemctl start ir-log-viewer-${service}.service
        done
        echo "All log viewers started"
        ;;

    stop)
        echo "Stopping log viewer services..."
        for service in $SERVICES; do
            sudo systemctl stop ir-log-viewer-${service}.service
        done
        echo "All log viewers stopped"
        ;;

    restart)
        echo "Restarting log viewer services..."
        for service in $SERVICES; do
            sudo systemctl restart ir-log-viewer-${service}.service
        done
        echo "All log viewers restarted"
        ;;

    status)
        sudo systemctl status ir-log-viewer-*.service
        ;;

    *)
        echo "Usage: $0 [start|stop|restart|status]"
        exit 1
        ;;
esac
