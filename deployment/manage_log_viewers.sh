#!/bin/bash
# Simple log viewer service management script
#
# Setup: ln -sf /home/vinay/security-ops-platform/deployment/manage_log_viewers.sh ~/bin/start_log_service
# Usage: start_log_service [start|stop|restart|status]
#        start_log_service (no args) - stops all existing services and starts them

cd /home/vinay/security-ops-platform || exit 1

ACTION="${1:-restart}"

start_viewers() {
    echo "Starting log viewer services..."

    # Port 8031: All IR Services (journalctl)
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8031 --title "All IR Services" --journalctl "ir-*" >> logs/log_viewer_all.log 2>&1 &

    # Port 8032: the notification service
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8032 --title "the notification service Bot" --file /home/vinay/security-ops-platform/logs/toodles.log >> logs/log_viewer_toodles.log 2>&1 &

    # Port 8033: the case orchestrator
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8033 --title "the case orchestrator Bot" --file /home/vinay/security-ops-platform/logs/msoar.log >> logs/log_viewer_msoar.log 2>&1 &

    # Port 8034: MoneyBall
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8034 --title "MoneyBall Bot" --file /home/vinay/security-ops-platform/logs/money_ball.log >> logs/log_viewer_moneyball.log 2>&1 &

    # Port 8035: the orchestration service
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8035 --title "the orchestration service Bot" --file /home/vinay/security-ops-platform/logs/jarvis.log >> logs/log_viewer_jarvis.log 2>&1 &

    # Port 8036: the alert triage service
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8036 --title "the alert triage service Bot" --file /home/vinay/security-ops-platform/logs/barnacles.log >> logs/log_viewer_barnacles.log 2>&1 &

    # Port 8038: the threat-intel service
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8038 --title "the threat-intel service Bot" --file /home/vinay/security-ops-platform/logs/tars.log >> logs/log_viewer_tars.log 2>&1 &

    # Port 8037: Scheduler
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8037 --title "Scheduler" --file /home/vinay/security-ops-platform/logs/scheduler.log >> logs/log_viewer_jobs.log 2>&1 &

    # Port 8039: Web App
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8039 --title "Web App" --file /home/vinay/security-ops-platform/logs/web_server.log >> logs/log_viewer_web_server.log 2>&1 &

    # Port 8041: CASE
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8041 --title "CASE Bot" --file /home/vinay/security-ops-platform/logs/case.log >> logs/log_viewer_case.log 2>&1 &

    # Port 8042: the security assistant bot
    nohup /home/vinay/security-ops-platform/.venv/bin/python deployment/log_viewer.py --port 8042 --title "the security assistant bot Bot" --file /home/vinay/security-ops-platform/logs/pokedex.log >> logs/log_viewer_pokedex.log 2>&1 &

    sleep 2
    echo "All log viewers started"
}

stop_viewers() {
    echo "Stopping log viewer services..."
    pkill -f "deployment/log_viewer.py" || true
    sleep 2
    echo "All log viewers stopped"
}

case "$ACTION" in
    start)
        start_viewers
        ;;

    stop)
        stop_viewers
        ;;

    restart)
        stop_viewers
        start_viewers
        ;;

    status)
        echo "Log viewer processes:"
        # shellcheck disable=SC2009
        ps aux | grep "deployment/log_viewer.py" | grep -v grep || echo "No log viewers running"
        ;;

    *)
        echo "Usage: $0 [start|stop|restart|status]"
        exit 1
        ;;
esac
