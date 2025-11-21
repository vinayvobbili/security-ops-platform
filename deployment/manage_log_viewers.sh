#!/bin/bash
# Simple log viewer service management script
#
# Setup: ln -sf /home/vinay/pub/IR/deployment/manage_log_viewers.sh ~/bin/start_log_service
# Usage: start_log_service [start|stop|restart|status]
#        start_log_service (no args) - stops all existing services and starts them

cd /home/vinay/pub/IR || exit 1

ACTION="${1:-restart}"

start_viewers() {
    echo "Starting log viewer services..."

    # Port 8031: All IR Services (journalctl)
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8031 --title "All IR Services" --journalctl "ir-*" >> logs/log_viewer_all.log 2>&1 &

    # Port 8032: Toodles
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8032 --title "Toodles Bot" --file /home/vinay/pub/IR/logs/toodles.log >> logs/log_viewer_toodles.log 2>&1 &

    # Port 8033: MSOAR
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8033 --title "MSOAR Bot" --file /home/vinay/pub/IR/logs/msoar.log >> logs/log_viewer_msoar.log 2>&1 &

    # Port 8034: MoneyBall
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8034 --title "MoneyBall Bot" --file /home/vinay/pub/IR/logs/money_ball.log >> logs/log_viewer_moneyball.log 2>&1 &

    # Port 8035: Jarvis
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8035 --title "Jarvis Bot" --file /home/vinay/pub/IR/logs/jarvis.log >> logs/log_viewer_jarvis.log 2>&1 &

    # Port 8036: Barnacles
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8036 --title "Barnacles Bot" --file /home/vinay/pub/IR/logs/barnacles.log >> logs/log_viewer_barnacles.log 2>&1 &

    # Port 8038: TARS
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8038 --title "TARS Bot" --file /home/vinay/pub/IR/logs/tars.log >> logs/log_viewer_tars.log 2>&1 &

    # Port 8037: All Jobs Scheduler
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8037 --title "All Jobs Scheduler" --file /home/vinay/pub/IR/logs/all_jobs.log >> logs/log_viewer_jobs.log 2>&1 &

    # Port 8039: Web Server
    nohup /home/vinay/pub/IR/.venv/bin/python deployment/log_viewer.py --port 8039 --title "Web Server" --file /home/vinay/pub/IR/logs/web_server.log >> logs/log_viewer_web_server.log 2>&1 &

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
