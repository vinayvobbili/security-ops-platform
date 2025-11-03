#!/bin/bash

echo "Restarting IR Web Server service..."
sudo systemctl restart ir-web-server.service

echo ""
echo "Checking status..."
sudo systemctl status ir-web-server.service --no-pager -l

echo ""
echo "Recent logs (last 20 lines):"
echo "-----------------------------------"
sudo journalctl -u ir-web-server.service -n 20 --no-pager
echo "-----------------------------------"

echo ""
echo "✅ To view live logs: sudo journalctl -u ir-web-server.service -f"
echo "✅ To check status: sudo systemctl status ir-web-server.service"
echo "✅ To stop: sudo systemctl stop ir-web-server.service"
