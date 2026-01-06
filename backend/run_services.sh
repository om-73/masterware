#!/bin/bash
trap "kill 0" EXIT

echo "[*] Starting History Service (5053)..."
python backend/services/history/app.py &

echo "[*] Starting Scan Service (5051)..."
python backend/services/scan/app.py &

echo "[*] Starting Monitor Service (5052)..."
python backend/services/monitor/app.py &

# Wait a bit for services to start
sleep 2

echo "[*] Starting Gateway (5050)..."
python backend/services/gateway/app.py &

wait
