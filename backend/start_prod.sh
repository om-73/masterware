#!/bin/bash

# Start supporting services in background
python services/history/app.py &
python services/scan/app.py &
python services/monitor/app.py &

# Wait for them to spin up
sleep 5

# Start Gateway (Foreground)
# Render provides PORT env var, gateway uses it.
python services/gateway/app.py
