#!/bin/bash

# Start supporting services in background
# We explicitly set PORT for these because otherwise they inherit the global PORT (e.g. 10000) from Render
# and collide with the Gateway.
PORT=5053 python services/history/app.py &
PORT=5051 python services/scan/app.py &
PORT=5052 python services/monitor/app.py &

# Wait for them to spin up
sleep 5

# Start Gateway (Foreground)
# Render provides PORT env var, gateway uses it (e.g. 10000) to expose to the world.
python services/gateway/app.py
