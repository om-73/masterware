FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (if any needed for reportlab or others)
# ReportLab sometimes needs libraries for fonts/images, but basic usage is usually fine.
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend Code
# We copy the entire backend directory into /app
COPY backend/ .

# Copy Shared Code? 
# The structure is web_malware_tester/backend and shared is inside backend.
# The user structure was:
# backend/
#   services/
#   shared/
# So copying backend/ . to /app puts services/ and shared/ in /app.
# Python paths in app.py use `../../shared`, so if app.py is in /app/services/scan/app.py
# then ../../shared resolves to /app/shared. This is correct.

# Make startup script executable
RUN chmod +x start_prod.sh

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV MONITOR_DIR=/app/services/monitor/monitored_folder
ENV QUARANTINE_DIR=/app/services/monitor/quarantine

# Expose the port (Render sets $PORT automatically, but good to document)
EXPOSE 5050

# Run
CMD ["./start_prod.sh"]
