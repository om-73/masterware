import os
import sys
from flask import Flask, jsonify, request
from flask_cors import CORS

from monitor import monitor_service
from quarantine import quarantine_file, restore_file, get_quarantine_list, delete_quarantine

app = Flask(__name__)
CORS(app)

# Start Monitor
monitor_service.start()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Monitor Service Running"})

@app.route('/api/monitor/logs', methods=['GET', 'POST'])
def handle_monitor_logs():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(base_dir, "monitor_log.txt")

    if request.method == 'POST':
        data = request.json
        filename = data.get('filename', 'unknown')
        score = data.get('score', 0)
        risk = data.get('risk', 'Unknown')
        
        import time
        log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {filename} | Score: {score} | Risk: {risk} (Manual Scan)\n"
        
        with open(log_file, "a") as f:
            f.write(log_entry)
        return jsonify({"success": True})

    logs = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            # Read last 20 lines
            lines = f.readlines()[-20:]
            for line in lines:
                parts = line.strip().split(" | ")
                if len(parts) >= 3:
                     logs.append({
                         "time": parts[0],
                         "file": parts[1],
                         "info": " | ".join(parts[2:])
                     })
    return jsonify(logs)

@app.route('/api/quarantine', methods=['GET'])
def list_quarantine():
    return jsonify(get_quarantine_list())

@app.route('/api/quarantine/restore', methods=['POST'])
def restore_item():
    data = request.json
    qid = data.get('id')
    success, msg = restore_file(qid)
    return jsonify({"success": success, "message": msg})

@app.route('/api/quarantine/delete', methods=['POST'])
def delete_item():
    data = request.json
    qid = data.get('id')
    if delete_quarantine(qid):
        return jsonify({"success": True, "message": "Deleted"})
    return jsonify({"success": False, "message": "Failed"})

import atexit
atexit.register(monitor_service.stop)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5052))
    app.run(host='0.0.0.0', port=port)
