import os
import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SERVICES = {
    "scan": "http://localhost:5051",
    "monitor": "http://localhost:5052",
    "history": "http://localhost:5053"
}

def proxy_request(service_url, path):
    url = f"{service_url}{path}"
    try:
        if request.method == 'GET':
            resp = requests.get(url, params=request.args, timeout=10)
        elif request.method == 'POST':
            # Handle file uploads specially
            if request.files:
                files = {k: (v.filename, v.stream, v.content_type, v.headers) for k, v in request.files.items()}
                resp = requests.post(url, files=files, data=request.form, timeout=30)
            else:
                resp = requests.post(url, json=request.json, timeout=10)
        elif request.method == 'DELETE':
            resp = requests.delete(url, timeout=10)
        else:
            return jsonify({"error": "Method not supported"}), 405

        return Response(resp.content, resp.status_code, headers=dict(resp.headers))
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Service unavailable: {str(e)}"}), 503

@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "Gateway API Running", "services": SERVICES})

@app.route('/api/scan', methods=['POST'])
def route_scan():
    return proxy_request(SERVICES['scan'], '/api/scan')

@app.route('/api/report/<resource_id>', methods=['GET'])
def route_report(resource_id):
    return proxy_request(SERVICES['scan'], f'/api/report/{resource_id}')

@app.route('/api/report/<resource_id>/pdf', methods=['GET'])
def route_report_pdf(resource_id):
    # Proxy PDF stream
    url = f"{SERVICES['scan']}/api/report/{resource_id}/pdf"
    try:
        resp = requests.get(url, stream=True)
        return Response(resp.iter_content(chunk_size=1024), content_type=resp.headers['Content-Type'])
    except:
         return jsonify({"error": "PDF Service unavailable"}), 503

@app.route('/api/history', methods=['GET', 'POST'])
def route_history():
    return proxy_request(SERVICES['history'], '/api/history')

@app.route('/api/monitor/logs', methods=['GET', 'POST'])
def route_monitor_logs():
    return proxy_request(SERVICES['monitor'], '/api/monitor/logs')

@app.route('/api/quarantine', methods=['GET'])
def route_quarantine():
    return proxy_request(SERVICES['monitor'], '/api/quarantine')

@app.route('/api/quarantine/restore', methods=['POST'])
def route_quarantine_restore():
    return proxy_request(SERVICES['monitor'], '/api/quarantine/restore')

@app.route('/api/quarantine/delete', methods=['POST'])
def route_quarantine_delete():
    return proxy_request(SERVICES['monitor'], '/api/quarantine/delete')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5050))
    app.run(host='0.0.0.0', port=port)
