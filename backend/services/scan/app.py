import os
import sys
import requests
import hashlib
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from pdf_gen import generate_pdf_report

# Add shared directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
shared_dir = os.path.abspath(os.path.join(current_dir, '../../shared'))
sys.path.append(shared_dir)

from analyzer import analyze_local

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join(current_dir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
HISTORY_SERVICE_URL = "http://localhost:5053/api/history"
MONITOR_SERVICE_URL = "http://localhost:5052/api/monitor/logs"

# Load API Key
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    # Try reading from parent dir or ../../apikey.txt if possible, or just default
    # For simplicity, we use the hardcoded default or env var
    VIRUSTOTAL_API_KEY = "f5f439718c900ca3b5e9efad27196385a31a4243900d348cde425da4d23905aa"

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Scan Service Running"})

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    file = request.files.get('file')
    url_input = request.form.get('url')

    if file and file.filename:
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        try:
            file.save(file_path)
            
            # Local Analysis
            local_report = analyze_local(file_path, file.filename)
            md5 = get_md5(file_path)
            
            # Check VT
            check_response = requests.get(f"https://www.virustotal.com/api/v3/files/{md5}", headers=headers)
            if check_response.status_code == 200:
                os.remove(file_path)

                
                # Notify Monitor (Cached result)
                try:
                    stats = check_response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get('malicious', 0)
                    risk = "Safe"
                    if malicious > 0: risk = "Critical"
                    
                    requests.post(MONITOR_SERVICE_URL, json={
                        "filename": file.filename,
                        "score": malicious, # Using malicious count as score for cached
                        "risk": risk
                    }, timeout=1)
                except:
                    pass
                
                return jsonify({
                    "success": True, 
                    "type": "file", 
                    "id": md5, 
                    "cached": True,
                    "local_analysis": local_report 
                })

            # Upload to VT
            with open(file_path, 'rb') as f:
                files = {"file": (file.filename, f)}
                upload_response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
            
            os.remove(file_path)

            if upload_response.status_code != 200:
                return jsonify({
                    "success": True,
                    "type": "local_only",
                    "local_analysis": local_report,
                    "message": "Cloud scan failed, showing local analysis."
                })
            
            analysis_id = upload_response.json().get("data", {}).get("id")
            
            # --- Integration: Notify Monitor Service ---
            try:
                # We don't have the final score from VT yet (async), so we log the local analysis result
                # or indicate it's a cloud scan in progress.
                # Ideally, we log the local result now.
                requests.post(MONITOR_SERVICE_URL, json={
                    "filename": file.filename,
                    "score": local_report.get('score', 0),
                    "risk": local_report.get('risk', 'Unknown')
                }, timeout=1)
            except:
                pass
            
            return jsonify({
                "success": True, 
                "type": "file_analysis",
                "id": analysis_id,
                "md5": md5,
                "local_analysis": local_report
            })

        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({"success": False, "error": str(e)}), 500

    elif url_input:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={'url': url_input})
        if response.status_code != 200:
            return jsonify({"success": False, "error": f"URL Scan failed: {response.text}"}), 400
        
        analysis_id = response.json().get("data", {}).get("id")
        return jsonify({
            "success": True,
            "type": "url_analysis",
            "id": analysis_id,
            "url": url_input
        })

    return jsonify({"success": False, "error": "No file or URL provided"}), 400

@app.route('/api/report/<resource_id>/pdf', methods=['GET'])
def get_report_pdf(resource_id):
    # Reuse cached report logic, simplified: call internal get_report logic or just fetch again
    # For now, we fetch the report data internally
    
    # Mocking request args for internal call or just reusing logic (simplest to just reuse logic or call route)
    # We'll just call the VT API again or DB to get data. Ideally we refactor 'get_report' logic to a function.
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    if len(resource_id) == 32 and "-" not in resource_id: 
        url = f"https://www.virustotal.com/api/v3/files/{resource_id}"
    else:
        url = f"https://www.virustotal.com/api/v3/analyses/{resource_id}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
             return jsonify({"error": "Could not fetch report data"}), 404
             
        data = response.json()
        pdf_buffer = generate_pdf_report(data, filename=f"Report_{resource_id}.pdf")
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"Report_{resource_id}.pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/<resource_id>', methods=['GET'])
def get_report(resource_id):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    resource_type = request.args.get('type', 'unknown')
    filename = request.args.get('filename', 'unknown')

    if len(resource_id) == 32 and "-" not in resource_id: 
        url = f"https://www.virustotal.com/api/v3/files/{resource_id}"
    else:
        url = f"https://www.virustotal.com/api/v3/analyses/{resource_id}"

    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        return jsonify({"success": False, "status": "error", "error": response.text}), response.status_code

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    status = attributes.get("status")

    if status in ["queued", "in_progress"]:
         return jsonify({"success": True, "status": "pending"})
    
    # Check stats for saving history
    if "last_analysis_results" in attributes:
        stats = attributes.get("last_analysis_stats")
        results = attributes.get("last_analysis_results")
    else:
        stats = attributes.get("stats")
        results = attributes.get("results")

    if stats:
        # Save to History Service asynchronously (fire and forget or wait)
        try:
            requests.post(HISTORY_SERVICE_URL, json={
                "filename": filename,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "score_malicious": stats.get('malicious', 0),
                "score_total": sum(stats.values()),
                "status": "completed"
            }, timeout=2) # Short timeout
        except:
            pass 

    return jsonify({
        "success": True,
        "status": "completed",
        "data": {
            "stats": stats,
            "results": results,
            "meta": data.get("meta")
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5051))
    app.run(host='0.0.0.0', port=port)
