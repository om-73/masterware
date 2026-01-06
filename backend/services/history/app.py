import os
import sqlite3
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

DB_FILE = 'malware.db'

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            filename TEXT,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            score_malicious INTEGER,
            score_total INTEGER,
            status TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "History Service Running"})

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM history ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return jsonify([dict(row) for row in scans])

@app.route('/api/history', methods=['POST'])
def add_history():
    data = request.json
    try:
        conn = get_db_connection()
        # Check existing
        existing = conn.execute('SELECT id FROM history WHERE resource_id = ?', (data.get('resource_id'),)).fetchone()
        if not existing:
            conn.execute('''
                INSERT INTO history (timestamp, filename, resource_type, resource_id, score_malicious, score_total, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                data.get('filename'),
                data.get('resource_type'),
                data.get('resource_id'),
                data.get('score_malicious', 0),
                data.get('score_total', 0),
                data.get('status', 'completed')
            ))
            conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5053))
    app.run(host='0.0.0.0', port=port)
