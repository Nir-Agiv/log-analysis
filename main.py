import os
import threading
import time
import sqlite3
from flask import Flask, render_template, jsonify, request

import config
import parser
import rules

# Use paths from the config module
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "alerts.db")
LOG_FILES = [os.path.join(BASE_DIR, f) for f in config.LOG_FILES]

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_alert_to_db(alert):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, alert_type, description, ip_address) VALUES (?, ?, ?, ?)",
            (alert['timestamp'], alert['alert_type'], alert['description'], alert.get('ip_address'))
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

class LogMonitor(threading.Thread):
    def __init__(self, log_file):
        super().__init__()
        self.log_file = log_file
        self.daemon = True
        self.stop_event = threading.Event()

    def run(self):
        print(f"Starting to monitor log file: {self.log_file}")
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                while not self.stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    
                    parsed_line = parser.parse_log_line(line)
                    if parsed_line:
                        print(f"Parsed: {parsed_line}")
                        triggered_alerts = rules.apply_rules(parsed_line)
                        for alert in triggered_alerts:
                            print(f"ALERT! {alert}")
                            add_alert_to_db(alert)
        except Exception as e:
            print(f"Error monitoring {os.path.basename(self.log_file)}: {e}")

    def stop(self):
        self.stop_event.set()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    # Get filter parameters from the request URL
    ip_filter = request.args.get('ip')
    type_filter = request.args.get('type')

    query = "SELECT * FROM alerts"
    params = []
    conditions = []

    if ip_filter:
        conditions.append("ip_address LIKE ?")
        params.append(f"%{ip_filter}%")
    if type_filter:
        conditions.append("alert_type LIKE ?")
        params.append(f"%{type_filter}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY id DESC LIMIT 100"

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)

if __name__ == '__main__':
    # Ensure log files exist
    for lf in LOG_FILES:
        if not os.path.exists(lf):
            print(f"Log file not found at {lf}. Creating an empty file.")
            open(lf, 'a').close()
            
    init_db()
    
    # Start one monitor thread for each log file
    monitors = [LogMonitor(f) for f in LOG_FILES]
    for m in monitors:
        m.start()

    print("Flask server starting. Open http://127.0.0.1:5000 in your browser.")
    app.run(debug=True, use_reloader=False)