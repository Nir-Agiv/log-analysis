import os
import threading
import time
import sqlite3
from flask import Flask, render_template, jsonify

import parser
import rules

# --- Robust Path Configuration ---
# Get the absolute path of the directory where the script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Join the base directory path with the filenames to create absolute paths
LOG_FILE = os.path.join(BASE_DIR, "auth.log")
DATABASE = os.path.join(BASE_DIR, "alerts.db")

app = Flask(__name__)

def init_db():
    """Initializes the SQLite database and creates the alerts table if it doesn't exist."""
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
    """Adds a detected alert to the database."""
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
        """Monitors the log file for new lines and processes them."""
        print(f"Starting to monitor log file: {self.log_file}")
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                while not self.stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.5) # Increased sleep time slightly
                        continue
                    
                    parsed_line = parser.parse_log_line(line)
                    if parsed_line:
                        print(f"Parsed: {parsed_line}")
                        triggered_alerts = rules.apply_rules(parsed_line)
                        for alert in triggered_alerts:
                            print(f"ALERT! {alert}")
                            add_alert_to_db(alert)

        except FileNotFoundError:
            print(f"Error: Log file not found at {self.log_file}. Please create it in the same directory as the script.")
        except Exception as e:
            print(f"An error occurred in the log monitor: {e}")

    def stop(self):
        self.stop_event.set()

@app.route('/')
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    """API endpoint to fetch all alerts from the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)


if __name__ == '__main__':
    # Ensure auth.log exists before starting
    if not os.path.exists(LOG_FILE):
        print(f"Log file not found at {LOG_FILE}. Creating an empty file.")
        open(LOG_FILE, 'a').close()
        
    init_db()
    
    monitor = LogMonitor(LOG_FILE)
    monitor.start()

    print("Flask server starting. Open http://127.0.0.1:5000 in your browser.")
    # use_reloader=False is critical to prevent the background thread from running twice.
    app.run(debug=True, use_reloader=False)