# Log Analysis Tool for Security Events

This project is a simple but effective Security Information and Event Management (SIEM) tool built in Python. It monitors log files in real-time, parses them for security-relevant events, applies rules to detect threats, and presents the findings in a live-updating web interface.

## Features

-   **Real-time Log Monitoring:** Continuously watches a specified log file for new entries.
-   **Log Parsing:** Uses regex to parse structured data from unstructured log lines (e.g., SSH `auth.log`).
-   **Rule-Based Event Detection:**
    -   Identifies individual events like successful and failed logins.
    -   Detects complex patterns like **Brute-Force Attacks** (N failed logins from an IP in a time window).
-   **Web-Based UI:** A simple dashboard built with Flask that displays detected alerts in real-time.
-   **Persistent Storage:** Alerts are stored in a local SQLite database.
-   **Modular Design:** Code is separated into modules for parsing, rule logic, and web presentation.
-   **Unit Tested:** Core logic for parsing and rule detection is covered by unit tests using `pytest`.

## Project Structure
log_analysis/
├── main.py # Main application file (Flask server & log monitor)
├── parser.py # Logic for parsing log files
├── rules.py # Logic for event detection rules
├── test_project.py # Unit tests for parser and rules
├── static/
│ └── styles.css # Basic CSS for the web UI
├── templates/
│ └── index.html # HTML for the web UI
├── alerts.db # SQLite database file (created on run)
├── requirements.txt # Python dependencies
└── auth.log # Sample log file for testing

## Setup and Installation

1.  **Clone the repository or create the files as shown below.**

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## How to Run

1.  **Generate some sample log data.** The tool monitors `auth.log` in the same directory. You can add the provided sample lines to this file to see the tool in action.

2.  **Run the main application:**
    ```bash
    python main.py
    ```
    *Important: The Flask development server's reloader can cause issues with background threads. The script runs with `use_reloader=False` to prevent this.*

3.  **Open your web browser** and navigate to: `http://127.0.0.1:5000`

    You will see the dashboard. As you add new lines to `auth.log`, new alerts will appear in the table automatically.

## How to Run Tests

To ensure the core logic is working correctly, you can run the unit tests:

```bash
pytest
```