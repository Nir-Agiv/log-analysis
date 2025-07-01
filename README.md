# Log Analysis Tool for Security Events

This project is a flexible and extensible Security Information and Event Management (SIEM) tool built in Python. It monitors multiple log files in real-time, parses them for security-relevant events, applies a stateful rule engine to detect threats, and presents the findings in a live-updating, interactive web interface.

## Features

-   **External Configuration:** All major settings (log files, rule thresholds) are managed via a simple `config.ini` file, making the tool highly adaptable without code changes.
-   **Multi-File Monitoring:** Continuously watches multiple specified log files (e.g., `auth.log`, `access.log`) simultaneously, each in its own thread.
-   **Extensible Log Parsing:** Uses a modular regex-based system to parse structured data from different log formats, currently supporting:
    -   SSH `auth.log`
    -   Nginx `access.log`
-   **Advanced Rule-Based Event Detection:**
    -   **Brute-Force Attack:** Detects N failed SSH logins from an IP in a set time window.
    -   **New IP Login:** Flags successful SSH logins for a known user from a new, previously unseen IP address.
    -   **Web Scanning:** Identifies potential web vulnerability scanning by detecting numerous `404 Not Found` errors from a single IP.
-   **Interactive Web UI:** A dashboard built with Flask that not only displays alerts in real-time but also allows for **interactive filtering** by IP address or alert type.
-   **Persistent Storage:** All generated alerts are stored in a local SQLite database, preserving history between sessions.
-   **Modular and Tested:** The code is cleanly separated into modules for configuration, parsing, rules, and presentation. Critical logic is covered by unit tests using `pytest`.

## Project Structure
log_analysis/
├── main.py # Main application file (Flask server & log monitors)
├── config.py # Reads and provides configuration settings
├── config.ini # Configuration file for settings and rules
├── parser.py # Logic for parsing log files
├── rules.py # Logic for event detection rules
├── test_project.py # Unit tests for parser and rules
├── static/
│ └── styles.css # CSS for the web UI
├── templates/
│ └── index.html # HTML for the web UI
├── alerts.db # SQLite database file (created on run)
├── requirements.txt # Python dependencies
├── auth.log # Sample SSH log file for testing
└── access.log # Sample Nginx log file for testing

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

1.  **Configure the tool.** Open `config.ini` and verify the settings. By default, it's set to monitor `auth.log` and `access.log`. You can change file names or rule thresholds here.

2.  **Run the main application:**
    ```bash
    python main.py
    ```
    The console will confirm which log files are being monitored.
    *Important: The script runs with `use_reloader=False` to prevent issues with the background monitoring threads.*

3.  **Open your web browser** and navigate to: `http://127.0.0.1:5000`

4.  **Trigger Events and View Results:**
    -   You will see the dashboard. As you add new lines to the configured log files (`auth.log` or `access.log`), new alerts will appear in the table automatically.
    -   Use the **filter boxes** at the top of the page to search for alerts by IP address or type (e.g., "Brute-Force").

## How to Run Tests

To ensure the core logic is working correctly, you can run the unit tests:

```bash
pytest
```