import pytest
import time
from parser import parse_log_line
from rules import apply_rules, clear_rules_state, BRUTE_FORCE_ATTEMPTS

# --- Fixture to ensure a clean state for each test function ---
@pytest.fixture(autouse=True)
def clean_rules_state():
    """This fixture automatically runs before each test, ensuring a clean slate."""
    clear_rules_state()

# --- Tests for parser.py ---

def test_parse_failed_login():
    log_line = "Dec 10 08:45:01 sshd[12345]: Failed password for invalid user john from 192.168.1.10 port 22 ssh2"
    parsed = parse_log_line(log_line)
    assert parsed is not None
    assert parsed['event_type'] == "Failed Login"
    assert parsed['user'] == "john"
    assert parsed['ip_address'] == "192.168.1.10"

def test_parse_successful_login():
    log_line = "Dec 10 08:45:09 sshd[12347]: Accepted password for user ec2-user from 198.51.100.2 port 22 ssh2"
    parsed = parse_log_line(log_line)
    assert parsed is not None
    assert parsed['event_type'] == "Successful Login"
    assert parsed['user'] == "ec2-user"
    assert parsed['ip_address'] == "198.51.100.2"

def test_parse_irrelevant_line():
    log_line = "Dec 10 09:00:00 systemd: Starting daily cleanup..."
    parsed = parse_log_line(log_line)
    assert parsed is None

# --- Tests for rules.py ---

def test_no_alert_on_single_failed_login():
    parsed_log = {
        "event_type": "Failed Login",
        "ip_address": "10.0.0.1",
        "timestamp": "Dec 10 09:01:00"
    }
    alerts = apply_rules(parsed_log)
    assert len(alerts) == 0

def test_brute_force_alert_triggers_correctly():
    ip_to_test = "10.0.0.2"
    alerts = []
    
    # Simulate N-1 failed logins
    for _ in range(BRUTE_FORCE_ATTEMPTS - 1):
        parsed_log = {
            "event_type": "Failed Login",
            "ip_address": ip_to_test,
            "timestamp": "Dec 10 09:02:00"
        }
        alerts = apply_rules(parsed_log)
        assert len(alerts) == 0  # No alert should be triggered yet

    # The final attempt that should trigger the alert
    final_parsed_log = {
        "event_type": "Failed Login",
        "ip_address": ip_to_test,
        "timestamp": "Dec 10 09:02:05"
    }
    alerts = apply_rules(final_parsed_log)
    
    assert len(alerts) == 1
    assert alerts[0]['alert_type'] == "Brute-Force Detected"
    assert ip_to_test in alerts[0]['description']

def test_brute_force_cooldown():
    ip_to_test = "10.0.0.3"
    
    # Trigger the first alert
    for _ in range(BRUTE_FORCE_ATTEMPTS):
        parsed_log = {"event_type": "Failed Login", "ip_address": ip_to_test, "timestamp": "Dec 10 09:03:00"}
        alerts = apply_rules(parsed_log)

    # The last call should have triggered an alert
    assert len(alerts) == 1
    assert alerts[0]['alert_type'] == "Brute-Force Detected"

    # One more failed login immediately after should NOT trigger another alert
    another_log = {"event_type": "Failed Login", "ip_address": ip_to_test, "timestamp": "Dec 10 09:03:01"}
    alerts = apply_rules(another_log)
    assert len(alerts) == 0