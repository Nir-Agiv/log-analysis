import pytest
from parser import parse_log_line
from rules import apply_rules, clear_state_for_testing
from config import BRUTE_FORCE_ATTEMPTS, WEB_SCAN_ATTEMPTS

@pytest.fixture(autouse=True)
def clean_state():
    clear_state_for_testing()

# --- Tests for parser.py ---

def test_parse_ssh_failed_login():
    log_line = "Jul 02 10:20:01 sshd[1235]: Failed password for invalid user root from 203.0.113.45 port 22 ssh2"
    parsed = parse_log_line(log_line)
    assert parsed is not None
    assert parsed['log_type'] == "ssh"
    assert parsed['event_type'] == "Failed Login"

def test_parse_ssh_successful_login():
    log_line = "Jul 02 10:15:01 sshd[1234]: Accepted password for jane.doe from 198.51.100.10 port 22 ssh2"
    parsed = parse_log_line(log_line)
    assert parsed is not None 
    assert parsed['log_type'] == "ssh"
    assert parsed['event_type'] == "Successful Login"

def test_parse_nginx_web_request():
    log_line = '45.9.20.69 - - [02/Jul/2025:11:10:02 +0000] "GET /admin.php HTTP/1.1" 404 153 "-" "Scanner/1.0"'
    parsed = parse_log_line(log_line)
    assert parsed is not None
    assert parsed['log_type'] == "nginx"

def test_parse_irrelevant_line():
    log_line = "Jul 02 12:00:00 systemd: System shutdown initiated."
    parsed = parse_log_line(log_line)
    assert parsed is None

# --- Tests for rules.py ---

def test_brute_force_triggers_on_correct_attempt():
    ip_to_test = "203.0.113.45"
    for _ in range(BRUTE_FORCE_ATTEMPTS - 1):
        parsed = {"log_type": "ssh", "event_type": "Failed Login", "ip_address": ip_to_test, "timestamp": "...", "raw_log": ""}
        assert len(apply_rules(parsed)) == 0
    final_parsed = {"log_type": "ssh", "event_type": "Failed Login", "ip_address": ip_to_test, "timestamp": "...", "raw_log": ""}
    alerts = apply_rules(final_parsed)
    assert len(alerts) == 1
    assert alerts[0]['alert_type'] == "Brute-Force Detected"

def test_new_ip_login_logic():
    """
    This test now correctly reflects the rule's logic:
    1. Alert on the VERY FIRST login for a user (as it's a "new IP").
    2. Do NOT alert on a second login from that same IP.
    3. DO alert on a login from a different, new IP.
    """
    user = "jane.doe"
    first_ip = "198.51.100.10"
    second_ip = "8.8.4.4"

    # 1. First login from first_ip. Should trigger an alert.
    parsed_first = {"log_type": "ssh", "event_type": "Successful Login", "user": user, "ip_address": first_ip, "timestamp": "...", "raw_log": ""}
    alerts = apply_rules(parsed_first)
    assert len(alerts) == 1
    assert alerts[0]['alert_type'] == "New IP Login"

    # 2. Second login from the SAME IP (first_ip). Should NOT trigger an alert.
    alerts = apply_rules(parsed_first)
    assert len(alerts) == 0

    # 3. First login from second_ip. Should trigger an alert.
    parsed_second = {"log_type": "ssh", "event_type": "Successful Login", "user": user, "ip_address": second_ip, "timestamp": "...", "raw_log": ""}
    alerts = apply_rules(parsed_second)
    assert len(alerts) == 1
    assert alerts[0]['alert_type'] == "New IP Login"
    
    # 4. Second login from second_ip. Should NOT trigger an alert.
    alerts = apply_rules(parsed_second)
    assert len(alerts) == 0

def test_web_scan_triggers_on_correct_attempt():
    ip_to_test = "45.9.20.69"
    for _ in range(WEB_SCAN_ATTEMPTS - 1):
        parsed = {"log_type": "nginx", "status_code": 404, "ip_address": ip_to_test, "timestamp": "...", "raw_log": ""}
        assert len(apply_rules(parsed)) == 0
    final_parsed = {"log_type": "nginx", "status_code": 404, "ip_address": ip_to_test, "timestamp": "...", "raw_log": ""}
    alerts = apply_rules(final_parsed)
    assert len(alerts) == 1
    assert alerts[0]['alert_type'] == "Web Scanning Detected"

def test_web_scan_ignores_other_status_codes():
    ip_to_test = "1.2.3.4"
    for _ in range(WEB_SCAN_ATTEMPTS + 5):
        parsed_200 = {"log_type": "nginx", "status_code": 200, "ip_address": ip_to_test, "timestamp": "...", "raw_log": ""}
        assert len(apply_rules(parsed_200)) == 0