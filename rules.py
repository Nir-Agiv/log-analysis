import time
from collections import defaultdict, deque
from config import (BRUTE_FORCE_ATTEMPTS, BRUTE_FORCE_TIME_WINDOW,
                    WEB_SCAN_ATTEMPTS, WEB_SCAN_TIME_WINDOW)

# --- State Management for Rules ---
failed_logins = defaultdict(deque)      # For brute-force
known_user_ips = defaultdict(set)       # For new IP detection
web_404_counts = defaultdict(deque)     # For web scanning

alerted_events = {}  # { (alert_type, ip): timestamp }

def apply_rules(parsed_log):
    alerts = []
    if not parsed_log:
        return alerts

    log_type = parsed_log.get("log_type")

    if log_type == "ssh":
        alerts.extend(_check_ssh_rules(parsed_log))
    elif log_type == "nginx":
        alerts.extend(_check_nginx_rules(parsed_log))
    
    return alerts

def _check_ssh_rules(parsed_log):
    """Checks all rules related to SSH logs."""
    alerts = []
    event_type = parsed_log.get("event_type")
    ip = parsed_log.get("ip_address")
    user = parsed_log.get("user")
    current_time = time.time()
    
    # Rule 1: Brute-Force Detection
    if event_type == "Failed Login":
        failed_logins[ip].append(current_time)
        while failed_logins[ip] and failed_logins[ip][0] < current_time - BRUTE_FORCE_TIME_WINDOW:
            failed_logins[ip].popleft()
        
        if len(failed_logins[ip]) >= BRUTE_FORCE_ATTEMPTS:
            alert_key = ("Brute-Force", ip)
            if not _is_on_cooldown(alert_key, current_time):
                alerts.append({
                    "alert_type": "Brute-Force Detected",
                    "description": f"{len(failed_logins[ip])} failed logins from IP {ip} in {BRUTE_FORCE_TIME_WINDOW}s.",
                    "ip_address": ip, "timestamp": parsed_log["timestamp"],
                    "raw_log": parsed_log["raw_log"]
                })
                alerted_events[alert_key] = current_time

    # Rule 2: Successful Login from New IP
    elif event_type == "Successful Login":
        if ip not in known_user_ips[user]:
            alert_key = ("New IP Login", f"{user}@{ip}")
            if not _is_on_cooldown(alert_key, current_time, cooldown=86400): # 24h cooldown for this alert
                alerts.append({
                    "alert_type": "New IP Login",
                    "description": f"User '{user}' logged in from a new IP address: {ip}",
                    "ip_address": ip, "timestamp": parsed_log["timestamp"],
                    "raw_log": parsed_log["raw_log"]
                })
                alerted_events[alert_key] = current_time
        # "Learn" this IP for the user
        known_user_ips[user].add(ip)

    return alerts

def _check_nginx_rules(parsed_log):
    """Checks all rules related to Nginx logs."""
    alerts = []
    ip = parsed_log.get("ip_address")
    status_code = parsed_log.get("status_code")
    current_time = time.time()
    
    # Rule 3: Web Scanning Detection (many 404s)
    if status_code == 404:
        web_404_counts[ip].append(current_time)
        while web_404_counts[ip] and web_404_counts[ip][0] < current_time - WEB_SCAN_TIME_WINDOW:
            web_404_counts[ip].popleft()

        if len(web_404_counts[ip]) >= WEB_SCAN_ATTEMPTS:
            alert_key = ("Web Scan", ip)
            if not _is_on_cooldown(alert_key, current_time):
                alerts.append({
                    "alert_type": "Web Scanning Detected",
                    "description": f"{len(web_404_counts[ip])} 'Not Found' (404) errors from IP {ip} in {WEB_SCAN_TIME_WINDOW}s.",
                    "ip_address": ip, "timestamp": parsed_log["timestamp"],
                    "raw_log": parsed_log["raw_log"]
                })
                alerted_events[alert_key] = current_time

    return alerts

def _is_on_cooldown(alert_key, current_time, cooldown=300):
    """Checks if a specific alert for a specific key is on cooldown."""
    last_alert_time = alerted_events.get(alert_key)
    if last_alert_time and (current_time - last_alert_time < cooldown):
        return True
    return False

def clear_state_for_testing():
    """Resets all stateful dictionaries for clean testing."""
    failed_logins.clear()
    known_user_ips.clear()
    web_404_counts.clear()
    alerted_events.clear()