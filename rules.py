import time
from collections import defaultdict, deque

# --- Rule Configuration ---
# Brute-force rule: N attempts from the same IP within T seconds.
BRUTE_FORCE_ATTEMPTS = 5
BRUTE_FORCE_TIME_WINDOW = 60  # in seconds

# --- State Management ---
# Stores recent failed login attempts: {ip: deque([timestamp1, timestamp2, ...])}
failed_logins = defaultdict(deque)

# Stores IPs that have already triggered a brute-force alert to avoid spam.
# {ip: timestamp_of_last_alert}
alerted_ips = {}
ALERT_COOLDOWN = 300 # 5 minutes

def apply_rules(parsed_log):
    """
    Applies a set of security rules to a parsed log entry.
    
    Args:
        parsed_log (dict): A dictionary representing a single structured log event.
        
    Returns:
        list: A list of alert dictionaries. An empty list if no rules are triggered.
    """
    alerts = []
    if not parsed_log:
        return alerts

    # Rule 1: Detect Brute-Force Attacks
    if parsed_log["event_type"] == "Failed Login":
        ip = parsed_log["ip_address"]
        current_time = time.time()
        
        # Add current failed attempt timestamp to the deque for this IP
        failed_logins[ip].append(current_time)
        
        # Remove old timestamps that are outside the time window
        while failed_logins[ip] and failed_logins[ip][0] < current_time - BRUTE_FORCE_TIME_WINDOW:
            failed_logins[ip].popleft()
            
        # Check if the threshold has been met
        if len(failed_logins[ip]) >= BRUTE_FORCE_ATTEMPTS:
            # Check if we are in a cooldown period for this IP
            last_alert_time = alerted_ips.get(ip)
            if not last_alert_time or current_time - last_alert_time > ALERT_COOLDOWN:
                alerts.append({
                    "alert_type": "Brute-Force Detected",
                    "description": f"{len(failed_logins[ip])} failed logins from IP {ip} within {BRUTE_FORCE_TIME_WINDOW} seconds.",
                    "ip_address": ip,
                    "timestamp": parsed_log["timestamp"]
                })
                # Update the last alert time for this IP to start the cooldown
                alerted_ips[ip] = current_time
    
    # Add more rules here in the future
    # Example: Alert on successful login after many failures, etc.

    return alerts

def clear_rules_state():
    """Helper function for testing to reset the state of the rules engine."""
    failed_logins.clear()
    alerted_ips.clear()