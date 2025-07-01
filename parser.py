import re

# A list of regex patterns to identify different log events.
# Each pattern is a tuple: (event_type, regex_pattern)
LOG_PATTERNS = [
    (
        "Failed Login",
        re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password for(?: invalid user)? (\w+) from ([\d\.]+) port \d+ ssh2")
    ),
    (
        "Successful Login",
        re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for (\w+) from ([\d\.]+) port \d+ ssh2")
    ),
    (
        "Connection Closed",
        re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Connection closed by authenticating user (\w+) ([\d\.]+) port \d+ \[preauth\]")
    )
]

def parse_log_line(line):
    """
    Parses a single log line against a list of known regex patterns.
    
    Args:
        line (str): The raw log line.
        
    Returns:
        dict: A dictionary containing structured data if a pattern matches.
              Returns None if no pattern matches.
    """
    for event_type, pattern in LOG_PATTERNS:
        match = pattern.search(line)
        if match:
            # Depending on the event type, the extracted groups change.
            if event_type in ["Failed Login", "Successful Login"]:
                return {
                    "timestamp": match.group(1),
                    "event_type": event_type,
                    "user": match.group(2),
                    "ip_address": match.group(3),
                    "raw_log": line.strip()
                }
            elif event_type == "Connection Closed":
                 return {
                    "timestamp": match.group(1),
                    "event_type": event_type,
                    "user": match.group(2),
                    "ip_address": match.group(3),
                    "raw_log": line.strip()
                }
    return None