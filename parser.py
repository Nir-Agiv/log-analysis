import re

# A list of regex patterns to identify different log events.
LOG_PATTERNS = [
    # SSH Log Patterns
    (
        "ssh", "Failed Login",
        re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password for(?: invalid user)? ([\w.-]+) from ([\d\.]+) port \d+ ssh2")
    ),
    (
        "ssh", "Successful Login",
        re.compile(r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for ([\w.-]+) from ([\d\.]+) port \d+ ssh2")
    ),
    # Nginx Access Log Pattern
    (
        "nginx", "Web Request",
        re.compile(r'([\d\.]+) - - \[([^\]]+)\] "(\w+) ([^"]+) HTTP/[\d\.]+" (\d{3})')
    )
]

def parse_log_line(line):
    for log_type, event_type, pattern in LOG_PATTERNS:
        match = pattern.search(line)
        if match:
            if log_type == "ssh":
                return {
                    "log_type": log_type,
                    "timestamp": match.group(1),
                    "event_type": event_type,
                    "user": match.group(2),
                    "ip_address": match.group(3),
                    "raw_log": line.strip()
                }
            elif log_type == "nginx":
                return {
                    "log_type": log_type,
                    "ip_address": match.group(1),
                    "timestamp": match.group(2),
                    "event_type": event_type,
                    "method": match.group(3),
                    "path": match.group(4),
                    "status_code": int(match.group(5)),
                    "raw_log": line.strip()
                }
    return None