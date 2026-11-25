
import re
import ipaddress
from datetime import datetime


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)$'
)

AUTH_PATTERN = re.compile(
    r'^(?P<month>\w{3}) '
    r'(?P<day>\d{1,2}) '
    r'(?P<time>\d{2}:\d{2}:\d{2}) '
    r'(?P<hostname>\S+) '
    r'sshd\[(?P<pid>\d+)\]: '
    r'(?P<message>.*)$'
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def parse_apache_log(line):
    match = APACHE_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    if not validate_ip(data["ip"]):
        return None

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError:
        return None

    return {
        "log_type": "apache",
        "timestamp": timestamp.isoformat(),
        "ip_address": data["ip"],
        "method": data["method"],
        "path": data["path"],
        "status_code": int(data["status"]),
        "response_size": (
            int(data["size"]) if data["size"] != "-" else None
        ),
        "message": None
    }


def parse_auth_log(line):
    match = AUTH_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    ip_match = IP_PATTERN.search(message)

    if not ip_match:
        return None

    ip = ip_match.group()

    if not validate_ip(ip):
        return None

    username_match = re.search(
        r'(?:for|user)\s+(?:invalid user\s+)?(\S+)\s+from',
        message
    )

    username = (
        username_match.group(1)
        if username_match
        else None
    )

    if "Failed password" in message:
        event_type = "login_failed"
    elif "Accepted password" in message or "Accepted publickey" in message:
        event_type = "login_success"
    else:
        event_type = "other"

    return {
        "log_type": "authentication",
        "timestamp": f"{data['month']} {data['day']} {data['time']}",
        "ip_address": ip,
        "username": username,
        "event_type": event_type,
        "pid": int(data["pid"]),
        "message": message
    }


def parse_log_line(line, log_type):
    if log_type == "apache":
        return parse_apache_log(line)

    elif log_type == "auth":
        return parse_auth_log(line)

    raise ValueError(f"Unsupported log type: {log_type}")


def parse_log_file(file_path, log_type):
    parsed_entries = []
    malformed_entries = 0

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:

        for line in file:
            if not line.strip():
                continue

            result = parse_log_line(line, log_type)

            if result is None:
                malformed_entries += 1
            else:
                parsed_entries.append(result)

    return parsed_entries, malformed_entries
