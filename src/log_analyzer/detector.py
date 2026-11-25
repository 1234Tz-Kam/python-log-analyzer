
from collections import defaultdict
from datetime import datetime, timedelta

from .config import (
    FAILED_LOGIN_THRESHOLD,
    TIME_WINDOW_MINUTES,
    HIGH_SEVERITY_THRESHOLD,
    DEFAULT_LOG_YEAR
)

def detect_brute_force(entries):
    """Detect repeated failed login attempts from individual IPs."""

    failed_attempts = defaultdict(list)

    for entry in entries:
        if entry.get("event_type") != "login_failed":
            continue

        ip = entry.get("ip_address")
        timestamp = entry.get("timestamp")

        if not ip or not timestamp:
            continue

        try:
            if timestamp[:3].isalpha():
                timestamp = f"{timestamp} {DEFAULT_LOG_YEAR}"
                parsed_time = datetime.strptime(
                    timestamp,
                    "%b %d %H:%M:%S %Y"
                )
            else:
                parsed_time = datetime.fromisoformat(timestamp)

        except (ValueError, TypeError):
            continue

        failed_attempts[ip].append(parsed_time)

    alerts = []

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        for index, start_time in enumerate(timestamps):
            window_end = start_time + timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            attempts = [
                timestamp
                for timestamp in timestamps[index:]
                if timestamp <= window_end
            ]

            attempt_count = len(attempts)

            if attempt_count >= FAILED_LOGIN_THRESHOLD:
                severity = (
                    "HIGH"
                    if attempt_count >= HIGH_SEVERITY_THRESHOLD
                    else "MEDIUM"
                )

                alerts.append({
                    "alert_type": "potential_brute_force",
                    "severity": severity,
                    "ip_address": ip,
                    "failed_attempts": attempt_count,
                    "time_window_minutes": TIME_WINDOW_MINUTES,
                    "start_time": start_time.isoformat(),
                    "end_time": attempts[-1].isoformat(),
                    "description": (
                        f"{attempt_count} failed login attempts "
                        f"from {ip} within "
                        f"{TIME_WINDOW_MINUTES} minutes"
                    )
                })

                break

    return alerts
