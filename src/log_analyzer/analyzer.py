
from collections import Counter


def analyze_logs(entries):
    """Analyze parsed log entries and generate statistics."""

    total_entries = len(entries)

    ip_addresses = [
        entry["ip_address"]
        for entry in entries
        if entry.get("ip_address")
    ]

    unique_ips = set(ip_addresses)
    ip_activity = Counter(ip_addresses)

    failed_logins = sum(
        1 for entry in entries
        if entry.get("event_type") == "login_failed"
    )

    successful_logins = sum(
        1 for entry in entries
        if entry.get("event_type") == "login_success"
    )

    status_codes = Counter(
        str(entry["status_code"])
        for entry in entries
        if entry.get("status_code") is not None
    )

    targeted_usernames = Counter(
        entry["username"]
        for entry in entries
        if entry.get("username")
        and entry.get("event_type") == "login_failed"
    )

    return {
        "total_entries": total_entries,
        "unique_ip_count": len(unique_ips),
        "unique_ips": sorted(unique_ips),
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "status_code_distribution": dict(status_codes),
        "top_ip_addresses": ip_activity.most_common(10),
        "targeted_usernames": targeted_usernames.most_common(10)
    }
