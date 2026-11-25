
from src.log_analyzer.analyzer import analyze_logs


def test_analyze_auth_logs():
    entries = [
        {
            "ip_address": "203.0.113.45",
            "event_type": "login_failed",
            "username": "admin"
        },
        {
            "ip_address": "203.0.113.45",
            "event_type": "login_failed",
            "username": "root"
        },
        {
            "ip_address": "192.168.1.10",
            "event_type": "login_success",
            "username": "kamran"
        }
    ]

    result = analyze_logs(entries)

    assert result["total_entries"] == 3
    assert result["unique_ip_count"] == 2
    assert result["failed_logins"] == 2
    assert result["successful_logins"] == 1


def test_analyze_empty_logs():
    result = analyze_logs([])

    assert result["total_entries"] == 0
    assert result["unique_ip_count"] == 0
    assert result["failed_logins"] == 0
    assert result["successful_logins"] == 0


def test_top_ip_addresses():
    entries = [
        {"ip_address": "203.0.113.45"},
        {"ip_address": "203.0.113.45"},
        {"ip_address": "203.0.113.45"},
        {"ip_address": "192.168.1.10"}
    ]

    result = analyze_logs(entries)

    assert result["top_ip_addresses"][0] == (
        "203.0.113.45", 3
    )


def test_targeted_usernames():
    entries = [
        {
            "ip_address": "203.0.113.45",
            "event_type": "login_failed",
            "username": "admin"
        },
        {
            "ip_address": "203.0.113.45",
            "event_type": "login_failed",
            "username": "admin"
        },
        {
            "ip_address": "203.0.113.45",
            "event_type": "login_failed",
            "username": "root"
        }
    ]

    result = analyze_logs(entries)

    assert result["targeted_usernames"][0] == ("admin", 2)
