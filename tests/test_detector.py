
from datetime import datetime, timedelta

from src.log_analyzer.detector import detect_brute_force
from src.log_analyzer.config import (
    FAILED_LOGIN_THRESHOLD
)


def create_failed_entry(ip, timestamp):
    return {
        "ip_address": ip,
        "event_type": "login_failed",
        "timestamp": timestamp.isoformat()
    }


def test_detect_brute_force():
    start = datetime(2026, 11, 25, 10, 0, 0)

    entries = [
        create_failed_entry(
            "203.0.113.99",
            start + timedelta(seconds=i * 20)
        )
        for i in range(FAILED_LOGIN_THRESHOLD)
    ]

    alerts = detect_brute_force(entries)

    assert len(alerts) == 1
    assert alerts[0]["ip_address"] == "203.0.113.99"
    assert alerts[0]["severity"] == "MEDIUM"


def test_no_alert_below_threshold():
    start = datetime(2026, 11, 25, 10, 0, 0)

    entries = [
        create_failed_entry(
            "203.0.113.99",
            start + timedelta(seconds=i * 20)
        )
        for i in range(FAILED_LOGIN_THRESHOLD - 1)
    ]

    alerts = detect_brute_force(entries)

    assert len(alerts) == 0


def test_no_alert_outside_time_window():
    start = datetime(2026, 11, 25, 10, 0, 0)

    entries = [
        create_failed_entry(
            "203.0.113.99",
            start + timedelta(minutes=i * 2)
        )
        for i in range(FAILED_LOGIN_THRESHOLD)
    ]

    alerts = detect_brute_force(entries)

    assert len(alerts) == 0


def test_high_severity_detection():
    start = datetime(2026, 11, 25, 10, 0, 0)

    entries = [
        create_failed_entry(
            "203.0.113.99",
            start + timedelta(seconds=i * 10)
        )
        for i in range(10)
    ]

    alerts = detect_brute_force(entries)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"


def test_ignore_successful_logins():
    entries = [
        {
            "ip_address": "203.0.113.99",
            "event_type": "login_success",
            "timestamp": "2026-11-25T10:00:00"
        }
    ]

    alerts = detect_brute_force(entries)

    assert len(alerts) == 0
