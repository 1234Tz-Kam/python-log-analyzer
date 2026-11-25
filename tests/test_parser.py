
from pathlib import Path

from src.log_analyzer.parser import (
    validate_ip,
    parse_apache_log,
    parse_auth_log,
    parse_log_file
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOGS = PROJECT_ROOT / "data" / "sample_logs"
TEST_LOGS = PROJECT_ROOT / "data" / "test_logs"


def test_validate_ip():
    assert validate_ip("192.168.1.10") is True
    assert validate_ip("203.0.113.45") is True
    assert validate_ip("999.999.999.999") is False
    assert validate_ip("not-an-ip") is False


def test_parse_apache_log():
    line = (
        '203.0.113.45 - - '
        '[25/Nov/2026:09:02:33 +0530] '
        '"POST /login HTTP/1.1" 401 512'
    )

    result = parse_apache_log(line)

    assert result is not None
    assert result["ip_address"] == "203.0.113.45"
    assert result["method"] == "POST"
    assert result["path"] == "/login"
    assert result["status_code"] == 401


def test_parse_auth_log():
    line = (
        "Nov 25 09:01:12 server "
        "sshd[1202]: Failed password for invalid user admin "
        "from 203.0.113.45 port 51235 ssh2"
    )

    result = parse_auth_log(line)

    assert result is not None
    assert result["ip_address"] == "203.0.113.45"
    assert result["username"] == "admin"
    assert result["event_type"] == "login_failed"


def test_parse_access_file():
    file_path = SAMPLE_LOGS / "access.log"

    entries, malformed = parse_log_file(file_path, "apache")

    assert len(entries) == 11
    assert malformed == 0


def test_parse_auth_file():
    file_path = SAMPLE_LOGS / "auth.log"

    entries, malformed = parse_log_file(file_path, "auth")

    assert len(entries) == 10
    assert malformed == 0


def test_parse_suspicious_file():
    file_path = SAMPLE_LOGS / "suspicious_activity.log"

    entries, malformed = parse_log_file(file_path, "auth")

    assert len(entries) == 9
    assert malformed == 0


def test_parse_malformed_file():
    file_path = TEST_LOGS / "malformed.log"

    entries, malformed = parse_log_file(file_path, "apache")

    assert len(entries) == 0
    assert malformed == 4
