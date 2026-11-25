
from pathlib import Path
from datetime import datetime


def generate_report(analysis, alerts, output_path):
    """Generate a readable text report of log analysis."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "=" * 55,
        "        PYTHON LOG ANALYZER - SECURITY REPORT",
        "=" * 55,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "GENERAL STATISTICS",
        "-" * 55,
        f"Total log entries: {analysis['total_entries']}",
        f"Unique IP addresses: {analysis['unique_ip_count']}",
        f"Failed logins: {analysis['failed_logins']}",
        f"Successful logins: {analysis['successful_logins']}",
        "",
        "TOP IP ADDRESSES",
        "-" * 55,
    ]

    for ip, count in analysis["top_ip_addresses"]:
        lines.append(f"{ip}: {count} events")

    lines.extend([
        "",
        "TARGETED USERNAMES",
        "-" * 55,
    ])

    for username, count in analysis["targeted_usernames"]:
        lines.append(f"{username}: {count} failed attempts")

    lines.extend([
        "",
        "SECURITY ALERTS",
        "-" * 55,
    ])

    if alerts:
        for alert in alerts:
            lines.extend([
                f"Alert: {alert['alert_type']}",
                f"Severity: {alert['severity']}",
                f"Source IP: {alert['ip_address']}",
                f"Failed attempts: {alert['failed_attempts']}",
                f"Description: {alert['description']}",
                "",
            ])
    else:
        lines.append("No suspicious activity detected.")

    lines.append("=" * 55)

    output_path.write_text("\n".join(lines), encoding="utf-8")
