
import argparse
from pathlib import Path

from .parser import parse_log_file
from .analyzer import analyze_logs
from .detector import detect_brute_force
from .exporter import export_json, export_csv
from .reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="Python Log Analyzer & Security Monitor"
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Path to the log file"
    )

    parser.add_argument(
        "--type",
        required=True,
        choices=["apache", "auth"],
        help="Log format: apache or auth"
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports"
    )

    args = parser.parse_args()

    log_file = Path(args.file)
    output_dir = Path(args.output)

    if not log_file.is_file():
        parser.error(f"Log file not found: {log_file}")

    entries, malformed = parse_log_file(log_file, args.type)

    analysis = analyze_logs(entries)

    alerts = detect_brute_force(entries)

    output_dir.mkdir(parents=True, exist_ok=True)

    export_json(analysis, output_dir / "analysis.json")
    export_csv(analysis, output_dir / "analysis.csv")

    export_json(alerts, output_dir / "alerts.json")

    generate_report(
        analysis,
        alerts,
        output_dir / "security_report.txt"
    )

    print("\n=== LOG ANALYSIS COMPLETE ===")
    print(f"Parsed entries: {len(entries)}")
    print(f"Malformed entries: {malformed}")
    print(f"Unique IP addresses: {analysis['unique_ip_count']}")
    print(f"Failed logins: {analysis['failed_logins']}")
    print(f"Security alerts: {len(alerts)}")
    print(f"\nReports saved in: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
