# Python Log Analyzer & Security Monitor

A Python-based command-line security monitoring tool that analyzes Apache access logs and Linux SSH authentication logs to identify suspicious activity and potential brute-force attacks.

## Features

- Apache access log parsing
- Linux SSH authentication log parsing
- IP address validation
- HTTP status code analysis
- Failed and successful login tracking
- Potential brute-force attack detection
- Configurable detection thresholds
- MEDIUM and HIGH severity alerts
- CSV and JSON report exports
- Automated testing with pytest
- Malformed log entry handling

## Technologies Used

- Python 3.11
- Regular Expressions
- JSON and CSV
- pytest
- Git and GitHub

## Project Structure

```text
python-log-analyzer/
├── data/
│   ├── sample_logs/
│   └── test_logs/
├── reports/
├── src/
│   └── log_analyzer/
│       ├── parser.py
│       ├── analyzer.py
│       ├── detector.py
│       ├── exporter.py
│       ├── reporter.py
│       ├── config.py
│       └── main.py
├── tests/
├── docs/
├── requirements.txt
├── run.py
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/1234Tz-Kam/python-log-analyzer.git
cd python-log-analyzer
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Analyze SSH authentication logs:

```bash
python run.py --file data/sample_logs/auth.log --type auth
```

Analyze Apache access logs:

```bash
python run.py --file data/sample_logs/access.log --type apache
```

Analyze suspicious activity:

```bash
python run.py --file data/sample_logs/suspicious_activity.log --type auth
```

## Brute-Force Detection

The detector identifies potential brute-force activity when an individual IP address generates at least 5 failed login attempts within a 5-minute window.

| Severity | Condition |
|---|---|
| MEDIUM | 5–9 failed attempts |
| HIGH | 10 or more failed attempts |

These thresholds are configurable in `src/log_analyzer/config.py`.

## Generated Reports

The application generates:

- `analysis.json`
- `analysis.csv`
- `alerts.json`
- `security_report.txt`

Reports are saved in the `reports/` directory by default.

## Testing

Run the automated test suite:

```bash
python -m pytest -v
```

**Current test result: 19 tests passing.**

## Disclaimer

This project uses synthetic sample log data for educational and testing purposes. Detection results are indicators for investigation, not definitive confirmation of malicious activity.

## Author

**Mohammed Kamran Khan**

Diploma in Computer Science & Engineering | Cybersecurity Enthusiast

GitHub: [1234Tz-Kam](https://github.com/1234Tz-Kam)