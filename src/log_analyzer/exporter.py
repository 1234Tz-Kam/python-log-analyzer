
import csv
import json
from pathlib import Path


def export_json(data, output_path):
    """Export analysis results to a JSON file."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, default=str)


def export_csv(data, output_path):
    """Export analysis results to a CSV file."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)
        writer.writerow(["Metric", "Value"])

        for key, value in data.items():
            writer.writerow([key, json.dumps(value, default=str)])
