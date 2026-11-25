
import csv
import json

from src.log_analyzer.exporter import export_json, export_csv


def test_export_json(tmp_path):
    data = {
        "total_entries": 10,
        "failed_logins": 5
    }

    output_file = tmp_path / "analysis.json"

    export_json(data, output_file)

    assert output_file.exists()

    with output_file.open("r", encoding="utf-8") as file:
        result = json.load(file)

    assert result["total_entries"] == 10
    assert result["failed_logins"] == 5


def test_export_csv(tmp_path):
    data = {
        "total_entries": 10,
        "failed_logins": 5
    }

    output_file = tmp_path / "analysis.csv"

    export_csv(data, output_file)

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:
        rows = list(csv.reader(file))

    assert rows[0] == ["Metric", "Value"]
    assert rows[1][0] == "total_entries"
    assert rows[2][0] == "failed_logins"


def test_export_creates_missing_directory(tmp_path):
    data = {"total_entries": 5}

    output_file = tmp_path / "new_folder" / "analysis.json"

    export_json(data, output_file)

    assert output_file.exists()
