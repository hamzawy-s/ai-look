"""JSON report exporter. HTML/PDF/CSV renderers can be added behind this interface."""
import csv
import json
from pathlib import Path
from core_engine import Finding

class Reporter:
    def export_json(self, findings: list[Finding], path: str) -> None:
        Path(path).write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")

    def export_csv(self, findings: list[Finding], path: str) -> None:
        fields = ["id", "type", "target", "parameter", "method", "severity", "confidence", "risk_score", "status"]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for f in findings:
                row = f.model_dump()
                row["severity"] = f.severity.value
                row["status"] = f.status.value
                writer.writerow({key: row.get(key) for key in fields})
