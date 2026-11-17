"""JSON report exporter. HTML/PDF/CSV renderers can be added behind this interface."""
import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from core_engine import Finding

class Reporter:
    def export_scan_result(self, result, path: str) -> None:
        """Export candidates and confirmed findings as distinct report sections."""
        candidates = []
        for candidate in getattr(result, "candidates", []):
            candidates.append(asdict(candidate) if is_dataclass(candidate) else candidate)
        coverage_records = []
        for record in getattr(result, "coverage_records", []):
            if hasattr(record, "model_dump"):
                coverage_records.append(record.model_dump(mode="json"))
            elif is_dataclass(record):
                coverage_records.append(asdict(record))
            else:
                coverage_records.append(record)
        payload = {
            "findings": [finding.model_dump(mode="json") for finding in result.findings],
            "candidates": candidates,
            "coverage_records": coverage_records,
            "coverage_outcome": result.coverage_outcome.value,
            "reason": result.reason,
            "evidence_count": result.evidence_count,
        }
        Path(path).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

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
