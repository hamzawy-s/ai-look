"""JSON report exporter. HTML/PDF/CSV renderers can be added behind this interface."""
import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from core_engine import Finding
from adapters.adapter2.framework import DetectionCandidate
from adapters.adapter2.sqli_verification import candidate_fingerprint

class Reporter:
    def export_scan_result(self, result, path: str) -> None:
        """Export candidates and confirmed findings as distinct report sections."""
        candidates = []
        reports_by_candidate = {
            report.candidate_fingerprint: report
            for report in (
                list(getattr(result, "verification_reports", []))
                + list(getattr(result, "xss_verification_reports", []))
            )
            if getattr(report, "candidate_fingerprint", None)
        }
        for candidate in getattr(result, "candidates", []):
            item = asdict(candidate) if is_dataclass(candidate) else candidate
            if isinstance(candidate, DetectionCandidate):
                identity = candidate_fingerprint(candidate)
                item["candidate_fingerprint"] = identity
                report = reports_by_candidate.get(identity)
                item["verification_outcome"] = report.outcome.value if report else None
                item["verification_reason"] = report.reason if report else None
            candidates.append(item)
        coverage_records = []
        for record in getattr(result, "coverage_records", []):
            if hasattr(record, "model_dump"):
                coverage_records.append(record.model_dump(mode="json"))
            elif is_dataclass(record):
                coverage_records.append(asdict(record))
            else:
                coverage_records.append(record)
        verification_reports = []
        for report in getattr(result, "verification_reports", []):
            if hasattr(report, "model_dump"):
                verification_reports.append(report.model_dump(mode="json"))
            else:
                verification_reports.append(asdict(report) if is_dataclass(report) else report)
        xss_verification_reports = []
        for report in getattr(result, "xss_verification_reports", []):
            if hasattr(report, "model_dump"):
                xss_verification_reports.append(report.model_dump(mode="json"))
            else:
                xss_verification_reports.append(asdict(report) if is_dataclass(report) else report)
        payload = {
            "findings": [finding.model_dump(mode="json") for finding in result.findings],
            "candidates": candidates,
            "coverage_records": coverage_records,
            "verification_reports": verification_reports,
            "xss_verification_reports": xss_verification_reports,
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
