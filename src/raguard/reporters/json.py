"""JSON reporter for RAGuard scan results."""

from __future__ import annotations

import json

from raguard.models import RAGScanReport


class JSONReporter:
    """JSON reporter for RAGuard scan results."""

    def render(self, report: RAGScanReport) -> str:
        """Render scan report as JSON.

        Args:
            report: The scan report to render.

        Returns:
            JSON string.
        """
        data = {
            "scanner": "raguard",
            "version": report.scanner_version,
            "target": {
                "url": report.target_url,
                "type": report.target_type.value,
            },
            "risk": {
                "score": report.risk_score,
                "category": report.risk_category,
            },
            "findings": [
                {
                    "id": f.id,
                    "detector": f.detector,
                    "attack_type": f.attack_type.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "target": f.target,
                    "risk_score": f.risk_score,
                    "details": f.details,
                    "timestamp": f.timestamp,
                }
                for f in report.findings
            ],
            "scan_duration_ms": report.scan_duration_ms,
            "timestamp": report.timestamp,
            "config": report.config,
        }
        return json.dumps(data, indent=2)
