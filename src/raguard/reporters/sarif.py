"""SARIF reporter for GitHub Code Scanning integration."""

from __future__ import annotations

import json

from raguard.models import RAGScanReport, Severity


class SARIFReporter:
    """SARIF v2.1.0 reporter for GitHub Code Scanning."""

    def render(self, report: RAGScanReport) -> str:
        """Render scan report as SARIF JSON.

        Args:
            report: The scan report to render.

        Returns:
            SARIF JSON string.
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RAGuard",
                            "fullName": "RAGuard RAG Security Scanner",
                            "version": report.scanner_version,
                            "informationUri": "https://github.com/Carlos-Projects/RAGuard",
                            "rules": self._build_rules(report),
                        }
                    },
                    "results": self._build_results(report),
                    "invocations": [
                        {
                            "startTimeUtc": report.timestamp,
                            "executionSuccessful": True,
                            "toolConfigurationNotifications": [],
                        }
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _build_rules(self, report: RAGScanReport) -> list[dict]:
        """Build SARIF rules from unique findings."""
        rules = {}
        for finding in report.findings:
            rule_id = f"RAGUARD_{finding.attack_type.value.upper()}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.attack_type.value.replace("_", " ").title(),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity),
                    },
                    "helpUri": "https://github.com/Carlos-Projects/RAGuard",
                    "properties": {
                        "tags": ["rag-security", finding.attack_type.value],
                        "precision": "high",
                    },
                }
        return list(rules.values())

    def _build_results(self, report: RAGScanReport) -> list[dict]:
        """Build SARIF results from findings."""
        results = []
        for finding in report.findings:
            rule_id = f"RAGUARD_{finding.attack_type.value.upper()}"
            results.append(
                {
                    "ruleId": rule_id,
                    "level": self._severity_to_sarif_level(finding.severity),
                    "message": {
                        "text": finding.description,
                        "markdown": f"**{finding.title}**\n\n{finding.description}\n\n**Recommendation:** {finding.recommendation}",
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.target or report.target_url,
                                },
                            },
                        }
                    ],
                    "properties": {
                        "risk_score": finding.risk_score,
                        "confidence": finding.confidence.value,
                        "detector": finding.detector,
                    },
                }
            )
        return results

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Map RAGuard severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "note")
