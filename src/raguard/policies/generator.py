"""MCPGuard policy generator from RAGuard scan findings."""

from __future__ import annotations

import yaml

from raguard.models import RAGFinding, RAGScanReport, Severity


class PolicyGenerator:
    """Generates MCPGuard-compatible YAML policies from RAGuard findings."""

    def to_mcpguard_yaml(self, report: RAGScanReport) -> str:
        """Generate MCPGuard-compatible YAML policy from scan report.

        Args:
            report: The scan report to generate policies from.

        Returns:
            YAML string compatible with MCPGuard.
        """
        policies = {
            "version": "1.0",
            "source": "raguard",
            "generated_at": report.timestamp,
            "target": report.target_url,
            "risk_score": report.risk_score,
            "rules": self._generate_rules(report),
        }
        return yaml.dump(policies, default_flow_style=False, sort_keys=False)

    def _generate_rules(self, report: RAGScanReport) -> list[dict]:
        """Generate individual rules from findings."""
        rules = []

        for finding in report.findings:
            rule = self._finding_to_rule(finding)
            rules.append(rule)

        return rules

    def _finding_to_rule(self, finding: RAGFinding) -> dict:
        """Convert a single finding to an MCPGuard rule."""
        action = "deny" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "alert"

        return {
            "id": f"raguard_{finding.id}",
            "name": finding.title,
            "description": finding.description,
            "action": action,
            "severity": finding.severity.value,
            "attack_type": finding.attack_type.value,
            "detector": finding.detector,
            "conditions": {
                "match_patterns": self._extract_patterns(finding),
                "risk_threshold": finding.risk_score,
            },
            "recommendation": finding.recommendation,
            "metadata": {
                "confidence": finding.confidence.value,
                "target": finding.target,
                "details": finding.details,
            },
        }

    def _extract_patterns(self, finding: RAGFinding) -> list[str]:
        """Extract matchable patterns from a finding."""
        patterns = []
        details = finding.details

        if "pattern" in details:
            patterns.append(str(details["pattern"]))
        if "query" in details:
            patterns.append(str(details["query"]))
        if "method" in details:
            patterns.append(str(details["method"]))

        # Add attack type as pattern
        patterns.append(finding.attack_type.value)

        return patterns
