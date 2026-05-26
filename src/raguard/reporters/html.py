"""HTML reporter using Jinja2 templates."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from raguard.models import RAGScanReport, Severity

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RAGuard Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 30px; }
        h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
        h2 { color: #16213e; margin-top: 30px; }
        .risk-score { font-size: 48px; font-weight: bold; text-align: center; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .critical { background: #ffebee; color: #c62828; }
        .high { background: #fff3e0; color: #e65100; }
        .medium { background: #fff8e1; color: #f57f17; }
        .low { background: #e8f5e9; color: #2e7d32; }
        .info { background: #e3f2fd; color: #1565c0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #1a1a2e; color: white; }
        tr:hover { background: #f5f5f5; }
        .severity-critical { color: #c62828; font-weight: bold; }
        .severity-high { color: #e65100; font-weight: bold; }
        .severity-medium { color: #f57f17; }
        .severity-low { color: #2e7d32; }
        .severity-info { color: #1565c0; }
        .meta { color: #666; font-size: 14px; margin: 10px 0; }
        .recommendation { background: #e3f2fd; padding: 10px; border-radius: 4px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RAGuard Scan Report</h1>
        <p class="meta">Generated: {{ report.timestamp }} | Duration: {{ "%.0f"|format(report.scan_duration_ms) }}ms</p>
        <p class="meta">Target: {{ report.target_url }} ({{ report.target_type.value }})</p>

        <div class="risk-score {{ report.risk_category }}">
            {{ report.risk_score }}/100 — {{ report.risk_category|upper }}
        </div>

        <h2>Summary</h2>
        <p>{{ report.summary }}</p>
        <p>Total findings: {{ report.total_findings }} | Critical: {{ report.findings|selectattr("severity","equalto",severity_critical)|list|length }} | High: {{ report.findings|selectattr("severity","equalto",severity_high)|list|length }}</p>

        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Attack Type</th>
                    <th>Title</th>
                    <th>Detector</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in report.findings %}
                <tr>
                    <td class="severity-{{ finding.severity.value }}">{{ finding.severity.value|upper }}</td>
                    <td>{{ finding.attack_type.value }}</td>
                    <td>{{ finding.title }}</td>
                    <td>{{ finding.detector }}</td>
                    <td>{{ finding.risk_score }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% for finding in report.findings %}
        <h3>{{ finding.title }}</h3>
        <p><strong>Severity:</strong> <span class="severity-{{ finding.severity.value }}">{{ finding.severity.value|upper }}</span></p>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        <div class="recommendation"><strong>Recommendation:</strong> {{ finding.recommendation }}</div>
        <hr>
        {% endfor %}
    </div>
</body>
</html>
"""


class HTMLReporter:
    """HTML reporter using Jinja2 templates."""

    def render(self, report: RAGScanReport) -> str:
        """Render scan report as HTML.

        Args:
            report: The scan report to render.

        Returns:
            HTML string.
        """
        template = Template(HTML_TEMPLATE)
        return template.render(
            report=report,
            severity_critical=Severity.CRITICAL,
            severity_high=Severity.HIGH,
        )

    def render_to_file(self, report: RAGScanReport, output_path: str) -> None:
        """Render and save report to HTML file.

        Args:
            report: The scan report.
            output_path: Path to save the HTML file.
        """
        html = self.render(report)
        Path(output_path).write_text(html)
