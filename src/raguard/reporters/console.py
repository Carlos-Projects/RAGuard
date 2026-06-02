"""Console reporter using Rich for terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from raguard.models import RAGScanReport, Severity


class ConsoleReporter:
    """Rich console reporter for RAGuard scan results."""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet

    def render(self, report: RAGScanReport) -> str:
        """Render scan report to Rich console output.

        Args:
            report: The scan report to render.

        Returns:
            String representation (also prints to console).
        """
        console = Console()
        output_parts = []

        if self.quiet:
            if report.findings:
                console.print(self._findings_table(report))
                output_parts.append(f"{len(report.findings)} findings")
            return "\n".join(output_parts)

        color_map = {
            "none": "green",
            "low": "yellow",
            "medium": "orange1",
            "high": "red",
            "critical": "bold red",
        }
        color = color_map.get(report.risk_category, "white")

        header = Panel(
            f"[bold]Risk Score:[/] [{color}]{report.risk_score}/100 ({report.risk_category})[/]\n"
            f"[bold]Target:[/] {report.target_url} ({report.target_type.value})\n"
            f"[bold]Findings:[/] {report.total_findings} | "
            f"[bold]Duration:[/] {report.scan_duration_ms:.0f}ms",
            title="RAGuard Scan Results",
        )
        console.print(header)
        output_parts.append("RAGuard Scan Results")

        if report.summary:
            summary_panel = Panel(report.summary, title="Summary")
            console.print(summary_panel)
            output_parts.append(report.summary)

        if report.findings:
            console.print(self._findings_table(report))
            output_parts.append(f"{len(report.findings)} findings")

        return "\n".join(output_parts)

    def _findings_table(self, report: RAGScanReport) -> Table:
        table = Table(title=f"Findings ({len(report.findings)})")
        table.add_column("Severity", style="bold")
        table.add_column("Attack Type", style="cyan")
        table.add_column("Title")
        table.add_column("Detector")
        table.add_column("Risk")

        for finding in report.findings:
            sev_style = "red" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            table.add_row(
                f"[{sev_style}]{finding.severity.value.upper()}[/{sev_style}]",
                finding.attack_type.value,
                finding.title[:50],
                finding.detector,
                str(finding.risk_score),
            )

        return table
