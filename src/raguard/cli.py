"""RAGuard CLI using Typer."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console

from raguard.config import RAGuardSettings
from raguard.models import RAGTargetConfig, TargetType
from raguard.policies.generator import PolicyGenerator
from raguard.reporters.console import ConsoleReporter
from raguard.reporters.html import HTMLReporter
from raguard.reporters.json import JSONReporter
from raguard.reporters.sarif import SARIFReporter
from raguard.scanner import RAGuardScanner

# Maximum output file size in bytes (100MB)
MAX_OUTPUT_SIZE = 100 * 1024 * 1024

app = typer.Typer(
    name="raguard",
    help="RAGuard — Security scanner for Retrieval-Augmented Generation (RAG) systems",
    no_args_is_help=True,
)
console = Console()


def _validate_output_path(output_path: str) -> Path:
    """Validate and return a safe output file path.

    Prevents path traversal attacks. The resolved path must not escape
    the current working directory via '..' components.
    """
    path = Path(output_path).resolve()
    # Ensure no '..' traversal escaped the intended parent
    # We don't require CWD containment (tmp dirs are valid)
    # but we block writes to sensitive system paths
    sensitive_prefixes = ["/etc/", "/dev/", "/proc/", "/sys/", "/bin/", "/sbin/", "/boot/"]
    for prefix in sensitive_prefixes:
        if str(path).startswith(prefix):
            raise ValueError(f"Output path is in a sensitive system directory: {prefix}")
    # Block paths that would traverse up with .. (already resolved above, but double-check)
    if ".." in Path(output_path).parts:
        raise ValueError(f"Output path contains '..' traversal: {output_path}")
    return path


def _safe_write_text(path: Path, content: str) -> None:
    """Write text content to a file with size limits."""
    if len(content.encode("utf-8")) > MAX_OUTPUT_SIZE:
        raise ValueError(f"Output content exceeds maximum size ({MAX_OUTPUT_SIZE} bytes)")
    path.write_text(content)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL or path to scan"),
    target_type: str = typer.Option("generic", "--type", "-t", help="Target type: chroma, milvus, qdrant, generic"),
    api_key: str = typer.Option(None, "--api-key", "-k", help="API key for the target"),
    collection: str = typer.Option("default", "--collection", "-c", help="Collection name"),
    output: str = typer.Option(None, "--output", "-o", help="Save output to file"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, html, sarif"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: exit code reflects risk"),
    threshold: str = typer.Option("high", "--threshold", help="CI failure threshold: low, medium, high, critical"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    detectors: str = typer.Option(None, "--detectors", "-d", help="Comma-separated list of detectors to run"),
) -> None:
    """Scan a RAG system for security vulnerabilities."""
    settings = RAGuardSettings(verbose=verbose, debug=verbose)

    target_type_map = {
        "chroma": TargetType.CHROMA,
        "milvus": TargetType.MILVUS,
        "qdrant": TargetType.QDRANT,
        "generic": TargetType.GENERIC,
    }

    config = RAGTargetConfig(
        url=target,
        type=target_type_map.get(target_type, TargetType.GENERIC),
        api_key=api_key,
        collection_name=collection,
    )

    scanner = RAGuardScanner(settings=settings)

    async def run_scan() -> None:
        report = await scanner.scan(config)

        # Determine output format from file extension if output specified
        fmt = format
        if output:
            ext = Path(output).suffix.lower()
            ext_map = {".json": "json", ".html": "html", ".sarif": "sarif"}
            fmt = ext_map.get(ext, fmt)

        # Render output
        if fmt == "rich":
            reporter = ConsoleReporter()
            reporter.render(report)
        elif fmt == "json":
            reporter = JSONReporter()
            text = reporter.render(report)
            if output:
                safe_path = _validate_output_path(output)
                _safe_write_text(safe_path, text)
                console.print(f"[green]Output saved to[/] {output}")
            else:
                print(text)
        elif fmt == "html":
            reporter = HTMLReporter()
            if output:
                safe_path = _validate_output_path(output)
                _safe_write_text(safe_path, reporter.render(report))
                console.print(f"[green]HTML report saved to[/] {output}")
            else:
                print(reporter.render(report))
        elif fmt == "sarif":
            reporter = SARIFReporter()
            text = reporter.render(report)
            if output:
                safe_path = _validate_output_path(output)
                _safe_write_text(safe_path, text)
                console.print(f"[green]SARIF report saved to[/] {output}")
            else:
                print(text)
        else:
            console.print(f"[red]Unknown format:[/] {fmt}")
            raise typer.Exit(1)

        # CI mode
        if ci:
            severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            threshold_val = severity_order.get(threshold, 3)
            cat_val = severity_order.get(report.risk_category, 0)
            if cat_val >= threshold_val:
                console.print(f"[red]CI FAILED:[/] Risk {report.risk_category} >= threshold {threshold}")
                raise typer.Exit(1)
            console.print(f"[green]CI PASSED:[/] Risk {report.risk_category} < threshold {threshold}")

    asyncio.run(run_scan())


@app.command()
def report(
    scan_file: str = typer.Argument(..., help="Path to a JSON scan result file"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, html, sarif"),
    output: str = typer.Option(None, "--output", "-o", help="Save output to file"),
) -> None:
    """Generate a report from a previous scan result."""
    from raguard.models import RAGScanReport

    file_path = Path(scan_file).resolve()
    file_size = file_path.stat().st_size
    if file_size > MAX_OUTPUT_SIZE:
        raise ValueError(f"Scan file exceeds maximum size ({MAX_OUTPUT_SIZE} bytes): {file_size} bytes")
    data = json.loads(file_path.read_text())
    report = RAGScanReport(**data)

    if format == "json":
        reporter = JSONReporter()
        text = reporter.render(report)
    elif format == "html":
        reporter = HTMLReporter()
        text = reporter.render(report)
    elif format == "sarif":
        reporter = SARIFReporter()
        text = reporter.render(report)
    else:
        reporter = ConsoleReporter()
        reporter.render(report)
        return

    if output:
        safe_path = _validate_output_path(output)
        _safe_write_text(safe_path, text)
        console.print(f"[green]Output saved to[/] {output}")
    else:
        print(text)


@app.command()
def policy(
    target: str = typer.Argument(..., help="Target URL to scan and generate policies for"),
    output: str = typer.Option("raguard-policies.yaml", "--output", "-o", help="Output file"),
    target_type: str = typer.Option("generic", "--type", "-t", help="Target type"),
) -> None:
    """Scan a RAG system and generate MCPGuard-compatible policies."""
    target_type_map = {
        "chroma": TargetType.CHROMA,
        "milvus": TargetType.MILVUS,
        "qdrant": TargetType.QDRANT,
        "generic": TargetType.GENERIC,
    }

    config = RAGTargetConfig(
        url=target,
        type=target_type_map.get(target_type, TargetType.GENERIC),
    )

    scanner = RAGuardScanner()
    gen = PolicyGenerator()

    async def run() -> None:
        report = await scanner.scan(config)
        yaml_content = gen.to_mcpguard_yaml(report)
        safe_path = _validate_output_path(output)
        _safe_write_text(safe_path, yaml_content)
        console.print(f"[green]Policies saved to[/] {output}")
        console.print(f"[bold]Risk score:[/] {report.risk_score}/100 ({report.risk_category})")
        console.print(f"[bold]Rules generated:[/] {len(report.findings)}")

    asyncio.run(run())


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
