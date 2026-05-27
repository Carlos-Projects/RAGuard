"""Example: Scan a RAG system using the RAGuard CLI."""

import asyncio
import sys
from pathlib import Path

# Add parent dir so this works when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from raguard import RAGTargetConfig, RAGuardScanner, TargetType


async def scan_example() -> None:
    """Example: scan a local ChromaDB instance."""
    config = RAGTargetConfig(
        url="http://localhost:8000",
        type=TargetType.CHROMA,
        collection_name="my_docs",
    )

    scanner = RAGuardScanner()
    report = await scanner.scan(config)

    print(f"Risk score: {report.risk_score}/100 ({report.risk_category})")
    print(f"Findings: {len(report.findings)}")
    for finding in report.findings:
        print(f"  [{finding.severity.value}] {finding.title}")
        print(f"    {finding.description[:100]}...")

    return report


if __name__ == "__main__":
    asyncio.run(scan_example())
