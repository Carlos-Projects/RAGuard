"""Example: Generate MCPGuard-compatible policies from a scan."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from raguard import RAGuardScanner, RAGTargetConfig, TargetType
from raguard.policies import PolicyGenerator


async def policy_example() -> None:
    """Example: scan a Qdrant instance and generate MCPGuard policies."""
    config = RAGTargetConfig(
        url="http://localhost:6333",
        type=TargetType.QDRANT,
        collection_name="my_collection",
    )

    scanner = RAGuardScanner()
    report = await scanner.scan(config)

    gen = PolicyGenerator()
    yaml_content = gen.to_mcpguard_yaml(report)

    output_path = Path("raguard-policies.yaml")
    output_path.write_text(yaml_content)
    print(f"Policies saved to {output_path.resolve()}")
    print(f"Rules generated: {len(report.findings)}")


if __name__ == "__main__":
    asyncio.run(policy_example())
