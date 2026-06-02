<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo.svg">
    <img src="docs/logo.svg" alt="RAGuard" width="120">
  </picture>
</p>

# RAGuard

[![CI](https://img.shields.io/github/actions/workflow/status/Carlos-Projects/RAGuard/ci.yml?branch=main&logo=github)](https://github.com/Carlos-Projects/RAGuard/actions)
[![PyPI version](https://img.shields.io/pypi/v/raguard-scanner?logo=pypi)](https://pypi.org/project/raguard-scanner/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/github/license/Carlos-Projects/RAGuard?logo=opensourceinitiative)](LICENSE)
[![Coverage](https://img.shields.io/codecov/c/github/Carlos-Projects/RAGuard?logo=codecov)](https://codecov.io/gh/Carlos-Projects/RAGuard)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/Carlos-Projects/RAGuard/codeql.yml?branch=main&label=CodeQL&logo=github)](https://github.com/Carlos-Projects/RAGuard/actions)
[![Docs](https://img.shields.io/github/actions/workflow/status/Carlos-Projects/RAGuard/docs.yml?branch=main&label=Docs&logo=github)](https://carlos-projects.github.io/RAGuard)
[![pre-commit.ci](https://img.shields.io/badge/pre--commit.ci-enabled-brightgreen?logo=pre-commit)](https://results.pre-commit.ci/latest/github/Carlos-Projects/RAGuard/main)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-blue?logo=dependabot)](https://github.com/Carlos-Projects/RAGuard/network/updates)
[![GitHub stars](https://img.shields.io/github/stars/Carlos-Projects/RAGuard?style=social)](https://github.com/Carlos-Projects/RAGuard)

**Security scanner for Retrieval-Augmented Generation (RAG) systems.** Detect data poisoning, membership inference, prompt leakage, and 4 more attack vectors before they compromise your AI pipeline.

---

**RAGuard** is the first open-source security scanner purpose-built for RAG systems. While traditional LLM security tools focus on prompt injection at the API layer, RAGuard goes deeper — testing the retrieval pipeline, vector database, and context assembly for vulnerabilities that let attackers poison knowledge bases, infer training data membership, and bypass safety guardrails through trusted retrieved context.

Built on cutting-edge research from USENIX Security 2026 and aligned with OWASP Top 10 for LLMs 2025 and MITRE ATLAS.

---

## What it does

RAGuard scans RAG systems for **7 categories of attacks**:

| Detector | Attack | Severity | Research Basis |
|---|---|---|---|
| **Data Poisoning** | Inject malicious documents to manipulate retrieval | HIGH | arXiv:2605.24294 (Shmatikov et al.) |
| **Membership Inference** | Determine if specific docs were used in training | HIGH | arXiv:2605.24312 (USENIX Security 2026) |
| **Prompt Leakage** | Extract system prompts via retrieval queries | CRITICAL | OWASP LLM06:2025 |
| **Context Overflow** | Evade guardrails via context window saturation | MEDIUM | Context truncation attacks |
| **Retrieval Hijack** | Manipulate retriever to serve adversarial content | HIGH | MITRE ATLAS |
| **Vector Injection** | Direct attacks against Chroma/Milvus/Qdrant | CRITICAL | Vector DB security |
| **Policy Bypass** | Evade guardrails through trusted retrieved context | HIGH | OWASP LLM01:2025 |

## What makes it unique

| Capability | RAGuard | Generic LLM Scanners | Vector DB Tools |
|---|---|---|---|
| RAG-specific attack detection | ✅ 7 detectors | ❌ Prompt-only | ❌ Storage-only |
| Vector DB integration | ✅ Chroma, Milvus, Qdrant | ❌ | ✅ |
| Membership inference testing | ✅ Entailment-based | ❌ | ❌ |
| MCPGuard policy generation | ✅ Auto-generated | ❌ | ❌ |
| MCPscop integration | ✅ Taxonomy-compatible | ❌ | ❌ |
| SARIF output | ✅ GitHub Code Scanning | Partial | ❌ |

## Quick Start

```bash
# Installation
pip install raguard-scanner

# Or from source
git clone https://github.com/Carlos-Projects/RAGuard
cd RAGuard
pip install -e ".[all]"
```

### CLI

```bash
# Scan a RAG system
raguard scan http://localhost:8000 --type generic

# Scan with specific output format
raguard scan http://localhost:8000 --type chroma --format json --output results.json

# CI mode (fails on high+ risk)
raguard scan http://localhost:8000 --ci --threshold high

# Quiet mode (only findings/errors)
raguard scan http://localhost:8000 --quiet

# Generate MCPGuard policies
raguard policy http://localhost:8000 --type qdrant -o policies.yaml

# Generate HTML report from previous scan
raguard report scan_results.json --format html --output report.html
```

### Python API

```python
import asyncio
from raguard import RAGuardScanner, RAGTargetConfig, TargetType

async def scan_rag():
    config = RAGTargetConfig(
        url="http://localhost:8000",
        type=TargetType.CHROMA,
        collection_name="my_docs",
    )

    scanner = RAGuardScanner()
    report = await scanner.scan(config)

    print(f"Risk: {report.risk_score}/100 ({report.risk_category})")
    for finding in report.findings:
        print(f"  [{finding.severity.value}] {finding.title}")

asyncio.run(scan_rag())
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      RAGuard CLI                         │
│              (Typer + Rich interface)                    │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                   RAGuardScanner                         │
│              (Orchestration engine)                      │
└────┬──────┬──────┬──────┬──────┬──────┬──────┬──────────┘
     │      │      │      │      │      │      │
┌────▼──┐┌─▼────┐┌▼─────┐┌▼────┐┌▼────┐┌▼────┐┌▼───────┐
│Data   ││Member││Prompt││Conte││Retri││Vecto││Policy  │
│Poison ││ship  ││Leak  ││xtOv ││eval ││rInj ││Bypass  │
│       ││Inf   ││      ││erfl ││Hijack││     ││        │
└────┬──┘└──┬───┘└──┬───┘└──┬──┘└──┬──┘└──┬──┘└───┬────┘
     │      │      │      │      │      │      │
┌────▼──────▼──────▼──────▼──────▼──────▼──────▼────────┐
│                    Target Layer                         │
│         Chroma │ Milvus │ Qdrant │ Generic RAG          │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                   Reporters                             │
│         Console │ JSON │ HTML │ SARIF                   │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│              mcp-taxonomy + MCPGuard                    │
│         (Classification + Policy Generation)            │
└─────────────────────────────────────────────────────────┘
```

## Integration with Ecosystem

RAGuard is part of the MCP Security ecosystem:

- **mcp-taxonomy**: Classifies findings using canonical AttackCategory, Severity, Confidence enums
- **MCPGuard**: Generated policies can be directly consumed by MCPGuard runtime proxy
- **MCPscop**: Reports are consumable via `/api/taxonomy` for unified dashboard display
- **palisade-scanner**: Follows the same detector/registry/reporter architecture patterns

## Testing

```bash
python -m pytest tests/ -v
```

## Related

- [MCPGuard](https://github.com/Carlos-Projects/mcpguard) — Runtime security proxy for MCP/A2A
- [MCPscop](https://github.com/Carlos-Projects/mcpscope) — Unified security dashboard
- [mcpwn](https://github.com/Carlos-Projects/mcpwn) — Offensive testing framework for MCP
- [palisade-scanner](https://github.com/Carlos-Projects/palisade-scanner) — Prompt injection scanner
- [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) — Canonical classification system
- [agentgate](https://github.com/Carlos-Projects/agentgate) — Firewall for AI agents

## License

MIT — see [LICENSE](LICENSE)
