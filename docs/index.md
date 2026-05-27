# RAGuard Documentation

RAGuard is a security scanner for Retrieval-Augmented Generation (RAG) systems.

## Contents

- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Python API](#python-api)
- [Detectors](#detectors)
- [Targets](#targets)
- [Reporters](#reporters)
- [Policy Generation](#policy-generation)

## Installation

```bash
pip install raguard-scanner
```

Or with vector database support:

```bash
pip install "raguard-scanner[chroma]"
pip install "raguard-scanner[milvus]"
pip install "raguard-scanner[qdrant]"
```

## CLI Usage

```bash
# Basic scan
raguard scan http://localhost:8000

# Scan with HTML report
raguard scan http://localhost:8000 -f html -o report.html

# CI mode (exit code 1 on findings)
raguard scan http://localhost:8000 --ci

# Generate MCPGuard-compatible policy
raguard policy http://localhost:8000 -o policy.yaml

# Generate report from previous scan
raguard report results.json -f html -o report.html
```

## Python API

```python
from raguard import RAGuardScanner

scanner = RAGuardScanner(url="http://localhost:8000")
report = scanner.scan()

print(f"Risk score: {report.risk_score}")
print(f"Findings: {len(report.findings)}")
```

## Detectors

RAGuard includes 7 built-in detectors:

| Detector | Description |
|----------|-------------|
| Data Poisoning | Detects potential data poisoning vectors |
| Membership Inference | Tests for membership inference vulnerabilities |
| Prompt Leakage | Detects prompt leakage and extraction risks |
| Context Overflow | Detects context window overflow attempts |
| Retrieval Hijack | Tests for retrieval manipulation attacks |
| Vector Injection | Detects vector database injection vectors |
| Policy Bypass | Tests for policy bypass and role escalation |

## Targets

- ChromaDB
- Milvus
- Qdrant
- Generic RAG (HTTP API)

## Reporters

- Console (Rich)
- JSON
- HTML
- SARIF v2.1.0
