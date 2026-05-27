# CLI Usage

## Scan

```bash
# Basic scan
raguard scan http://localhost:8000 --type generic

# Specify output format
raguard scan http://localhost:8000 --type chroma --format json --output results.json

# CI mode (exit code 1 on high+ risk)
raguard scan http://localhost:8000 --ci --threshold high

# Select specific detectors
raguard scan http://localhost:8000 --detectors "data_poisoning,prompt_leakage"
```

## Report

```bash
# Convert scan results to HTML report
raguard report scan_results.json --format html --output report.html

# SARIF for GitHub Code Scanning
raguard report scan_results.json --format sarif --output results.sarif
```

## Policy

```bash
# Generate MCPGuard-compatible policy
raguard policy http://localhost:8000 --type qdrant -o policies.yaml
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--type` | Target type: chroma, milvus, qdrant, generic | generic |
| `--format` | Output format: console, json, html, sarif | console |
| `--output` | Output file path (for json/html/sarif) | stdout |
| `--threshold` | Minimum severity: low, medium, high, critical | medium |
| `--ci` | Exit with code 1 if findings >= threshold | false |
| `--detectors` | Comma-separated detector names | all |
| `--api-key` | API key for the target | env or none |
| `--collection` | Collection name for vector DBs | default |
| `--timeout` | Request timeout in seconds | 30 |
