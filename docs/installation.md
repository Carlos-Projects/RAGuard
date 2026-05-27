# Installation

## PyPI

```bash
pip install raguard-scanner
```

With optional vector database support:

```bash
pip install "raguard-scanner[chroma]"
pip install "raguard-scanner[milvus]"
pip install "raguard-scanner[qdrant]"
pip install "raguard-scanner[all]"
```

## From Source

```bash
git clone https://github.com/Carlos-Projects/RAGuard.git
cd RAGuard
pip install -e ".[dev]"
```

## Docker

```bash
docker pull ghcr.io/carlos-projects/raguard:latest
docker run ghcr.io/carlos-projects/raguard:latest scan http://localhost:8000
```
