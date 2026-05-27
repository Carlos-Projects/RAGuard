# Architecture

RAGuard follows a modular architecture with four layers:

```mermaid
graph TD
    CLI[CLI / Typer] --> Scanner[RAGuardScanner]
    Scanner --> Detectors[Detector Registry]
    Detectors --> D1[Data Poisoning]
    Detectors --> D2[Membership Inference]
    Detectors --> D3[Prompt Leakage]
    Detectors --> D4[Context Overflow]
    Detectors --> D5[Retrieval Hijack]
    Detectors --> D6[Vector Injection]
    Detectors --> D7[Policy Bypass]
    Scanner --> Targets[Target Layer]
    Targets --> T1[ChromaDB]
    Targets --> T2[Milvus]
    Targets --> T3[Qdrant]
    Targets --> T4[Generic RAG]
    Scanner --> Reporters[Reporter Layer]
    Reporters --> R1[Console]
    Reporters --> R2[JSON]
    Reporters --> R3[HTML]
    Reporters --> R4[SARIF]
    Scanner --> Taxonomy[mcp-taxonomy]
```

## Detector System

Detectors are registered via a decorator pattern:

```python
from raguard.detectors import register_detector
from raguard.detectors.base import BaseDetector

@register_detector
class MyDetector(BaseDetector):
    name = "my_detector"
    description = "Detects my specific attack"
```

## Target System

Targets abstract vector database interactions behind a common interface. Each target implements `scan()` which performs the actual security checks against the specific database.

## Reporter System

Reporters format findings into different output formats. Each reporter implements `render()` and optionally `render_to_file()`.
