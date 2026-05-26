# Changelog

## 0.1.0 (2026-05-26)

Initial release of RAGuard — Security scanner for Retrieval-Augmented Generation (RAG) systems.

### Features

- **7 RAG Security Detectors:**
  - Data Poisoning — Detect malicious document injection (arXiv:2605.24294)
  - Membership Inference — Entailment-based membership detection (USENIX Security 2026)
  - Prompt Leakage — Extract system prompts via retrieval queries (OWASP LLM06:2025)
  - Context Overflow — Detect context window saturation attacks
  - Retrieval Hijack — Manipulate retriever to serve adversarial content (MITRE ATLAS)
  - Vector Injection — Direct attacks against Chroma/Milvus/Qdrant
  - Policy Bypass — Guardrail evasion through trusted retrieved context (OWASP LLM01:2025)

- **4 Vector Database Targets:** Chroma, Milvus, Qdrant, Generic RAG API
- **4 Report Formats:** Console (Rich), JSON, HTML (Jinja2), SARIF (GitHub Code Scanning)
- **MCPGuard Policy Generation:** Auto-generate YAML policies from scan findings
- **mcp-taxonomy Integration:** RAG-specific AttackCategory and DetectionMethod values
- **CI/CD:** GitHub Actions (pytest + ruff) with automated PyPI publishing

### Installation

```bash
pip install raguard-scanner
```
