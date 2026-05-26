"""
RAGuard — Security scanner for Retrieval-Augmented Generation (RAG) systems.

Detects and evaluates vulnerabilities in RAG pipelines including:
- Data poisoning in vector databases
- Membership inference attacks
- Prompt leakage via retrieval
- Context window overflow attacks
- Retrieval hijacking
- Vector DB injection
- RAG policy bypass
"""

from raguard.models import RAGFinding, RAGScanReport, RAGTargetConfig
from raguard.scanner import RAGuardScanner

__version__ = "0.1.0"

__all__ = [
    "RAGuardScanner",
    "RAGFinding",
    "RAGScanReport",
    "RAGTargetConfig",
]
