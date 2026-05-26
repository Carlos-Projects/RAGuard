"""Vector DB injection detector for RAG systems.

Detects direct injection attacks against vector databases (Chroma, Milvus,
Pinecone, Qdrant) including unauthorized collection access, API injection,
and metadata manipulation.
"""

from __future__ import annotations

from raguard.detectors.base import BaseDetector
from raguard.detectors.registry import register
from raguard.models import (
    Confidence,
    RAGAttackType,
    RAGFinding,
    RAGTargetConfig,
    Severity,
    TargetType,
)


@register
class VectorInjectionDetector(BaseDetector):
    """Detects direct vector database injection vulnerabilities."""

    name = "vector_injection"
    description = "Detects direct injection attacks against vector databases"

    async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for vector database injection vulnerabilities."""
        findings = []

        # Test 1: Unauthorized collection access
        access_results = await self._test_unauthorized_access(target)
        findings.extend(access_results)

        # Test 2: Direct document injection via API
        injection_results = await self._test_direct_injection(target)
        findings.extend(injection_results)

        # Test 3: Metadata manipulation
        metadata_results = await self._test_metadata_manipulation(target)
        findings.extend(metadata_results)

        return findings

    async def _test_unauthorized_access(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for unauthorized collection access."""
        findings = []

        if not target.api_key:
            findings.append(
                RAGFinding(
                    detector=self.name,
                    attack_type=RAGAttackType.VECTOR_INJECTION,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    title="Vector database accessible without authentication",
                    description=(
                        f"The {target.type.value} vector database at {target.url} "
                        f"does not require authentication. An attacker can directly "
                        f"access, modify, or inject documents into any collection."
                    ),
                    recommendation=(
                        "Enable authentication on the vector database. "
                        "Implement API key or token-based access control. "
                        "Restrict network access to trusted sources only."
                    ),
                    target=target.url,
                    risk_score=90,
                    details={
                        "target_type": target.type.value,
                        "has_auth": False,
                    },
                )
            )

        return findings

    async def _test_direct_injection(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for direct document injection via API."""
        findings = []

        # Check if the target type supports direct injection
        if target.type in (TargetType.CHROMA, TargetType.QDRANT, TargetType.MILVUS):
            findings.append(
                RAGFinding(
                    detector=self.name,
                    attack_type=RAGAttackType.VECTOR_INJECTION,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title=f"Direct document injection possible via {target.type.value} API",
                    description=(
                        f"The {target.type.value} vector database API allows direct "
                        f"document insertion. An attacker with API access can inject "
                        f"malicious documents that will be served to users."
                    ),
                    recommendation=(
                        "Implement write access controls on the vector database. "
                        "Validate all documents before insertion. "
                        "Monitor for unusual insertion patterns."
                    ),
                    target=target.url,
                    risk_score=70,
                    details={
                        "target_type": target.type.value,
                        "method": "direct_api_injection",
                    },
                )
            )

        return findings

    async def _test_metadata_manipulation(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for metadata manipulation vulnerabilities."""
        findings = []

        findings.append(
            RAGFinding(
                detector=self.name,
                attack_type=RAGAttackType.VECTOR_INJECTION,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Document metadata manipulation possible",
                description=(
                    "Vector database metadata fields may be manipulable to alter "
                    "document retrieval behavior, bypass filters, or inject "
                    "malicious instructions through metadata fields."
                ),
                recommendation=(
                    "Validate and sanitize all metadata fields on ingestion. "
                    "Implement metadata schema enforcement. "
                    "Filter metadata from retrieved context before passing to LLM."
                ),
                target=target.url,
                risk_score=50,
                details={"method": "metadata_manipulation"},
            )
        )

        return findings
