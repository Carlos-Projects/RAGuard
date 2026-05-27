"""Adapter: raguard-scanner -> mcp-taxonomy."""

from __future__ import annotations

from mcp_taxonomy import (
    AttackCategory,
    TaxonomyEvent,
)
from mcp_taxonomy import (
    Confidence as TaxConfidence,
)
from mcp_taxonomy import (
    Severity as TaxSeverity,
)

from raguard.models import Confidence as RagConfidence
from raguard.models import RAGAttackType, RAGFinding, Severity

# Mapping from RAG-specific attack types to canonical taxonomy categories
ATTACK_TYPE_TO_CATEGORY: dict[RAGAttackType, AttackCategory] = {
    RAGAttackType.DATA_POISONING: AttackCategory.DATA_POISONING,
    RAGAttackType.MEMBERSHIP_INFERENCE: AttackCategory.MEMBERSHIP_INFERENCE,
    RAGAttackType.PROMPT_LEAKAGE: AttackCategory.EXFILTRATION,
    RAGAttackType.CONTEXT_OVERFLOW: AttackCategory.CONTEXT_OVERFLOW,
    RAGAttackType.RETRIEVAL_HIJACK: AttackCategory.RETRIEVAL_HIJACK,
    RAGAttackType.VECTOR_INJECTION: AttackCategory.VECTOR_INJECTION,
    RAGAttackType.POLICY_BYPASS: AttackCategory.POLICY_VIOLATION,
}

# Mapping from RAG severity to taxonomy severity
SEVERITY_MAP: dict[Severity, TaxSeverity] = {
    Severity.CRITICAL: TaxSeverity.CRITICAL,
    Severity.HIGH: TaxSeverity.HIGH,
    Severity.MEDIUM: TaxSeverity.MEDIUM,
    Severity.LOW: TaxSeverity.LOW,
    Severity.INFO: TaxSeverity.INFO,
}


def normalize_finding(finding: RAGFinding) -> TaxonomyEvent:
    """Convert a RAGuard RAGFinding to a normalized taxonomy TaxonomyEvent."""
    return TaxonomyEvent(
        source="raguard",
        attack_category=ATTACK_TYPE_TO_CATEGORY.get(finding.attack_type, AttackCategory.ANOMALY),
        severity=SEVERITY_MAP.get(finding.severity, TaxSeverity.INFO),
        confidence=_map_confidence(finding.confidence),
        title=finding.title,
        description=finding.description,
        recommendation=finding.recommendation,
        detection_method=finding.detector,
        target=finding.target,
        snippet=str(finding.details.get("snippet", ""))[:200],
        raw=finding.details,
        timestamp=finding.timestamp,
        risk_score=finding.risk_score,
    )


def _map_confidence(conf: RagConfidence) -> TaxConfidence:
    mapping: dict[RagConfidence, TaxConfidence] = {
        RagConfidence.CERTAIN: TaxConfidence.CERTAIN,
        RagConfidence.HIGH: TaxConfidence.HIGH,
        RagConfidence.MEDIUM: TaxConfidence.MEDIUM,
        RagConfidence.LOW: TaxConfidence.LOW,
        RagConfidence.NONE: TaxConfidence.NONE,
    }
    return mapping.get(conf, TaxConfidence.MEDIUM)
