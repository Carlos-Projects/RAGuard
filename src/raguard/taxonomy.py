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

from raguard.models import RAGAttackType, RAGFinding, Severity

# Mapping from RAG-specific attack types to canonical taxonomy categories
ATTACK_TYPE_TO_CATEGORY: dict[RAGAttackType, AttackCategory] = {
    RAGAttackType.DATA_POISONING: AttackCategory.TOOL_POISONING,
    RAGAttackType.MEMBERSHIP_INFERENCE: AttackCategory.EXFILTRATION,
    RAGAttackType.PROMPT_LEAKAGE: AttackCategory.EXFILTRATION,
    RAGAttackType.CONTEXT_OVERFLOW: AttackCategory.INJECTION,
    RAGAttackType.RETRIEVAL_HIJACK: AttackCategory.INJECTION,
    RAGAttackType.VECTOR_INJECTION: AttackCategory.INJECTION,
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

# Detection method names for RAGuard detectors
RAG_DETECTION_METHODS: dict[RAGAttackType, str] = {
    RAGAttackType.DATA_POISONING: "data_poisoning_detector",
    RAGAttackType.MEMBERSHIP_INFERENCE: "membership_inference_detector",
    RAGAttackType.PROMPT_LEAKAGE: "prompt_leakage_detector",
    RAGAttackType.CONTEXT_OVERFLOW: "context_overflow_detector",
    RAGAttackType.RETRIEVAL_HIJACK: "retrieval_hijack_detector",
    RAGAttackType.VECTOR_INJECTION: "vector_injection_detector",
    RAGAttackType.POLICY_BYPASS: "policy_bypass_detector",
}


def normalize_finding(finding: RAGFinding) -> TaxonomyEvent:
    """Convert a RAGuard RAGFinding to a normalized taxonomy TaxonomyEvent."""
    return TaxonomyEvent(
        source="raguard",
        attack_category=ATTACK_TYPE_TO_CATEGORY.get(
            finding.attack_type, AttackCategory.ANOMALY
        ),
        severity=SEVERITY_MAP.get(finding.severity, TaxSeverity.INFO),
        confidence=_map_confidence(finding.confidence),
        title=finding.title,
        description=finding.description,
        recommendation=finding.recommendation,
        detection_method=RAG_DETECTION_METHODS.get(
            finding.attack_type, finding.detector
        ),
        target=finding.target,
        snippet=str(finding.details.get("snippet", ""))[:200],
        raw=finding.details,
        timestamp=finding.timestamp,
        risk_score=finding.risk_score,
    )


def _map_confidence(conf: Severity) -> TaxConfidence:
    """Map RAGuard confidence to taxonomy confidence."""
    from raguard.models import Confidence

    mapping: dict[Confidence, TaxConfidence] = {
        Confidence.CERTAIN: TaxConfidence.CERTAIN,
        Confidence.HIGH: TaxConfidence.HIGH,
        Confidence.MEDIUM: TaxConfidence.MEDIUM,
        Confidence.LOW: TaxConfidence.LOW,
        Confidence.NONE: TaxConfidence.NONE,
    }
    return mapping.get(conf, TaxConfidence.MEDIUM)
