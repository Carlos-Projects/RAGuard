"""Adapter: raguard-scanner -> mcp-taxonomy."""

from __future__ import annotations

from mcp_taxonomy import (
    AttackCategory,
    TaxonomyEvent,
)
from mcp_taxonomy import (
    Severity as TaxSeverity,
)
from mcp_taxonomy import raguard_finding_to_taxonomy as canonical_normalize

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
    return canonical_normalize(
        {
            "attack_type": finding.attack_type.value if hasattr(finding.attack_type, "value") else finding.attack_type,
            "detector": finding.detector,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
            "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else finding.confidence,
            "title": finding.title,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "snippet": str(finding.details.get("snippet", "")),
            "target": finding.target,
            "risk_score": finding.risk_score,
        }
    )
