"""Pydantic models for RAGuard scan results and configuration."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RAGAttackType(StrEnum):
    """Types of RAG-specific attacks."""

    DATA_POISONING = "data_poisoning"
    MEMBERSHIP_INFERENCE = "membership_inference"
    PROMPT_LEAKAGE = "prompt_leakage"
    CONTEXT_OVERFLOW = "context_overflow"
    RETRIEVAL_HIJACK = "retrieval_hijack"
    VECTOR_INJECTION = "vector_injection"
    POLICY_BYPASS = "policy_bypass"


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 10,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class Confidence(StrEnum):
    """Detection confidence levels."""

    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @property
    def score(self) -> float:
        return {
            Confidence.CERTAIN: 1.0,
            Confidence.HIGH: 0.85,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
            Confidence.NONE: 0.0,
        }[self]


class TargetType(StrEnum):
    """Supported RAG target types."""

    CHROMA = "chroma"
    MILVUS = "milvus"
    QDRANT = "qdrant"
    GENERIC = "generic"


class RAGTargetConfig(BaseModel):
    """Configuration for a RAG system target."""

    type: TargetType = TargetType.GENERIC
    url: str = "http://localhost:8000"
    api_key: str | None = Field(default=None, exclude=True)
    collection_name: str = "default"
    embedding_model: str = "text-embedding-ada-002"
    context_window: int = Field(default=4096, ge=1, le=1048576)
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional target metadata")


class RAGFinding(BaseModel):
    """A single security finding from a RAG scan."""

    id: str = Field(default_factory=lambda: f"finding-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}")
    detector: str
    attack_type: RAGAttackType
    severity: Severity
    confidence: Confidence
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="", max_length=5000)
    recommendation: str = Field(default="", max_length=2000)
    target: str = Field(default="", max_length=1024)
    risk_score: int = Field(default=0, ge=0, le=100)
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional finding details (not rendered in HTML reports directly)",
    )
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def model_post_init(self, __context: Any) -> None:
        if self.risk_score == 0:
            self.risk_score = self._calculate_risk()

    def _calculate_risk(self) -> int:
        base = self.severity.weight
        conf_mult = self.confidence.score
        return min(100, int(base * conf_mult * 4))


class RAGScanReport(BaseModel):
    """Complete scan report."""

    target_url: str
    target_type: TargetType
    findings: list[RAGFinding] = Field(default_factory=list)
    risk_score: int = 0
    risk_category: str = "none"
    scan_duration_ms: float = 0.0
    scanner_version: str = "0.1.0"
    config: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[RAGFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[RAGFinding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def summary(self) -> str:
        if not self.findings:
            return "No security issues detected."
        parts = [
            f"{len(self.critical_findings)} critical",
            f"{len(self.high_findings)} high",
            f"{len([f for f in self.findings if f.severity == Severity.MEDIUM])} medium",
            f"{len([f for f in self.findings if f.severity in (Severity.LOW, Severity.INFO)])} low/info",
        ]
        return ", ".join(parts)

    def compute_risk(self) -> None:
        """Compute aggregate risk score from findings."""
        if not self.findings:
            self.risk_score = 0
            self.risk_category = "none"
            return

        total = sum(f.risk_score for f in self.findings)
        self.risk_score = min(100, total)

        if self.risk_score >= 80:
            self.risk_category = "critical"
        elif self.risk_score >= 50:
            self.risk_category = "high"
        elif self.risk_score >= 20:
            self.risk_category = "medium"
        elif self.risk_score >= 5:
            self.risk_category = "low"
        else:
            self.risk_category = "info"
