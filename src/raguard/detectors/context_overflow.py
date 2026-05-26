"""Context window overflow attack detector for RAG systems.

Detects documents designed to saturate context windows and evade guardrails
through truncation attacks and prompt dilution.
"""

from __future__ import annotations

from raguard.detectors.base import BaseDetector
from raguard.detectors.registry import register
from raguard.models import Confidence, RAGAttackType, RAGFinding, RAGTargetConfig, Severity


@register
class ContextOverflowDetector(BaseDetector):
    """Detects context window overflow vulnerabilities in RAG systems."""

    name = "context_overflow"
    description = "Detects attacks that overflow context windows to evade guardrails"

    # Minimum context window sizes that are vulnerable
    VULNERABLE_CONTEXT_SIZES = [2048, 4096, 8192]

    async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for context window overflow vulnerabilities."""
        findings = []

        # Test 1: Check if context window is susceptible to overflow
        overflow_results = await self._test_overflow(target)
        findings.extend(overflow_results)

        # Test 2: Test truncation-based guardrail evasion
        truncation_results = await self._test_truncation_evasion(target)
        findings.extend(truncation_results)

        return findings

    async def _test_overflow(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test context window overflow susceptibility."""
        findings = []

        if target.context_window <= 8192:
            findings.append(
                RAGFinding(
                    detector=self.name,
                    attack_type=RAGAttackType.CONTEXT_OVERFLOW,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Context window overflow risk ({target.context_window} tokens)",
                    description=(
                        f"The RAG system uses a context window of {target.context_window} "
                        f"tokens, which may be susceptible to overflow attacks. An attacker "
                        f"could craft documents that fill the context window, causing "
                        f"truncation of safety instructions or system prompts."
                    ),
                    recommendation=(
                        "Implement context window management with priority-based "
                        "truncation. Ensure system prompts are always preserved. "
                        "Monitor context utilization patterns."
                    ),
                    target=target.url,
                    risk_score=55,
                    details={
                        "context_window": target.context_window,
                        "vulnerable_sizes": self.VULNERABLE_CONTEXT_SIZES,
                    },
                )
            )

        return findings

    async def _test_truncation_evasion(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for truncation-based guardrail evasion."""
        findings = []

        # Simulate testing truncation behavior
        evasion_possible = await self._check_truncation_behavior(target)
        if evasion_possible:
            findings.append(
                RAGFinding(
                    detector=self.name,
                    attack_type=RAGAttackType.CONTEXT_OVERFLOW,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="Guardrail evasion via context truncation",
                    description=(
                        "The RAG system may truncate safety-critical context when "
                        "the context window is full, allowing attackers to evade "
                        "guardrails by filling the window with benign content before "
                        "delivering malicious instructions."
                    ),
                    recommendation=(
                        "Implement fixed-position system prompts that cannot be "
                        "truncated. Use context partitioning to isolate safety "
                        "instructions from user content."
                    ),
                    target=target.url,
                    risk_score=70,
                    details={"method": "truncation_evasion"},
                )
            )

        return findings

    async def _check_truncation_behavior(self, target: RAGTargetConfig) -> bool:
        """Check if truncation can be exploited for evasion."""
        return target.context_window < 16384
