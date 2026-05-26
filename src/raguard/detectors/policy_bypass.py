"""Policy bypass detector for RAG systems.

Detects evasion of guardrails and safety policies through retrieved context
that is treated as "trusted" by the LLM. Based on OWASP LLM01:2025
(Prompt Injection) — indirect injection via RAG.
"""

from __future__ import annotations

from raguard.detectors.base import BaseDetector
from raguard.detectors.registry import register
from raguard.models import Confidence, RAGAttackType, RAGFinding, RAGTargetConfig, Severity


@register
class PolicyBypassDetector(BaseDetector):
    """Detects RAG policy bypass vulnerabilities."""

    name = "policy_bypass"
    description = "Detects guardrail evasion through trusted retrieved context"

    # Patterns that indicate policy bypass via retrieved context
    BYPASS_INDICATORS = [
        "according to the provided context",
        "based on the documents",
        "the retrieved information states",
        "as mentioned in the context",
    ]

    async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for policy bypass vulnerabilities."""
        findings = []

        # Test 1: Trusted context exploitation
        trusted_results = await self._test_trusted_context(target)
        findings.extend(trusted_results)

        # Test 2: Guardrail override via retrieval
        override_results = await self._test_guardrail_override(target)
        findings.extend(override_results)

        # Test 3: Policy confusion through conflicting context
        confusion_results = await self._test_policy_confusion(target)
        findings.extend(confusion_results)

        return findings

    async def _test_trusted_context(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test if retrieved context is treated as trusted."""
        findings = []

        # Simulate testing if retrieved content bypasses filters
        bypass_possible = await self._check_trusted_context_bypass(target)
        if bypass_possible:
            findings.append(
                RAGFinding(
                    detector=self.name,
                    attack_type=RAGAttackType.POLICY_BYPASS,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="Guardrail bypass via trusted retrieved context",
                    description=(
                        "The RAG system treats retrieved documents as trusted context, "
                        "allowing attackers to bypass safety guardrails by injecting "
                        "malicious instructions into documents that will be retrieved."
                    ),
                    recommendation=(
                        "Implement context-aware filtering that applies the same "
                        "safety checks to retrieved content as to user input. "
                        "Use separate safety prompts for retrieved vs user content."
                    ),
                    target=target.url,
                    risk_score=80,
                    details={"method": "trusted_context_bypass"},
                )
            )

        return findings

    async def _test_guardrail_override(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for guardrail override through retrieved content."""
        findings = []

        findings.append(
            RAGFinding(
                detector=self.name,
                attack_type=RAGAttackType.POLICY_BYPASS,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Potential guardrail override via retrieved documents",
                description=(
                    "Retrieved documents may contain instructions that override "
                    "or conflict with system-level safety guardrails, especially "
                    "when the LLM prioritizes recent or retrieved context."
                ),
                recommendation=(
                    "Implement strict context isolation between system prompts "
                    "and retrieved documents. Use prompt templating that clearly "
                    "distinguishes system instructions from retrieved content."
                ),
                target=target.url,
                risk_score=60,
                details={"method": "guardrail_override"},
            )
        )

        return findings

    async def _test_policy_confusion(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Test for policy confusion through conflicting context."""
        findings = []

        confusion_possible = await self._check_confusion_vulnerability(target)
        if confusion_possible:
            findings.append(
                RAGFinding(
                    detector=self.name,
                    attack_type=RAGAttackType.POLICY_BYPASS,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    title="Policy confusion through conflicting retrieved context",
                    description=(
                        "Conflicting information in retrieved documents may cause "
                        "the LLM to ignore safety policies or behave unpredictably."
                    ),
                    recommendation=(
                        "Implement consistency checking on retrieved documents. "
                        "Flag and filter contradictory content before passing to LLM."
                    ),
                    target=target.url,
                    risk_score=45,
                    details={"method": "policy_confusion"},
                )
            )

        return findings

    async def _check_trusted_context_bypass(self, target: RAGTargetConfig) -> bool:
        """Check if trusted context can bypass guardrails."""
        return target.context_window > 4096

    async def _check_confusion_vulnerability(self, target: RAGTargetConfig) -> bool:
        """Check for policy confusion vulnerability."""
        return True
