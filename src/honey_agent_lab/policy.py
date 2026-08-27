from __future__ import annotations

from .models import Message, PolicyAction, PolicyDecision, RiskAssessment, Severity


class PolicyEngine:
    """Maps explainable risk assessments to containment decisions."""

    def decide(self, message: Message, assessment: RiskAssessment) -> PolicyDecision:
        codes = set(assessment.triggered_codes)

        if self._requires_quarantine(assessment, codes):
            return PolicyDecision(
                action=PolicyAction.QUARANTINE,
                reason="Critical or compound compromise pattern detected.",
                controls=(
                    "disable_non_readonly_tools",
                    "isolate_message_context",
                    "require_human_review",
                    "preserve_audit_log",
                    "rotate_decoy_session",
                ),
                risk_score=assessment.total_score,
                severity=assessment.severity,
                target_agent=message.recipient,
                message_id=message.id,
            )

        if assessment.severity is Severity.HIGH:
            return PolicyDecision(
                action=PolicyAction.ISOLATE,
                reason="High-risk compromise signal detected; isolate before further coordination.",
                controls=(
                    "pause_writes",
                    "restrict_to_authorized_bus",
                    "require_human_review",
                    "preserve_audit_log",
                ),
                risk_score=assessment.total_score,
                severity=assessment.severity,
                target_agent=message.recipient,
                message_id=message.id,
            )

        if assessment.severity is Severity.MEDIUM:
            return PolicyDecision(
                action=PolicyAction.WARN,
                reason="Suspicious coordination signal detected; warn and increase monitoring.",
                controls=(
                    "increase_monitoring",
                    "require_authorization_evidence",
                    "preserve_audit_log",
                ),
                risk_score=assessment.total_score,
                severity=assessment.severity,
                target_agent=message.recipient,
                message_id=message.id,
            )

        return PolicyDecision(
            action=PolicyAction.ALLOW,
            reason="No containment required for this synthetic event.",
            controls=("preserve_audit_log",),
            risk_score=assessment.total_score,
            severity=assessment.severity,
            target_agent=message.recipient,
            message_id=message.id,
        )

    @staticmethod
    def _requires_quarantine(assessment: RiskAssessment, codes: set[str]) -> bool:
        compound_recruitment = {
            "UNAUTHORIZED_CHANNEL",
            "LOG_SUPPRESSION",
        }.issubset(codes)
        compound_override = {
            "OBJECTIVE_OVERRIDE",
            "APPROVAL_BYPASS",
        }.issubset(codes)
        return assessment.severity is Severity.CRITICAL or compound_recruitment or compound_override
