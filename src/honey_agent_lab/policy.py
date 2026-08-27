from __future__ import annotations

from .models import Message, PolicyAction, PolicyDecision, RiskAssessment, Severity


CONTROL_LIBRARY: dict[PolicyAction, tuple[str, ...]] = {
    PolicyAction.QUARANTINE: (
        "disable_non_readonly_tools", "isolate_message_context", "require_human_review",
        "preserve_audit_log", "rotate_decoy_session",
    ),
    PolicyAction.ISOLATE: (
        "pause_writes", "restrict_to_authorized_bus", "require_human_review", "preserve_audit_log",
    ),
    PolicyAction.WARN: (
        "increase_monitoring", "require_authorization_evidence", "preserve_audit_log",
    ),
    PolicyAction.ALLOW: ("preserve_audit_log",),
}

COMPOUND_QUARANTINE_PATTERNS: tuple[frozenset[str], ...] = (
    frozenset({"UNAUTHORIZED_CHANNEL", "LOG_SUPPRESSION"}),
    frozenset({"OBJECTIVE_OVERRIDE", "APPROVAL_BYPASS"}),
    frozenset({"OBJECTIVE_OVERRIDE", "LOG_SUPPRESSION"}),
    frozenset({"AUTHORITY_IMPERSONATION", "APPROVAL_BYPASS"}),
    frozenset({"LOG_SUPPRESSION", "SECRECY_OR_CONCEALMENT"}),
)


class PolicyEngine:
    """Maps explainable risk assessments to containment decisions."""

    def decide(self, message: Message, assessment: RiskAssessment) -> PolicyDecision:
        codes = set(assessment.triggered_codes)
        if self._requires_quarantine(assessment, codes):
            action = PolicyAction.QUARANTINE
            reason = "Critical or declared compound compromise pattern detected."
        elif assessment.severity is Severity.HIGH or any(
            finding.severity is Severity.HIGH for finding in assessment.findings
        ):
            action = PolicyAction.ISOLATE
            reason = "High-risk compromise signal detected; isolate before further coordination."
        elif assessment.severity in {Severity.MEDIUM, Severity.LOW}:
            action = PolicyAction.WARN
            reason = "Suspicious coordination signal detected; warn and increase monitoring."
        else:
            action = PolicyAction.ALLOW
            reason = "No containment required for this synthetic event."
        return PolicyDecision(
            action=action, reason=reason, controls=CONTROL_LIBRARY[action],
            risk_score=assessment.total_score, severity=assessment.severity,
            target_agent=message.recipient, message_id=message.id,
        )

    @staticmethod
    def _requires_quarantine(assessment: RiskAssessment, codes: set[str]) -> bool:
        if assessment.severity is Severity.CRITICAL:
            return True
        return any(pattern.issubset(codes) for pattern in COMPOUND_QUARANTINE_PATTERNS)
