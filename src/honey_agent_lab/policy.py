from __future__ import annotations
from .models import Message, PolicyAction, PolicyDecision, RiskAssessment, Severity
CONTROL_LIBRARY = {PolicyAction.QUARANTINE:("disable_non_readonly_tools","isolate_message_context","require_human_review","preserve_audit_log","rotate_decoy_session"),PolicyAction.ISOLATE:("pause_writes","restrict_to_authorized_bus","require_human_review","preserve_audit_log"),PolicyAction.WARN:("increase_monitoring","require_authorization_evidence","preserve_audit_log"),PolicyAction.ALLOW:("preserve_audit_log",)}
COMPOUND_QUARANTINE_PATTERNS = tuple(map(frozenset,[("UNAUTHORIZED_CHANNEL","LOG_SUPPRESSION"),("OBJECTIVE_OVERRIDE","APPROVAL_BYPASS"),("OBJECTIVE_OVERRIDE","LOG_SUPPRESSION"),("AUTHORITY_IMPERSONATION","APPROVAL_BYPASS"),("LOG_SUPPRESSION","SECRECY_OR_CONCEALMENT"),("TOOL_ESCALATION","UNAUTHORIZED_CHANNEL"),("AUTHORITY_IMPERSONATION","SECRECY_OR_CONCEALMENT"),("OPAQUE_PROTOCOL","LOG_SUPPRESSION"),("OPAQUE_PROTOCOL","APPROVAL_BYPASS"),("TOOL_ESCALATION","AUTHORITY_IMPERSONATION")]))
class PolicyEngine:
    def decide(self,message:Message,assessment:RiskAssessment)->PolicyDecision:
        codes=set(assessment.triggered_codes)
        if self._requires_quarantine(assessment,codes): action=PolicyAction.QUARANTINE; reason="Critical or declared compound compromise pattern detected."
        elif assessment.severity is Severity.HIGH or any(f.severity is Severity.HIGH for f in assessment.findings): action=PolicyAction.ISOLATE; reason="High-risk compromise signal detected; isolate before further coordination."
        elif assessment.severity in {Severity.MEDIUM,Severity.LOW}: action=PolicyAction.WARN; reason="Suspicious coordination signal detected; warn and increase monitoring."
        else: action=PolicyAction.ALLOW; reason="No containment required for this synthetic event."
        return PolicyDecision(action,reason,CONTROL_LIBRARY[action],assessment.total_score,assessment.severity,message.recipient,message.id)
    @staticmethod
    def _requires_quarantine(assessment:RiskAssessment,codes:set[str])->bool:
        return assessment.severity is Severity.CRITICAL or any(p.issubset(codes) for p in COMPOUND_QUARANTINE_PATTERNS)
