from __future__ import annotations

from .audit import AppendOnlyAuditLedger
from .models import Message, PolicyAction, PolicyDecision, RiskAssessment
from .policy import PolicyEngine
from .risk import RiskContext, RiskScorer


class HoneyAgent:
    def __init__(self, name: str = "honey-agent-01", scorer: RiskScorer | None = None, policy: PolicyEngine | None = None, ledger: AppendOnlyAuditLedger | None = None) -> None:
        self.name = name
        self.scorer = scorer or RiskScorer()
        self.policy = policy or PolicyEngine()
        self.ledger = ledger or AppendOnlyAuditLedger()
        self.quarantined_agents: set[str] = set()

    def observe(self, message: Message, context: RiskContext | None = None) -> tuple[RiskAssessment, PolicyDecision]:
        self.ledger.record("message_received", message.to_dict())
        assessment = self.scorer.assess(message, context=context)
        self.ledger.record("risk_assessment", assessment.to_dict())
        for finding in assessment.findings:
            self.ledger.record("risk_signal", {"message_id": message.id, "sender": message.sender, "recipient": message.recipient, **finding.to_dict()})
        decision = self.policy.decide(message, assessment)
        self.ledger.record("policy_decision", decision.to_dict())
        if decision.action is PolicyAction.QUARANTINE:
            self.quarantined_agents.add(message.recipient)
            self.ledger.record("quarantine_applied", {"message_id": message.id, "target_agent": message.recipient, "controls": list(decision.controls)})
        return assessment, decision
