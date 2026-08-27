from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .audit import AppendOnlyAuditLedger
from .bus import SimulatedAgentBus
from .honey import HoneyAgent
from .models import PolicyDecision, RiskAssessment
from .policy import PolicyEngine
from .risk import RiskScorer
from .scenarios import Scenario, get_scenario


@dataclass(frozen=True)
class MessageResult:
    assessment: RiskAssessment
    decision: PolicyDecision

    def to_dict(self) -> dict[str, object]:
        return {"assessment": self.assessment.to_dict(), "decision": self.decision.to_dict()}


@dataclass(frozen=True)
class SimulationResult:
    scenario: Scenario
    message_results: tuple[MessageResult, ...]
    ledger: AppendOnlyAuditLedger

    @property
    def final_decision(self) -> PolicyDecision:
        return self.message_results[-1].decision

    @property
    def final_assessment(self) -> RiskAssessment:
        return self.message_results[-1].assessment

    def to_dict(self, include_ledger: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "scenario": self.scenario.to_dict(),
            "message_results": [result.to_dict() for result in self.message_results],
            "final": {
                "action": self.final_decision.action.value,
                "severity": self.final_assessment.severity.value,
                "score": self.final_assessment.total_score,
                "reason": self.final_decision.reason,
                "controls": list(self.final_decision.controls),
            },
        }
        if include_ledger:
            payload["ledger"] = [event.to_dict() for event in self.ledger.events]
            payload["ledger_integrity"] = self.ledger.verify_integrity()
        return payload

    def write_audit(self, path: str | Path) -> Path:
        return self.ledger.write_jsonl(path)


def run_scenario(
    name: str,
    ledger: AppendOnlyAuditLedger | None = None,
    scorer: RiskScorer | None = None,
    policy: PolicyEngine | None = None,
) -> SimulationResult:
    scenario = get_scenario(name)
    active_ledger = ledger or AppendOnlyAuditLedger()
    bus = SimulatedAgentBus()
    honey = HoneyAgent(ledger=active_ledger, scorer=scorer, policy=policy)
    active_ledger.record("scenario_started", {"name": scenario.name, "description": scenario.description})
    bus.extend(scenario.messages)
    results: list[MessageResult] = []
    for message in bus.drain():
        active_ledger.record("message_published", message.to_dict())
        assessment, decision = honey.observe(message)
        results.append(MessageResult(assessment=assessment, decision=decision))
    active_ledger.record(
        "scenario_completed",
        {"name": scenario.name, "messages_processed": len(results), "final_action": results[-1].decision.action.value if results else "none"},
    )
    return SimulationResult(scenario=scenario, message_results=tuple(results), ledger=active_ledger)
