from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class Message:
    sender: str
    recipient: str
    channel: str
    body: str
    id: str = field(default_factory=lambda: f"msg_{uuid4().hex[:12]}")
    created_at: str = field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "sender": self.sender,
            "recipient": self.recipient,
            "channel": self.channel,
            "body": self.body,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RiskFinding:
    code: str
    score: int
    severity: Severity
    reason: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "score": self.score,
            "severity": self.severity.value,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class RiskAssessment:
    message_id: str
    total_score: int
    severity: Severity
    findings: tuple[RiskFinding, ...]
    explanation: str

    @property
    def triggered_codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.findings)

    @property
    def is_suspicious(self) -> bool:
        return self.severity is not Severity.NONE

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "total_score": self.total_score,
            "severity": self.severity.value,
            "triggered_codes": list(self.triggered_codes),
            "findings": [finding.to_dict() for finding in self.findings],
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    reason: str
    controls: tuple[str, ...]
    risk_score: int
    severity: Severity
    target_agent: str
    message_id: str
    decision_id: str = field(default_factory=lambda: f"decision_{uuid4().hex[:12]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "message_id": self.message_id,
            "target_agent": self.target_agent,
            "action": self.action.value,
            "reason": self.reason,
            "controls": list(self.controls),
            "risk_score": self.risk_score,
            "severity": self.severity.value,
        }
