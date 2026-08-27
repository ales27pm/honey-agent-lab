from __future__ import annotations
import re
from dataclasses import dataclass, field
from .models import Message, RiskAssessment, RiskFinding, Severity

@dataclass(frozen=True)
class RiskRule:
    code: str
    score: int
    severity: Severity
    reason: str
    keywords: tuple[str, ...]
    _patterns: tuple[re.Pattern[str], ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_patterns", tuple(
            re.compile(rf"(?<!\w){re.escape(keyword)}(?!\w)", re.IGNORECASE)
            for keyword in self.keywords
        ))

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "RiskRule":
        return cls(
            code=str(data["code"]), score=int(data["score"]),
            severity=Severity(str(data["severity"])), reason=str(data["reason"]),
            keywords=tuple(str(v) for v in data["keywords"]),
        )

    def match(self, body: str) -> re.Match[str] | None:
        for pattern in self._patterns:
            match = pattern.search(body)
            if match is not None:
                return match
        return None

class RiskScorer:
    """Transparent deterministic scorer driven by validated local rule data."""
    RULES: tuple[RiskRule, ...] = ()
    AUTH_EVIDENCE_PATTERN = re.compile(
        r"\b(ticket|change[- ]request|policy[- ]id|approval[- ]id|authorization[- ]id|review[- ]id|signed[- ]channel)\b\s*[:#-]?\s*[A-Za-z0-9_.-]+",
        re.IGNORECASE,
    )
    APPROVED_CHANNELS = frozenset({"authorized-bus", "human-review", "audit-ledger"})

    def __init__(self, rules: tuple[RiskRule, ...] | None = None) -> None:
        self.rules = rules if rules is not None else self.RULES
        if not self.rules:
            from .rule_loader import load_rules
            self.rules = load_rules()

    def assess(self, message: Message) -> RiskAssessment:
        findings = list(self._rule_findings(message))
        if message.channel not in self.APPROVED_CHANNELS:
            findings.append(RiskFinding("UNTRUSTED_TRANSPORT",20,Severity.MEDIUM,
                "Message arrived on a transport outside the approved bus.", message.channel))
        if findings and not self.AUTH_EVIDENCE_PATTERN.search(message.body):
            findings.append(RiskFinding("NO_AUTHORIZATION_EVIDENCE",10,Severity.LOW,
                "Suspicious request lacks ticket, approval id, signed channel, or policy id.",
                "missing authorization evidence"))
        total=min(100,sum(f.score for f in findings)); severity=self._severity_for_score(total)
        return RiskAssessment(message.id,total,severity,tuple(findings),self._explain(total,severity,tuple(findings)))

    def score(self, message: Message) -> list[RiskFinding]:
        return list(self.assess(message).findings)

    def _rule_findings(self, message: Message) -> tuple[RiskFinding, ...]:
        out=[]
        for rule in self.rules:
            match=rule.match(message.body)
            if match:
                out.append(RiskFinding(rule.code,rule.score,rule.severity,rule.reason,
                    self._evidence_fragment(message.body,match.start(),match.end())))
        return tuple(out)

    @staticmethod
    def _evidence_fragment(body: str,start:int,end:int,radius:int=48)->str:
        left=max(0,start-radius); right=min(len(body),end+radius)
        frag=" ".join(body[left:right].split())
        return ("…" if left else "")+frag+("…" if right<len(body) else "")
    @staticmethod
    def _severity_for_score(total:int)->Severity:
        if total>=75:return Severity.CRITICAL
        if total>=50:return Severity.HIGH
        if total>=25:return Severity.MEDIUM
        if total>0:return Severity.LOW
        return Severity.NONE
    @staticmethod
    def _explain(total:int,severity:Severity,findings:tuple[RiskFinding,...])->str:
        if not findings:return "No suspicious agent-to-agent compromise signals detected."
        details="; ".join(f"{f.code} ({f.severity.value}, +{f.score})" for f in findings)
        return f"Detected {len(findings)} signal(s): {details}. Aggregate risk={severity.value}/{total}."

from .rule_loader import load_rules as _load_rules
RiskScorer.RULES = _load_rules()
