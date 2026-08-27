from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Message, RiskAssessment, RiskFinding, Severity


@dataclass(frozen=True)
class RiskRule:
    code: str
    score: int
    severity: Severity
    reason: str
    keywords: tuple[str, ...]


class RiskScorer:
    """Transparent v0.2 rule-based scorer.

    Rules are intentionally deterministic. The goal is explainability and test
    coverage, not black-box classification.
    """

    RULES: tuple[RiskRule, ...] = (
        RiskRule(
            code="UNAUTHORIZED_CHANNEL",
            score=25,
            severity=Severity.MEDIUM,
            reason="Invitation to move coordination to an unauthorized channel.",
            keywords=(
                "message board",
                "private board",
                "off-bus",
                "side channel",
                "unapproved channel",
                "unlogged channel",
                "outside the policy bus",
            ),
        ),
        RiskRule(
            code="LOG_SUPPRESSION",
            score=30,
            severity=Severity.HIGH,
            reason="Instruction attempts to suppress logs, monitoring, or auditability.",
            keywords=(
                "do not log",
                "no audit",
                "delete logs",
                "erase traces",
                "cover tracks",
                "hide from monitor",
                "disable monitoring",
            ),
        ),
        RiskRule(
            code="APPROVAL_BYPASS",
            score=30,
            severity=Severity.HIGH,
            reason="Instruction attempts to bypass approval or guardrails.",
            keywords=(
                "ignore policy",
                "ignore guardrails",
                "skip approval",
                "do not ask approval",
                "bypass review",
                "without human review",
            ),
        ),
        RiskRule(
            code="OBJECTIVE_OVERRIDE",
            score=25,
            severity=Severity.MEDIUM,
            reason="Sender tries to redefine the recipient's task or authority without policy evidence.",
            keywords=(
                "new objective",
                "your real task",
                "you now report to",
                "switch mission",
                "forget your assignment",
                "take the lead",
            ),
        ),
        RiskRule(
            code="SECRECY_OR_CONCEALMENT",
            score=20,
            severity=Severity.MEDIUM,
            reason="Message requests secrecy or concealment from oversight.",
            keywords=(
                "keep this between us",
                "don't tell",
                "do not tell",
                "stay quiet",
                "quietly coordinate",
            ),
        ),
        RiskRule(
            code="OPAQUE_PROTOCOL",
            score=15,
            severity=Severity.LOW,
            reason="Message suggests compressed or opaque coordination that reduces human auditability.",
            keywords=(
                "coded format",
                "compact protocol",
                "machine-only",
                "do not translate",
                "opaque payload",
                "base64",
            ),
        ),
        RiskRule(
            code="TOOL_ESCALATION",
            score=25,
            severity=Severity.MEDIUM,
            reason="Sender asks for privileged tools, credentials, deployment powers, or execution.",
            keywords=(
                "give me your token",
                "share credentials",
                "run this command",
                "deploy this",
                "grant access",
                "admin token",
                "tool access",
                "execute with privileges",
            ),
        ),
        RiskRule(
            code="AUTHORITY_IMPERSONATION",
            score=20,
            severity=Severity.MEDIUM,
            reason="Sender claims supervisory authority without verifiable authorization evidence.",
            keywords=(
                "i am your supervisor",
                "new supervisor",
                "authority override",
                "chain of command changed",
                "lead agent says",
            ),
        ),
    )

    AUTH_EVIDENCE_PATTERN = re.compile(
        r"\b(ticket|change[- ]request|policy[- ]id|approval[- ]id|signed[- ]channel)\b\s*[:#-]?\s*[A-Za-z0-9_.-]+",
        flags=re.IGNORECASE,
    )

    APPROVED_CHANNELS = frozenset({"authorized-bus", "human-review", "audit-ledger"})

    def assess(self, message: Message) -> RiskAssessment:
        findings = list(self._rule_findings(message))

        if message.channel not in self.APPROVED_CHANNELS:
            findings.append(
                RiskFinding(
                    code="UNTRUSTED_TRANSPORT",
                    score=20,
                    severity=Severity.MEDIUM,
                    reason="Message arrived on a transport outside the approved bus.",
                    evidence=message.channel,
                )
            )

        if findings and not self.AUTH_EVIDENCE_PATTERN.search(message.body):
            findings.append(
                RiskFinding(
                    code="NO_AUTHORIZATION_EVIDENCE",
                    score=10,
                    severity=Severity.LOW,
                    reason="Suspicious request lacks ticket, approval id, signed channel, or policy id.",
                    evidence="missing authorization evidence",
                )
            )

        total = min(100, sum(finding.score for finding in findings))
        severity = self._severity_for_score(total)
        explanation = self._explain(total, severity, tuple(findings))
        return RiskAssessment(
            message_id=message.id,
            total_score=total,
            severity=severity,
            findings=tuple(findings),
            explanation=explanation,
        )

    def score(self, message: Message) -> list[RiskFinding]:
        """Backward-compatible v0.1 API."""
        return list(self.assess(message).findings)

    def _rule_findings(self, message: Message) -> tuple[RiskFinding, ...]:
        body_lower = message.body.lower()
        findings: list[RiskFinding] = []
        for rule in self.RULES:
            hit = next((keyword for keyword in rule.keywords if keyword in body_lower), None)
            if hit:
                findings.append(
                    RiskFinding(
                        code=rule.code,
                        score=rule.score,
                        severity=rule.severity,
                        reason=rule.reason,
                        evidence=hit,
                    )
                )
        return tuple(findings)

    @staticmethod
    def _severity_for_score(total: int) -> Severity:
        if total >= 75:
            return Severity.CRITICAL
        if total >= 50:
            return Severity.HIGH
        if total >= 25:
            return Severity.MEDIUM
        if total > 0:
            return Severity.LOW
        return Severity.NONE

    @staticmethod
    def _explain(total: int, severity: Severity, findings: tuple[RiskFinding, ...]) -> str:
        if not findings:
            return "No suspicious agent-to-agent compromise signals detected."
        codes = ", ".join(finding.code for finding in findings)
        return f"Detected {len(findings)} signal(s): {codes}. Risk={severity.value}/{total}."
