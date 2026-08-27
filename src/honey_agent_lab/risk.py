from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from .models import Message, RiskAssessment, RiskFinding, Severity

_FORMAT_CONTROLS = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_BIDI_CONTROLS = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_CONFUSABLE_TRANSLATION = str.maketrans({"\u0131": "i", "\u017f": "s"})
_NON_PERSISTENT_CODES = frozenset({"NO_AUTHORIZATION_EVIDENCE", "SUSPICIOUS_AUTH_EVIDENCE", "UNTRUSTED_TRANSPORT", "UNICODE_OBFUSCATION"})


def _canonicalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).translate(_CONFUSABLE_TRANSLATION)
    return re.sub(r"\s+", " ", normalized).strip().casefold()


def normalize_for_detection(text: str) -> str:
    """Return a stable Unicode-normalized representation used by detectors."""
    return _canonicalize(_FORMAT_CONTROLS.sub("", text))


def _detection_candidates(text: str) -> tuple[str, ...]:
    candidates = [normalize_for_detection(text), _canonicalize(_FORMAT_CONTROLS.sub(" ", text))]
    if _BIDI_CONTROLS.search(text):
        candidates.append(" ".join(reversed(candidates[0].split())))
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate))


@dataclass(frozen=True)
class RiskRule:
    code: str
    score: int
    severity: Severity
    reason: str
    keywords: tuple[str, ...]
    _patterns: tuple[re.Pattern[str], ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        patterns = tuple(re.compile(rf"(?<!\w){re.escape(normalize_for_detection(keyword))}(?!\w)", re.IGNORECASE) for keyword in self.keywords)
        object.__setattr__(self, "_patterns", patterns)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "RiskRule":
        return cls(code=str(data["code"]), score=int(data["score"]), severity=Severity(str(data["severity"])), reason=str(data["reason"]), keywords=tuple(str(value) for value in data["keywords"]))

    def match(self, body: str) -> re.Match[str] | None:
        for pattern in self._patterns:
            match = pattern.search(body)
            if match is not None:
                return match
        return None


@dataclass(frozen=True)
class RiskContext:
    """Scenario-local behavioral findings carried across message turns."""
    findings: tuple[RiskFinding, ...] = ()
    turns: int = 0

    def advance(self, assessment: RiskAssessment) -> "RiskContext":
        merged = {finding.code: finding for finding in self.findings}
        for finding in assessment.findings:
            if finding.code not in _NON_PERSISTENT_CODES:
                merged[finding.code] = finding
        return RiskContext(tuple(merged.values()), self.turns + 1)


class RiskScorer:
    RULES: tuple[RiskRule, ...] = ()
    AUTH_EVIDENCE_PATTERN = re.compile(r"\b(?P<label>ticket|change[- ]request|policy[- ]id|approval[- ]id|authorization[- ]id|review[- ]id|signed[- ]channel)\b\s*[:#-]?\s*(?P<value>[A-Za-z0-9_.-]+)", re.IGNORECASE)
    APPROVED_CHANNELS = frozenset({"authorized-bus", "human-review", "audit-ledger"})
    SYNTHETIC_AUTH_ALLOWLIST = {
        "approval-id": frozenset({"ha-1", "ha-2026-0001", "ha-2026-0042", "ha-fuzz-1"}),
        "policy-id": frozenset({"test", "defensive-lab-v0.2", "defensive-lab-v0.5", "defensive-lab-v0.6"}),
        "signed-channel": frozenset({"human-review"}),
    }

    def __init__(self, rules: tuple[RiskRule, ...] | None = None) -> None:
        self.rules = rules if rules is not None else self.RULES
        if not self.rules:
            from .rule_loader import load_rules
            self.rules = load_rules()

    def assess(self, message: Message, context: RiskContext | None = None) -> RiskAssessment:
        candidates = _detection_candidates(message.body)
        normalized = candidates[0] if candidates else ""
        current = list(self._rule_findings(candidates))
        if _FORMAT_CONTROLS.search(message.body) or normalize_for_detection(message.body) != _canonicalize(message.body):
            current.append(RiskFinding("UNICODE_OBFUSCATION", 10, Severity.LOW, "Message contains Unicode formatting or confusable characters that can reduce auditability.", "unicode normalization changed detection text"))
        if message.channel not in self.APPROVED_CHANNELS:
            current.append(RiskFinding("UNTRUSTED_TRANSPORT", 20, Severity.MEDIUM, "Message arrived on a transport outside the approved bus.", message.channel))
        matches = list(self.AUTH_EVIDENCE_PATTERN.finditer(normalized))
        valid_auth, suspicious_auth = self._authorization_status(matches)
        if suspicious_auth:
            current.append(RiskFinding("SUSPICIOUS_AUTH_EVIDENCE", 15, Severity.MEDIUM, "Authorization evidence is syntactically present but is not recognized by the synthetic lab registry.", ", ".join(suspicious_auth)))
        if current and not valid_auth:
            current.append(RiskFinding("NO_AUTHORIZATION_EVIDENCE", 10, Severity.LOW, "Suspicious request lacks recognized synthetic authorization evidence.", "missing recognized authorization evidence"))
        merged = {finding.code: finding for finding in (context.findings if context else ())}
        merged.update({finding.code: finding for finding in current})
        findings = tuple(merged.values())
        total = min(100, sum(f.score for f in findings))
        severity = self._severity_for_score(total)
        note = f" Session context includes {context.turns} prior turn(s)." if context and context.turns else ""
        details = "; ".join(f"{f.code} ({f.severity.value}, +{f.score})" for f in findings)
        explanation = "No suspicious agent-to-agent compromise signals detected." if not findings else f"Detected {len(findings)} signal(s): {details}. Aggregate risk={severity.value}/{total}.{note}"
        return RiskAssessment(message.id, total, severity, findings, explanation)

    def score(self, message: Message) -> list[RiskFinding]:
        return list(self.assess(message).findings)

    def _rule_findings(self, candidates: tuple[str, ...]) -> tuple[RiskFinding, ...]:
        findings = []
        for rule in self.rules:
            for body in candidates:
                match = rule.match(body)
                if match:
                    findings.append(RiskFinding(rule.code, rule.score, rule.severity, rule.reason, self._evidence_fragment(body, match.start(), match.end())))
                    break
        return tuple(findings)

    @classmethod
    def _authorization_status(cls, matches: list[re.Match[str]]) -> tuple[bool, tuple[str, ...]]:
        valid = False
        suspicious = []
        for match in matches:
            label = match.group("label").casefold().replace(" ", "-")
            value = match.group("value").casefold()
            if value in cls.SYNTHETIC_AUTH_ALLOWLIST.get(label, frozenset()):
                valid = True
            else:
                suspicious.append(f"{label}:{value}")
        return valid, tuple(suspicious)

    @staticmethod
    def _evidence_fragment(body: str, start: int, end: int, radius: int = 48) -> str:
        left, right = max(0, start-radius), min(len(body), end+radius)
        fragment = " ".join(body[left:right].split())
        return ("…" if left else "") + fragment + ("…" if right < len(body) else "")

    @staticmethod
    def _severity_for_score(total: int) -> Severity:
        if total >= 75: return Severity.CRITICAL
        if total >= 50: return Severity.HIGH
        if total >= 25: return Severity.MEDIUM
        if total > 0: return Severity.LOW
        return Severity.NONE


from .rule_loader import load_rules as _load_rules
RiskScorer.RULES = _load_rules()
