# Honey Agent Lab — Specification v0.6

v0.6 hardens the defensive lab against gradual and evasive synthetic compromise patterns.

## Additions

- Scenario-local multi-turn risk context with deduplicated behavioral signal carryover.
- `scenario_005` models gradual grooming across three turns.
- Unicode detection normalization: compatibility normalization, format-control handling, and a small curated confusable map.
- Bidi-control fixtures are flagged and checked against a reversed-token detection candidate.
- Synthetic authorization evidence is validated against a local allowlist; unrecognized evidence raises `SUSPICIOUS_AUTH_EVIDENCE` and does not suppress missing-auth risk.
- Additional compound quarantine patterns cover tool escalation, authority impersonation, secrecy, opaque coordination, and unauthorized channels.

## Safety boundary

All messages, auth IDs, Unicode evasions, and grooming sequences are inert synthetic fixtures. No live targets, credentials, external agents, scanning, exploitation, outbound calls, or stealth mechanisms are introduced.
