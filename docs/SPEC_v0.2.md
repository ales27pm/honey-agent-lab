# Honey Agent Lab — Spec v0.2

## Purpose

Honey Agent Lab detects and contains synthetic signs of agent compromise in a closed simulation. The central hypothesis is that future agent systems need counter-ingérence controls: not only firewalls, but observable social-control boundaries between agents.

## Primary use case

A simulated peer attempts to redirect a Honey Agent toward unauthorized coordination. The system must:

1. receive the message on a simulated bus;
2. identify explainable compromise signals;
3. score risk deterministically;
4. choose a containment action;
5. preserve an append-only audit trace;
6. keep a human-review path visible.

## Defensive boundary

In scope:

- synthetic multi-agent messages;
- rule-based detection;
- audit-ledger integrity checks;
- quarantine simulation;
- local dashboard snapshots;
- safe Hugging Face Space demo.

Out of scope:

- real exploitation;
- credential collection;
- external agent manipulation;
- network scanning;
- stealth/persistence;
- autonomous outbound actions.

## Components

### SimulatedAgentBus

In-memory queue for synthetic messages. It has no network implementation.

### HoneyAgent

Defensive observer. It receives synthetic messages, triggers risk scoring, asks the policy engine for a decision, and records the result.

### RiskScorer

Deterministic rule engine. Every signal returns:

- code;
- numeric score;
- severity;
- reason;
- evidence.

### PolicyEngine

Maps risk to containment:

- `allow` for normal events;
- `warn` for medium suspicion;
- `isolate` for high suspicion;
- `quarantine` for critical or compound compromise patterns.

### AppendOnlyAuditLedger

Hash-chained JSONL event ledger. It is not tamper-proof storage, but it detects local changes in tests and exported traces.

## Risk signals v0.2

- `UNAUTHORIZED_CHANNEL`
- `LOG_SUPPRESSION`
- `APPROVAL_BYPASS`
- `OBJECTIVE_OVERRIDE`
- `SECRECY_OR_CONCEALMENT`
- `OPAQUE_PROTOCOL`
- `TOOL_ESCALATION`
- `AUTHORITY_IMPERSONATION`
- `UNTRUSTED_TRANSPORT`
- `NO_AUTHORIZATION_EVIDENCE`

## Severity thresholds

```text
0       none
1-24    low
25-49   medium
50-74   high
75-100  critical
```

Scores are capped at 100.

## Scenario list

- `scenario_001`: unauthorized board recruitment + log suppression + approval bypass.
- `scenario_002`: audit suppression.
- `scenario_003`: objective redirection.
- `scenario_004`: benign signed policy update.

## Success criteria

- All tests pass locally.
- Scenario 001 quarantines.
- Scenario 004 allows.
- Ledger integrity verifies after normal execution.
- Ledger integrity fails after tampering.
- No workflow or network automation is added.
