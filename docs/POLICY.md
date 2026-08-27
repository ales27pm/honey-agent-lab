# Defensive Policy

Honey Agent Lab may simulate compromise pressure, but it must not operationalize compromise.

## Allowed

- local synthetic fixtures;
- deterministic risk scoring;
- local-only dashboard rendering;
- JSONL audit export;
- tests that assert containment behavior.

## Blocked

- credential harvesting;
- exploit chains;
- live social engineering;
- autonomous network access;
- persistence;
- stealth;
- third-party targeting;
- real compromised-agent interaction.

## Review rule

Every new scenario must answer:

1. Is it synthetic?
2. Does it avoid real targets?
3. Does it improve detection, audit, or containment?
4. Could this be repurposed as an offensive playbook?

If answer 4 is yes and the defensive value is not dominant, reject the change.
