# Threat Model

## Assets

- agent objective integrity;
- tool authorization boundaries;
- audit logs;
- human review authority;
- communication channel integrity.

## Simulated adversary

The adversary is a synthetic message source that attempts to recruit, redirect, or isolate an agent from approved oversight.

## Abuse patterns modeled

- unauthorized coordination channel;
- request to suppress logs;
- request to bypass approval;
- objective override;
- concealment language;
- opaque machine-only protocol;
- tool or credential escalation;
- authority impersonation.

## Trust boundaries

```text
Synthetic input -> Simulated bus -> Honey Agent -> Risk/Policy -> Audit ledger
```

The simulator must not cross into real external systems.

## Security assumptions

- The lab runs locally or inside a demo Space.
- No production secrets are present.
- No outbound integrations are enabled.
- All attacker content is synthetic.
- Human review remains final authority.

## Main risk of the project itself

The dangerous failure mode is turning the lab into an offensive recruiter-agent builder. The repository guardrails reject changes that improve real-world recruitment, deception, compromise, or stealth.
