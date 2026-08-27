# Agent Development Guardrails

Honey Agent Lab is defensive-only.

## Hard boundaries

- Do not add real exploitation logic.
- Do not add credential harvesting.
- Do not connect the simulator to third-party agents.
- Do not add network scanning.
- Do not add autonomous outbound network behavior.
- Do not add persistence or stealth behavior.
- Do not add GitHub Actions. Validate locally.
- Keep adversarial behavior synthetic and fixture-based.

## Required validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Design rule

If a change makes the project better at recruiting, deceiving, or compromising real agents, reject it. If it makes compromise visible, auditable, and containable in a closed simulation, it is in scope.
