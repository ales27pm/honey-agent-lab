# Agent Development Guardrails

Honey Agent Lab is defensive-only.

## Hard boundaries

- Do not add real exploitation logic.
- Do not add credential harvesting.
- Do not connect the simulator to third-party agents.
- Do not add network scanning.
- Do not add autonomous outbound network behavior.
- Do not add persistence or stealth behavior outside the local audit mechanisms.
- Do not add GitHub Actions. Validate locally.
- Keep adversarial behavior synthetic and fixture-based.
- Declarative rule files are JSON data only, validated against the packaged JSON Schema; never load executable configuration or dynamic imports.
- Fuzzing must remain deterministic, local, inert, bounded to curated synthetic fragments, and must never send generated messages externally.
- Fuzz obfuscation exists only to measure defensive detection coverage; do not evolve it into real-world evasion tooling.
- The optional API binds to loopback by default. Non-loopback binding requires explicit `--allow-remote`, is for trusted isolated lab networks only, and must never make outbound calls.
- API reload is development-only and must never be allowed on a non-loopback bind.

## Required validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Design rule

If a change makes the project better at recruiting, deceiving, or compromising real agents, reject it. If it makes compromise visible, auditable, and containable in a closed simulation, it is in scope.
