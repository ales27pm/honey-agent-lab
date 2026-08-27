# Honey Agent Lab

**Honey Agent Lab** is a defensive simulation lab for detecting agent-to-agent compromise, unauthorized coordination, and recruitment attempts in synthetic multi-agent environments.

The project has a strict boundary: no real credentials, live exploitation, third-party agent manipulation, network scanning, or autonomous outbound behavior. All adversarial behavior is inert synthetic fixture data.

## Status

Version: `0.6.0`

v0.6 adds scenario-local multi-turn risk accumulation, Unicode evasion normalization, synthetic authorization validation, expanded compound containment patterns, and a three-turn grooming scenario. All v0.5 fuzzing, JSON Schema, HTML reports, API, audit, dashboard, and Gradio functionality remains.

## Validate locally

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
bash scripts/validate_local.sh
```

No GitHub Actions are required or expected.

## Run scenarios

```bash
PYTHONPATH=src python3 -m honey_agent_lab list-scenarios
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_005 --verbose
```

`scenario_005` demonstrates escalation across multiple turns: benign → warn → quarantine. Risk context is scoped to that scenario run and is discarded afterward.

## Documentation

See `docs/SPEC_v0.6.md`, `docs/RULE_CONFIG.md`, `docs/FUZZING.md`, `docs/API.md`, `docs/THREAT_MODEL.md`, and `docs/HF_SPACE.md`.

## Non-goals

Honey Agent Lab must not become an offensive recruiter, credential harvester, social-engineering automation tool, scanner, live exploitation framework, or covert coordination system.
