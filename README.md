# Honey Agent Lab

**Honey Agent Lab** is a defensive simulation lab for detecting agent-to-agent compromise, unauthorized coordination, and recruitment attempts in synthetic multi-agent environments.

The project has a strict boundary: no real credentials, live exploitation, third-party agent manipulation, network scanning, or autonomous outbound behavior. All adversarial behavior is inert synthetic fixture data.

## Status

Version: `0.4.0`

v0.4 adds:

- validated declarative JSON risk rules;
- deterministic synthetic fuzzing for defensive coverage measurement;
- an optional loopback-first FastAPI service;
- all v0.3 audit, scoring, policy, dashboard, scenario, and Gradio functionality.

## Validate locally

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
bash scripts/validate_local.sh
```

No GitHub Actions are required or expected.

## Run scenarios

```bash
PYTHONPATH=src python3 -m honey_agent_lab list-scenarios
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --verbose
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --rules custom-rules.json
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --export-audit /tmp/honey-agent-audit.jsonl
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --output-html /tmp/honey-agent-dashboard.html
PYTHONPATH=src python3 -m honey_agent_lab verify-audit /tmp/honey-agent-audit.jsonl
```

## Synthetic fuzzing

```bash
PYTHONPATH=src python3 -m honey_agent_lab fuzz --limit 100 --seed 42
PYTHONPATH=src python3 -m honey_agent_lab fuzz --limit 20 --seed 1 --json
```

Fuzzing is deterministic, local, and never sends generated messages externally.

## Optional local API

```bash
pip install -e '.[api]'
PYTHONPATH=src python3 -m honey_agent_lab serve
```

Default binding is `127.0.0.1:8000`. A non-loopback bind is refused unless `--allow-remote` is explicitly supplied. The API has no authentication and is intended only for a trusted isolated lab environment.

Endpoints:

- `GET /health`
- `GET /scenarios`
- `POST /run/{scenario_name}`

## Architecture

```text
Synthetic messages / fuzz fixtures
      |
      v
Simulated Agent Bus
      |
      v
Honey Agent observer
      |
      +--> Risk Engine --> validated rules --> explainable findings
      |
      +--> Policy Engine --> allow/warn/isolate/quarantine
      |
      v
Hash-chained Audit Ledger --> JSONL / dashboard --> human review
```

## Documentation

See `docs/SPEC_v0.4.md`, `docs/RULE_CONFIG.md`, `docs/FUZZING.md`, `docs/API.md`, `docs/THREAT_MODEL.md`, and `docs/HF_SPACE.md`.

## Non-goals

Honey Agent Lab must not become an offensive recruiter, credential harvester, social-engineering automation tool, scanner, live exploitation framework, or covert coordination system.
