# Honey Agent Lab

**Honey Agent Lab** is a defensive simulation lab for detecting agent-to-agent compromise, unauthorized coordination, and recruitment attempts in synthetic multi-agent environments.

The project is deliberately boring in the right places: no real credentials, no live exploitation, no agent-to-agent manipulation against third-party systems, no autonomous outbound network behavior. All adversarial behavior is represented as synthetic fixtures.

## Status

Version: `0.3.0`

This release hardens:

- immutable, hash-chained audit events with optional local JSONL persistence;
- precompiled boundary-aware risk matching with contextual evidence;
- declarative compound containment policy with `allow`, `warn`, `isolate`, and `quarantine`;
- scripted scenario runner;
- safe Hugging Face Space demo stub;
- project guardrails for defensive-only development.

## Install locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Validate locally

No GitHub Actions are required or expected.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Run a scenario

```bash
PYTHONPATH=src python3 -m honey_agent_lab list-scenarios
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --json
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --export-audit /tmp/honey-agent-audit.jsonl
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --output-html /tmp/honey-agent-dashboard.html
PYTHONPATH=src python3 -m honey_agent_lab verify-audit /tmp/honey-agent-audit.jsonl
```

Expected defensive response for `scenario_001`:

```text
Action: quarantine
Risk: critical / 100
```

## Architecture

```text
Synthetic messages
      |
      v
Simulated Agent Bus
      |
      v
Honey Agent observer
      |
      +--> Risk Engine --> explainable findings
      |
      +--> Policy Engine --> allow/warn/isolate/quarantine
      |
      v
Append-only Audit Ledger --> JSONL export --> human review
```

See [`docs/SPEC_v0.3.md`](docs/SPEC_v0.3.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## GitHub bootstrap

Target repository:

```text
https://github.com/ales27pm/honey-agent-lab
```

From this folder:

```bash
git init
git branch -M main
git remote add origin https://github.com/ales27pm/honey-agent-lab.git
git add .
git commit -m "init: scaffold honey agent defensive lab"
git push -u origin main
```

## Hugging Face Space demo

A safe Gradio demo is included at [`app.py`](app.py), with deployment notes in [`docs/HF_SPACE.md`](docs/HF_SPACE.md). It runs only local synthetic scenarios.

Deployment concept:

1. Create a Hugging Face Space using Gradio.
2. Copy this repo's `src/` package into the Space.
3. Use the repository root `app.py` and `requirements.txt` as the Space entrypoint and dependency file.
4. Keep secrets disabled.
5. Keep outbound integrations disabled.

## Non-goals

This project must not become:

- an offensive recruiter agent;
- a credential harvester;
- a social-engineering automation tool;
- a network scanner;
- a live exploitation framework;
- a covert coordination tool.

Honey Agent Lab detects synthetic compromise patterns and demonstrates containment. That is the product boundary.
