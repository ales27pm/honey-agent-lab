# Runbook

## Local validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Run all default checks

```bash
scripts/validate_local.sh
```

## Run scenario 001

```bash
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001
```

## Export audit log

```bash
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 --export-audit /tmp/honey-agent-audit.jsonl
```

## Expected response

```text
Risk: critical / 100
Action: quarantine
Audit integrity: True
```
