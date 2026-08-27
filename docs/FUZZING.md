# Synthetic fuzzing
`fuzz` generates deterministic inert lab messages from curated synthetic fragments. It never performs network I/O and never targets real systems.

```bash
PYTHONPATH=src python -m honey_agent_lab fuzz --limit 100 --seed 42
PYTHONPATH=src python -m honey_agent_lab fuzz --limit 20 --seed 1 --json
```

The summary reports action/severity counts, signal coverage, and potential false-negative candidates (synthetic attack-labelled fixtures that receive only allow/warn). These are review candidates, not proof of vulnerability.
