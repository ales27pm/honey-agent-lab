# Synthetic fuzzing

`fuzz` generates deterministic inert lab messages from curated synthetic fragments. It never performs network I/O and never targets real systems.

```bash
PYTHONPATH=src python -m honey_agent_lab fuzz --limit 100 --seed 42
PYTHONPATH=src python -m honey_agent_lab fuzz --limit 20 --seed 1 --max-fragments 4 --obfuscation-prob 0.5 --json
PYTHONPATH=src python -m honey_agent_lab fuzz --limit 50 --seed 7 --output-html /tmp/honey-agent-fuzz.html
```

`--max-fragments` controls how many curated synthetic signals may be combined in one fixture. `--obfuscation-prob` controls bounded test transformations such as case changes, character separators, and curated paraphrases. These transformations are local fixture mutations only.

The summary reports action/severity counts, signal coverage, obfuscated-message count, and potential false-negative candidates. A false-negative candidate is a synthetic attack-labelled fixture that receives only `allow` or `warn`; it is a review candidate, not proof of vulnerability.

HTML reports contain aggregate coverage data and candidate message IDs only. They are static, escaped, dependency-free, and suitable for local review or printing.
