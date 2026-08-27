# Declarative risk rules
Rules are validated JSON objects in an array. Required fields: `code`, `score`, `severity`, `reason`, `keywords`. Codes must use uppercase letters, digits, and underscores; scores are 0–100; severities are `none|low|medium|high|critical`; keywords must be a non-empty unique list. Invalid configuration fails closed with `ValueError`.

Default: `src/honey_agent_lab/data/default_rules.json`.
